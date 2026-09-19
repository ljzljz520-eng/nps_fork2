package credential

import (
	"errors"
	"os"
	"strings"
	"sync"
)

// Environment variables used to externally inject master keys. Inline values
// and file-backed values are both supported; the dual previous-key slots open
// the rotation window during which envelopes sealed under the retired key can
// still be read while new writes use the incoming key.
const (
	EnvMasterKey         = "NPS_CREDENTIAL_MASTER_KEY"
	EnvMasterKeyFile     = "NPS_CREDENTIAL_MASTER_KEY_FILE"
	EnvMasterKeyID       = "NPS_CREDENTIAL_MASTER_KEY_ID"
	EnvPreviousKey       = "NPS_CREDENTIAL_PREVIOUS_KEY"
	EnvPreviousKeyFile   = "NPS_CREDENTIAL_PREVIOUS_KEY_FILE"
	EnvPreviousKeyID     = "NPS_CREDENTIAL_PREVIOUS_KEY_ID"
	DefaultCurrentKeyID  = "current"
	DefaultPreviousKeyID = "previous"
)

// KeyConfig injects one master key into the ring.
type KeyConfig struct {
	ID       string
	Material string
	File     string
}

// Config configures the credential manager from externally supplied material.
type Config struct {
	Current  KeyConfig
	Previous KeyConfig
}

type keyEntry struct {
	id  string
	key []byte
}

// Manager is a master key ring. It seals new envelopes under the current key
// and can open envelopes sealed under either the current or the immediately
// previous key, providing a two-key rotation window.
type Manager struct {
	mu       sync.RWMutex
	enabled  bool
	current  keyEntry
	previous *keyEntry
}

var (
	defaultManager     *Manager
	defaultManagerOnce sync.Once
)

// NewManager builds a manager from injected configuration. With no current key
// the manager is disabled and secret fields pass through unchanged; this keeps
// zero-config and test deployments working while any envelope that does appear
// still fails closed because it cannot be opened.
func NewManager(config Config) (*Manager, error) {
	manager := &Manager{}
	if err := manager.Configure(config); err != nil {
		return nil, err
	}
	return manager, nil
}

// Configure replaces the complete key ring.
func (m *Manager) Configure(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.current = keyEntry{}
	m.previous = nil
	m.enabled = false

	currentMaterial := readKeyMaterial(config.Current.Material, config.Current.File)
	currentKey := NormalizeMasterKey(currentMaterial)
	if len(currentKey) != masterKeySize {
		// No current key: encryption disabled. A configured-but-invalid value is
		// treated as absent so operators can disable the subsystem cleanly.
		return nil
	}
	currentID := strings.TrimSpace(config.Current.ID)
	if currentID == "" {
		currentID = DefaultCurrentKeyID
	}
	if err := validateKeyID(currentID); err != nil {
		return err
	}
	m.current = keyEntry{id: currentID, key: currentKey}
	m.enabled = true

	previousMaterial := readKeyMaterial(config.Previous.Material, config.Previous.File)
	if previousKey := NormalizeMasterKey(previousMaterial); len(previousKey) == masterKeySize {
		previousID := strings.TrimSpace(config.Previous.ID)
		if previousID == "" {
			previousID = DefaultPreviousKeyID
		}
		if err := validateKeyID(previousID); err != nil {
			return err
		}
		if previousID != currentID {
			m.previous = &keyEntry{id: previousID, key: previousKey}
		}
	}
	return nil
}

// Enabled reports whether at-rest authenticated encryption is active.
func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// CurrentKeyID returns the id used to seal new envelopes.
func (m *Manager) CurrentKeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current.id
}

// HasPreviousKey reports whether a retired key is still available for reads.
func (m *Manager) HasPreviousKey() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.previous != nil
}

// PreviousKeyID returns the retired key id during a rotation window.
func (m *Manager) PreviousKeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.previous == nil {
		return ""
	}
	return m.previous.id
}

// BeginRotation demotes the current key to the previous slot and installs the
// incoming key as current. After this call new envelopes use newKey while
// envelopes sealed under the old current key remain readable. Batch
// re-encryption should follow; once every ciphertext has been re-sealed the
// caller invokes RevokePreviousKey to close the window.
func (m *Manager) BeginRotation(newKey KeyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	material := readKeyMaterial(newKey.Material, newKey.File)
	normalized := NormalizeMasterKey(material)
	if len(normalized) != masterKeySize {
		return errors.New("credential: rotation requires a valid new master key")
	}
	id := strings.TrimSpace(newKey.ID)
	if id == "" {
		id = DefaultCurrentKeyID
	}
	if err := validateKeyID(id); err != nil {
		return err
	}
	if m.enabled {
		if id == m.current.id {
			return errors.New("credential: new rotation key id must differ from the current key id")
		}
		demoted := m.current
		m.previous = &demoted
	}
	m.current = keyEntry{id: id, key: normalized}
	m.enabled = true
	return nil
}

// RevokePreviousKey drops the retired key, closing the rotation window. Any
// envelope still sealed under it will subsequently fail closed.
func (m *Manager) RevokePreviousKey() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.previous == nil {
		return false
	}
	m.previous = nil
	return true
}

// SealString encrypts plaintext for the named field. Empty values pass through
// (an absent secret is not encrypted), already enveloped values are left
// untouched to keep repeated persistence idempotent, and a disabled manager
// returns the value unchanged.
func (m *Manager) SealString(field Field, plaintext string) (string, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" || IsEnvelope(plaintext) {
		return plaintext, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.enabled {
		return plaintext, nil
	}
	return sealPlaintext(m.current.key, m.current.id, field, []byte(plaintext))
}

// OpenString decrypts an envelope bound to field. Legacy plaintext values are
// returned unchanged so old records remain readable; any envelope that is
// malformed, references a missing key, or fails authentication returns an
// error and must never be treated as plaintext (fail closed).
func (m *Manager) OpenString(field Field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !IsEnvelope(value) {
		return value, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.enabled {
		return "", errors.New("credential: encrypted value present but credential manager is disabled")
	}
	plaintext, err := openEnvelope(m.lookupKeyLocked, field, value)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// NeedsReencryption reports whether an envelope was sealed under a non-current
// key and therefore should be re-sealed during a batch rotation pass.
func (m *Manager) NeedsReencryption(value string) bool {
	if !IsEnvelope(value) {
		// Plaintext legacy values are always candidates for sealing.
		return strings.TrimSpace(value) != ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	body, err := decodeBody(strings.TrimPrefix(value, envelopePrefix))
	if err != nil {
		return false
	}
	_, keyID, _, _, _, _, err := parseEnvelopeBody(body)
	if err != nil {
		return false
	}
	return keyID != m.current.id
}

func (m *Manager) lookupKeyLocked(keyID string) ([]byte, bool) {
	if m.current.id == keyID {
		return m.current.key, true
	}
	if m.previous != nil && m.previous.id == keyID {
		return m.previous.key, true
	}
	return nil, false
}

// Default returns the process-wide manager, lazily initializing it from the
// injected environment the first time it is required.
func Default() *Manager {
	defaultManagerOnce.Do(func() {
		defaultManager, _ = NewManager(configFromEnvironment())
	})
	return defaultManager
}

// ConfigureDefault replaces the process-wide manager. It is intended for
// explicit startup wiring and tests. The installed manager is pinned as the
// resolved default: the existing once is marked done in place so a subsequent
// lazy Default() call does not re-read the environment and clobber the
// explicit configuration (ResetDefault restores that environment-lazy
// behavior).
func ConfigureDefault(config Config) error {
	manager, err := NewManager(config)
	if err != nil {
		return err
	}
	defaultManager = manager
	defaultManagerOnce.Do(func() {})
	return nil
}

// ResetDefault clears the process-wide manager so the next Default() call
// re-reads the environment. Test-only helper.
func ResetDefault() {
	defaultManagerOnce = sync.Once{}
	defaultManager = nil
}

func configFromEnvironment() Config {
	return Config{
		Current: KeyConfig{
			ID:       firstNonEmpty(os.Getenv(EnvMasterKeyID), DefaultCurrentKeyID),
			Material: os.Getenv(EnvMasterKey),
			File:     os.Getenv(EnvMasterKeyFile),
		},
		Previous: KeyConfig{
			ID:       firstNonEmpty(os.Getenv(EnvPreviousKeyID), DefaultPreviousKeyID),
			Material: os.Getenv(EnvPreviousKey),
			File:     os.Getenv(EnvPreviousKeyFile),
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// SealString seals against the default manager.
func SealString(objectType string, objectID int64, field, plaintext string) (string, error) {
	return Default().SealString(Field{ObjectType: objectType, ObjectID: objectID, Name: field}, plaintext)
}

// OpenString opens against the default manager.
func OpenString(objectType string, objectID int64, field, value string) (string, error) {
	return Default().OpenString(Field{ObjectType: objectType, ObjectID: objectID, Name: field}, value)
}
