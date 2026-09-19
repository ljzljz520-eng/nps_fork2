package file

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/djylb/nps/lib/credential"
)

// Object type identifiers bound into authenticated-encryption additional data.
// They are part of the security contract and must never be renumbered.
const (
	aeadObjectUser   = "user"
	aeadObjectClient = "client"
	aeadObjectTunnel = "tunnel"
	aeadObjectHost   = "host"
)

// marshalPersistedValue marshals one stored record and encrypts its secrets.
func marshalPersistedValue(value any) ([]byte, error) {
	switch value.(type) {
	case *User:
		return marshalPersistedObject(aeadObjectUser, value)
	case *Client:
		return marshalPersistedObject(aeadObjectClient, value)
	case *Tunnel:
		return marshalPersistedObject(aeadObjectTunnel, value)
	case *Host:
		return marshalPersistedObject(aeadObjectHost, value)
	default:
		return json.Marshal(value)
	}
}

// marshalPersistedObject marshals one stored record and encrypts its secrets at
// rest. When no master key is injected records are marshalled exactly as
// before, keeping zero-config deployments and their on-disk format unchanged.
func marshalPersistedObject(objType string, value any) ([]byte, error) {
	if !credential.Default().Enabled() {
		return json.Marshal(value)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode %s for sealing: %w", objType, err)
	}
	if err := sealSensitiveMap(objType, doc); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// openPersistedArray decrypts every record in a persisted JSON array. Legacy
// plaintext records pass through unchanged; any envelope that is malformed,
// references a missing key, or fails authentication aborts the load so the
// process fails closed instead of silently treating ciphertext as plaintext.
func openPersistedArray(objType string, raw []byte) ([][]byte, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, err
	}
	opened := make([][]byte, 0, len(elements))
	for _, element := range elements {
		plain, err := openPersistedObject(objType, element)
		if err != nil {
			return nil, err
		}
		opened = append(opened, plain)
	}
	return opened, nil
}

// openPersistedObject decrypts the sensitive fields of one JSON record.
func openPersistedObject(objType string, raw json.RawMessage) ([]byte, error) {
	if !credential.Default().Enabled() && !bytes.Contains(raw, []byte(credential.EnvelopePrefix)) {
		return raw, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode %s for opening: %w", objType, err)
	}
	if err := openSensitiveMap(objType, doc); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

func sealSensitiveMap(objType string, doc map[string]any) error {
	id := mapObjectID(doc)
	switch objType {
	case aeadObjectUser:
		return sealUserSecrets(id, doc)
	case aeadObjectClient:
		return sealClientSecrets(id, doc)
	case aeadObjectTunnel:
		return sealTunnelSecrets(id, doc)
	case aeadObjectHost:
		return sealHostSecrets(id, doc)
	default:
		return nil
	}
}

func openSensitiveMap(objType string, doc map[string]any) error {
	id := mapObjectID(doc)
	switch objType {
	case aeadObjectUser:
		return openUserSecrets(id, doc)
	case aeadObjectClient:
		return openClientSecrets(id, doc)
	case aeadObjectTunnel:
		return openTunnelSecrets(id, doc)
	case aeadObjectHost:
		return openHostSecrets(id, doc)
	default:
		return nil
	}
}

func sealUserSecrets(id int64, doc map[string]any) error {
	return sealField(doc, "TOTPSecret", aeadObjectUser, id, "TOTPSecret")
}

func openUserSecrets(id int64, doc map[string]any) error {
	return openField(doc, "TOTPSecret", aeadObjectUser, id, "TOTPSecret")
}

func sealClientSecrets(id int64, doc map[string]any) error {
	if err := sealField(doc, "VerifyKey", aeadObjectClient, id, "VerifyKey"); err != nil {
		return err
	}
	if config, ok := doc["Cnf"].(map[string]any); ok {
		if err := sealField(config, "P", aeadObjectClient, id, "Cnf.P"); err != nil {
			return err
		}
	}
	return nil
}

func openClientSecrets(id int64, doc map[string]any) error {
	if err := openField(doc, "VerifyKey", aeadObjectClient, id, "VerifyKey"); err != nil {
		return err
	}
	if config, ok := doc["Cnf"].(map[string]any); ok {
		if err := openField(config, "P", aeadObjectClient, id, "Cnf.P"); err != nil {
			return err
		}
	}
	return nil
}

func sealTunnelSecrets(id int64, doc map[string]any) error {
	if err := sealField(doc, "Password", aeadObjectTunnel, id, "Password"); err != nil {
		return err
	}
	if err := sealMultiAccount(doc, "UserAuth", aeadObjectTunnel, id); err != nil {
		return err
	}
	if err := sealMultiAccount(doc, "MultiAccount", aeadObjectTunnel, id); err != nil {
		return err
	}
	return sealNestedClient(doc)
}

func openTunnelSecrets(id int64, doc map[string]any) error {
	if err := openField(doc, "Password", aeadObjectTunnel, id, "Password"); err != nil {
		return err
	}
	if err := openMultiAccount(doc, "UserAuth", aeadObjectTunnel, id); err != nil {
		return err
	}
	if err := openMultiAccount(doc, "MultiAccount", aeadObjectTunnel, id); err != nil {
		return err
	}
	return openNestedClient(doc)
}

func sealHostSecrets(id int64, doc map[string]any) error {
	if err := sealMultiAccount(doc, "UserAuth", aeadObjectHost, id); err != nil {
		return err
	}
	if err := sealMultiAccount(doc, "MultiAccount", aeadObjectHost, id); err != nil {
		return err
	}
	return sealNestedClient(doc)
}

func openHostSecrets(id int64, doc map[string]any) error {
	if err := openMultiAccount(doc, "UserAuth", aeadObjectHost, id); err != nil {
		return err
	}
	if err := openMultiAccount(doc, "MultiAccount", aeadObjectHost, id); err != nil {
		return err
	}
	return openNestedClient(doc)
}

func sealNestedClient(doc map[string]any) error {
	client, ok := doc["Client"].(map[string]any)
	if !ok {
		return nil
	}
	return sealClientSecrets(mapObjectID(client), client)
}

func openNestedClient(doc map[string]any) error {
	client, ok := doc["Client"].(map[string]any)
	if !ok {
		return nil
	}
	return openClientSecrets(mapObjectID(client), client)
}

func sealMultiAccount(doc map[string]any, key, objectType string, id int64) error {
	account, ok := doc[key].(map[string]any)
	if !ok {
		return nil
	}
	if err := sealField(account, "Content", objectType, id, key+".Content"); err != nil {
		return err
	}
	entries, ok := account["AccountMap"].(map[string]any)
	if !ok {
		return nil
	}
	for name, value := range entries {
		secret, ok := value.(string)
		if !ok || secret == "" {
			continue
		}
		sealed, err := credential.SealString(objectType, id, key+".AccountMap", secret)
		if err != nil {
			return fmt.Errorf("seal %s.%s: %w", key, name, err)
		}
		entries[name] = sealed
	}
	return nil
}

func openMultiAccount(doc map[string]any, key, objectType string, id int64) error {
	account, ok := doc[key].(map[string]any)
	if !ok {
		return nil
	}
	if err := openField(account, "Content", objectType, id, key+".Content"); err != nil {
		return err
	}
	entries, ok := account["AccountMap"].(map[string]any)
	if !ok {
		return nil
	}
	for name, value := range entries {
		secret, ok := value.(string)
		if !ok || secret == "" {
			continue
		}
		opened, err := credential.OpenString(objectType, id, key+".AccountMap", secret)
		if err != nil {
			return fmt.Errorf("open %s.%s: %w", key, name, err)
		}
		entries[name] = opened
	}
	return nil
}

func sealField(doc map[string]any, key, objectType string, id int64, field string) error {
	value, ok := doc[key].(string)
	if !ok || value == "" {
		return nil
	}
	sealed, err := credential.SealString(objectType, id, field, value)
	if err != nil {
		return fmt.Errorf("seal %s: %w", field, err)
	}
	doc[key] = sealed
	return nil
}

func openField(doc map[string]any, key, objectType string, id int64, field string) error {
	value, ok := doc[key].(string)
	if !ok || value == "" {
		return nil
	}
	opened, err := credential.OpenString(objectType, id, field, value)
	if err != nil {
		return fmt.Errorf("open %s: %w", field, err)
	}
	doc[key] = opened
	return nil
}

func mapObjectID(doc map[string]any) int64 {
	switch value := doc["Id"].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	case string:
		var parsed int64
		_, _ = fmt.Sscanf(value, "%d", &parsed)
		return parsed
	default:
		return 0
	}
}

// MaskConfigSnapshot replaces every secret in an exported configuration
// snapshot with a non-reversible marker so a default export never discloses
// passwords, TOTP secrets, verify keys, tunnel passwords or proxy accounts.
// The snapshot is mutated in place and returned for convenience.
func MaskConfigSnapshot(snapshot *ConfigSnapshot) *ConfigSnapshot {
	if snapshot == nil {
		return nil
	}
	for _, user := range snapshot.Users {
		maskUserConfigSecrets(user)
	}
	for _, client := range snapshot.Clients {
		maskClientConfigSecrets(client)
	}
	for _, tunnel := range snapshot.Tunnels {
		maskTunnelConfigSecrets(tunnel)
	}
	for _, host := range snapshot.Hosts {
		maskHostConfigSecrets(host)
	}
	return snapshot
}

func maskUserConfigSecrets(user *User) {
	if user == nil {
		return
	}
	user.Password = credential.MaskSecret(user.Password)
	user.TOTPSecret = credential.MaskSecret(user.TOTPSecret)
}

func maskClientConfigSecrets(client *Client) {
	if client == nil {
		return
	}
	client.VerifyKey = credential.MaskSecret(client.VerifyKey)
	if client.Cnf != nil {
		client.Cnf.P = credential.MaskSecret(client.Cnf.P)
	}
}

func maskTunnelConfigSecrets(tunnel *Tunnel) {
	if tunnel == nil {
		return
	}
	tunnel.Password = credential.MaskSecret(tunnel.Password)
	maskMultiAccountSecrets(tunnel.UserAuth)
	maskMultiAccountSecrets(tunnel.MultiAccount)
	maskClientConfigSecrets(tunnel.Client)
}

func maskHostConfigSecrets(host *Host) {
	if host == nil {
		return
	}
	maskMultiAccountSecrets(host.UserAuth)
	maskMultiAccountSecrets(host.MultiAccount)
	maskClientConfigSecrets(host.Client)
}

func maskMultiAccountSecrets(account *MultiAccount) {
	if account == nil {
		return
	}
	account.Content = credential.MaskSecret(account.Content)
	for name, secret := range account.AccountMap {
		account.AccountMap[name] = credential.MaskSecret(secret)
	}
}

// RewriteCredentialSeals re-persists every credential-bearing record so its
// secrets are sealed under the currently active master key. During the
// dual-key rotation window, install the incoming key (which retains the old
// key for reads), call this to batch-re-encrypt all four stores, then verify
// completion with CredentialRotationComplete and revoke the old key.
func (s *DbUtils) RewriteCredentialSeals() error {
	if s == nil || s.JsonDb == nil {
		return errors.New("credential: database is not initialized")
	}
	if !credential.Default().Enabled() {
		// No master key ring: there is nothing sealed to re-encrypt.
		return nil
	}
	backend := s.JsonDb.persistenceBackend()
	stores := []func(*JsonDb) error{
		backend.StoreUsers,
		backend.StoreClients,
		backend.StoreTasks,
		backend.StoreHosts,
	}
	for _, store := range stores {
		if err := store(s.JsonDb); err != nil {
			return err
		}
	}
	return nil
}

// CredentialRotationComplete reports that no persisted envelope still
// references the previous key id, i.e. every secret was re-sealed under the
// current key and the retired key is safe to revoke. With no previous key
// configured it reports complete.
func (s *DbUtils) CredentialRotationComplete() (bool, error) {
	if s == nil || s.JsonDb == nil {
		return false, errors.New("credential: database is not initialized")
	}
	manager := credential.Default()
	previousID := manager.PreviousKeyID()
	if previousID == "" {
		return true, nil
	}
	for _, filePath := range s.credentialStorePaths() {
		raw, err := readPersistedFile(filePath)
		if err != nil {
			return false, err
		}
		uses, err := fileContainsEnvelopeForKey(raw, previousID)
		if err != nil {
			return false, fmt.Errorf("scan %s for rotation completion: %w", filePath, err)
		}
		if uses {
			return false, nil
		}
	}
	return true, nil
}

// CompleteCredentialRotation batch re-encrypts every store and, once no record
// references the previous key, revokes it. The returned boolean reports whether
// a previous key was actually revoked.
func (s *DbUtils) CompleteCredentialRotation() (bool, error) {
	if err := s.RewriteCredentialSeals(); err != nil {
		return false, err
	}
	complete, err := s.CredentialRotationComplete()
	if err != nil || !complete {
		return false, err
	}
	return credential.Default().RevokePreviousKey(), nil
}

func (s *DbUtils) credentialStorePaths() []string {
	return []string{
		s.JsonDb.UserFilePath,
		s.JsonDb.ClientFilePath,
		s.JsonDb.TaskFilePath,
		s.JsonDb.HostFilePath,
	}
}

// fileContainsEnvelopeForKey walks arbitrary JSON and reports whether any
// string is an envelope sealed under keyID.
func fileContainsEnvelopeForKey(raw []byte, keyID string) (bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false, nil
	}
	var document any
	if err := json.Unmarshal(trimmed, &document); err != nil {
		return false, err
	}
	found := false
	var walk func(any)
	walk = func(node any) {
		if found {
			return
		}
		switch value := node.(type) {
		case map[string]any:
			for _, child := range value {
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		case string:
			if envelopeID, ok := credential.EnvelopeKeyID(value); ok && envelopeID == keyID {
				found = true
			}
		}
	}
	walk(document)
	return found, nil
}

// persistedObjectType maps a record template to its AEAD object type.
func persistedObjectType(template any) string {
	switch template.(type) {
	case User:
		return aeadObjectUser
	case Client:
		return aeadObjectClient
	case Tunnel:
		return aeadObjectTunnel
	case Host:
		return aeadObjectHost
	default:
		return ""
	}
}

// decodePersistedObject unmarshals an opened record into the concrete type
// indicated by template and hands it to the sink.
func decodePersistedObject(raw []byte, template any, sink func(any)) error {
	switch template.(type) {
	case User:
		var value User
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		sink(&value)
	case Client:
		var value Client
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		sink(&value)
	case Tunnel:
		var value Tunnel
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		sink(&value)
	case Host:
		var value Host
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		sink(&value)
	}
	return nil
}
