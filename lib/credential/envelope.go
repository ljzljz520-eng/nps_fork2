package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	// envelopeVersion is the on-wire envelope format version.
	envelopeVersion byte = 1
	// envelopePrefix prefixes every serialized envelope so encrypted values can
	// be distinguished from legacy plaintext values at read time.
	envelopePrefix = "npsae1."
	// EnvelopePrefix is the exported marker for serialized envelopes.
	EnvelopePrefix = envelopePrefix
	// envelopeMagic identifies an nps authenticated-encryption token.
	envelopeMagic = "NPSE"
	// keyIDMaxLength bounds the master key identifier.
	keyIDMaxLength = 128
	// masterKeySize is the expected size of a normalized master key.
	masterKeySize = 32
	// dekSize is the per-field data encryption key size for AES-256-GCM.
	dekSize = 32
	// wrapSaltSize is the HKDF salt used when deriving a per-envelope wrap key.
	wrapSaltSize = 16
	// gcmNonceSize is the standard AES-GCM nonce size.
	gcmNonceSize = 12
)

// Field designates the protected location of a secret. The object type and
// object id authenticate that a ciphertext cannot be moved onto a different
// object; the field name additionally prevents a ciphertext from being moved
// between two secrets on the same object.
type Field struct {
	ObjectType string
	ObjectID   int64
	Name       string
}

var (
	// ErrCorruptCiphertext is returned for a structurally invalid envelope.
	ErrCorruptCiphertext = errors.New("credential: corrupt or tampered ciphertext")
	// ErrUnknownKey is returned when an envelope references a key id that is no
	// longer present in the active key ring.
	ErrUnknownKey = errors.New("credential: unknown data key id")
	// ErrFieldMismatch is returned when an envelope is opened against a
	// different object type/id/field than it was sealed for.
	ErrFieldMismatch = errors.New("credential: ciphertext additional data mismatch")
	// ErrKeyIDInvalid is returned when a master key id is empty or too long.
	ErrKeyIDInvalid = errors.New("credential: invalid master key id")
)

// IsEnvelope reports whether value is a serialized authenticated envelope.
func IsEnvelope(value string) bool {
	return strings.HasPrefix(value, envelopePrefix)
}

// EnvelopeKeyID returns the master key id embedded in an envelope token. The
// boolean is false for plaintext values or envelopes that cannot be parsed.
func EnvelopeKeyID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !IsEnvelope(value) {
		return "", false
	}
	body, err := decodeBody(strings.TrimPrefix(value, envelopePrefix))
	if err != nil {
		return "", false
	}
	_, keyID, _, _, _, _, err := parseEnvelopeBody(body)
	if err != nil {
		return "", false
	}
	return keyID, true
}

// sealPlaintext encrypts plaintext with a freshly generated data key, wraps the
// data key under the master key identified by keyID, and returns the serialized
// envelope token.
func sealPlaintext(masterKey []byte, keyID string, field Field, plaintext []byte) (string, error) {
	if err := validateKeyID(keyID); err != nil {
		return "", err
	}
	if err := validateField(field); err != nil {
		return "", err
	}
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("credential: generate data key: %w", err)
	}
	wrapSalt := make([]byte, wrapSaltSize)
	if _, err := io.ReadFull(rand.Reader, wrapSalt); err != nil {
		return "", fmt.Errorf("credential: generate wrap salt: %w", err)
	}
	wrappedDEK, err := wrapDEK(masterKey, keyID, wrapSalt, dek)
	if err != nil {
		return "", err
	}
	gcm, err := newFieldGCM(dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("credential: generate nonce: %w", err)
	}
	additionalData := buildAdditionalData(envelopeVersion, field)
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)

	body := make([]byte, 0, len(envelopeMagic)+1+1+len(keyID)+wrapSaltSize+2+len(wrappedDEK)+gcmNonceSize+len(ciphertext))
	body = append(body, envelopeMagic...)
	body = append(body, envelopeVersion)
	idBytes := []byte(keyID)
	body = append(body, byte(len(idBytes)))
	body = append(body, idBytes...)
	body = append(body, wrapSalt...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(wrappedDEK)))
	body = append(body, wrappedDEK...)
	body = append(body, nonce...)
	body = append(body, ciphertext...)
	return envelopePrefix + encodeBody(body), nil
}

// openEnvelope authenticates and decrypts a serialized envelope using the
// master key selected by keyLookup, binding the result to field.
func openEnvelope(keyLookup func(keyID string) ([]byte, bool), field Field, token string) ([]byte, error) {
	if err := validateField(field); err != nil {
		return nil, err
	}
	body, err := decodeBody(strings.TrimPrefix(token, envelopePrefix))
	if err != nil {
		return nil, err
	}
	version, keyID, wrapSalt, wrappedDEK, nonce, ciphertext, err := parseEnvelopeBody(body)
	if err != nil {
		return nil, err
	}
	masterKey, ok := keyLookup(keyID)
	if !ok || len(masterKey) != masterKeySize {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	dek, err := unwrapDEK(masterKey, keyID, wrapSalt, wrappedDEK)
	if err != nil {
		return nil, err
	}
	gcm, err := newFieldGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, openErr := gcm.Open(nil, nonce, ciphertext, buildAdditionalData(version, field))
	if openErr != nil {
		// A GCM failure means the payload was altered or opened for the wrong
		// object/field. Collapse both into a fail-closed verification error.
		return nil, fmt.Errorf("%w: %v", ErrCorruptCiphertext, openErr)
	}
	return plaintext, nil
}

// buildAdditionalData constructs the canonical authenticated context. The
// object type and object id are the required bindings; the envelope version and
// field name further constrain where the ciphertext may be used.
func buildAdditionalData(version byte, field Field) []byte {
	var builder strings.Builder
	builder.WriteString("nps-credential\x00")
	builder.WriteByte(version)
	builder.WriteByte(0)
	builder.WriteString(field.ObjectType)
	builder.WriteByte(0)
	builder.WriteString(strconv.FormatInt(field.ObjectID, 10))
	builder.WriteByte(0)
	builder.WriteString(field.Name)
	return []byte(builder.String())
}

func wrapDEK(masterKey []byte, keyID string, salt, dek []byte) ([]byte, error) {
	gcm, err := newWrapGCM(masterKey, keyID, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("credential: generate wrap nonce: %w", err)
	}
	wrapped := gcm.Seal(nil, nonce, dek, []byte(wrapContext(keyID)))
	return append(nonce, wrapped...), nil
}

func unwrapDEK(masterKey []byte, keyID string, salt, wrapped []byte) ([]byte, error) {
	gcm, err := newWrapGCM(masterKey, keyID, salt)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcmNonceSize+gcm.Overhead() {
		return nil, ErrCorruptCiphertext
	}
	nonce, payload := wrapped[:gcmNonceSize], wrapped[gcmNonceSize:]
	dek, err := gcm.Open(nil, nonce, payload, []byte(wrapContext(keyID)))
	if err != nil {
		return nil, fmt.Errorf("%w: data key unwrap failed", ErrCorruptCiphertext)
	}
	if len(dek) != dekSize {
		return nil, ErrCorruptCiphertext
	}
	return dek, nil
}

func deriveWrapKey(masterKey []byte, keyID string, salt []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, salt, []byte(wrapContext(keyID)))
	wrapKey := make([]byte, masterKeySize)
	if _, err := io.ReadFull(reader, wrapKey); err != nil {
		return nil, fmt.Errorf("credential: derive wrap key: %w", err)
	}
	return wrapKey, nil
}

func wrapContext(keyID string) string {
	return "nps-credential/v1/dek-wrap/" + keyID
}

func newFieldGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credential: field cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credential: field gcm: %w", err)
	}
	return gcm, nil
}

func newWrapGCM(masterKey []byte, keyID string, salt []byte) (cipher.AEAD, error) {
	wrapKey, err := deriveWrapKey(masterKey, keyID, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("credential: wrap cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credential: wrap gcm: %w", err)
	}
	return gcm, nil
}

func validateKeyID(keyID string) error {
	if keyID == "" || len(keyID) > keyIDMaxLength {
		return ErrKeyIDInvalid
	}
	return nil
}

func validateField(field Field) error {
	if strings.TrimSpace(field.ObjectType) == "" || strings.TrimSpace(field.Name) == "" {
		return ErrFieldMismatch
	}
	return nil
}

func parseEnvelopeBody(body []byte) (version byte, keyID string, wrapSalt, wrappedDEK, nonce, ciphertext []byte, err error) {
	if len(body) < len(envelopeMagic)+1+1 {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	if string(body[:len(envelopeMagic)]) != envelopeMagic {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	pos := len(envelopeMagic)
	version = body[pos]
	if version != envelopeVersion {
		return 0, "", nil, nil, nil, nil, fmt.Errorf("%w: unsupported envelope version %d", ErrCorruptCiphertext, version)
	}
	pos++
	idLen := int(body[pos])
	pos++
	if idLen == 0 || pos+idLen > len(body) {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	keyID = string(body[pos : pos+idLen])
	if validateKeyID(keyID) != nil {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	pos += idLen
	if pos+wrapSaltSize+2 > len(body) {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	wrapSalt = body[pos : pos+wrapSaltSize]
	pos += wrapSaltSize
	wrappedLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if wrappedLen == 0 || pos+wrappedLen+gcmNonceSize > len(body) {
		return 0, "", nil, nil, nil, nil, ErrCorruptCiphertext
	}
	wrappedDEK = body[pos : pos+wrappedLen]
	pos += wrappedLen
	nonce = body[pos : pos+gcmNonceSize]
	pos += gcmNonceSize
	ciphertext = body[pos:]
	return version, keyID, wrapSalt, wrappedDEK, nonce, ciphertext, nil
}
