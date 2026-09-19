package credential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
)

func encodeBody(body []byte) string {
	return base64.RawURLEncoding.EncodeToString(body)
}

func decodeBody(encoded string) ([]byte, error) {
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		// Tolerate standard base64 padded payloads from other tooling.
		if fallback, fallbackErr := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded)); fallbackErr == nil {
			return fallback, nil
		}
		return nil, ErrCorruptCiphertext
	}
	return body, nil
}

// NormalizeMasterKey coerces externally supplied key material into a 32 byte
// AES-256 key. A 32 byte value supplied as raw text, hex, standard base64 or
// URL-safe base64 is used directly; any other passphrase is reduced through
// SHA-256 so operators can inject arbitrary high-entropy secrets.
func NormalizeMasterKey(material string) []byte {
	material = strings.TrimSpace(material)
	if material == "" {
		return nil
	}
	if raw := []byte(material); len(raw) == masterKeySize {
		return raw
	}
	if decoded, ok := decodeFlexible(material); ok && len(decoded) == masterKeySize {
		return decoded
	}
	digest := sha256.Sum256([]byte(material))
	return digest[:]
}

func decodeFlexible(value string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	return nil, false
}

// readKeyMaterial resolves an inline secret or a path to a secret file. File
// contents are trimmed of surrounding whitespace and trailing newlines.
func readKeyMaterial(inline, file string) string {
	if value := strings.TrimSpace(inline); value != "" {
		return value
	}
	path := strings.TrimSpace(file)
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
