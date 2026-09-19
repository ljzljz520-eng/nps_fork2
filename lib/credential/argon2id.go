// Package credential implements versioned credential encapsulation for nps.
//
// Login passwords are stored as one-way, parameter-versioned Argon2id hashes
// in the self-describing PHC string format. Secrets that must be read back
// (TOTP seeds, client verify keys, tunnel passwords, proxy account passwords)
// are protected by authenticated encryption whose additional data binds the
// ciphertext to an object type and object id; each data key is wrapped by an
// externally injected master key and the envelope carries the wrapping key id.
package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// argon2Algorithm is the algorithm identifier embedded in PHC strings.
	argon2Algorithm = "argon2id"
	// argon2Version is the Argon2 algorithm version (0x13 == 19).
	argon2Version = argon2.Version
	// phcSaltLength is the per-hash salt length in bytes.
	phcSaltLength = 16
	// phcKeyLength is the derived key length in bytes.
	phcKeyLength = 32
)

// PasswordParams is a parameterized Argon2id profile. New profiles can be
// introduced over time without invalidating existing hashes because every hash
// records the exact parameters it was created with.
type PasswordParams struct {
	// Time is the number of passes over the memory.
	Time uint32
	// Memory is the memory cost in KiB.
	Memory uint32
	// Threads is the degree of parallelism.
	Threads uint8
	// KeyLen is the output hash length in bytes.
	KeyLen uint32
	// SaltLen is the per-hash salt length in bytes.
	SaltLen uint32
}

// passwordProfiles is the versioned parameter registry. The profile id is not
// persisted verbatim; the PHC string already carries m/t/p and therefore
// describes itself. Profiles only pin which parameters newly minted hashes use
// and let VerifyPassword report whether an existing hash predates the current
// profile (and therefore should be rehashed on the next successful login).
var passwordProfiles = map[string]PasswordParams{
	// a2v1 is the first Argon2id profile, aligned with current OWASP guidance.
	"a2v1": {Time: 2, Memory: 19456, Threads: 1, KeyLen: phcKeyLength, SaltLen: phcSaltLength},
	// a2v0-interactive is retained only so stronger deployments may select a
	// cheaper profile; it is never the default.
	"a2v0-interactive": {Time: 2, Memory: 9216, Threads: 1, KeyLen: phcKeyLength, SaltLen: phcSaltLength},
}

// CurrentPasswordProfileID is the profile used when hashing new passwords.
const CurrentPasswordProfileID = "a2v1"

// CurrentPasswordProfile returns the parameters used for new password hashes.
func CurrentPasswordProfile() PasswordParams {
	return passwordProfiles[CurrentPasswordProfileID]
}

// PasswordProfile returns a registered parameter profile by id.
func PasswordProfile(id string) (PasswordParams, bool) {
	params, ok := passwordProfiles[strings.TrimSpace(id)]
	return params, ok
}

var (
	// ErrInvalidPasswordHash is returned when a stored PHC string is malformed.
	ErrInvalidPasswordHash = errors.New("credential: invalid argon2id password hash")
	// ErrEmptyPassword is returned when hashing or verifying an empty password.
	ErrEmptyPassword = errors.New("credential: empty password")
)

// HashPassword hashes a plaintext password with the current Argon2id profile,
// returning a self-describing PHC string.
func HashPassword(password string) (string, error) {
	return HashPasswordWithProfile(password, CurrentPasswordProfileID)
}

// HashPasswordWithProfile hashes a password using a named parameter profile.
// Already-hashed PHC strings are returned unchanged so callers can safely pass
// user supplied values through the hashing boundary.
func HashPasswordWithProfile(password, profileID string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", ErrEmptyPassword
	}
	if IsPasswordHash(password) {
		return password, nil
	}
	params, ok := PasswordProfile(profileID)
	if !ok {
		return "", fmt.Errorf("credential: unknown password profile %q", profileID)
	}
	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("credential: generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return encodePHC(params, salt, hash), nil
}

// VerifyPassword reports whether password matches the stored credential.
//
// The stored value is either a PHC Argon2id hash or a legacy plaintext value.
// The second return value is true when a successful match should be upgraded
// (legacy plaintext or an Argon2id hash created with outdated parameters),
// allowing the caller to transparently rehash after a successful commit.
func VerifyPassword(stored, password string) (match bool, upgrade bool, err error) {
	stored = strings.TrimSpace(stored)
	password = strings.TrimSpace(password)
	if stored == "" || password == "" {
		return false, false, nil
	}
	if !IsPasswordHash(stored) {
		// Legacy plaintext comparison. Constant time to avoid leaking the
		// comparison result through timing.
		return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1, true, nil
	}
	params, salt, expected, err := decodePHC(stored)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return false, false, nil
	}
	return true, params != CurrentPasswordProfile(), nil
}

// IsPasswordHash reports whether value is a recognizable Argon2id PHC string.
func IsPasswordHash(value string) bool {
	return strings.HasPrefix(value, "$"+argon2Algorithm+"$")
}

// NeedsPasswordRehash reports whether a stored hash predates the current
// parameter profile and should be rehashed on the next successful login.
func NeedsPasswordRehash(stored string) bool {
	params, _, _, err := decodePHC(stored)
	if err != nil {
		return false
	}
	return params != CurrentPasswordProfile()
}

func encodePHC(params PasswordParams, salt, hash []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Algorithm,
		argon2Version,
		params.Memory,
		params.Time,
		params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func decodePHC(encoded string) (params PasswordParams, salt []byte, hash []byte, err error) {
	encoded = strings.TrimSpace(encoded)
	parts := strings.Split(encoded, "$")
	// PHC strings split into ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash].
	if len(parts) != 6 || parts[0] != "" || parts[1] != argon2Algorithm {
		return PasswordParams{}, nil, nil, ErrInvalidPasswordHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2Version {
		return PasswordParams{}, nil, nil, fmt.Errorf("%w: unsupported version", ErrInvalidPasswordHash)
	}
	params, err = parsePHCParams(parts[3])
	if err != nil {
		return PasswordParams{}, nil, nil, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return PasswordParams{}, nil, nil, fmt.Errorf("%w: invalid salt", ErrInvalidPasswordHash)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return PasswordParams{}, nil, nil, fmt.Errorf("%w: invalid hash", ErrInvalidPasswordHash)
	}
	params.SaltLen = uint32(len(salt))
	params.KeyLen = uint32(len(hash))
	return params, salt, hash, nil
}

func parsePHCParams(raw string) (PasswordParams, error) {
	var params PasswordParams
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return PasswordParams{}, fmt.Errorf("%w: malformed parameters", ErrInvalidPasswordHash)
		}
		number, convErr := strconv.ParseUint(value, 10, 32)
		if convErr != nil {
			return PasswordParams{}, fmt.Errorf("%w: malformed parameters", ErrInvalidPasswordHash)
		}
		switch key {
		case "m":
			params.Memory = uint32(number)
		case "t":
			params.Time = uint32(number)
		case "p":
			params.Threads = uint8(number)
		default:
			return PasswordParams{}, fmt.Errorf("%w: unknown parameter %s", ErrInvalidPasswordHash, key)
		}
	}
	if params.Memory == 0 || params.Time == 0 || params.Threads == 0 {
		return PasswordParams{}, fmt.Errorf("%w: zero cost parameter", ErrInvalidPasswordHash)
	}
	return params, nil
}
