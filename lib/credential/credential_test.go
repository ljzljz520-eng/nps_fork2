package credential

import (
	"errors"
	"strings"
	"testing"
)

func testManager(t *testing.T, currentID string) *Manager {
	t.Helper()
	manager, err := NewManager(Config{
		Current: KeyConfig{ID: currentID, Material: "0123456789abcdef0123456789abcdef"},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return manager
}

func TestArgon2idHashAndVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !IsPasswordHash(hash) {
		t.Fatalf("expected PHC argon2id hash, got %q", hash)
	}
	if strings.Contains(hash, "s3cret-pass") {
		t.Fatal("hash must not contain plaintext password")
	}
	match, upgrade, err := VerifyPassword(hash, "s3cret-pass")
	if err != nil || !match || upgrade {
		t.Fatalf("expected current-profile match without upgrade, got match=%v upgrade=%v err=%v", match, upgrade, err)
	}
	match, _, err = VerifyPassword(hash, "wrong-pass")
	if err != nil || match {
		t.Fatalf("expected mismatch, got match=%v err=%v", match, err)
	}
}

func TestArgon2idSaltsAreUnique(t *testing.T) {
	first, _ := HashPassword("same-password")
	second, _ := HashPassword("same-password")
	if first == second {
		t.Fatal("expected distinct salts to produce distinct hashes")
	}
}

func TestLegacyPlaintextVerifyAndUpgrade(t *testing.T) {
	match, upgrade, err := VerifyPassword("legacy-plain", "legacy-plain")
	if err != nil || !match || !upgrade {
		t.Fatalf("expected legacy match requiring upgrade, got match=%v upgrade=%v err=%v", match, upgrade, err)
	}
	match, _, _ = VerifyPassword("legacy-plain", "other")
	if match {
		t.Fatal("legacy plaintext must not match a different password")
	}
}

func TestVerifyRejectsCorruptPHC(t *testing.T) {
	cases := []string{
		"$argon2id$v=99$m=1,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=19$m=0,t=0,p=0$AAAA$AAAA",
		"$argon2id$v=19$m=1,t=1,p=1$$",
	}
	for _, stored := range cases {
		if _, _, err := VerifyPassword(stored, "x"); err == nil {
			t.Fatalf("expected error for corrupt hash %q", stored)
		}
	}
}

func TestHashPasswordIdempotentOnExistingHash(t *testing.T) {
	hash, _ := HashPassword("password")
	again, err := HashPassword(hash)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if again != hash {
		t.Fatal("re-hashing an existing PHC string must be idempotent")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	manager := testManager(t, "k1")
	field := Field{ObjectType: "client", ObjectID: 42, Name: "VerifyKey"}
	sealed, err := manager.SealString(field, "super-vkey")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	if !IsEnvelope(sealed) || strings.Contains(sealed, "super-vkey") {
		t.Fatalf("unexpected sealed value %q", sealed)
	}
	opened, err := manager.OpenString(field, sealed)
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if opened != "super-vkey" {
		t.Fatalf("expected plaintext, got %q", opened)
	}
}

func TestSealIsIdempotentAndEmptyPassthrough(t *testing.T) {
	manager := testManager(t, "k1")
	field := Field{ObjectType: "tunnel", ObjectID: 7, Name: "Password"}
	if out, err := manager.SealString(field, ""); err != nil || out != "" {
		t.Fatalf("empty value should pass through, got %q err=%v", out, err)
	}
	sealed, _ := manager.SealString(field, "secret")
	again, _ := manager.SealString(field, sealed)
	if again != sealed {
		t.Fatal("re-sealing an envelope must be idempotent")
	}
	// Plaintext passes straight through when encryption is disabled.
	disabled := &Manager{}
	if out, err := disabled.OpenString(field, "plain"); err != nil || out != "plain" {
		t.Fatalf("disabled manager should pass plaintext, got %q err=%v", out, err)
	}
}

func TestFailClosedOnCorruptOrMissingKey(t *testing.T) {
	manager := testManager(t, "k1")
	field := Field{ObjectType: "client", ObjectID: 9, Name: "VerifyKey"}
	sealed, _ := manager.SealString(field, "vkey")

	// Tampered ciphertext must fail closed. Flip a character in the middle of
	// the body (always inside a full base64 quantum, so decoded ciphertext bits
	// change) rather than the final character, which may only carry pad bits.
	idx := len(envelopePrefix) + (len(sealed)-len(envelopePrefix))/2
	flipped := sealed[idx]
	replacement := byte('A')
	if flipped == 'A' {
		replacement = 'B'
	}
	tampered := sealed[:idx] + string(replacement) + sealed[idx+1:]
	if _, err := manager.OpenString(field, tampered); err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext")
	}

	// Garbage envelope with a valid prefix must fail closed rather than be read
	// as plaintext.
	if _, err := manager.OpenString(field, envelopePrefix+"not-a-token"); !errors.Is(err, ErrCorruptCiphertext) {
		t.Fatalf("expected ErrCorruptCiphertext, got %v", err)
	}

	// Disabled manager refuses to open an envelope.
	if _, err := (&Manager{}).OpenString(field, sealed); err == nil {
		t.Fatal("disabled manager must fail closed for an envelope")
	}

	// A key id absent from the ring fails closed.
	other := testManager(t, "different")
	if _, err := other.OpenString(field, sealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestAdditionalDataBindingPreventsMovement(t *testing.T) {
	manager := testManager(t, "k1")
	sealed, err := manager.SealString(Field{ObjectType: "client", ObjectID: 1, Name: "VerifyKey"}, "vkey")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	attempts := []Field{
		{ObjectType: "user", ObjectID: 1, Name: "VerifyKey"},
		{ObjectType: "client", ObjectID: 2, Name: "VerifyKey"},
		{ObjectType: "client", ObjectID: 1, Name: "Password"},
	}
	for _, attempt := range attempts {
		if _, err := manager.OpenString(attempt, sealed); err == nil {
			t.Fatalf("ciphertext moved to %+v opened successfully", attempt)
		}
	}
}

func TestRotationWindowAndRevocation(t *testing.T) {
	manager := testManager(t, "k-old")
	field := Field{ObjectType: "client", ObjectID: 5, Name: "VerifyKey"}
	oldSealed, _ := manager.SealString(field, "rotating-vkey")
	if manager.NeedsReencryption(oldSealed) {
		t.Fatal("fresh envelope should not need re-encryption")
	}

	if err := manager.BeginRotation(KeyConfig{ID: "k-new", Material: "fedcba9876543210fedcba9876543210"}); err != nil {
		t.Fatalf("BeginRotation: %v", err)
	}
	if manager.CurrentKeyID() != "k-new" || !manager.HasPreviousKey() {
		t.Fatal("expected new current key with previous key retained")
	}
	// Old ciphertext still opens during the dual-key window.
	if opened, err := manager.OpenString(field, oldSealed); err != nil || opened != "rotating-vkey" {
		t.Fatalf("old ciphertext should open in rotation window, got %q err=%v", opened, err)
	}
	if !manager.NeedsReencryption(oldSealed) {
		t.Fatal("old-key envelope should be flagged for re-encryption")
	}
	// New writes use the new key.
	newSealed, _ := manager.SealString(field, "rotating-vkey")
	if manager.NeedsReencryption(newSealed) {
		t.Fatal("new envelope should be sealed under current key")
	}

	if !manager.RevokePreviousKey() {
		t.Fatal("expected RevokePreviousKey to drop a key")
	}
	if _, err := manager.OpenString(field, oldSealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old ciphertext must fail closed after revocation, got %v", err)
	}
	if opened, err := manager.OpenString(field, newSealed); err != nil || opened != "rotating-vkey" {
		t.Fatalf("new ciphertext must still open after revocation, got %q err=%v", opened, err)
	}
}

func TestNormalizeMasterKey(t *testing.T) {
	if NormalizeMasterKey("") != nil {
		t.Fatal("empty material should normalize to nil")
	}
	if got := NormalizeMasterKey("0123456789abcdef0123456789abcdef"); len(got) != masterKeySize {
		t.Fatalf("raw 32-byte key should be used directly, got len=%d", len(got))
	}
	// Arbitrary passphrase is reduced deterministically to 32 bytes.
	first := NormalizeMasterKey("a long operator passphrase")
	second := NormalizeMasterKey("a long operator passphrase")
	if len(first) != masterKeySize || string(first) != string(second) {
		t.Fatal("passphrase normalization must be deterministic and 32 bytes")
	}
}

func TestMaskSecret(t *testing.T) {
	if MaskSecret("") != "" {
		t.Fatal("empty secret should stay empty in export")
	}
	if got := MaskSecret("ab"); got != MaskedMarker {
		t.Fatalf("short secret should be fully masked, got %q", got)
	}
	manager := testManager(t, "k1")
	sealed, _ := manager.SealString(Field{ObjectType: "client", ObjectID: 1, Name: "VerifyKey"}, "vkey")
	if got := MaskSecret(sealed); got != MaskedMarker {
		t.Fatalf("envelope should be fully masked, got %q", got)
	}
	hash, _ := HashPassword("pw")
	if got := MaskSecret(hash); got != MaskedMarker {
		t.Fatalf("password hash should be fully masked, got %q", got)
	}
	if got := MaskSecret("long-secret-value"); !strings.HasPrefix(got, "lo") || !strings.Contains(got, MaskedMarker) {
		t.Fatalf("long secret should retain a short prefix, got %q", got)
	}
}

func TestPlaintextLegacyRemainsReadable(t *testing.T) {
	manager := testManager(t, "k1")
	field := Field{ObjectType: "user", ObjectID: 3, Name: "TOTPSecret"}
	opened, err := manager.OpenString(field, "JBSWY3DPFQQHO33SNRSCC===")
	if err != nil || opened != "JBSWY3DPFQQHO33SNRSCC===" {
		t.Fatalf("legacy plaintext should remain readable, got %q err=%v", opened, err)
	}
	if !manager.NeedsReencryption("JBSWY3DPFQQHO33SNRSCC===") {
		t.Fatal("legacy plaintext should be flagged for sealing")
	}
}
