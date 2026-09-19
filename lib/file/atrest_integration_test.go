package file

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/djylb/nps/lib/credential"
)

// Raw 32-byte master key material. NormalizeMasterKey uses 32-byte input
// directly, so these are deterministic keys without base64/hex ambiguity.
const (
	testKey1Material = "11111111111111111111111111111111"
	testKey2Material = "22222222222222222222222222222222"
)

// enableTestCredentialRing installs an explicit key ring for the test and
// always restores a deterministic disabled ring afterwards so other tests in
// the package observe the zero-config (plaintext) default.
func enableTestCredentialRing(t *testing.T, id, material string) {
	t.Helper()
	if err := credential.ConfigureDefault(credential.Config{
		Current: credential.KeyConfig{ID: id, Material: material},
	}); err != nil {
		t.Fatalf("ConfigureDefault(%s): %v", id, err)
	}
	if !credential.Default().Enabled() || credential.Default().CurrentKeyID() != id {
		t.Fatalf("credential ring not active: enabled=%v current=%q", credential.Default().Enabled(), credential.Default().CurrentKeyID())
	}
	t.Cleanup(func() { _ = credential.ConfigureDefault(credential.Config{}) })
}

func sealedTestRecords() (*User, *Client, *Tunnel, *Host) {
	user := &User{
		Id:         1,
		Username:   "tenant",
		TOTPSecret: "TOTP-SECRET-XYZ",
	}
	client := &Client{
		Id:        7,
		VerifyKey: "VERIFYKEY-SECRET",
		Cnf:       &Config{U: "user", P: "CLIENT-CONN-PW"},
	}
	tunnel := &Tunnel{
		Id:       3,
		Mode:     "tcp",
		Password: "TUNNEL-PW",
		UserAuth: &MultiAccount{
			Content:    "UA-CONTENT",
			AccountMap: map[string]string{"alice": "ALICE-PW"},
		},
		Client: &Client{
			Id:        9,
			VerifyKey: "NESTED-VK",
			Cnf:       &Config{P: "NESTED-CONN-PW"},
		},
	}
	host := &Host{
		Id:   5,
		Host: "a.example",
		MultiAccount: &MultiAccount{
			Content:    "HOST-CONTENT",
			AccountMap: map[string]string{"bob": "BOB-PW"},
		},
	}
	return user, client, tunnel, host
}

func TestAtRestSealsSecretsAndOpensRoundTrip(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)

	user, client, tunnel, host := sealedTestRecords()

	secrets := []string{
		"TOTP-SECRET-XYZ", "VERIFYKEY-SECRET", "CLIENT-CONN-PW",
		"TUNNEL-PW", "UA-CONTENT", "ALICE-PW", "NESTED-VK", "NESTED-CONN-PW",
		"HOST-CONTENT", "BOB-PW",
	}

	cases := []struct {
		name    string
		objType string
		value   any
	}{
		{"user", aeadObjectUser, user},
		{"client", aeadObjectClient, client},
		{"tunnel", aeadObjectTunnel, tunnel},
		{"host", aeadObjectHost, host},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := marshalPersistedValue(tc.value)
			if err != nil {
				t.Fatalf("marshalPersistedValue: %v", err)
			}
			wire := string(sealed)
			if !strings.Contains(wire, credential.EnvelopePrefix) {
				t.Fatalf("%s persisted without an envelope: %s", tc.name, wire)
			}
			for _, secret := range secrets {
				if strings.Contains(wire, secret) {
					t.Fatalf("%s on-disk JSON leaks %q: %s", tc.name, secret, wire)
				}
			}

			opened, err := openPersistedObject(tc.objType, sealed)
			if err != nil {
				t.Fatalf("openPersistedObject: %v", err)
			}
			var sink any
			switch tc.value.(type) {
			case *User:
				if err := decodePersistedObject(opened, User{}, func(v any) { sink = v }); err != nil {
					t.Fatal(err)
				}
				got := sink.(*User)
				if got.TOTPSecret != "TOTP-SECRET-XYZ" {
					t.Fatalf("user TOTPSecret = %q", got.TOTPSecret)
				}
			case *Client:
				if err := decodePersistedObject(opened, Client{}, func(v any) { sink = v }); err != nil {
					t.Fatal(err)
				}
				got := sink.(*Client)
				if got.VerifyKey != "VERIFYKEY-SECRET" || got.Cnf == nil || got.Cnf.P != "CLIENT-CONN-PW" {
					t.Fatalf("client secrets = %+v / %+v", got.VerifyKey, got.Cnf)
				}
			case *Tunnel:
				if err := decodePersistedObject(opened, Tunnel{}, func(v any) { sink = v }); err != nil {
					t.Fatal(err)
				}
				got := sink.(*Tunnel)
				if got.Password != "TUNNEL-PW" || got.UserAuth == nil ||
					got.UserAuth.Content != "UA-CONTENT" ||
					got.UserAuth.AccountMap["alice"] != "ALICE-PW" ||
					got.Client == nil || got.Client.VerifyKey != "NESTED-VK" ||
					got.Client.Cnf == nil || got.Client.Cnf.P != "NESTED-CONN-PW" {
					t.Fatalf("tunnel secrets not recovered: %+v", got)
				}
			case *Host:
				if err := decodePersistedObject(opened, Host{}, func(v any) { sink = v }); err != nil {
					t.Fatal(err)
				}
				got := sink.(*Host)
				if got.MultiAccount == nil || got.MultiAccount.Content != "HOST-CONTENT" ||
					got.MultiAccount.AccountMap["bob"] != "BOB-PW" {
					t.Fatalf("host secrets not recovered: %+v", got.MultiAccount)
				}
			}
		})
	}
}

func TestAtRestAADBindsObjectIdentity(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)

	client := &Client{Id: 1, VerifyKey: "VERIFYKEY-SECRET", Cnf: &Config{P: "pw"}}
	sealed, err := marshalPersistedValue(client)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Re-label the record as a different object id. The envelope authenticates
	// object type+id+field name as AEAD additional data, so opening it as id 2
	// fails GCM verification rather than returning cross-object plaintext.
	var doc map[string]any
	if err := json.Unmarshal(sealed, &doc); err != nil {
		t.Fatal(err)
	}
	doc["Id"] = float64(2)
	relabeled, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPersistedObject(aeadObjectClient, relabeled); !errors.Is(err, credential.ErrCorruptCiphertext) {
		t.Fatalf("expected AAD authentication failure for changed object id, got %v", err)
	}
}

func TestAtRestTamperedCiphertextFailsClosed(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)

	client := &Client{Id: 1, VerifyKey: "VERIFYKEY-SECRET", Cnf: &Config{P: "pw"}}
	sealed, err := marshalPersistedValue(client)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(sealed, &doc); err != nil {
		t.Fatal(err)
	}
	doc["VerifyKey"] = flipEnvelopeMiddle(doc["VerifyKey"].(string))
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPersistedObject(aeadObjectClient, tampered); !errors.Is(err, credential.ErrCorruptCiphertext) {
		t.Fatalf("expected ErrCorruptCiphertext, got %v", err)
	}
}

func TestAtRestEnvelopeFailsClosedWhenManagerDisabled(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)
	client := &Client{Id: 1, VerifyKey: "VERIFYKEY-SECRET", Cnf: &Config{P: "pw"}}
	sealed, err := marshalPersistedValue(client)
	if err != nil {
		t.Fatal(err)
	}

	// Drop every master key: a persisted envelope must never be treated as
	// plaintext and must abort the load (fail closed).
	if err := credential.ConfigureDefault(credential.Config{}); err != nil {
		t.Fatal(err)
	}
	if _, err := openPersistedObject(aeadObjectClient, sealed); err == nil {
		t.Fatal("expected error opening an envelope with the manager disabled, got nil")
	}
}

func TestAtRestLegacyPlaintextReadAndMigrateOnWrite(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)

	// Legacy on-disk record predates envelope encryption.
	legacy := []byte(`[{"Id":1,"VerifyKey":"legacy-vk","Cnf":{"U":"u","P":"legacy-pw"}}]`)

	opened, err := openPersistedArray(aeadObjectClient, legacy)
	if err != nil {
		t.Fatalf("legacy plaintext must still load: %v", err)
	}
	var loaded *Client
	if err := decodePersistedObject(opened[0], Client{}, func(v any) { loaded = v.(*Client) }); err != nil {
		t.Fatal(err)
	}
	if loaded.VerifyKey != "legacy-vk" || loaded.Cnf == nil || loaded.Cnf.P != "legacy-pw" {
		t.Fatalf("legacy values changed on read: %+v", loaded)
	}

	// The next successful persistence seals the previously-plaintext secrets.
	resealed, err := marshalPersistedValue(loaded)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(resealed)
	if !strings.Contains(wire, credential.EnvelopePrefix) ||
		strings.Contains(wire, "legacy-vk") || strings.Contains(wire, "legacy-pw") {
		t.Fatalf("legacy plaintext was not migrated on write: %s", wire)
	}
	reopened, err := openPersistedObject(aeadObjectClient, resealed)
	if err != nil {
		t.Fatalf("reopened migrated record: %v", err)
	}
	var migrated *Client
	if err := decodePersistedObject(reopened, Client{}, func(v any) { migrated = v.(*Client) }); err != nil {
		t.Fatal(err)
	}
	if migrated.VerifyKey != "legacy-vk" || migrated.Cnf.P != "legacy-pw" {
		t.Fatalf("migrated values mismatch: %+v", migrated)
	}
}

func TestCredentialRotationReSealsAndRevokesOldKey(t *testing.T) {
	enableTestCredentialRing(t, "k1", testKey1Material)

	dir := t.TempDir()
	jdb := NewJsonDb(dir)
	// Point the stores directly at the temp dir so no conf/ parent is needed.
	jdb.UserFilePath = filepath.Join(dir, "users.json")
	jdb.ClientFilePath = filepath.Join(dir, "clients.json")
	jdb.TaskFilePath = filepath.Join(dir, "tasks.json")
	jdb.HostFilePath = filepath.Join(dir, "hosts.json")

	jdb.Users.Store(1, &User{Id: 1, TOTPSecret: "TOTP-SECRET-XYZ"})
	jdb.Clients.Store(1, &Client{Id: 1, VerifyKey: "vk1", Cnf: &Config{P: "conn-pw"}})
	store := &DbUtils{JsonDb: jdb}

	for _, seed := range []func(*JsonDb) error{
		jdb.persistenceBackend().StoreUsers,
		jdb.persistenceBackend().StoreClients,
		jdb.persistenceBackend().StoreTasks,
		jdb.persistenceBackend().StoreHosts,
	} {
		if err := seed(jdb); err != nil {
			t.Fatalf("seed store: %v", err)
		}
	}

	k1Clients, err := os.ReadFile(jdb.ClientFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if uses, err := fileContainsEnvelopeForKey(k1Clients, "k1"); err != nil || !uses {
		t.Fatalf("expected k1 envelopes on disk after seed, uses=%v err=%v", uses, err)
	}

	// Open the dual-key window: k2 seals new writes, k1 retained for reads.
	if err := credential.Default().BeginRotation(credential.KeyConfig{ID: "k2", Material: testKey2Material}); err != nil {
		t.Fatalf("BeginRotation: %v", err)
	}
	if !credential.Default().HasPreviousKey() || credential.Default().PreviousKeyID() != "k1" {
		t.Fatal("expected previous key k1 retained during rotation window")
	}
	if complete, err := store.CredentialRotationComplete(); err != nil || complete {
		t.Fatalf("rotation must not be complete before rewrite, complete=%v err=%v", complete, err)
	}
	// Old k1 ciphertext stays readable while both keys are present.
	if opened, err := openPersistedArray(aeadObjectClient, k1Clients); err != nil {
		t.Fatalf("k1 ciphertext must remain readable in dual-key window: %v", err)
	} else {
		var got *Client
		if err := decodePersistedObject(opened[0], Client{}, func(v any) { got = v.(*Client) }); err != nil {
			t.Fatal(err)
		}
		if got.VerifyKey != "vk1" {
			t.Fatalf("dual-key read recovered %q", got.VerifyKey)
		}
	}

	// Batch re-encrypt, verify, and revoke.
	revoked, err := store.CompleteCredentialRotation()
	if err != nil || !revoked {
		t.Fatalf("CompleteCredentialRotation revoked=%v err=%v", revoked, err)
	}
	if credential.Default().HasPreviousKey() {
		t.Fatal("retired key must be revoked after rotation completes")
	}

	k2Clients, err := os.ReadFile(jdb.ClientFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if uses, _ := fileContainsEnvelopeForKey(k2Clients, "k1"); uses {
		t.Fatal("k1 envelopes still present after re-encryption")
	}
	if uses, _ := fileContainsEnvelopeForKey(k2Clients, "k2"); !uses {
		t.Fatal("k2 envelopes missing after re-encryption")
	}
	if opened, err := openPersistedArray(aeadObjectClient, k2Clients); err != nil {
		t.Fatalf("k2 ciphertext must load: %v", err)
	} else {
		var got *Client
		if err := decodePersistedObject(opened[0], Client{}, func(v any) { got = v.(*Client) }); err != nil {
			t.Fatal(err)
		}
		if got.VerifyKey != "vk1" || got.Cnf.P != "conn-pw" {
			t.Fatalf("post-rotation values mismatch: %+v", got)
		}
	}

	// A stale k1 ciphertext must fail closed now that the old key is revoked.
	if _, err := openPersistedArray(aeadObjectClient, k1Clients); !errors.Is(err, credential.ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey for revoked-key ciphertext, got %v", err)
	}
}

func TestMaskConfigSnapshotMasksAllSecrets(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Users: []*User{{
			Id: 1, Username: "tenant", Password: "plain-password", TOTPSecret: "TOTP-SECRET",
		}},
		Clients: []*Client{{
			Id: 1, VerifyKey: "VERIFYKEY", Cnf: &Config{U: "u", P: "CONN-PW"},
		}},
		Tunnels: []*Tunnel{{
			Id:       1,
			Password: "TUNNEL-PW",
			UserAuth: &MultiAccount{Content: "UA", AccountMap: map[string]string{"alice": "ALICE-PW"}},
		}},
		Hosts: []*Host{{
			Id:           1,
			MultiAccount: &MultiAccount{Content: "HOST-CONTENT", AccountMap: map[string]string{"bob": "BOB-PW"}},
		}},
	}

	MaskConfigSnapshot(snapshot)

	user := snapshot.Users[0]
	if !strings.Contains(user.Password, credential.MaskedMarker) || user.Password == "plain-password" ||
		!strings.Contains(user.TOTPSecret, credential.MaskedMarker) || user.TOTPSecret == "TOTP-SECRET" {
		t.Fatalf("user secrets not masked: %+v", user)
	}
	client := snapshot.Clients[0]
	if client.VerifyKey == "VERIFYKEY" || !strings.Contains(client.VerifyKey, credential.MaskedMarker) ||
		client.Cnf.P == "CONN-PW" {
		t.Fatalf("client secrets not masked: %+v", client)
	}
	tunnel := snapshot.Tunnels[0]
	if tunnel.Password == "TUNNEL-PW" || tunnel.UserAuth.Content == "UA" ||
		tunnel.UserAuth.AccountMap["alice"] == "ALICE-PW" {
		t.Fatalf("tunnel secrets not masked: %+v", tunnel)
	}
	host := snapshot.Hosts[0]
	if host.MultiAccount.Content == "HOST-CONTENT" || host.MultiAccount.AccountMap["bob"] == "BOB-PW" {
		t.Fatalf("host secrets not masked: %+v", host.MultiAccount)
	}
}

// flipEnvelopeMiddle changes one character in the middle of the envelope's
// base64 body (avoiding the trailing pad-bit quantum) to break authentication.
func flipEnvelopeMiddle(value string) string {
	bytes := []byte(value)
	idx := len(credential.EnvelopePrefix) + (len(bytes)-len(credential.EnvelopePrefix))/2
	if bytes[idx] == 'A' {
		bytes[idx] = 'B'
	} else {
		bytes[idx] = 'A'
	}
	return string(bytes)
}
