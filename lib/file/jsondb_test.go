package file

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadJsonFileSupportsAllTypes(t *testing.T) {
	t.Run("clients", func(t *testing.T) {
		input := []byte(`[{"Id":1,"VerifyKey":"v1"},{"Id":2,"VerifyKey":"v2"}]`)
		ids := make([]int, 0)
		keys := make([]string, 0)

		err := loadSyncMapFromBytes(input, "clients.json", Client{}, func(value interface{}) {
			c := value.(*Client)
			ids = append(ids, c.Id)
			keys = append(keys, c.VerifyKey)
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
			t.Fatalf("unexpected ids: %v", ids)
		}
		if len(keys) != 2 || keys[0] != "v1" || keys[1] != "v2" {
			t.Fatalf("unexpected verify keys: %v", keys)
		}
	})

	t.Run("hosts", func(t *testing.T) {
		input := []byte(`[{"Id":10,"Host":"a.com"},{"Id":11,"Host":"b.com"}]`)
		hosts := make([]string, 0)

		err := loadSyncMapFromBytes(input, "hosts.json", Host{}, func(value interface{}) {
			h := value.(*Host)
			hosts = append(hosts, h.Host)
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(hosts) != 2 || hosts[0] != "a.com" || hosts[1] != "b.com" {
			t.Fatalf("unexpected hosts: %v", hosts)
		}
	})

	t.Run("tunnels", func(t *testing.T) {
		input := []byte(`[{"Id":21,"Mode":"tcp"},{"Id":22,"Mode":"udp"}]`)
		modes := make([]string, 0)

		err := loadSyncMapFromBytes(input, "tasks.json", Tunnel{}, func(value interface{}) {
			tn := value.(*Tunnel)
			modes = append(modes, tn.Mode)
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(modes) != 2 || modes[0] != "tcp" || modes[1] != "udp" {
			t.Fatalf("unexpected modes: %v", modes)
		}
	})
}

func TestLoadJsonFileInvalidJSONReturnsError(t *testing.T) {
	err := loadSyncMapFromBytes([]byte(`[{"Id":1}`), "clients.json", Client{}, func(value interface{}) {})
	if err == nil {
		t.Fatalf("expected json unmarshal error")
	}
}

func TestCreateEmptyFileCreatesParentAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "conf", "clients.json")

	if err := createEmptyFile(target); err != nil {
		t.Fatalf("expected createEmptyFile to succeed, got %v", err)
	}
	if err := createEmptyFile(target); err != nil {
		t.Fatalf("expected repeated createEmptyFile to be idempotent, got %v", err)
	}
}

func TestStoreSyncMapToFileSkipsNoStoreEntries(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "clients.json")
	m := &sync.Map{}

	m.Store(1, &Client{Id: 1, VerifyKey: "visible-1", NoStore: false})
	m.Store(2, &Client{Id: 2, VerifyKey: "hidden", NoStore: true})
	m.Store(3, &Client{Id: 3, VerifyKey: "visible-3", NoStore: false})

	storeSyncMapToFile(m, path)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected stored file to exist, got %v", err)
	}

	var clients []Client
	if err = json.Unmarshal(b, &clients); err != nil {
		t.Fatalf("expected valid json array, got %v", err)
	}

	if len(clients) != 2 {
		t.Fatalf("expected only 2 storable clients, got %d", len(clients))
	}

	found := map[int]bool{}
	for i := range clients {
		found[clients[i].Id] = true
	}
	if !found[1] || !found[3] || found[2] {
		t.Fatalf("unexpected persisted ids: %+v", found)
	}
}

func TestStoreSyncMapToFileDoesNotPersistLegacyClientWebLoginFields(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "clients.json")
	m := &sync.Map{}

	client := &Client{Id: 1, VerifyKey: "visible-1"}
	client.SetLegacyWebLoginImport("tenant", "pw", "JBSWY3DPEHPK3PXP")
	m.Store(1, client)

	storeSyncMapToFile(m, path)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected stored file to exist, got %v", err)
	}
	content := string(b)
	for _, token := range []string{"WebUserName", "WebPassword", "WebTotpSecret"} {
		if strings.Contains(content, token) {
			t.Fatalf("persisted client json should not contain %s, got %s", token, content)
		}
	}
}

func TestStoreSyncMapToFileDoesNotPersistLegacyClientBlacklistField(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "clients.json")
	m := &sync.Map{}

	client := &Client{Id: 1, VerifyKey: "visible-1"}
	client.SetLegacyBlackIPImport([]string{"127.0.0.1", "10.0.0.0/8"})
	m.Store(1, client)

	storeSyncMapToFile(m, path)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected stored file to exist, got %v", err)
	}
	if content := string(b); strings.Contains(content, "BlackIpList") {
		t.Fatalf("persisted client json should not contain BlackIpList, got %s", content)
	}
}

func TestLoadJsonFileImportsLegacyClientWebLoginFields(t *testing.T) {
	input := []byte(`[{"Id":1,"VerifyKey":"v1","WebUserName":"tenant","WebPassword":"pw","WebTotpSecret":"JBSWY3DPEHPK3PXP"}]`)
	var loaded []*Client

	err := loadSyncMapFromBytes(input, "clients.json", Client{}, func(value interface{}) {
		loaded = append(loaded, value.(*Client))
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 client, got %d", len(loaded))
	}
	username, password, totpSecret := loaded[0].LegacyWebLoginImport()
	if username != "tenant" || password != "pw" || totpSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("unexpected imported legacy login: username=%q password=%q totp=%q", username, password, totpSecret)
	}
}

func TestLoadJsonFileImportsLegacyClientBlacklistField(t *testing.T) {
	input := []byte(`[{"Id":1,"VerifyKey":"v1","BlackIpList":[" 127.0.0.1 ","10.0.0.0/8"]}]`)
	var loaded []*Client

	err := loadSyncMapFromBytes(input, "clients.json", Client{}, func(value interface{}) {
		loaded = append(loaded, value.(*Client))
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 client, got %d", len(loaded))
	}
	legacy := loaded[0].LegacyBlackIPImport()
	if len(legacy) != 2 || legacy[0] != "127.0.0.1" || legacy[1] != "10.0.0.0/8" {
		t.Fatalf("unexpected imported legacy blacklist: %v", legacy)
	}
}

func TestStoreGlobalToFileDoesNotPersistLegacyBlacklistField(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "global.json")

	glob := &Glob{EntryAclMode: AclBlacklist, EntryAclRules: "10.0.0.1"}
	glob.SetLegacyBlackIPImport([]string{"127.0.0.1"})

	storeGlobalToFile(glob, path)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected stored file to exist, got %v", err)
	}
	if content := string(b); strings.Contains(content, "BlackIpList") {
		t.Fatalf("persisted global json should not contain BlackIpList, got %s", content)
	}
}

func TestWriteSyncMapToFileReturnsErrorWhenParentMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "clients.json")
	m := &sync.Map{}
	m.Store(1, &Client{Id: 1, VerifyKey: "visible-1"})

	if err := writeSyncMapToFile(m, path); err == nil {
		t.Fatal("writeSyncMapToFile() error = nil, want non-nil for missing parent directory")
	}
}

func TestStoreSyncMapToFileDoesNotPanicOnWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "clients.json")
	m := &sync.Map{}
	m.Store(1, &Client{Id: 1, VerifyKey: "visible-1"})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("storeSyncMapToFile() panic = %v, want logged error", r)
		}
	}()
	storeSyncMapToFile(m, path)
}

func TestWriteGlobalToFileReturnsErrorWhenParentMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "global.json")
	if err := writeGlobalToFile(&Glob{}, path); err == nil {
		t.Fatal("writeGlobalToFile() error = nil, want non-nil for missing parent directory")
	}
}

func TestStoreGlobalToFileDoesNotPanicOnWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "global.json")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("storeGlobalToFile() panic = %v, want logged error", r)
		}
	}()
	storeGlobalToFile(&Glob{}, path)
}

func TestGlobJSONImportsLegacyBlacklistField(t *testing.T) {
	var glob Glob
	if err := json.Unmarshal([]byte(`{"EntryAclMode":0,"EntryAclRules":"","BlackIpList":[" 127.0.0.1 ","10.0.0.0/8"]}`), &glob); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	legacy := glob.LegacyBlackIPImport()
	if len(legacy) != 2 || legacy[0] != "127.0.0.1" || legacy[1] != "10.0.0.0/8" {
		t.Fatalf("unexpected imported global legacy blacklist: %v", legacy)
	}
}

func TestLoadGlobalFromJsonFileClearsPriorStateOnEmptyPayload(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	db.JsonDb.Global = &Glob{EntryAclMode: AclBlacklist, EntryAclRules: "10.0.0.1"}
	if err := os.WriteFile(db.JsonDb.GlobalFilePath, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile(global.json) error = %v", err)
	}

	db.JsonDb.LoadGlobalFromJsonFile()

	if db.JsonDb.Global == nil {
		t.Fatal("Global = nil, want initialized empty global after reload")
	}
	if db.JsonDb.Global.EntryAclMode != AclOff || db.JsonDb.Global.EntryAclRules != "" {
		t.Fatalf("Global = %+v, want cleared empty global after reload", db.JsonDb.Global)
	}
}

func TestLoadUserFromJsonFileKeepsExistingStateOnReadError(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	if err := db.NewUser(&User{Id: 7, Username: "tenant", Password: "pw", Status: 1}); err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker) error = %v", err)
	}
	db.JsonDb.UserFilePath = filepath.Join(blocker, "users.json")

	db.JsonDb.LoadUserFromJsonFile()

	lookedUp, err := db.GetUserByUsername("tenant")
	if err != nil {
		t.Fatalf("GetUserByUsername(tenant) error = %v", err)
	}
	if lookedUp.Id != 7 {
		t.Fatalf("GetUserByUsername(tenant) id = %d, want 7", lookedUp.Id)
	}
}

func TestLoadGlobalFromJsonFileKeepsExistingStateOnReadError(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	db.JsonDb.Global = &Glob{EntryAclMode: AclBlacklist, EntryAclRules: "10.0.0.1"}
	InitializeGlobalRuntime(db.JsonDb.Global)

	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker) error = %v", err)
	}
	db.JsonDb.GlobalFilePath = filepath.Join(blocker, "global.json")

	db.JsonDb.LoadGlobalFromJsonFile()

	if db.JsonDb.Global == nil {
		t.Fatal("Global = nil, want previous global preserved on read error")
	}
	if db.JsonDb.Global.EntryAclMode != AclBlacklist || db.JsonDb.Global.EntryAclRules != "10.0.0.1" {
		t.Fatalf("Global = %+v, want preserved prior global on read error", db.JsonDb.Global)
	}
}
