package file

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/rate"
)

func NewJsonDb(runPath string) *JsonDb {
	return &JsonDb{
		RunPath:        runPath,
		TaskFilePath:   filepath.Join(runPath, "conf", "tasks.json"),
		HostFilePath:   filepath.Join(runPath, "conf", "hosts.json"),
		ClientFilePath: filepath.Join(runPath, "conf", "clients.json"),
		UserFilePath:   filepath.Join(runPath, "conf", "users.json"),
		GlobalFilePath: filepath.Join(runPath, "conf", "global.json"),
		persistence:    newJSONFilePersistenceBackend(),
	}
}

type JsonDb struct {
	Tasks              sync.Map
	Hosts              sync.Map
	HostsTmp           sync.Map
	Clients            sync.Map
	ownerClientIndex   groupIDIndex
	managerClientIndex groupIDIndex
	taskClientIndex    groupIDIndex
	hostClientIndex    groupIDIndex
	Users              sync.Map
	Global             *Glob
	RunPath            string
	ClientIncreaseId   int32  //client increased id
	TaskIncreaseId     int32  //task increased id
	HostIncreaseId     int32  //host increased id
	UserIncreaseId     int32  //user increased id
	TaskFilePath       string //task file path
	HostFilePath       string //host file path
	ClientFilePath     string //client file path
	UserFilePath       string //user file path
	GlobalFilePath     string //global file path
	persistence        persistenceBackend
	deferredStores     jsonDBDeferredStoreState
}

type jsonDBStoreMask uint8

const (
	jsonDBStoreUsers jsonDBStoreMask = 1 << iota
	jsonDBStoreClients
	jsonDBStoreTasks
	jsonDBStoreHosts
	jsonDBStoreGlobal
)

// deferredStores coalesces repeated persistence requests during a bulk mutation
// window so hot service paths can update many in-memory records and flush once.
type jsonDBDeferredStoreState struct {
	mu    sync.Mutex
	depth int
	dirty jsonDBStoreMask
}

type persistenceBackend interface {
	LoadUsers(*JsonDb) ([]*User, error)
	LoadClients(*JsonDb) ([]*Client, error)
	LoadTasks(*JsonDb) ([]*Tunnel, error)
	LoadHosts(*JsonDb) ([]*Host, error)
	LoadGlobal(*JsonDb) (*Glob, error)
	StoreUsers(*JsonDb) error
	StoreClients(*JsonDb) error
	StoreTasks(*JsonDb) error
	StoreHosts(*JsonDb) error
	StoreGlobal(*JsonDb) error
}

type jsonFilePersistenceBackend struct{}

var defaultJSONPersistenceBackend persistenceBackend = jsonFilePersistenceBackend{}

func newJSONFilePersistenceBackend() persistenceBackend {
	return defaultJSONPersistenceBackend
}

func (jsonFilePersistenceBackend) LoadUsers(db *JsonDb) ([]*User, error) {
	return loadUsersFromFile(db.UserFilePath)
}

func (jsonFilePersistenceBackend) LoadClients(db *JsonDb) ([]*Client, error) {
	return loadClientsFromFile(db.ClientFilePath)
}

func (jsonFilePersistenceBackend) LoadTasks(db *JsonDb) ([]*Tunnel, error) {
	return loadTasksFromFile(db.TaskFilePath)
}

func (jsonFilePersistenceBackend) LoadHosts(db *JsonDb) ([]*Host, error) {
	return loadHostsFromFile(db.HostFilePath)
}

func (jsonFilePersistenceBackend) LoadGlobal(db *JsonDb) (*Glob, error) {
	return loadGlobalFromFile(db.GlobalFilePath)
}

func (jsonFilePersistenceBackend) StoreUsers(db *JsonDb) error {
	return writeSyncMapToFile(&db.Users, db.UserFilePath)
}

func (jsonFilePersistenceBackend) StoreClients(db *JsonDb) error {
	return writeSyncMapToFile(&db.Clients, db.ClientFilePath)
}

func (jsonFilePersistenceBackend) StoreTasks(db *JsonDb) error {
	return writeSyncMapToFile(&db.Tasks, db.TaskFilePath)
}

func (jsonFilePersistenceBackend) StoreHosts(db *JsonDb) error {
	return writeSyncMapToFile(&db.Hosts, db.HostFilePath)
}

func (jsonFilePersistenceBackend) StoreGlobal(db *JsonDb) error {
	return writeGlobalToFile(db.Global, db.GlobalFilePath)
}

func (s *JsonDb) LoadUsers() {
	loaded, err := s.persistenceBackend().LoadUsers(s)
	if err != nil {
		logs.Error("load users from %s error: %v", s.UserFilePath, err)
		return
	}

	s.Users = sync.Map{}
	s.UserIncreaseId = 0
	runtimePlatformUserIndex().Clear()
	runtimeUsernameIndex().Clear()
	for _, post := range loaded {
		post.Username = strings.TrimSpace(post.Username)
		if !s.prepareLoadedUserReplace(post) {
			continue
		}
		InitializeUserRuntime(post)
		s.Users.Store(post.Id, post)
		if post.Id > int(s.UserIncreaseId) {
			s.UserIncreaseId = int32(post.Id)
		}
	}
	s.rebindLoadedClientOwners()
}

func (s *JsonDb) LoadUserFromJsonFile() {
	s.LoadUsers()
}

func (s *JsonDb) LoadTasks() {
	loaded, err := s.persistenceBackend().LoadTasks(s)
	if err != nil {
		logs.Error("load tasks from %s error: %v", s.TaskFilePath, err)
		return
	}

	s.Tasks = sync.Map{}
	s.TaskIncreaseId = 0
	runtimeTaskPasswordIndex().Clear()
	s.taskClientIndex.clear()
	for _, post := range loaded {
		if post == nil {
			continue
		}
		var err error
		if post.Client == nil || post.Client.Id <= 0 {
			continue
		}
		if post.Client, err = s.GetClient(post.Client.Id); err != nil {
			continue
		}
		if post.Password != "" {
			hash := crypt.Md5(post.Password)
			if idxID, ok := runtimeTaskPasswordIndex().Get(hash); ok && idxID != post.Id {
				continue
			}
		}
		s.prepareLoadedTunnelReplace(post)
		if post.Password != "" {
			runtimeTaskPasswordIndex().Add(crypt.Md5(post.Password), post.Id)
		}
		post.NowConn = 0
		normalizeTunnelProtocolFields(post)
		InitializeTunnelRuntime(post)
		post.CompileEntryACL()
		post.CompileDestACL()
		s.Tasks.Store(post.Id, post)
		s.taskClientIndex.add(post.Client.Id, post.Id)
		if post.Id > int(s.TaskIncreaseId) {
			s.TaskIncreaseId = int32(post.Id)
		}
	}
	s.taskClientIndex.markReady()
}

func (s *JsonDb) LoadTaskFromJsonFile() {
	s.LoadTasks()
}

func (s *JsonDb) LoadClients() {
	loaded, err := s.persistenceBackend().LoadClients(s)
	if err != nil {
		logs.Error("load clients from %s error: %v", s.ClientFilePath, err)
		return
	}

	s.Clients = sync.Map{}
	s.ClientIncreaseId = 0
	runtimeBlake2bVkeyIndex().Clear()
	s.clearClientUserIndexes()
	for _, post := range loaded {
		if post == nil {
			continue
		}
		post.VerifyKey = strings.TrimSpace(post.VerifyKey)
		if !s.prepareLoadedClientReplace(post) {
			continue
		}
		if post.RateLimit > 0 {
			post.Rate = rate.NewRate(int64(post.RateLimit) * 1024)
		} else {
			post.Rate = rate.NewRate(0)
		}
		post.Rate.Start()
		post.NowConn = 0
		applyClientSetupHook(post)
		if owner, ok := loadUserEntry(&s.Users, post.OwnerID()); ok {
			post.BindOwnerUser(owner)
		}
		s.Clients.Store(post.Id, post)
		s.addClientUserIndexes(post)
		if post.Id > int(s.ClientIncreaseId) {
			s.ClientIncreaseId = int32(post.Id)
		}
	}
	s.markClientUserIndexesReady()
	s.relinkLoadedClientReferences()
}

func (s *JsonDb) LoadClientFromJsonFile() {
	s.LoadClients()
}

func (s *JsonDb) LoadHosts() {
	loaded, err := s.persistenceBackend().LoadHosts(s)
	if err != nil {
		logs.Error("load hosts from %s error: %v", s.HostFilePath, err)
		return
	}

	s.Hosts = sync.Map{}
	s.HostIncreaseId = 0
	runtimeHostIndex().Destroy()
	s.hostClientIndex.clear()
	for _, post := range loaded {
		if post == nil {
			continue
		}
		var err error
		if post.Client == nil || post.Client.Id <= 0 {
			continue
		}
		if post.Client, err = s.GetClient(post.Client.Id); err != nil {
			continue
		}
		normalizeHostRoutingFields(post)
		if s.loadedHostRouteExists(post) {
			continue
		}
		s.prepareLoadedHostReplace(post)
		post.NowConn = 0
		finalizeHostForStore(post)
		s.Hosts.Store(post.Id, post)
		runtimeHostIndex().Add(post.Host, post.Id)
		s.hostClientIndex.add(post.Client.Id, post.Id)
		if post.Id > int(s.HostIncreaseId) {
			s.HostIncreaseId = int32(post.Id)
		}
	}
	s.hostClientIndex.markReady()
}

func (s *JsonDb) LoadHostFromJsonFile() {
	s.LoadHosts()
}

func (s *JsonDb) LoadGlobal() {
	global, err := s.persistenceBackend().LoadGlobal(s)
	if err != nil {
		logs.Error("load global config from %s error: %v", s.GlobalFilePath, err)
		return
	}
	if global == nil {
		global = &Glob{}
		InitializeGlobalRuntime(global)
	}
	s.Global = global
}

func (s *JsonDb) LoadGlobalFromJsonFile() {
	s.LoadGlobal()
}

func (s *JsonDb) rebindLoadedClientOwners() {
	if s == nil {
		return
	}
	s.Clients.Range(func(key, value interface{}) bool {
		client, ok := value.(*Client)
		if !ok || client == nil {
			s.Clients.CompareAndDelete(key, value)
			return true
		}
		ownerID := client.OwnerID()
		if ownerID <= 0 {
			client.BindOwnerUser(nil)
			return true
		}
		if owner, ok := loadUserEntry(&s.Users, ownerID); ok {
			client.BindOwnerUser(owner)
			return true
		}
		client.BindOwnerUser(nil)
		return true
	})
}

func (s *JsonDb) relinkLoadedClientReferences() {
	if s == nil {
		return
	}
	s.Tasks.Range(func(key, value interface{}) bool {
		tunnel, ok := value.(*Tunnel)
		if !ok || tunnel == nil {
			s.Tasks.CompareAndDelete(key, value)
			return true
		}
		clientID := 0
		if tunnel.Client != nil {
			clientID = tunnel.Client.Id
		}
		if clientID <= 0 {
			s.dropLoadedTunnel(tunnel)
			return true
		}
		if current, err := s.GetClient(clientID); err == nil {
			tunnel.Client = current
			return true
		}
		s.dropLoadedTunnel(tunnel)
		return true
	})
	s.Hosts.Range(func(key, value interface{}) bool {
		host, ok := value.(*Host)
		if !ok || host == nil {
			s.Hosts.CompareAndDelete(key, value)
			return true
		}
		clientID := 0
		if host.Client != nil {
			clientID = host.Client.Id
		}
		if clientID <= 0 {
			s.dropLoadedHost(host)
			return true
		}
		if current, err := s.GetClient(clientID); err == nil {
			host.Client = current
			return true
		}
		s.dropLoadedHost(host)
		return true
	})
}

func (s *JsonDb) dropLoadedTunnel(tunnel *Tunnel) {
	if s == nil || tunnel == nil {
		return
	}
	if tunnel.Client != nil {
		s.taskClientIndex.remove(tunnel.Client.Id, tunnel.Id)
	}
	if tunnel.Password != "" {
		hash := crypt.Md5(tunnel.Password)
		if id, ok := runtimeTaskPasswordIndex().Get(hash); ok && id == tunnel.Id {
			runtimeTaskPasswordIndex().Remove(hash)
		}
	}
	if tunnel.Rate != nil {
		tunnel.Rate.Stop()
	}
	s.Tasks.Delete(tunnel.Id)
}

func (s *JsonDb) dropLoadedHost(host *Host) {
	if s == nil || host == nil {
		return
	}
	if host.Client != nil {
		s.hostClientIndex.remove(host.Client.Id, host.Id)
	}
	runtimeHostIndex().Remove(host.Host, host.Id)
	if host.Rate != nil {
		host.Rate.Stop()
	}
	s.Hosts.Delete(host.Id)
}

func (s *JsonDb) prepareLoadedClientReplace(client *Client) bool {
	if s == nil || client == nil || client.Id <= 0 {
		return true
	}
	if client.VerifyKey != "" {
		hash := crypt.Blake2b(client.VerifyKey)
		if id, ok := runtimeBlake2bVkeyIndex().Get(hash); ok && id != client.Id {
			return false
		}
	}
	if current, ok := loadClientEntry(&s.Clients, client.Id); ok {
		if current.VerifyKey != "" {
			hash := crypt.Blake2b(current.VerifyKey)
			if id, ok := runtimeBlake2bVkeyIndex().Get(hash); ok && id == current.Id {
				runtimeBlake2bVkeyIndex().Remove(hash)
			}
		}
		s.removeClientUserIndexesByID(current.Id)
		if current.Rate != nil {
			current.Rate.Stop()
		}
	}
	if client.VerifyKey != "" {
		runtimeBlake2bVkeyIndex().Add(crypt.Blake2b(client.VerifyKey), client.Id)
	}
	return true
}

func (s *JsonDb) prepareLoadedUserReplace(user *User) bool {
	if s == nil || user == nil {
		return true
	}
	username := strings.TrimSpace(user.Username)
	if username != "" {
		if id, ok := runtimeUsernameIndex().Get(username); ok && id != user.Id {
			return false
		}
	}
	platformID := indexedUserExternalPlatformID(user)
	if platformID != "" {
		if id, ok := runtimePlatformUserIndex().Get(platformID); ok && id != user.Id {
			return false
		}
	}
	if user.Id <= 0 {
		return true
	}
	if current, ok := loadUserEntry(&s.Users, user.Id); ok {
		if existingUsername := indexedUsername(current); existingUsername != "" {
			if id, ok := runtimeUsernameIndex().Get(existingUsername); ok && id == current.Id {
				runtimeUsernameIndex().Remove(existingUsername)
			}
		}
		if platformID := indexedUserExternalPlatformID(current); platformID != "" {
			if id, ok := runtimePlatformUserIndex().Get(platformID); ok && id == current.Id {
				runtimePlatformUserIndex().Remove(platformID)
			}
		}
		if current.Rate != nil {
			current.Rate.Stop()
		}
	}
	if username != "" {
		runtimeUsernameIndex().Add(username, user.Id)
	}
	if platformID != "" {
		runtimePlatformUserIndex().Add(platformID, user.Id)
	}
	return true
}

func (s *JsonDb) prepareLoadedTunnelReplace(tunnel *Tunnel) {
	if s == nil || tunnel == nil || tunnel.Id <= 0 {
		return
	}
	if current, ok := loadTaskEntry(&s.Tasks, tunnel.Id); ok {
		if current.Client != nil {
			s.taskClientIndex.remove(current.Client.Id, current.Id)
		}
		if current.Password != "" {
			hash := crypt.Md5(current.Password)
			if id, ok := runtimeTaskPasswordIndex().Get(hash); ok && id == current.Id {
				runtimeTaskPasswordIndex().Remove(hash)
			}
		}
		if current.Rate != nil {
			current.Rate.Stop()
		}
	}
}

func (s *JsonDb) prepareLoadedHostReplace(host *Host) {
	if s == nil || host == nil || host.Id <= 0 {
		return
	}
	if current, ok := loadHostEntry(&s.Hosts, host.Id); ok {
		if current.Client != nil {
			s.hostClientIndex.remove(current.Client.Id, current.Id)
		}
		runtimeHostIndex().Remove(current.Host, current.Id)
		if current.Rate != nil {
			current.Rate.Stop()
		}
	}
}

func (s *JsonDb) loadedHostRouteExists(host *Host) bool {
	if s == nil || host == nil {
		return false
	}
	normalizeHostRoutingFields(host)
	exist := false
	s.Hosts.Range(func(key, value interface{}) bool {
		current, ok := value.(*Host)
		if !ok || current == nil {
			s.Hosts.CompareAndDelete(key, value)
			return true
		}
		normalizeHostRoutingFields(current)
		if current.Id != host.Id &&
			current.Host == host.Host &&
			current.Location == host.Location &&
			(current.Scheme == "all" || current.Scheme == host.Scheme) {
			exist = true
			return false
		}
		return true
	})
	return exist
}

func (s *JsonDb) GetClient(id int) (c *Client, err error) {
	if current, ok := loadClientEntry(&s.Clients, id); ok {
		c = current
		return
	}
	err = ErrClientNotFound
	return
}

var hostLock sync.Mutex

func (s *JsonDb) StoreHosts() {
	if s.deferStore(jsonDBStoreHosts) {
		return
	}
	s.storeHostsNow()
}

func (s *JsonDb) storeHostsNow() {
	hostLock.Lock()
	defer hostLock.Unlock()
	if err := s.persistenceBackend().StoreHosts(s); err != nil {
		logs.Error("store to file %s error %v", s.HostFilePath, err)
	}
}

func (s *JsonDb) StoreHostToJsonFile() {
	s.StoreHosts()
}

var taskLock sync.Mutex

func (s *JsonDb) StoreTasks() {
	if s.deferStore(jsonDBStoreTasks) {
		return
	}
	s.storeTasksNow()
}

func (s *JsonDb) storeTasksNow() {
	taskLock.Lock()
	defer taskLock.Unlock()
	if err := s.persistenceBackend().StoreTasks(s); err != nil {
		logs.Error("store to file %s error %v", s.TaskFilePath, err)
	}
}

func (s *JsonDb) StoreTasksToJsonFile() {
	s.StoreTasks()
}

var clientLock sync.Mutex

func (s *JsonDb) StoreClients() {
	if s.deferStore(jsonDBStoreClients) {
		return
	}
	s.storeClientsNow()
}

func (s *JsonDb) storeClientsNow() {
	clientLock.Lock()
	defer clientLock.Unlock()
	if err := s.persistenceBackend().StoreClients(s); err != nil {
		logs.Error("store to file %s error %v", s.ClientFilePath, err)
	}
}

func (s *JsonDb) StoreClientsToJsonFile() {
	s.StoreClients()
}

var userLock sync.Mutex

func (s *JsonDb) StoreUsers() {
	if s.deferStore(jsonDBStoreUsers) {
		return
	}
	s.storeUsersNow()
}

func (s *JsonDb) storeUsersNow() {
	userLock.Lock()
	defer userLock.Unlock()
	if err := s.persistenceBackend().StoreUsers(s); err != nil {
		logs.Error("store to file %s error %v", s.UserFilePath, err)
	}
}

func (s *JsonDb) StoreUsersToJsonFile() {
	s.StoreUsers()
}

var globalLock sync.Mutex

func (s *JsonDb) StoreGlobal() {
	if s.deferStore(jsonDBStoreGlobal) {
		return
	}
	s.storeGlobalNow()
}

func (s *JsonDb) storeGlobalNow() {
	globalLock.Lock()
	defer globalLock.Unlock()
	if err := s.persistenceBackend().StoreGlobal(s); err != nil {
		logs.Error("store to file %s error %v", s.GlobalFilePath, err)
	}
}

func (s *JsonDb) StoreGlobalToJsonFile() {
	s.StoreGlobal()
}

func (s *JsonDb) WithDeferredPersistence(run func() error) error {
	if run == nil {
		return nil
	}
	if s == nil {
		return run()
	}
	release := s.beginDeferredPersistence()
	defer release()
	return run()
}

func (s *JsonDb) beginDeferredPersistence() func() {
	if s == nil {
		return func() {}
	}
	s.deferredStores.mu.Lock()
	s.deferredStores.depth++
	s.deferredStores.mu.Unlock()
	return func() {
		s.endDeferredPersistence()
	}
}

func (s *JsonDb) endDeferredPersistence() {
	if s == nil {
		return
	}
	dirty := s.releaseDeferredStoreMask()
	if dirty == 0 {
		return
	}
	s.flushDeferredStoreMask(dirty)
}

func (s *JsonDb) releaseDeferredStoreMask() jsonDBStoreMask {
	if s == nil {
		return 0
	}
	s.deferredStores.mu.Lock()
	defer s.deferredStores.mu.Unlock()
	if s.deferredStores.depth <= 0 {
		return 0
	}
	s.deferredStores.depth--
	if s.deferredStores.depth != 0 {
		return 0
	}
	dirty := s.deferredStores.dirty
	s.deferredStores.dirty = 0
	return dirty
}

func (s *JsonDb) deferStore(mask jsonDBStoreMask) bool {
	if s == nil {
		return false
	}
	s.deferredStores.mu.Lock()
	defer s.deferredStores.mu.Unlock()
	if s.deferredStores.depth == 0 {
		return false
	}
	s.deferredStores.dirty |= mask
	return true
}

func (s *JsonDb) flushDeferredStoreMask(mask jsonDBStoreMask) {
	if s == nil || mask == 0 {
		return
	}
	if mask&jsonDBStoreUsers != 0 {
		s.storeUsersNow()
	}
	if mask&jsonDBStoreClients != 0 {
		s.storeClientsNow()
	}
	if mask&jsonDBStoreTasks != 0 {
		s.storeTasksNow()
	}
	if mask&jsonDBStoreHosts != 0 {
		s.storeHostsNow()
	}
	if mask&jsonDBStoreGlobal != 0 {
		s.storeGlobalNow()
	}
}

func (s *JsonDb) GetClientId() int32 {
	return atomic.AddInt32(&s.ClientIncreaseId, 1)
}

func (s *JsonDb) GetUserId() int32 {
	return atomic.AddInt32(&s.UserIncreaseId, 1)
}

func (s *JsonDb) GetTaskId() int32 {
	return atomic.AddInt32(&s.TaskIncreaseId, 1)
}

func (s *JsonDb) GetHostId() int32 {
	return atomic.AddInt32(&s.HostIncreaseId, 1)
}

func storeSyncMapToFile(m *sync.Map, filePath string) {
	if err := writeSyncMapToFile(m, filePath); err != nil {
		logs.Error("store to file %s error %v", filePath, err)
	}
}

func writeSyncMapToFile(m *sync.Map, filePath string) (err error) {
	tmpFilePath := filePath + ".tmp"
	file, err := os.Create(tmpFilePath)
	if err != nil {
		return fmt.Errorf("create temp file %s: %w", tmpFilePath, err)
	}
	cleanupTmp := true
	defer func() {
		_ = file.Close()
		if cleanupTmp {
			_ = os.Remove(tmpFilePath)
		}
	}()

	writer := bufio.NewWriter(file)
	if _, err = writer.WriteString("[\n"); err != nil {
		return fmt.Errorf("write json array header %s: %w", tmpFilePath, err)
	}

	first := true
	var rangeErr error
	m.Range(func(key, value interface{}) bool {
		switch v := value.(type) {
		case *Tunnel:
			if v.NoStore {
				return true
			}
		case *Host:
			if v.NoStore {
				return true
			}
		case *Client:
			if v.NoStore {
				return true
			}
		}

		data, marshalErr := marshalPersistedValue(value)
		if marshalErr != nil {
			rangeErr = fmt.Errorf("marshal %T: %w", value, marshalErr)
			return false
		}
		if !first {
			if _, rangeErr = writer.WriteString(",\n"); rangeErr != nil {
				rangeErr = fmt.Errorf("write json separator %s: %w", tmpFilePath, rangeErr)
				return false
			}
		}
		first = false
		if _, rangeErr = writer.WriteString("  "); rangeErr != nil {
			rangeErr = fmt.Errorf("write json indent %s: %w", tmpFilePath, rangeErr)
			return false
		}
		if _, rangeErr = writer.Write(data); rangeErr != nil {
			rangeErr = fmt.Errorf("write json payload %s: %w", tmpFilePath, rangeErr)
			return false
		}
		return true
	})
	if rangeErr != nil {
		return rangeErr
	}

	if _, err = writer.WriteString("\n]\n"); err != nil {
		return fmt.Errorf("write json array footer %s: %w", tmpFilePath, err)
	}
	if err = writer.Flush(); err != nil {
		return fmt.Errorf("flush json file %s: %w", tmpFilePath, err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync json file %s: %w", tmpFilePath, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close json file %s: %w", tmpFilePath, err)
	}

	if err = os.Rename(tmpFilePath, filePath); err != nil {
		return fmt.Errorf("replace json file %s: %w", filePath, err)
	}
	cleanupTmp = false
	return nil
}

func storeGlobalToFile(m *Glob, filePath string) {
	if err := writeGlobalToFile(m, filePath); err != nil {
		logs.Error("store to file %s error %v", filePath, err)
	}
}

func writeGlobalToFile(m *Glob, filePath string) (err error) {
	tmpFilePath := filePath + ".tmp"
	file, err := os.Create(tmpFilePath)
	if err != nil {
		return fmt.Errorf("create temp file %s: %w", tmpFilePath, err)
	}
	cleanupTmp := true
	defer func() {
		_ = file.Close()
		if cleanupTmp {
			_ = os.Remove(tmpFilePath)
		}
	}()

	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal global payload: %w", err)
	}
	if _, err = file.Write(b); err != nil {
		return fmt.Errorf("write global payload %s: %w", tmpFilePath, err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync global payload %s: %w", tmpFilePath, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close global payload %s: %w", tmpFilePath, err)
	}

	if err = os.Rename(tmpFilePath, filePath); err != nil {
		return fmt.Errorf("replace global file %s: %w", filePath, err)
	}
	cleanupTmp = false
	return nil
}

func loadUsersFromFile(filePath string) ([]*User, error) {
	loaded := make([]*User, 0)
	if err := loadSyncMapFromFile(filePath, User{}, func(v interface{}) {
		loaded = append(loaded, v.(*User))
	}); err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadClientsFromFile(filePath string) ([]*Client, error) {
	loaded := make([]*Client, 0)
	if err := loadSyncMapFromFile(filePath, Client{}, func(v interface{}) {
		loaded = append(loaded, v.(*Client))
	}); err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadTasksFromFile(filePath string) ([]*Tunnel, error) {
	loaded := make([]*Tunnel, 0)
	if err := loadSyncMapFromFile(filePath, Tunnel{}, func(v interface{}) {
		loaded = append(loaded, v.(*Tunnel))
	}); err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadHostsFromFile(filePath string) ([]*Host, error) {
	loaded := make([]*Host, 0)
	if err := loadSyncMapFromFile(filePath, Host{}, func(v interface{}) {
		loaded = append(loaded, v.(*Host))
	}); err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadGlobalFromFile(filePath string) (*Glob, error) {
	b, err := readPersistedFile(filePath)
	if err != nil {
		return nil, err
	}
	global := &Glob{}
	InitializeGlobalRuntime(global)
	if len(bytes.TrimSpace(b)) == 0 {
		return global, nil
	}
	post := new(Glob)
	if json.Unmarshal(b, post) != nil {
		return global, nil
	}
	InitializeGlobalRuntime(post)
	return post, nil
}

func loadSyncMapFromFile(filePath string, t interface{}, f func(value interface{})) error {
	b, err := readPersistedFile(filePath)
	if err != nil {
		return err
	}
	return loadSyncMapFromBytes(b, filePath, t, f)
}

func loadSyncMapFromBytes(b []byte, filePath string, t interface{}, f func(value interface{})) error {
	objType := persistedObjectType(t)
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil
	}
	// Prefer the current JSON array format first.
	if trimmed[0] == '[' {
		elements, err := openPersistedArray(objType, b)
		if err != nil {
			return err
		}
		for _, raw := range elements {
			if err := decodePersistedObject(raw, t, f); err != nil {
				return err
			}
		}
		return nil
	}
	// Fall back to the older line-delimited format.
	logs.Warn("Load %s as obsolete line-delimited json file", filePath)
	return loadObsoleteJsonFile(b, t, f, objType)
}

func loadObsoleteJsonFile(b []byte, t interface{}, f func(value interface{}), objType string) error {
	// The legacy format is split by "\n"+common.CONN_DATA_SEQ.
	separator := []byte("\n" + common.CONN_DATA_SEQ)
	for _, raw := range bytes.Split(b, separator) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		opened, err := openPersistedObject(objType, raw)
		if err != nil {
			return err
		}
		if err := decodePersistedObject(opened, t, f); err != nil {
			fmt.Println("Error:", err)
			return err
		}
	}
	return nil
}

func readPersistedFile(filePath string) ([]byte, error) {
	if !common.FileExists(filePath) {
		if err := createEmptyFile(filePath); err != nil {
			return nil, err
		}
	}
	return common.ReadAllFromFile(filePath)
}

func createEmptyFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if !common.FileExists(dir) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}

	if !common.FileExists(filePath) {
		file, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
	}

	return nil
}

func (s *JsonDb) persistenceBackend() persistenceBackend {
	if s != nil && s.persistence != nil {
		return s.persistence
	}
	return newJSONFilePersistenceBackend()
}

func (s *JsonDb) clearClientUserIndexes() {
	if s == nil {
		return
	}
	s.ownerClientIndex.clear()
	s.managerClientIndex.clear()
}

func (s *JsonDb) markClientUserIndexesReady() {
	if s == nil {
		return
	}
	s.ownerClientIndex.markReady()
	s.managerClientIndex.markReady()
}

func (s *JsonDb) addClientUserIndexes(client *Client) {
	if s == nil || client == nil || client.Id <= 0 {
		return
	}
	s.ownerClientIndex.add(client.OwnerID(), client.Id)
	for _, managerUserID := range client.ManagerUserIDs {
		s.managerClientIndex.add(managerUserID, client.Id)
	}
}

func (s *JsonDb) removeClientUserIndexesByID(clientID int) {
	if s == nil || clientID <= 0 {
		return
	}
	s.ownerClientIndex.removeID(clientID)
	s.managerClientIndex.removeID(clientID)
}
