package file

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/credential"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/logs"
)

type DbUtils struct {
	JsonDb *JsonDb
}

var (
	Db                  *DbUtils
	once                sync.Once
	dbMu                sync.RWMutex
	HostIndex           = index.NewDomainIndex()
	Blake2bVkeyIndex    = index.NewStringIDIndex()
	TaskPasswordIndex   = index.NewStringIDIndex()
	PlatformUserIndex   = index.NewStringIDIndex()
	UsernameIndex       = index.NewStringIDIndex()
	ErrUserNotFound     = errors.New("user not found")
	ErrClientNotFound   = errors.New("client not found")
	ErrTaskNotFound     = errors.New("task not found")
	ErrHostNotFound     = errors.New("host not found")
	ErrRevisionConflict = errors.New("resource revision conflict")
)

var (
	hostIndexPtr         atomic.Pointer[index.DomainIndex]
	blake2bVkeyIndexPtr  atomic.Pointer[index.StringIDIndex]
	taskPasswordIndexPtr atomic.Pointer[index.StringIDIndex]
	platformUserIndexPtr atomic.Pointer[index.StringIDIndex]
	usernameIndexPtr     atomic.Pointer[index.StringIDIndex]
)

// RuntimeIndexes groups the mutable package-level indexes so tests and
// migration paths can swap them as one coherent set instead of writing each
// global pointer independently.
type RuntimeIndexes struct {
	HostIndex         *index.DomainIndex
	Blake2bVkeyIndex  *index.StringIDIndex
	TaskPasswordIndex *index.StringIDIndex
	PlatformUserIndex *index.StringIDIndex
	UsernameIndex     *index.StringIDIndex
}

func init() {
	hostIndexPtr.Store(HostIndex)
	blake2bVkeyIndexPtr.Store(Blake2bVkeyIndex)
	taskPasswordIndexPtr.Store(TaskPasswordIndex)
	platformUserIndexPtr.Store(PlatformUserIndex)
	usernameIndexPtr.Store(UsernameIndex)
}

func NewRuntimeIndexes() RuntimeIndexes {
	return RuntimeIndexes{
		HostIndex:         index.NewDomainIndex(),
		Blake2bVkeyIndex:  index.NewStringIDIndex(),
		TaskPasswordIndex: index.NewStringIDIndex(),
		PlatformUserIndex: index.NewStringIDIndex(),
		UsernameIndex:     index.NewStringIDIndex(),
	}
}

func SnapshotRuntimeIndexes() RuntimeIndexes {
	return RuntimeIndexes{
		HostIndex:         runtimeHostIndex(),
		Blake2bVkeyIndex:  runtimeBlake2bVkeyIndex(),
		TaskPasswordIndex: runtimeTaskPasswordIndex(),
		PlatformUserIndex: runtimePlatformUserIndex(),
		UsernameIndex:     runtimeUsernameIndex(),
	}
}

func ReplaceRuntimeIndexes(indexes RuntimeIndexes) RuntimeIndexes {
	indexes = normalizeRuntimeIndexes(indexes)
	previous := SnapshotRuntimeIndexes()

	HostIndex = indexes.HostIndex
	Blake2bVkeyIndex = indexes.Blake2bVkeyIndex
	TaskPasswordIndex = indexes.TaskPasswordIndex
	PlatformUserIndex = indexes.PlatformUserIndex
	UsernameIndex = indexes.UsernameIndex

	hostIndexPtr.Store(indexes.HostIndex)
	blake2bVkeyIndexPtr.Store(indexes.Blake2bVkeyIndex)
	taskPasswordIndexPtr.Store(indexes.TaskPasswordIndex)
	platformUserIndexPtr.Store(indexes.PlatformUserIndex)
	usernameIndexPtr.Store(indexes.UsernameIndex)

	return previous
}

func normalizeRuntimeIndexes(indexes RuntimeIndexes) RuntimeIndexes {
	if indexes.HostIndex == nil {
		indexes.HostIndex = index.NewDomainIndex()
	}
	if indexes.Blake2bVkeyIndex == nil {
		indexes.Blake2bVkeyIndex = index.NewStringIDIndex()
	}
	if indexes.TaskPasswordIndex == nil {
		indexes.TaskPasswordIndex = index.NewStringIDIndex()
	}
	if indexes.PlatformUserIndex == nil {
		indexes.PlatformUserIndex = index.NewStringIDIndex()
	}
	if indexes.UsernameIndex == nil {
		indexes.UsernameIndex = index.NewStringIDIndex()
	}
	return indexes
}

func runtimeHostIndex() *index.DomainIndex {
	if current := hostIndexPtr.Load(); current != nil {
		return current
	}
	hostIndexPtr.Store(HostIndex)
	return HostIndex
}

func CurrentHostIndex() *index.DomainIndex {
	return runtimeHostIndex()
}

func runtimeBlake2bVkeyIndex() *index.StringIDIndex {
	if current := blake2bVkeyIndexPtr.Load(); current != nil {
		return current
	}
	blake2bVkeyIndexPtr.Store(Blake2bVkeyIndex)
	return Blake2bVkeyIndex
}

func CurrentBlake2bVkeyIndex() *index.StringIDIndex {
	return runtimeBlake2bVkeyIndex()
}

func runtimeTaskPasswordIndex() *index.StringIDIndex {
	if current := taskPasswordIndexPtr.Load(); current != nil {
		return current
	}
	taskPasswordIndexPtr.Store(TaskPasswordIndex)
	return TaskPasswordIndex
}

func CurrentTaskPasswordIndex() *index.StringIDIndex {
	return runtimeTaskPasswordIndex()
}

func runtimePlatformUserIndex() *index.StringIDIndex {
	if current := platformUserIndexPtr.Load(); current != nil {
		return current
	}
	platformUserIndexPtr.Store(PlatformUserIndex)
	return PlatformUserIndex
}

func CurrentPlatformUserIndex() *index.StringIDIndex {
	return runtimePlatformUserIndex()
}

func runtimeUsernameIndex() *index.StringIDIndex {
	if current := usernameIndexPtr.Load(); current != nil {
		return current
	}
	usernameIndexPtr.Store(UsernameIndex)
	return UsernameIndex
}

func CurrentUsernameIndex() *index.StringIDIndex {
	return runtimeUsernameIndex()
}

// ReplaceDb swaps the cached DB instance and marks lazy initialization as satisfied.
// Passing nil clears the cached instance so GetDb can initialize it again on demand.
func ReplaceDb(db *DbUtils) {
	dbMu.Lock()
	defer dbMu.Unlock()
	Db = db
	once = sync.Once{}
	if db != nil {
		once.Do(func() {})
	}
}

// GetDb init data from file
func GetDb() *DbUtils {
	dbMu.RLock()
	current := Db
	dbMu.RUnlock()
	if current != nil {
		return current
	}
	dbMu.Lock()
	defer dbMu.Unlock()
	once.Do(func() {
		// Eagerly initialize the externally injected credential master key
		// before any record is opened so an envelope on disk is authenticated
		// against the correct key ring from the very first load.
		keyRing := credential.Default()
		if keyRing.Enabled() {
			logs.Info("credential at-rest encryption enabled with master key id %q", keyRing.CurrentKeyID())
			if keyRing.HasPreviousKey() {
				logs.Info("credential previous master key %q retained for the rotation window", keyRing.PreviousKeyID())
			}
		} else {
			logs.Info("credential at-rest encryption disabled (no master key injected)")
		}
		jsonDb := NewJsonDb(common.GetRunPath())
		jsonDb.LoadUsers()
		jsonDb.LoadClients()
		jsonDb.LoadTasks()
		jsonDb.LoadHosts()
		jsonDb.LoadGlobal()
		Db = &DbUtils{JsonDb: jsonDb}
	})
	return Db
}

func (s *DbUtils) Ready() bool {
	return s != nil && s.JsonDb != nil
}

func (s *DbUtils) NextClientID() int {
	if !s.Ready() {
		return 0
	}
	return int(s.JsonDb.GetClientId())
}

func (s *DbUtils) NextUserID() int {
	if !s.Ready() {
		return 0
	}
	return int(s.JsonDb.GetUserId())
}

func (s *DbUtils) NextTaskID() int {
	if !s.Ready() {
		return 0
	}
	return int(s.JsonDb.GetTaskId())
}

func (s *DbUtils) NextHostID() int {
	if !s.Ready() {
		return 0
	}
	return int(s.JsonDb.GetHostId())
}

func (s *DbUtils) StoreUsers() {
	if !s.Ready() {
		return
	}
	s.JsonDb.StoreUsers()
}

func (s *DbUtils) StoreClients() {
	if !s.Ready() {
		return
	}
	s.JsonDb.StoreClients()
}

func (s *DbUtils) StoreTasks() {
	if !s.Ready() {
		return
	}
	s.JsonDb.StoreTasks()
}

func (s *DbUtils) StoreHosts() {
	if !s.Ready() {
		return
	}
	s.JsonDb.StoreHosts()
}

func (s *DbUtils) StoreGlobal() {
	if !s.Ready() {
		return
	}
	s.JsonDb.StoreGlobal()
}

func (s *DbUtils) RangeClients(fn func(*Client) bool) {
	if !s.Ready() || fn == nil {
		return
	}
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		if _, ok := key.(int); !ok {
			s.JsonDb.Clients.CompareAndDelete(key, value)
			return true
		}
		client, ok := value.(*Client)
		if !ok || client == nil {
			s.JsonDb.Clients.CompareAndDelete(key, value)
			return true
		}
		return fn(client)
	})
}

func (s *DbUtils) RangeUsers(fn func(*User) bool) {
	if !s.Ready() || fn == nil {
		return
	}
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		if _, ok := key.(int); !ok {
			s.JsonDb.Users.CompareAndDelete(key, value)
			return true
		}
		user, ok := value.(*User)
		if !ok || user == nil {
			s.JsonDb.Users.CompareAndDelete(key, value)
			return true
		}
		return fn(user)
	})
}

func (s *DbUtils) RangeTasks(fn func(*Tunnel) bool) {
	if !s.Ready() || fn == nil {
		return
	}
	s.JsonDb.Tasks.Range(func(key, value interface{}) bool {
		if _, ok := key.(int); !ok {
			s.JsonDb.Tasks.CompareAndDelete(key, value)
			return true
		}
		task, ok := value.(*Tunnel)
		if !ok || task == nil {
			s.JsonDb.Tasks.CompareAndDelete(key, value)
			return true
		}
		return fn(task)
	})
}

func (s *DbUtils) RangeHosts(fn func(*Host) bool) {
	if !s.Ready() || fn == nil {
		return
	}
	s.JsonDb.Hosts.Range(func(key, value interface{}) bool {
		if _, ok := key.(int); !ok {
			s.JsonDb.Hosts.CompareAndDelete(key, value)
			return true
		}
		host, ok := value.(*Host)
		if !ok || host == nil {
			s.JsonDb.Hosts.CompareAndDelete(key, value)
			return true
		}
		return fn(host)
	})
}

func GetMapKeys(m *sync.Map, isSort bool, sortKey, order string) (keys []int) {
	if m == nil {
		return nil
	}
	if (sortKey == "InletFlow" || sortKey == "ExportFlow") && isSort {
		return sortClientByKey(m, sortKey, order)
	}
	m.Range(func(key, value interface{}) bool {
		id, ok := key.(int)
		if !ok {
			m.CompareAndDelete(key, value)
			return true
		}
		keys = append(keys, id)
		return true
	})
	sort.Ints(keys)
	return
}

func loadClientEntry(m *sync.Map, key interface{}) (*Client, bool) {
	if m == nil {
		return nil, false
	}
	value, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	client, ok := value.(*Client)
	if !ok || client == nil {
		m.CompareAndDelete(key, value)
		return nil, false
	}
	return client, true
}

func loadUserEntry(m *sync.Map, key interface{}) (*User, bool) {
	if m == nil {
		return nil, false
	}
	value, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	user, ok := value.(*User)
	if !ok || user == nil {
		m.CompareAndDelete(key, value)
		return nil, false
	}
	return user, true
}

func loadTaskEntry(m *sync.Map, key interface{}) (*Tunnel, bool) {
	if m == nil {
		return nil, false
	}
	value, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	task, ok := value.(*Tunnel)
	if !ok || task == nil {
		m.CompareAndDelete(key, value)
		return nil, false
	}
	return task, true
}

func loadHostEntry(m *sync.Map, key interface{}) (*Host, bool) {
	if m == nil {
		return nil, false
	}
	value, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	host, ok := value.(*Host)
	if !ok || host == nil {
		m.CompareAndDelete(key, value)
		return nil, false
	}
	return host, true
}

func resolveStoredClientRef(s *DbUtils, client *Client) (*Client, error) {
	if s == nil || s.JsonDb == nil {
		return nil, errors.New("db is nil")
	}
	if client == nil || client.Id == 0 {
		return nil, errors.New("client is nil")
	}
	stored, err := s.GetClient(client.Id)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

type clientFlowSortField uint8

const (
	clientFlowSortFieldInvalid clientFlowSortField = iota
	clientFlowSortFieldInlet
	clientFlowSortFieldExport
)

type clientFlowSortEntry struct {
	id         int
	inletFlow  int64
	exportFlow int64
}

func resolveClientFlowSortField(sortKey string) clientFlowSortField {
	switch sortKey {
	case "InletFlow":
		return clientFlowSortFieldInlet
	case "ExportFlow":
		return clientFlowSortFieldExport
	default:
		return clientFlowSortFieldInvalid
	}
}

func (e clientFlowSortEntry) sortValue(field clientFlowSortField) int64 {
	switch field {
	case clientFlowSortFieldInlet:
		return e.inletFlow
	case clientFlowSortFieldExport:
		return e.exportFlow
	default:
		return 0
	}
}

func sortClientByKey(m *sync.Map, sortKey, order string) (res []int) {
	if m == nil {
		return nil
	}
	field := resolveClientFlowSortField(sortKey)
	if field == clientFlowSortFieldInvalid {
		return nil
	}
	entries := make([]clientFlowSortEntry, 0)
	m.Range(func(key, value interface{}) bool {
		if _, ok := key.(int); !ok {
			m.CompareAndDelete(key, value)
			return true
		}
		client, ok := value.(*Client)
		if !ok || client == nil {
			m.CompareAndDelete(key, value)
			return true
		}
		inletFlow, exportFlow := flowSnapshot(client.Flow)
		entries = append(entries, clientFlowSortEntry{
			id:         client.Id,
			inletFlow:  inletFlow,
			exportFlow: exportFlow,
		})
		return true
	})
	descending := order == "desc"
	sort.Slice(entries, func(i, j int) bool {
		left := entries[i].sortValue(field)
		right := entries[j].sortValue(field)
		if left == right {
			return entries[i].id < entries[j].id
		}
		if descending {
			return left < right
		}
		return left > right
	})
	res = make([]int, 0, len(entries))
	for _, entry := range entries {
		res = append(res, entry.id)
	}
	return res
}

func (s *DbUtils) SaveGlobal(t *Glob) error {
	if t == nil {
		t = &Glob{}
	}
	InitializeGlobalRuntime(t)
	s.JsonDb.Global = t
	s.JsonDb.StoreGlobal()
	return nil
}

func (s *DbUtils) GetGlobal() (c *Glob) {
	return s.JsonDb.Global
}

func (s *DbUtils) WithDeferredPersistence(run func() error) error {
	if run == nil {
		return nil
	}
	if s == nil || s.JsonDb == nil {
		return run()
	}
	return s.JsonDb.WithDeferredPersistence(run)
}

func (s *DbUtils) FlushToDisk() {
	if s == nil || s.JsonDb == nil {
		return
	}
	s.JsonDb.storeUsersNow()
	s.JsonDb.storeClientsNow()
	s.JsonDb.storeTasksNow()
	s.JsonDb.storeHostsNow()
	s.JsonDb.storeGlobalNow()
}
