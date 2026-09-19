package file

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
)

type Store interface {
	GetUser(id int) (*User, error)
	GetUserByUsername(username string) (*User, error)
	CreateUser(*User) error
	UpdateUser(*User) error
	GetClient(vkey string) (*Client, error)
	GetClientByID(id int) (*Client, error)
	UpdateClient(*Client) error
	GetAllClients() []*Client
	GetClientsByUserId(userID int) []*Client
	GetTunnelsByUserId(userID int) int
	GetHostsByUserId(userID int) int
	Flush() error
}

type ConfigExporter interface {
	ExportConfigSnapshot() (*ConfigSnapshot, error)
}

type ConfigImporter interface {
	ImportConfigSnapshot(*ConfigSnapshot) error
}

type TrafficDelta struct {
	ClientID  int    `json:"client_id"`
	VerifyKey string `json:"vkey"`
	In        int64  `json:"in"`
	Out       int64  `json:"out"`
}

type ConfigSnapshot struct {
	Users   []*User   `json:"users"`
	Clients []*Client `json:"clients"`
	Tunnels []*Tunnel `json:"tunnels"`
	Hosts   []*Host   `json:"hosts"`
	Global  *Glob     `json:"global,omitempty"`
}

var GlobalStore Store

type LocalStore struct {
	db *DbUtils
}

func NewLocalStore() *LocalStore {
	s := &LocalStore{db: GetDb()}
	SetClientSetupHook(nil)
	return s
}

func (s *LocalStore) GetUser(id int) (*User, error) {
	return s.db.GetUser(id)
}

func (s *LocalStore) GetUserByUsername(username string) (*User, error) {
	return s.db.GetUserByUsername(username)
}

func (s *LocalStore) CreateUser(user *User) error {
	return s.db.NewUser(user)
}

func (s *LocalStore) UpdateUser(user *User) error {
	return s.db.UpdateUser(user)
}

func (s *LocalStore) GetClient(vkey string) (*Client, error) {
	return s.db.GetClientByVerifyKey(vkey)
}

func (s *LocalStore) GetClientByID(id int) (*Client, error) {
	return s.db.GetClient(id)
}

func (s *LocalStore) UpdateClient(client *Client) error {
	if client == nil {
		return nil
	}
	return s.db.UpdateClient(client)
}

func (s *LocalStore) GetAllClients() []*Client {
	clients := make([]*Client, 0)
	if s == nil || s.db == nil {
		return clients
	}
	s.db.RangeClients(func(client *Client) bool {
		clients = append(clients, client)
		return true
	})
	return clients
}

func (s *LocalStore) GetClientsByUserId(userID int) []*Client {
	return s.db.GetClientsByUserId(userID)
}

func (s *LocalStore) GetTunnelsByUserId(userID int) int {
	return s.db.GetTunnelsByUserId(userID)
}

func (s *LocalStore) GetHostsByUserId(userID int) int {
	return s.db.GetHostsByUserId(userID)
}

func (s *LocalStore) Flush() error {
	s.db.FlushToDisk()
	return nil
}

func (s *LocalStore) WithDeferredPersistence(run func() error) error {
	if run == nil {
		return nil
	}
	if s == nil || s.db == nil {
		return run()
	}
	return s.db.WithDeferredPersistence(run)
}

func (s *LocalStore) ExportConfigSnapshot() (*ConfigSnapshot, error) {
	return buildConfigSnapshot(s.db), nil
}

// ExportMaskedConfigSnapshot returns a configuration snapshot with every
// secret replaced by a non-reversible marker. It is intended for human-facing
// exports; node replication and restore keep using ExportConfigSnapshot.
func (s *LocalStore) ExportMaskedConfigSnapshot() (*ConfigSnapshot, error) {
	snapshot, err := s.ExportConfigSnapshot()
	if err != nil {
		return nil, err
	}
	return MaskConfigSnapshot(snapshot), nil
}

func (s *LocalStore) ImportConfigSnapshot(snapshot *ConfigSnapshot) error {
	return applyConfigSnapshot(s.db, snapshot)
}

func buildConfigSnapshot(db *DbUtils) *ConfigSnapshot {
	snapshot := &ConfigSnapshot{
		Global: &Glob{},
	}
	if db == nil || db.JsonDb == nil {
		return snapshot
	}
	snapshot.Global = cloneGlobForConfig(db.JsonDb.Global)
	db.RangeUsers(func(user *User) bool {
		snapshot.Users = append(snapshot.Users, cloneUserForConfig(user))
		return true
	})
	db.RangeClients(func(client *Client) bool {
		snapshot.Clients = append(snapshot.Clients, cloneClientForConfig(client))
		return true
	})
	db.RangeTasks(func(tunnel *Tunnel) bool {
		snapshot.Tunnels = append(snapshot.Tunnels, cloneTunnelForConfig(tunnel))
		return true
	})
	db.RangeHosts(func(host *Host) bool {
		snapshot.Hosts = append(snapshot.Hosts, cloneHostForConfig(host))
		return true
	})
	sort.Slice(snapshot.Users, func(i, j int) bool { return snapshot.Users[i].Id < snapshot.Users[j].Id })
	sort.Slice(snapshot.Clients, func(i, j int) bool { return snapshot.Clients[i].Id < snapshot.Clients[j].Id })
	sort.Slice(snapshot.Tunnels, func(i, j int) bool { return snapshot.Tunnels[i].Id < snapshot.Tunnels[j].Id })
	sort.Slice(snapshot.Hosts, func(i, j int) bool { return snapshot.Hosts[i].Id < snapshot.Hosts[j].Id })
	return snapshot
}

func applyConfigSnapshot(db *DbUtils, snapshot *ConfigSnapshot) error {
	if snapshot == nil {
		return errors.New("config snapshot is nil")
	}
	if db == nil || db.JsonDb == nil {
		return errors.New("store database is not initialized")
	}
	clonedSnapshot := cloneConfigSnapshot(snapshot)

	jsonDB := db.JsonDb
	runtimeBlake2bVkeyIndex().Clear()
	runtimeTaskPasswordIndex().Clear()
	runtimeHostIndex().Destroy()
	runtimePlatformUserIndex().Clear()
	runtimeUsernameIndex().Clear()
	jsonDB.clearClientUserIndexes()
	jsonDB.taskClientIndex.clear()
	jsonDB.hostClientIndex.clear()

	jsonDB.Users = sync.Map{}
	jsonDB.Clients = sync.Map{}
	jsonDB.Tasks = sync.Map{}
	jsonDB.Hosts = sync.Map{}
	jsonDB.UserIncreaseId = 0
	jsonDB.ClientIncreaseId = 0
	jsonDB.TaskIncreaseId = 0
	jsonDB.HostIncreaseId = 0

	clientByID := make(map[int]*Client, len(clonedSnapshot.Clients))
	for _, user := range clonedSnapshot.Users {
		if user == nil || user.Id <= 0 {
			continue
		}
		user.Username = strings.TrimSpace(user.Username)
		user.NormalizeIdentity()
		if !jsonDB.prepareLoadedUserReplace(user) {
			continue
		}
		InitializeUserRuntime(user)
		jsonDB.Users.Store(user.Id, user)
		if user.Id > int(jsonDB.UserIncreaseId) {
			jsonDB.UserIncreaseId = int32(user.Id)
		}
	}

	for _, client := range clonedSnapshot.Clients {
		if client == nil || client.Id <= 0 {
			continue
		}
		client.VerifyKey = strings.TrimSpace(client.VerifyKey)
		client.IsConnect = false
		client.NowConn = 0
		if owner, ok := loadUserEntry(&jsonDB.Users, client.OwnerID()); ok {
			client.BindOwnerUser(owner)
		} else {
			client.BindOwnerUser(nil)
		}
		if !jsonDB.prepareLoadedClientReplace(client) {
			continue
		}
		InitializeClientRuntime(client)
		clientByID[client.Id] = client
		jsonDB.Clients.Store(client.Id, client)
		jsonDB.addClientUserIndexes(client)
		if client.Id > int(jsonDB.ClientIncreaseId) {
			jsonDB.ClientIncreaseId = int32(client.Id)
		}
	}
	jsonDB.markClientUserIndexesReady()

	for _, tunnel := range clonedSnapshot.Tunnels {
		if tunnel == nil || tunnel.Id <= 0 {
			continue
		}
		initializeImportedTunnel(tunnel, clientByID)
		if tunnel.Client == nil || tunnel.Client.Id <= 0 {
			continue
		}
		if tunnel.Password != "" {
			hash := crypt.Md5(tunnel.Password)
			if id, ok := runtimeTaskPasswordIndex().Get(hash); ok && id != tunnel.Id {
				continue
			}
		}
		jsonDB.prepareLoadedTunnelReplace(tunnel)
		InitializeTunnelRuntime(tunnel)
		jsonDB.Tasks.Store(tunnel.Id, tunnel)
		jsonDB.taskClientIndex.add(tunnel.Client.Id, tunnel.Id)
		if tunnel.Id > int(jsonDB.TaskIncreaseId) {
			jsonDB.TaskIncreaseId = int32(tunnel.Id)
		}
		if tunnel.Password != "" {
			runtimeTaskPasswordIndex().Add(crypt.Md5(tunnel.Password), tunnel.Id)
		}
	}
	jsonDB.taskClientIndex.markReady()

	for _, host := range clonedSnapshot.Hosts {
		if host == nil || host.Id <= 0 {
			continue
		}
		initializeImportedHost(host, clientByID)
		if host.Client == nil || host.Client.Id <= 0 {
			continue
		}
		normalizeHostRoutingFields(host)
		if jsonDB.loadedHostRouteExists(host) {
			continue
		}
		jsonDB.prepareLoadedHostReplace(host)
		finalizeHostForStore(host)
		jsonDB.Hosts.Store(host.Id, host)
		runtimeHostIndex().Add(host.Host, host.Id)
		jsonDB.hostClientIndex.add(host.Client.Id, host.Id)
		if host.Id > int(jsonDB.HostIncreaseId) {
			jsonDB.HostIncreaseId = int32(host.Id)
		}
	}
	jsonDB.hostClientIndex.markReady()

	if clonedSnapshot.Global != nil {
		InitializeGlobalRuntime(clonedSnapshot.Global)
		jsonDB.Global = clonedSnapshot.Global
	} else {
		jsonDB.Global = &Glob{}
		InitializeGlobalRuntime(jsonDB.Global)
	}

	return nil
}

func initializeImportedTunnel(tunnel *Tunnel, clients map[int]*Client) {
	if tunnel == nil {
		return
	}
	if tunnel.Client != nil {
		tunnel.Client = resolveImportedClient(tunnel.Client, clients)
	}
	if tunnel.Flow == nil {
		tunnel.Flow = new(Flow)
	}
	tunnel.NowConn = 0
	tunnel.RunStatus = false
	if tunnel.Target == nil {
		tunnel.Target = &Target{}
	}
	normalizeTunnelProtocolFields(tunnel)
	tunnel.UserAuth = normalizeMultiAccount(tunnel.UserAuth)
	tunnel.MultiAccount = normalizeMultiAccount(tunnel.MultiAccount)
	tunnel.CompileEntryACL()
	tunnel.CompileDestACL()
}

func initializeImportedHost(host *Host, clients map[int]*Client) {
	if host == nil {
		return
	}
	if host.Client != nil {
		host.Client = resolveImportedClient(host.Client, clients)
	}
	if host.Flow == nil {
		host.Flow = new(Flow)
	}
	host.NowConn = 0
	if host.Target == nil {
		host.Target = &Target{}
	}
	host.UserAuth = normalizeMultiAccount(host.UserAuth)
	host.MultiAccount = normalizeMultiAccount(host.MultiAccount)
	if host.CertType == "" {
		host.CertType = common.GetCertType(host.CertFile)
	}
	if host.CertHash == "" {
		host.CertHash = crypt.FNV1a64(host.CertType, host.CertFile, host.KeyFile)
	}
	host.CompileEntryACL()
}

func resolveImportedClient(raw *Client, clients map[int]*Client) *Client {
	if raw == nil {
		return nil
	}
	if client, ok := clients[raw.Id]; ok {
		return client
	}
	return nil
}

func cloneConfigSnapshot(snapshot *ConfigSnapshot) *ConfigSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := &ConfigSnapshot{
		Users:   make([]*User, 0, len(snapshot.Users)),
		Clients: make([]*Client, 0, len(snapshot.Clients)),
		Tunnels: make([]*Tunnel, 0, len(snapshot.Tunnels)),
		Hosts:   make([]*Host, 0, len(snapshot.Hosts)),
		Global:  cloneGlobForConfig(snapshot.Global),
	}
	for _, user := range snapshot.Users {
		cloned.Users = append(cloned.Users, cloneUserForConfig(user))
	}
	for _, client := range snapshot.Clients {
		cloned.Clients = append(cloned.Clients, cloneClientForConfig(client))
	}
	for _, tunnel := range snapshot.Tunnels {
		cloned.Tunnels = append(cloned.Tunnels, cloneTunnelForConfig(tunnel))
	}
	for _, host := range snapshot.Hosts {
		cloned.Hosts = append(cloned.Hosts, cloneHostForConfig(host))
	}
	return cloned
}

func cloneUserForConfig(user *User) *User {
	if user == nil {
		return nil
	}
	user.RLock()
	defer user.RUnlock()
	return &User{
		Id:                 user.Id,
		Username:           user.Username,
		Password:           user.Password,
		TOTPSecret:         user.TOTPSecret,
		Kind:               user.Kind,
		ExternalPlatformID: user.ExternalPlatformID,
		Hidden:             user.Hidden,
		Status:             user.Status,
		ExpireAt:           user.ExpireAt,
		FlowLimit:          user.FlowLimit,
		TotalFlow:          cloneFlowForConfig(user.TotalFlow),
		MaxClients:         user.MaxClients,
		MaxTunnels:         user.MaxTunnels,
		MaxHosts:           user.MaxHosts,
		MaxConnections:     user.MaxConnections,
		RateLimit:          user.RateLimit,
		EntryAclMode:       user.EntryAclMode,
		EntryAclRules:      user.EntryAclRules,
		DestAclMode:        user.DestAclMode,
		DestAclRules:       user.DestAclRules,
		Revision:           user.Revision,
		UpdatedAt:          user.UpdatedAt,
		TotalTraffic:       cloneTrafficStatsForConfig(user.TotalTraffic),
	}
}

func cloneClientForConfig(client *Client) *Client {
	if client == nil {
		return nil
	}
	client.RLock()
	defer client.RUnlock()
	return &Client{
		Cnf:              cloneConfigForConfig(client.Cnf),
		Id:               client.Id,
		UserId:           client.UserId,
		OwnerUserID:      client.OwnerUserID,
		ManagerUserIDs:   append([]int(nil), client.ManagerUserIDs...),
		SourceType:       client.SourceType,
		SourcePlatformID: client.SourcePlatformID,
		SourceActorID:    client.SourceActorID,
		Revision:         client.Revision,
		UpdatedAt:        client.UpdatedAt,
		VerifyKey:        client.VerifyKey,
		Mode:             client.Mode,
		Addr:             client.Addr,
		LocalAddr:        client.LocalAddr,
		Remark:           client.Remark,
		Status:           client.Status,
		IsConnect:        client.IsConnect,
		ExpireAt:         client.ExpireAt,
		FlowLimit:        client.FlowLimit,
		RateLimit:        client.RateLimit,
		Flow:             cloneFlowForConfig(client.Flow),
		ExportFlow:       client.ExportFlow,
		InletFlow:        client.InletFlow,
		BridgeTraffic:    cloneTrafficStatsForConfig(client.BridgeTraffic),
		ServiceTraffic:   cloneTrafficStatsForConfig(client.ServiceTraffic),
		NoStore:          client.NoStore,
		NoDisplay:        client.NoDisplay,
		MaxConn:          client.MaxConn,
		NowConn:          client.NowConn,
		ConfigConnAllow:  client.ConfigConnAllow,
		MaxTunnelNum:     client.MaxTunnelNum,
		Version:          client.Version,
		EntryAclMode:     client.EntryAclMode,
		EntryAclRules:    client.EntryAclRules,
		CreateTime:       client.CreateTime,
		LastOnlineTime:   client.LastOnlineTime,
	}
}

func cloneTunnelForConfig(tunnel *Tunnel) *Tunnel {
	if tunnel == nil {
		return nil
	}
	tunnel.RLock()
	defer tunnel.RUnlock()
	cloned := &Tunnel{
		Id:             tunnel.Id,
		Revision:       tunnel.Revision,
		UpdatedAt:      tunnel.UpdatedAt,
		Port:           tunnel.Port,
		ServerIp:       tunnel.ServerIp,
		Mode:           tunnel.Mode,
		Status:         tunnel.Status,
		RunStatus:      tunnel.RunStatus,
		Client:         cloneClientForConfig(tunnel.Client),
		Ports:          tunnel.Ports,
		ExpireAt:       tunnel.ExpireAt,
		FlowLimit:      tunnel.FlowLimit,
		RateLimit:      tunnel.RateLimit,
		Flow:           cloneFlowForConfig(tunnel.Flow),
		ServiceTraffic: cloneTrafficStatsForConfig(tunnel.ServiceTraffic),
		MaxConn:        tunnel.MaxConn,
		NowConn:        tunnel.NowConn,
		Password:       tunnel.Password,
		Remark:         tunnel.Remark,
		TargetAddr:     tunnel.TargetAddr,
		TargetType:     tunnel.TargetType,
		EntryAclMode:   tunnel.EntryAclMode,
		EntryAclRules:  tunnel.EntryAclRules,
		DestAclMode:    tunnel.DestAclMode,
		DestAclRules:   tunnel.DestAclRules,
		NoStore:        tunnel.NoStore,
		IsHttp:         tunnel.IsHttp,
		HttpProxy:      tunnel.HttpProxy,
		Socks5Proxy:    tunnel.Socks5Proxy,
		LocalPath:      tunnel.LocalPath,
		StripPre:       tunnel.StripPre,
		ReadOnly:       tunnel.ReadOnly,
		Target:         cloneTargetForConfig(tunnel.Target),
		UserAuth:       cloneMultiAccountForConfig(tunnel.UserAuth),
		MultiAccount:   cloneMultiAccountForConfig(tunnel.MultiAccount),
	}
	cloneHealthForConfig(&cloned.Health, &tunnel.Health)
	return cloned
}

func cloneHostForConfig(host *Host) *Host {
	if host == nil {
		return nil
	}
	host.RLock()
	defer host.RUnlock()
	cloned := &Host{
		Id:               host.Id,
		Revision:         host.Revision,
		UpdatedAt:        host.UpdatedAt,
		Host:             host.Host,
		HeaderChange:     host.HeaderChange,
		RespHeaderChange: host.RespHeaderChange,
		HostChange:       host.HostChange,
		Location:         host.Location,
		PathRewrite:      host.PathRewrite,
		Remark:           host.Remark,
		Scheme:           host.Scheme,
		RedirectURL:      host.RedirectURL,
		HttpsJustProxy:   host.HttpsJustProxy,
		TlsOffload:       host.TlsOffload,
		AutoSSL:          host.AutoSSL,
		CertType:         host.CertType,
		CertHash:         host.CertHash,
		CertFile:         host.CertFile,
		KeyFile:          host.KeyFile,
		NoStore:          host.NoStore,
		IsClose:          host.IsClose,
		AutoHttps:        host.AutoHttps,
		AutoCORS:         host.AutoCORS,
		CompatMode:       host.CompatMode,
		ExpireAt:         host.ExpireAt,
		FlowLimit:        host.FlowLimit,
		RateLimit:        host.RateLimit,
		Flow:             cloneFlowForConfig(host.Flow),
		ServiceTraffic:   cloneTrafficStatsForConfig(host.ServiceTraffic),
		MaxConn:          host.MaxConn,
		NowConn:          host.NowConn,
		Client:           cloneClientForConfig(host.Client),
		EntryAclMode:     host.EntryAclMode,
		EntryAclRules:    host.EntryAclRules,
		TargetIsHttps:    host.TargetIsHttps,
		Target:           cloneTargetForConfig(host.Target),
		UserAuth:         cloneMultiAccountForConfig(host.UserAuth),
		MultiAccount:     cloneMultiAccountForConfig(host.MultiAccount),
	}
	cloneHealthForConfig(&cloned.Health, &host.Health)
	return cloned
}

func cloneGlobForConfig(glob *Glob) *Glob {
	if glob == nil {
		return &Glob{}
	}
	glob.RLock()
	defer glob.RUnlock()
	return &Glob{
		EntryAclMode:  glob.EntryAclMode,
		EntryAclRules: glob.EntryAclRules,
	}
}

func cloneConfigForConfig(config *Config) *Config {
	if config == nil {
		return nil
	}
	return &Config{
		U:        config.U,
		P:        config.P,
		Compress: config.Compress,
		Crypt:    config.Crypt,
	}
}

func cloneFlowForConfig(flow *Flow) *Flow {
	if flow == nil {
		return nil
	}
	flow.RLock()
	defer flow.RUnlock()
	return &Flow{
		ExportFlow: flow.ExportFlow,
		InletFlow:  flow.InletFlow,
		FlowLimit:  flow.FlowLimit,
		TimeLimit:  flow.TimeLimit,
	}
}

func cloneTrafficStatsForConfig(stats *TrafficStats) *TrafficStats {
	if stats == nil {
		return nil
	}
	in, out, _ := stats.Snapshot()
	return &TrafficStats{
		InletBytes:  in,
		ExportBytes: out,
	}
}

func cloneTargetForConfig(target *Target) *Target {
	return cloneTargetSnapshot(target)
}

func cloneMultiAccountForConfig(account *MultiAccount) *MultiAccount {
	return cloneMultiAccountSnapshot(account)
}

func cloneHealthForConfig(dst *Health, src *Health) {
	if dst == nil {
		return
	}
	*dst = Health{}
	if src == nil {
		return
	}
	src.RLock()
	defer src.RUnlock()
	dst.HealthCheckTimeout = src.HealthCheckTimeout
	dst.HealthMaxFail = src.HealthMaxFail
	dst.HealthCheckInterval = src.HealthCheckInterval
	dst.HealthNextTime = src.HealthNextTime
	dst.HttpHealthUrl = src.HttpHealthUrl
	dst.HealthRemoveArr = append([]string(nil), src.HealthRemoveArr...)
	dst.HealthCheckType = src.HealthCheckType
	dst.HealthCheckTarget = src.HealthCheckTarget
	if len(src.HealthMap) > 0 {
		dst.HealthMap = make(map[string]int, len(src.HealthMap))
		for key, value := range src.HealthMap {
			dst.HealthMap[key] = value
		}
	}
}
