package file

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/credential"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/logs"
)

type legacyClientWebLoginImport struct {
	Username   string
	Password   string
	TOTPSecret string
}

type clientJSONAlias Client
type globJSONAlias Glob

type clientJSONCompat struct {
	clientJSONAlias
	BlackIpList   []string `json:"BlackIpList,omitempty"`
	WebUserName   string   `json:"WebUserName,omitempty"`
	WebPassword   string   `json:"WebPassword,omitempty"`
	WebTotpSecret string   `json:"WebTotpSecret,omitempty"`
}

type globJSONCompat struct {
	globJSONAlias
	BlackIpList []string `json:"BlackIpList,omitempty"`
}

func (c *Client) UnmarshalJSON(data []byte) error {
	var decoded clientJSONCompat
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	c.applyJSONAlias(&decoded.clientJSONAlias)
	c.SetLegacyBlackIPImport(decoded.BlackIpList)
	c.SetLegacyWebLoginImport(decoded.WebUserName, decoded.WebPassword, decoded.WebTotpSecret)
	return nil
}

func (g *Glob) UnmarshalJSON(data []byte) error {
	var decoded globJSONCompat
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	g.applyJSONAlias(&decoded.globJSONAlias)
	g.SetLegacyBlackIPImport(decoded.BlackIpList)
	return nil
}

func (c *Client) applyJSONAlias(decoded *clientJSONAlias) {
	if c == nil || decoded == nil {
		return
	}
	c.Cnf = decoded.Cnf
	c.Id = decoded.Id
	c.UserId = decoded.UserId
	c.OwnerUserID = decoded.OwnerUserID
	c.ManagerUserIDs = append([]int(nil), decoded.ManagerUserIDs...)
	c.SourceType = decoded.SourceType
	c.SourcePlatformID = decoded.SourcePlatformID
	c.SourceActorID = decoded.SourceActorID
	c.Revision = decoded.Revision
	c.UpdatedAt = decoded.UpdatedAt
	c.VerifyKey = decoded.VerifyKey
	c.Mode = decoded.Mode
	c.Addr = decoded.Addr
	c.LocalAddr = decoded.LocalAddr
	c.Remark = decoded.Remark
	c.Status = decoded.Status
	c.IsConnect = decoded.IsConnect
	c.ExpireAt = decoded.ExpireAt
	c.FlowLimit = decoded.FlowLimit
	c.RateLimit = decoded.RateLimit
	c.Flow = decoded.Flow
	c.ExportFlow = decoded.ExportFlow
	c.InletFlow = decoded.InletFlow
	c.Rate = decoded.Rate
	c.BridgeTraffic = decoded.BridgeTraffic
	c.ServiceTraffic = decoded.ServiceTraffic
	c.BridgeMeter = decoded.BridgeMeter
	c.ServiceMeter = decoded.ServiceMeter
	c.TotalMeter = decoded.TotalMeter
	c.NoStore = decoded.NoStore
	c.NoDisplay = decoded.NoDisplay
	c.MaxConn = decoded.MaxConn
	c.NowConn = decoded.NowConn
	c.ConfigConnAllow = decoded.ConfigConnAllow
	c.MaxTunnelNum = decoded.MaxTunnelNum
	c.Version = decoded.Version
	c.EntryAclMode = decoded.EntryAclMode
	c.EntryAclRules = decoded.EntryAclRules
}

func (g *Glob) applyJSONAlias(decoded *globJSONAlias) {
	if g == nil || decoded == nil {
		return
	}
	g.EntryAclMode = decoded.EntryAclMode
	g.EntryAclRules = decoded.EntryAclRules
}

func cloneLegacyBlacklistImport(entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	cloned := make([]string, len(entries))
	copy(cloned, entries)
	return cloned
}

func (c *Client) SetLegacyBlackIPImport(entries []string) {
	if c == nil {
		return
	}
	c.legacyBlackIPList = normalizePolicyRuleEntries(entries)
}

func (c *Client) LegacyBlackIPImport() []string {
	if c == nil {
		return nil
	}
	return cloneLegacyBlacklistImport(c.legacyBlackIPList)
}

func (c *Client) ClearLegacyBlackIPImport() {
	if c == nil {
		return
	}
	c.legacyBlackIPList = nil
}

func (g *Glob) SetLegacyBlackIPImport(entries []string) {
	if g == nil {
		return
	}
	g.legacyBlackIPList = normalizePolicyRuleEntries(entries)
}

func (g *Glob) LegacyBlackIPImport() []string {
	if g == nil {
		return nil
	}
	return cloneLegacyBlacklistImport(g.legacyBlackIPList)
}

func (g *Glob) ClearLegacyBlackIPImport() {
	if g == nil {
		return
	}
	g.legacyBlackIPList = nil
}

func (c *Client) SetLegacyWebLoginImport(username, password, totpSecret string) {
	if c == nil {
		return
	}
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	totpSecret = strings.ToUpper(strings.TrimSpace(totpSecret))
	if username == "" && password == "" && totpSecret == "" {
		c.legacyWebLogin = nil
		return
	}
	c.legacyWebLogin = &legacyClientWebLoginImport{
		Username:   username,
		Password:   password,
		TOTPSecret: totpSecret,
	}
}

func (c *Client) HasLegacyWebLoginImport() bool {
	if c == nil || c.legacyWebLogin == nil {
		return false
	}
	return c.legacyWebLogin.Username != "" || c.legacyWebLogin.Password != "" || c.legacyWebLogin.TOTPSecret != ""
}

func (c *Client) LegacyWebLoginImport() (username, password, totpSecret string) {
	if c == nil || c.legacyWebLogin == nil {
		return "", "", ""
	}
	return c.legacyWebLogin.Username, c.legacyWebLogin.Password, c.legacyWebLogin.TOTPSecret
}

func (c *Client) ClearLegacyWebLoginImport() {
	if c == nil {
		return
	}
	c.legacyWebLogin = nil
}

func (c *Client) NormalizeLegacyWebLoginImport() {
	if c == nil || c.legacyWebLogin == nil {
		return
	}
	c.legacyWebLogin.Username = strings.TrimSpace(c.legacyWebLogin.Username)
	c.legacyWebLogin.Password = strings.TrimSpace(c.legacyWebLogin.Password)
	c.legacyWebLogin.TOTPSecret = strings.ToUpper(strings.TrimSpace(c.legacyWebLogin.TOTPSecret))
	if c.legacyWebLogin.TOTPSecret != "" && !crypt.IsValidTOTPSecret(c.legacyWebLogin.TOTPSecret) {
		c.legacyWebLogin.TOTPSecret, _ = crypt.GenerateTOTPSecret()
	}
	if idx := strings.LastIndex(c.legacyWebLogin.Password, common.TOTP_SEQ); idx != -1 {
		secret := c.legacyWebLogin.Password[idx+len(common.TOTP_SEQ):]
		c.legacyWebLogin.Password = c.legacyWebLogin.Password[:idx]
		if !crypt.IsValidTOTPSecret(secret) {
			secret, _ = crypt.GenerateTOTPSecret()
		}
		c.legacyWebLogin.TOTPSecret = secret
	}
	if c.legacyWebLogin.Username == "" && c.legacyWebLogin.Password == "" && c.legacyWebLogin.TOTPSecret == "" {
		c.legacyWebLogin = nil
	}
}

func MigrateLegacyData() {
	db := GetDb()
	if db == nil || db.JsonDb == nil {
		return
	}

	changed := false
	usersByUsername := make(map[string]*User)

	if db.JsonDb.Global == nil {
		db.JsonDb.Global = &Glob{}
	}
	globalMode, globalRules := promoteLegacyBlacklistPolicy(
		db.JsonDb.Global.EntryAclMode,
		db.JsonDb.Global.EntryAclRules,
		db.JsonDb.Global.LegacyBlackIPImport(),
	)
	if db.JsonDb.Global.EntryAclMode != globalMode ||
		db.JsonDb.Global.EntryAclRules != globalRules ||
		len(db.JsonDb.Global.LegacyBlackIPImport()) != 0 {
		db.JsonDb.Global.EntryAclMode = globalMode
		db.JsonDb.Global.EntryAclRules = globalRules
		db.JsonDb.Global.ClearLegacyBlackIPImport()
		changed = true
	}
	db.JsonDb.Global.CompileSourcePolicy()

	db.RangeUsers(func(user *User) bool {
		beforeKind := user.Kind
		beforePlatformID := user.ExternalPlatformID
		beforeHidden := user.Hidden
		beforeEntryRules := user.EntryAclRules
		beforeDestRules := user.DestAclRules

		InitializeUserRuntime(user)
		user.EntryAclRules = normalizePolicyRules(user.EntryAclRules)
		user.DestAclRules = normalizePolicyRules(user.DestAclRules)
		user.CompileSourcePolicy()
		user.CompileDestACL()

		if beforeKind != user.Kind ||
			beforePlatformID != user.ExternalPlatformID ||
			beforeHidden != user.Hidden ||
			beforeEntryRules != user.EntryAclRules ||
			beforeDestRules != user.DestAclRules {
			changed = true
		}
		usersByUsername[user.Username] = user
		return true
	})

	for _, key := range GetMapKeys(&db.JsonDb.Clients, false, "", "") {
		client, ok := loadClientEntry(&db.JsonDb.Clients, key)
		if !ok {
			continue
		}

		beforeMode := client.EntryAclMode
		beforeRules := client.EntryAclRules
		beforeLegacyCount := len(client.LegacyBlackIPImport())
		beforeWebUser, beforeWebPassword, beforeWebTotp := client.LegacyWebLoginImport()

		applyClientSetupHook(client)
		client.NormalizeLegacyWebLoginImport()

		if client.OwnerID() > 0 {
			client.ClearLegacyWebLoginImport()
			if owner, ok := loadUserEntry(&db.JsonDb.Users, client.OwnerID()); ok {
				client.BindOwnerUser(owner)
			} else {
				client.BindOwnerUser(nil)
			}
			afterWebUser, afterWebPassword, afterWebTotp := client.LegacyWebLoginImport()
			if beforeWebUser != afterWebUser ||
				beforeWebPassword != afterWebPassword ||
				beforeWebTotp != afterWebTotp ||
				beforeMode != client.EntryAclMode ||
				beforeRules != client.EntryAclRules ||
				beforeLegacyCount != len(client.LegacyBlackIPImport()) {
				changed = true
			}
			continue
		}

		username, password, totpSecret := client.LegacyWebLoginImport()
		username = strings.TrimSpace(username)
		password = strings.TrimSpace(password)
		totpSecret = strings.ToUpper(strings.TrimSpace(totpSecret))
		if username == "" {
			client.SetOwnerUserID(0)
			client.ClearLegacyWebLoginImport()
			client.BindOwnerUser(nil)
			afterWebUser, afterWebPassword, afterWebTotp := client.LegacyWebLoginImport()
			if beforeWebUser != afterWebUser ||
				beforeWebPassword != afterWebPassword ||
				beforeWebTotp != afterWebTotp ||
				beforeMode != client.EntryAclMode ||
				beforeRules != client.EntryAclRules ||
				beforeLegacyCount != len(client.LegacyBlackIPImport()) {
				changed = true
			}
			continue
		}

		user, ok := usersByUsername[username]
		if ok && (user.Hidden || user.Kind != "local" || !legacyPasswordMatches(user.Password, password)) {
			ok = false
		}
		if !ok {
			candidate := username
			if existing, exists := usersByUsername[candidate]; exists &&
				(!legacyPasswordMatches(existing.Password, password) || existing.Hidden || existing.Kind != "local") {
				candidate = candidate + "__legacy_" + strconv.Itoa(client.Id)
				logs.Warn("legacy user credential conflict for %s, migrated client %d into %s", username, client.Id, candidate)
			}
			user = &User{
				Id:         int(db.JsonDb.GetUserId()),
				Username:   candidate,
				Password:   hashLegacyPassword(password),
				TOTPSecret: totpSecret,
				Kind:       "local",
				Status:     1,
				MaxTunnels: 0,
				MaxHosts:   0,
				TotalFlow:  new(Flow),
			}
			user.TouchMeta()
			db.JsonDb.Users.Store(user.Id, user)
			usersByUsername[user.Username] = user
			changed = true
		} else if totpSecret != "" {
			switch {
			case user.TOTPSecret == "":
				user.TOTPSecret = totpSecret
				user.TouchMeta()
				changed = true
			case user.TOTPSecret != totpSecret:
				logs.Warn("legacy client %d TOTP secret differs from existing user %s; keeping existing user secret", client.Id, user.Username)
			}
		}

		user.EnsureTotalFlow()
		if client.Flow != nil {
			user.TotalFlow.Add(client.Flow.InletFlow, client.Flow.ExportFlow)
		}
		client.SetOwnerUserID(user.Id)
		client.BindOwnerUser(user)
		client.ClearLegacyWebLoginImport()
		client.TouchMeta("legacy_migration", "", "migration")
		changed = true
	}

	db.RangeTasks(func(tunnel *Tunnel) bool {
		beforeEntryRules := tunnel.EntryAclRules
		beforeDestRules := tunnel.DestAclRules
		tunnel.EntryAclRules = normalizePolicyRules(tunnel.EntryAclRules)
		tunnel.DestAclRules = normalizePolicyRules(tunnel.DestAclRules)
		tunnel.CompileEntryACL()
		tunnel.CompileDestACL()
		if beforeEntryRules != tunnel.EntryAclRules || beforeDestRules != tunnel.DestAclRules {
			changed = true
		}
		return true
	})

	db.RangeHosts(func(host *Host) bool {
		beforeEntryRules := host.EntryAclRules
		host.EntryAclRules = normalizePolicyRules(host.EntryAclRules)
		host.CompileEntryACL()
		if beforeEntryRules != host.EntryAclRules {
			changed = true
		}
		return true
	})

	if changed {
		db.FlushToDisk()
	}
}

// legacyPasswordMatches reports whether a legacy-import plaintext password
// corresponds to the stored value, accepting both Argon2id hashes and legacy
// plaintext so the one-time migration does not treat upgraded accounts as
// conflicts.
func legacyPasswordMatches(stored, supplied string) bool {
	if stored == "" || supplied == "" {
		return stored == "" && supplied == ""
	}
	match, _, err := credential.VerifyPassword(stored, supplied)
	return err == nil && match
}

// hashLegacyPassword stores legacy-import passwords as Argon2id hashes; if
// hashing unexpectedly fails it keeps the plaintext so the next successful
// login can migrate it instead of locking the account out.
func hashLegacyPassword(plain string) string {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return ""
	}
	hashed, err := credential.HashPassword(plain)
	if err != nil {
		logs.Error("hash legacy import password failed: %v", err)
		return plain
	}
	return hashed
}
