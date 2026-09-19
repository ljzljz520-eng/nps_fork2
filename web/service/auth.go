package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/nps/lib/credential"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
)

const (
	SessionIdentityKey     = "session_identity"
	SessionIdentityVersion = 1
)

type AuthService interface {
	Authenticate(AuthenticateInput) (*SessionIdentity, error)
	RegisterUser(RegisterUserInput) (*RegisterUserResult, error)
}

type DefaultAuthService struct {
	Resolver       PermissionResolver
	ConfigProvider func() *servercfg.Snapshot
	Repo           AuthRepository
	Backend        Backend
}

type AuthenticateInput struct {
	Username string
	Password string
	TOTP     string
}

type RegisterUserInput struct {
	Username string
	Password string
}

type RegisterUserResult struct {
	SubjectID string
	Username  string
	ClientIDs []int
}

type SessionIdentity struct {
	Version       int               `json:"version"`
	Authenticated bool              `json:"authenticated"`
	Kind          string            `json:"kind,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	SubjectID     string            `json:"subject_id,omitempty"`
	Username      string            `json:"username,omitempty"`
	IsAdmin       bool              `json:"is_admin"`
	ClientIDs     []int             `json:"client_ids,omitempty"`
	Roles         []string          `json:"roles,omitempty"`
	Permissions   []string          `json:"permissions,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

const (
	StandaloneTokenPrefix  = "nps_st_"
	StandaloneTokenVersion = 1
)

type standaloneTokenClaims struct {
	Version  int              `json:"v"`
	IssuedAt int64            `json:"iat"`
	Expires  int64            `json:"exp"`
	Identity *SessionIdentity `json:"identity"`
}

func ValidAuthKey(configKey, md5Key string, timestamp int, nowUnix int64) bool {
	if configKey == "" || md5Key == "" {
		return false
	}
	if math.Abs(float64(nowUnix-int64(timestamp))) > 20 {
		return false
	}
	expected := crypt.Md5(configKey + strconv.Itoa(timestamp))
	if len(expected) != len(md5Key) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(md5Key)) == 1
}

func HasAuthorizationScheme(header, scheme string) bool {
	header = strings.TrimSpace(header)
	scheme = strings.TrimSpace(scheme)
	if header == "" || scheme == "" {
		return false
	}
	prefix := strings.ToLower(scheme) + " "
	return len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix)
}

func ParseBearerAuthorizationHeader(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if !HasAuthorizationScheme(header, "bearer") {
		return "", false
	}
	const prefix = "bearer "
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func (s DefaultAuthService) Authenticate(input AuthenticateInput) (*SessionIdentity, error) {
	cfg := s.config()
	username := strings.TrimSpace(input.Username)
	password := input.Password

	if identity, ok := authenticateAdmin(username, input.Password, input.TOTP, cfg); ok {
		return s.normalizeIdentity(identity), nil
	}
	if username == "" && strings.TrimSpace(password) == "" {
		return nil, ErrInvalidCredentials
	}

	if cfg.Feature.AllowUserLogin && username != "" {
		user, err := s.repo().GetUserByUsername(username)
		if err != nil && !errors.Is(err, file.ErrUserNotFound) {
			return nil, err
		}
		if user != nil {
			matched, upgraded := verifyUserCredentials(user, password, input.TOTP)
			if matched {
				if upgraded {
					// Legacy plaintext password verified successfully; commit the
					// parameter-versioned Argon2id replacement now that the login
					// has succeeded. Migration failures never block the login.
					if saver, ok := s.repo().(interface{ SaveUser(*file.User) error }); ok {
						if err := saver.SaveUser(user); err != nil {
							logs.Error("migrate legacy password hash for user %d failed: %v", user.Id, err)
						}
					}
				}
				matchedClientIDs, err := s.userClientIDs(user.Id)
				if err != nil {
					return nil, err
				}
				identity := &SessionIdentity{
					Version:       SessionIdentityVersion,
					Authenticated: true,
					Kind:          "user",
					Provider:      "local",
					SubjectID:     buildUserSubjectID(username, matchedClientIDs, "password"),
					Username:      username,
					ClientIDs:     matchedClientIDs,
					Roles:         []string{RoleUser},
					Attributes: map[string]string{
						"login_mode": "password",
						"user_id":    strconv.Itoa(user.Id),
					},
				}
				return s.normalizeIdentity(identity), nil
			}
		}
	}
	if cfg.Feature.AllowUserVkeyLogin && username == "" {
		identity, err := s.authenticateByClientVKey(password)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			return s.normalizeIdentity(identity), nil
		}
	}
	return nil, ErrInvalidCredentials
}

func (s DefaultAuthService) authenticateByClientVKey(vkey string) (*SessionIdentity, error) {
	vkey = strings.TrimSpace(vkey)
	if vkey == "" {
		return nil, nil
	}
	client, err := s.managementClientByVerifyKey(vkey)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}
	username := clientVKeyLoginUsername(client)
	return &SessionIdentity{
		Version:       SessionIdentityVersion,
		Authenticated: true,
		Kind:          "client",
		Provider:      "local",
		SubjectID:     buildClientVKeySubjectID(client.Id),
		Username:      username,
		ClientIDs:     []int{client.Id},
		Roles:         []string{RoleClient},
		Attributes: map[string]string{
			"login_mode": "client_vkey",
			"client_id":  strconv.Itoa(client.Id),
		},
	}, nil
}

func (s DefaultAuthService) managementClientByVerifyKey(vkey string) (*file.Client, error) {
	repo := s.repo()
	now := time.Now()
	return FindClientByVerifyKey(repo, vkey, func(client *file.Client) (bool, error) {
		if !clientVKeySessionAllowed(client, now) {
			return false, nil
		}
		allowed, err := clientVKeyOwnerAllowed(repo, client, now)
		if err != nil {
			return false, err
		}
		return allowed, nil
	})
}

func clientVKeyLoginUsername(client *file.Client) string {
	if client == nil || client.Id <= 0 {
		return "vkey-client"
	}
	return "vkey-client-" + strconv.Itoa(client.Id)
}

func (s DefaultAuthService) RegisterUser(input RegisterUserInput) (*RegisterUserResult, error) {
	cfg := s.config()
	username := strings.TrimSpace(input.Username)
	password := input.Password

	switch {
	case username == "" || strings.TrimSpace(password) == "":
		return nil, ErrInvalidRegistration
	case username == strings.TrimSpace(cfg.Web.Username):
		return nil, ErrReservedUsername
	}

	hashedPassword, err := credential.HashPassword(password)
	if err != nil {
		return nil, ErrInvalidRegistration
	}
	user := &file.User{
		Id:         s.repo().NextUserID(),
		Username:   username,
		Password:   hashedPassword,
		Kind:       "local",
		Status:     1,
		TotalFlow:  &file.Flow{},
		MaxTunnels: 0,
		MaxHosts:   0,
	}
	user.TouchMeta()
	if err := s.repo().CreateUser(user); err != nil {
		return nil, err
	}
	client := &file.Client{
		Id:     s.repo().NextClientID(),
		UserId: user.Id,
		Status: true,
		Cnf:    &file.Config{},
		Flow:   &file.Flow{},
	}
	client.SetOwnerUserID(user.Id)
	client.TouchMeta("node_user", "", "register")
	if err := s.repo().CreateClient(client); err != nil {
		if rollbackErr := s.repo().DeleteUser(user.Id); rollbackErr != nil {
			return nil, errors.Join(err, rollbackErr)
		}
		return nil, err
	}
	return &RegisterUserResult{
		SubjectID: "user:" + strings.TrimSpace(username),
		Username:  username,
		ClientIDs: []int{client.Id},
	}, nil
}

func (identity *SessionIdentity) Normalize() *SessionIdentity {
	return NormalizeSessionIdentityWithResolver(identity, DefaultPermissionResolver())
}

func MarshalSessionIdentity(identity *SessionIdentity) (string, error) {
	return MarshalSessionIdentityWithResolver(identity, DefaultPermissionResolver())
}

func MarshalSessionIdentityWithResolver(identity *SessionIdentity, resolver PermissionResolver) (string, error) {
	if identity == nil {
		return "", nil
	}
	data, err := json.Marshal(NormalizeSessionIdentityWithResolver(identity, resolver))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ParseSessionIdentity(raw string) (*SessionIdentity, error) {
	return ParseSessionIdentityWithResolver(raw, DefaultPermissionResolver())
}

func ParseSessionIdentityWithResolver(raw string, resolver PermissionResolver) (*SessionIdentity, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var identity SessionIdentity
	if err := json.Unmarshal([]byte(raw), &identity); err != nil {
		return nil, err
	}
	return NormalizeSessionIdentityWithResolver(&identity, resolver), nil
}

func IsStandaloneToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), StandaloneTokenPrefix)
}

func IssueStandaloneToken(cfg *servercfg.Snapshot, identity *SessionIdentity, now time.Time) (string, int64, int64, error) {
	secret := standaloneTokenSecret(cfg)
	if secret == "" {
		return "", 0, 0, ErrStandaloneTokenUnavailable
	}
	if identity == nil || !identity.Authenticated {
		return "", 0, 0, ErrUnauthenticated
	}
	if now.IsZero() {
		now = time.Now()
	}
	issuedAt := now.Unix()
	expiresAt := now.Add(cfg.StandaloneTokenTTL()).Unix()
	claimsBytes, err := json.Marshal(standaloneTokenClaims{
		Version:  StandaloneTokenVersion,
		IssuedAt: issuedAt,
		Expires:  expiresAt,
		Identity: identity,
	})
	if err != nil {
		return "", 0, 0, err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature := standaloneTokenSignature(secret, payload)
	return StandaloneTokenPrefix + payload + "." + signature, issuedAt, expiresAt, nil
}

func ParseStandaloneToken(cfg *servercfg.Snapshot, token string, now time.Time) (*SessionIdentity, error) {
	secret := standaloneTokenSecret(cfg)
	if secret == "" {
		return nil, ErrStandaloneTokenUnavailable
	}
	payload, signature, ok := splitStandaloneToken(token)
	if !ok {
		return nil, ErrStandaloneTokenInvalid
	}
	expected := standaloneTokenSignature(secret, payload)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return nil, ErrStandaloneTokenInvalid
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, ErrStandaloneTokenInvalid
	}
	var claims standaloneTokenClaims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, ErrStandaloneTokenInvalid
	}
	if claims.Version != StandaloneTokenVersion || claims.Identity == nil {
		return nil, ErrStandaloneTokenInvalid
	}
	if now.IsZero() {
		now = time.Now()
	}
	if claims.Expires <= 0 || now.Unix() >= claims.Expires {
		return nil, ErrStandaloneTokenExpired
	}
	if claims.Identity == nil || !claims.Identity.Authenticated {
		return nil, ErrStandaloneTokenInvalid
	}
	return claims.Identity, nil
}

func ResolveStandaloneTokenIdentity(cfg *servercfg.Snapshot, resolver PermissionResolver, repo Repository, token string, now time.Time) (*SessionIdentity, error) {
	identity, err := ParseStandaloneToken(cfg, token, now)
	if err != nil {
		return nil, err
	}
	return RefreshSessionIdentity(identity, resolver, repo, now)
}

func splitStandaloneToken(token string) (string, string, bool) {
	token = strings.TrimSpace(token)
	if !IsStandaloneToken(token) {
		return "", "", false
	}
	raw := strings.TrimPrefix(token, StandaloneTokenPrefix)
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok || strings.TrimSpace(payload) == "" || strings.TrimSpace(signature) == "" {
		return "", "", false
	}
	return payload, signature, true
}

func standaloneTokenSignature(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func standaloneTokenSecret(cfg *servercfg.Snapshot) string {
	cfg = servercfg.Resolve(cfg)
	return strings.TrimSpace(cfg.StandaloneTokenSecret())
}

func authenticateAdmin(username, password, totp string, cfg *servercfg.Snapshot) (*SessionIdentity, bool) {
	if identity, ok := AutoAdminIdentity(cfg); ok && strings.TrimSpace(username) == "" && password == "" && strings.TrimSpace(totp) == "" {
		return identity, true
	}
	if username != strings.TrimSpace(cfg.Web.Username) {
		return nil, false
	}
	if !adminCredentialsMatch(password, totp, cfg) {
		return nil, false
	}
	return newAdminIdentity(cfg, "password"), true
}

func adminCredentialsMatch(password, totp string, cfg *servercfg.Snapshot) bool {
	if strings.TrimSpace(cfg.Web.Username) == "" {
		return false
	}
	totpSecret := strings.TrimSpace(cfg.Web.TOTPSecret)
	expectedPassword := cfg.Web.Password
	if totpSecret == "" && expectedPassword == "" {
		return false
	}
	if totpSecret != "" {
		valid := false
		if totp != "" {
			valid, _ = crypt.ValidateTOTPCode(totpSecret, totp)
		} else {
			passwordLength := len(password)
			if passwordLength >= crypt.TotpLen {
				code := password[passwordLength-crypt.TotpLen:]
				password = password[:passwordLength-crypt.TotpLen]
				valid, _ = crypt.ValidateTOTPCode(totpSecret, code)
			}
		}
		if !valid {
			return false
		}
	}
	return passwordMatchesHashOrLegacy(expectedPassword, password)
}

// passwordMatchesHashOrLegacy verifies a supplied password against a stored
// value that is either a parameter-versioned Argon2id PHC string or a legacy
// plaintext password. A stored value that claims to be a PHC hash but is
// malformed fails closed rather than falling back to a plaintext comparison.
func passwordMatchesHashOrLegacy(stored, supplied string) bool {
	if !credential.IsPasswordHash(stored) {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(supplied)) == 1
	}
	match, _, err := credential.VerifyPassword(stored, supplied)
	return err == nil && match
}

func AutoAdminIdentity(cfg *servercfg.Snapshot) (*SessionIdentity, bool) {
	if !adminAutoLoginEnabled(cfg) {
		return nil, false
	}
	return newAdminIdentity(cfg, "auto").Normalize(), true
}

func adminAutoLoginEnabled(cfg *servercfg.Snapshot) bool {
	if cfg == nil {
		return false
	}
	return strings.TrimSpace(cfg.Web.Username) == "" &&
		cfg.Web.Password == "" &&
		strings.TrimSpace(cfg.Web.TOTPSecret) == ""
}

func newAdminIdentity(cfg *servercfg.Snapshot, loginMode string) *SessionIdentity {
	resolvedUsername := "admin"
	if cfg != nil && strings.TrimSpace(cfg.Web.Username) != "" {
		resolvedUsername = strings.TrimSpace(cfg.Web.Username)
	}
	return &SessionIdentity{
		Version:       SessionIdentityVersion,
		Authenticated: true,
		Kind:          "admin",
		Provider:      "local",
		SubjectID:     "admin:" + resolvedUsername,
		Username:      resolvedUsername,
		IsAdmin:       true,
		Roles:         []string{RoleAdmin},
		Attributes: map[string]string{
			"login_mode": loginMode,
		},
	}
}

// verifyUserCredentials validates a local user's password/TOTP. It returns
// whether authentication succeeded and, on success, whether the stored legacy
// plaintext password was just upgraded in place to an Argon2id hash and needs
// to be persisted by the caller.
func verifyUserCredentials(user *file.User, password, totp string) (bool, bool) {
	if !localUserSessionAllowed(user, time.Now()) {
		return false, false
	}
	totpSecret := strings.TrimSpace(user.TOTPSecret)
	if totpSecret == "" && user.Password == "" {
		return false, false
	}
	if totpSecret != "" {
		valid := false
		if strings.TrimSpace(totp) != "" {
			valid, _ = crypt.ValidateTOTPCode(totpSecret, totp)
		} else {
			passwordLength := len(password)
			if passwordLength >= crypt.TotpLen {
				code := password[passwordLength-crypt.TotpLen:]
				password = password[:passwordLength-crypt.TotpLen]
				valid, _ = crypt.ValidateTOTPCode(totpSecret, code)
			}
		}
		if !valid {
			return false, false
		}
	}
	storedPassword := user.Password
	if storedPassword == "" {
		// TOTP-only account: an empty password is accepted once the code above
		// validated, any supplied password must be empty.
		return password == "", false
	}
	match, upgrade, err := credential.VerifyPassword(storedPassword, password)
	if err != nil || !match {
		return false, false
	}
	if upgrade {
		hashed, hashErr := credential.HashPassword(password)
		if hashErr != nil {
			logs.Error("rehash legacy password for user %d failed: %v", user.Id, hashErr)
			return true, false
		}
		user.Password = hashed
		return true, true
	}
	return true, false
}

func buildUserSubjectID(username string, clientIDs []int, loginMode string) string {
	return "user:" + strings.TrimSpace(username)
}

func buildClientVKeySubjectID(clientID int) string {
	if clientID <= 0 {
		return "client:vkey"
	}
	return "client:vkey:" + strconv.Itoa(clientID)
}

func clientVKeySessionAllowed(client *file.Client, now time.Time) bool {
	if client == nil || client.NoDisplay || !client.Status {
		return false
	}
	if expireAt := client.EffectiveExpireAt(); expireAt > 0 && !now.IsZero() && now.Unix() >= expireAt {
		return false
	}
	return true
}

func clientVKeyOwnerAllowed(repo interface {
	GetUser(int) (*file.User, error)
}, client *file.Client, now time.Time) (bool, error) {
	if client == nil {
		return false, nil
	}
	if client.OwnerID() <= 0 {
		return true, nil
	}
	if repo == nil {
		repo = DefaultBackend().Repository
	}
	user, err := resolveClientOwnerUser(repo, client)
	if err != nil {
		if errors.Is(err, file.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	if user == nil {
		return false, nil
	}
	return localUserSessionAllowed(user, now), nil
}

func NormalizeSessionIdentityWithResolver(identity *SessionIdentity, resolver PermissionResolver) *SessionIdentity {
	if resolver == nil {
		resolver = DefaultPermissionResolver()
	}
	return resolver.NormalizeIdentity(identity)
}

func (s DefaultAuthService) normalizeIdentity(identity *SessionIdentity) *SessionIdentity {
	return NormalizeSessionIdentityWithResolver(identity, s.resolver())
}

func (s DefaultAuthService) resolver() PermissionResolver {
	if !isNilServiceValue(s.Resolver) {
		return s.Resolver
	}
	return DefaultPermissionResolver()
}

func (s DefaultAuthService) config() *servercfg.Snapshot {
	return servercfg.ResolveProvider(s.ConfigProvider)
}

func (s DefaultAuthService) repo() AuthRepository {
	if !isNilServiceValue(s.Repo) {
		return s.Repo
	}
	if !isNilServiceValue(s.Backend.Repository) {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}

func (s DefaultAuthService) userClientIDs(userID int) ([]int, error) {
	clientIDs, err := ManagedClientIDsByUser(s.repo(), userID)
	if err != nil {
		return nil, err
	}
	if len(clientIDs) == 0 {
		return make([]int, 0), nil
	}
	return clientIDs, nil
}

func RefreshSessionIdentity(identity *SessionIdentity, resolver PermissionResolver, repo Repository, now time.Time) (*SessionIdentity, error) {
	normalized := NormalizeSessionIdentityWithResolver(identity, resolver)
	if normalized == nil || !normalized.Authenticated || normalized.IsAdmin {
		return normalized, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	if repo == nil {
		repo = DefaultBackend().Repository
	}
	switch strings.TrimSpace(normalized.Kind) {
	case "user":
		return refreshUserSessionIdentity(normalized, resolver, repo, now)
	case "client":
		return refreshClientSessionIdentity(normalized, resolver, repo, now)
	default:
		return normalized, nil
	}
}

func refreshUserSessionIdentity(normalized *SessionIdentity, resolver PermissionResolver, repo Repository, now time.Time) (*SessionIdentity, error) {
	userID := sessionIdentityAttributeIntValue(normalized, "user_id")
	if userID <= 0 {
		return normalized, nil
	}
	user, err := repo.GetUser(userID)
	if err != nil {
		if errors.Is(err, file.ErrUserNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, err
	}
	if user == nil || !localUserSessionAllowed(user, now) {
		return nil, ErrUnauthenticated
	}
	refreshed := *normalized
	refreshed.Username = strings.TrimSpace(user.Username)
	refreshed.SubjectID = buildUserSubjectID(refreshed.Username, nil, sessionIdentityAttributeValue(normalized, "login_mode"))
	clientIDs, err := ManagedClientIDsByUser(repo, userID)
	if err != nil {
		return nil, err
	}
	refreshed.ClientIDs = clientIDs
	refreshed.Attributes = cloneSessionIdentityAttributes(normalized)
	refreshed.Attributes["user_id"] = strconv.Itoa(userID)
	return NormalizeSessionIdentityWithResolver(&refreshed, resolver), nil
}

func refreshClientSessionIdentity(normalized *SessionIdentity, resolver PermissionResolver, repo Repository, now time.Time) (*SessionIdentity, error) {
	clientID := sessionIdentityAttributeIntValue(normalized, "client_id")
	if clientID <= 0 {
		return normalized, nil
	}
	client, err := repo.GetClient(clientID)
	if err != nil {
		if errors.Is(err, file.ErrClientNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, err
	}
	if client == nil || !clientVKeySessionAllowed(client, now) {
		return nil, ErrUnauthenticated
	}
	allowed, err := clientVKeyOwnerAllowed(repo, client, now)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrUnauthenticated
	}
	refreshed := *normalized
	refreshed.Username = clientVKeyLoginUsername(client)
	refreshed.SubjectID = buildClientVKeySubjectID(client.Id)
	refreshed.ClientIDs = []int{client.Id}
	refreshed.Attributes = cloneSessionIdentityAttributes(normalized)
	refreshed.Attributes["client_id"] = strconv.Itoa(client.Id)
	refreshed.Attributes["login_mode"] = "client_vkey"
	return NormalizeSessionIdentityWithResolver(&refreshed, resolver), nil
}

func localUserSessionAllowed(user *file.User, now time.Time) bool {
	if user == nil {
		return false
	}
	user.NormalizeIdentity()
	if user.Hidden || user.Kind != "local" {
		return false
	}
	if user.Status == 0 {
		return false
	}
	if user.ExpireAt > 0 && now.Unix() >= user.ExpireAt {
		return false
	}
	return true
}

func sessionIdentityAttributeValue(identity *SessionIdentity, key string) string {
	if identity == nil || identity.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(identity.Attributes[strings.TrimSpace(key)])
}

func sessionIdentityAttributeIntValue(identity *SessionIdentity, key string) int {
	value := sessionIdentityAttributeValue(identity, key)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func cloneSessionIdentityAttributes(identity *SessionIdentity) map[string]string {
	if identity == nil || len(identity.Attributes) == 0 {
		return map[string]string{}
	}
	copied := make(map[string]string, len(identity.Attributes))
	for key, value := range identity.Attributes {
		copied[key] = value
	}
	return copied
}
