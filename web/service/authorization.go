package service

import (
	"strconv"
	"strings"

	"github.com/djylb/nps/lib/file"
)

const (
	RoleAnonymous = "anonymous"
	RoleAdmin     = "admin"
	RoleClient    = "client"
	RoleUser      = "user"
)

const (
	PermissionAll             = "*"
	PermissionManagementAdmin = "management:admin"
	PermissionClientsCreate   = "clients:create"
	PermissionClientsRead     = "clients:read"
	PermissionClientsUpdate   = "clients:update"
	PermissionClientsDelete   = "clients:delete"
	PermissionClientsStatus   = "clients:status"
	PermissionTunnelsCreate   = "tunnels:create"
	PermissionTunnelsRead     = "tunnels:read"
	PermissionTunnelsUpdate   = "tunnels:update"
	PermissionTunnelsDelete   = "tunnels:delete"
	PermissionTunnelsControl  = "tunnels:control"
	PermissionHostsCreate     = "hosts:create"
	PermissionHostsRead       = "hosts:read"
	PermissionHostsUpdate     = "hosts:update"
	PermissionHostsDelete     = "hosts:delete"
	PermissionHostsControl    = "hosts:control"
	PermissionGlobalManage    = "global:manage"
)

type PermissionResolver interface {
	NormalizePrincipal(Principal) Principal
	NormalizeIdentity(*SessionIdentity) *SessionIdentity
	KnownRoles() []string
	KnownPermissions() []string
	PermissionCatalog() map[string][]string
}

type StaticPermissionResolver struct{}

func DefaultPermissionResolver() PermissionResolver {
	return StaticPermissionResolver{}
}

type AuthorizationService interface {
	NormalizePrincipal(Principal) Principal
	ClientScope(Principal) ClientScope
	Permissions(Principal) []string
	Allows(Principal, string) bool
	ResolveClient(Principal, int) (int, error)
	RequirePermission(Principal, string) error
	RequireAdmin(Principal) error
	RequireClient(Principal, int) error
	RequireTunnel(Principal, int) error
	RequireHost(Principal, int) error
}

type DefaultAuthorizationService struct {
	Resolver PermissionResolver
	Repo     AuthorizationRepository
	Backend  Backend
}

type Principal struct {
	Authenticated bool
	Kind          string
	SubjectID     string
	Username      string
	IsAdmin       bool
	ClientIDs     []int
	Roles         []string
	Permissions   []string
	Attributes    map[string]string
}

type ClientScope struct {
	All             bool
	PrimaryClientID int
	ClientIDs       []int
}

type principalContext struct {
	Principal       Principal
	Kind            string
	PlatformID      string
	PlatformActorID string
	UserID          int
	ServiceUserID   int
	SourceType      string
}

// NodeAccessScope centralizes node-control visibility and mutation scope derived
// from an authenticated principal.
type NodeAccessScope struct {
	actorKind        string
	full             bool
	accountWide      bool
	platformID       string
	serviceUserID    int
	userID           int
	allowedClientIDs map[int]struct{}
}

type ProtectedActionAccessInput struct {
	Principal         Principal
	Permission        string
	ClientScope       bool
	Ownership         string
	RequestedClientID int
	ResourceID        int
}

type ProtectedActionAccessResult struct {
	ResolvedClientID int
}

func (StaticPermissionResolver) NormalizePrincipal(principal Principal) Principal {
	normalized := principal
	normalized.Kind = strings.TrimSpace(normalized.Kind)
	normalized.SubjectID = strings.TrimSpace(normalized.SubjectID)
	normalized.Username = strings.TrimSpace(normalized.Username)
	normalized.ClientIDs = normalizePrincipalClientIDs(normalized.ClientIDs)
	normalized.Roles = normalizePrincipalStrings(normalized.Roles)
	normalized.Permissions = normalizePrincipalStrings(normalized.Permissions)
	if normalized.Attributes != nil {
		copied := make(map[string]string, len(normalized.Attributes))
		for key, value := range normalized.Attributes {
			copied[strings.TrimSpace(key)] = value
		}
		normalized.Attributes = copied
	}
	if normalized.IsAdmin || containsString(normalized.Roles, RoleAdmin) || permissionSetAllows(normalized.Permissions, PermissionManagementAdmin) {
		normalized.Authenticated = true
		normalized.IsAdmin = true
		if normalized.Kind == "" {
			normalized.Kind = "admin"
		}
	}
	if !normalized.Authenticated {
		normalized.Authenticated = normalized.IsAdmin ||
			normalized.SubjectID != "" ||
			normalized.Username != "" ||
			len(normalized.ClientIDs) > 0
	}
	if !normalized.Authenticated {
		normalized.Kind = "anonymous"
		normalized.SubjectID = ""
		normalized.Username = ""
		normalized.IsAdmin = false
		normalized.ClientIDs = nil
		normalized.Roles = []string{RoleAnonymous}
		normalized.Permissions = nil
		normalized.Attributes = nil
		return normalized
	}
	if len(normalized.Roles) == 0 {
		if normalized.IsAdmin {
			normalized.Roles = []string{RoleAdmin}
		} else if normalized.Kind == "client" {
			normalized.Roles = []string{RoleClient}
		} else {
			normalized.Roles = []string{RoleUser}
		}
	}
	if normalized.Kind == "" {
		if normalized.IsAdmin {
			normalized.Kind = "admin"
		} else if containsString(normalized.Roles, RoleClient) {
			normalized.Kind = "client"
		} else {
			normalized.Kind = "user"
		}
	}
	normalized.Permissions = normalizePermissionSet(normalized.IsAdmin, normalized.Roles, normalized.Permissions)
	return normalized
}

func (r StaticPermissionResolver) NormalizeIdentity(identity *SessionIdentity) *SessionIdentity {
	if identity == nil {
		return nil
	}
	normalized := *identity
	if normalized.Version == 0 {
		normalized.Version = SessionIdentityVersion
	}
	if normalized.Authenticated {
		normalized.ClientIDs = normalizeClientIDs(normalized.ClientIDs)
	}
	if !normalized.Authenticated {
		normalized.Kind = "anonymous"
		normalized.Provider = ""
		normalized.SubjectID = ""
		normalized.Username = ""
		normalized.IsAdmin = false
		normalized.ClientIDs = nil
		normalized.Roles = []string{RoleAnonymous}
		normalized.Permissions = nil
		normalized.Attributes = nil
		return &normalized
	}

	principal := r.NormalizePrincipal(Principal{
		Authenticated: normalized.Authenticated,
		Kind:          normalized.Kind,
		SubjectID:     normalized.SubjectID,
		Username:      normalized.Username,
		IsAdmin:       normalized.IsAdmin,
		ClientIDs:     normalized.ClientIDs,
		Roles:         normalized.Roles,
		Permissions:   normalized.Permissions,
		Attributes:    normalized.Attributes,
	})
	normalized.Authenticated = principal.Authenticated
	normalized.Kind = principal.Kind
	normalized.SubjectID = principal.SubjectID
	normalized.Username = principal.Username
	normalized.IsAdmin = principal.IsAdmin
	normalized.ClientIDs = append([]int(nil), principal.ClientIDs...)
	normalized.Roles = append([]string(nil), principal.Roles...)
	normalized.Permissions = append([]string(nil), principal.Permissions...)
	if len(principal.Attributes) > 0 {
		normalized.Attributes = make(map[string]string, len(principal.Attributes))
		for key, value := range principal.Attributes {
			normalized.Attributes[key] = value
		}
	} else {
		normalized.Attributes = nil
	}
	return &normalized
}

func (StaticPermissionResolver) KnownRoles() []string {
	return []string{RoleAnonymous, RoleClient, RoleUser, RoleAdmin}
}

func (StaticPermissionResolver) KnownPermissions() []string {
	return []string{
		PermissionManagementAdmin,
		PermissionClientsCreate,
		PermissionClientsRead,
		PermissionClientsUpdate,
		PermissionClientsDelete,
		PermissionClientsStatus,
		PermissionTunnelsCreate,
		PermissionTunnelsRead,
		PermissionTunnelsUpdate,
		PermissionTunnelsDelete,
		PermissionTunnelsControl,
		PermissionHostsCreate,
		PermissionHostsRead,
		PermissionHostsUpdate,
		PermissionHostsDelete,
		PermissionHostsControl,
		PermissionGlobalManage,
	}
}

func (StaticPermissionResolver) PermissionCatalog() map[string][]string {
	return map[string][]string{
		"clients": {
			PermissionClientsCreate,
			PermissionClientsRead,
			PermissionClientsUpdate,
			PermissionClientsDelete,
			PermissionClientsStatus,
		},
		"tunnels": {
			PermissionTunnelsCreate,
			PermissionTunnelsRead,
			PermissionTunnelsUpdate,
			PermissionTunnelsDelete,
			PermissionTunnelsControl,
		},
		"hosts": {
			PermissionHostsCreate,
			PermissionHostsRead,
			PermissionHostsUpdate,
			PermissionHostsDelete,
			PermissionHostsControl,
		},
		"global": {
			PermissionGlobalManage,
		},
	}
}

func KnownRoles() []string {
	return DefaultPermissionResolver().KnownRoles()
}

func KnownPermissions() []string {
	return DefaultPermissionResolver().KnownPermissions()
}

func PermissionCatalog() map[string][]string {
	return DefaultPermissionResolver().PermissionCatalog()
}

func (s DefaultAuthorizationService) NormalizePrincipal(principal Principal) Principal {
	return s.resolver().NormalizePrincipal(principal)
}

func (s DefaultAuthorizationService) ClientScope(principal Principal) ClientScope {
	normalized := s.NormalizePrincipal(principal)
	scope := ClientScope{
		All:       s.Allows(normalized, PermissionManagementAdmin),
		ClientIDs: append([]int(nil), normalized.ClientIDs...),
	}
	for _, clientID := range normalized.ClientIDs {
		if clientID > 0 {
			scope.PrimaryClientID = clientID
			break
		}
	}
	return scope
}

func (s DefaultAuthorizationService) Permissions(principal Principal) []string {
	normalized := s.NormalizePrincipal(principal)
	return append([]string(nil), normalized.Permissions...)
}

func (s DefaultAuthorizationService) Allows(principal Principal, permission string) bool {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return false
	}
	return permissionSetAllows(normalized.Permissions, permission)
}

func (s DefaultAuthorizationService) ResolveClient(principal Principal, requestedClientID int) (int, error) {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return 0, ErrUnauthenticated
	}
	if s.Allows(normalized, PermissionManagementAdmin) {
		return requestedClientID, nil
	}
	if requestedClientID > 0 {
		if s.canAccessClient(normalized, requestedClientID) {
			return requestedClientID, nil
		}
		return 0, ErrForbidden
	}
	scope := s.ClientScope(normalized)
	if len(scope.ClientIDs) == 0 {
		return 0, ErrForbidden
	}
	if scope.PrimaryClientID > 0 && len(scope.ClientIDs) == 1 {
		return scope.PrimaryClientID, nil
	}
	return 0, nil
}

func (s DefaultAuthorizationService) RequirePermission(principal Principal, permission string) error {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return ErrUnauthenticated
	}
	if s.Allows(normalized, permission) {
		return nil
	}
	return ErrForbidden
}

func (s DefaultAuthorizationService) RequireAdmin(principal Principal) error {
	return s.RequirePermission(principal, PermissionManagementAdmin)
}

func (s DefaultAuthorizationService) RequireClient(principal Principal, clientID int) error {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return ErrUnauthenticated
	}
	if s.canAccessClient(normalized, clientID) {
		return nil
	}
	return ErrForbidden
}

func (s DefaultAuthorizationService) RequireTunnel(principal Principal, tunnelID int) error {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return ErrUnauthenticated
	}
	if s.Allows(normalized, PermissionManagementAdmin) {
		return nil
	}
	for _, clientID := range normalized.ClientIDs {
		if s.repo().ClientOwnsTunnel(clientID, tunnelID) {
			return nil
		}
	}
	return ErrForbidden
}

func (s DefaultAuthorizationService) RequireHost(principal Principal, hostID int) error {
	normalized := s.NormalizePrincipal(principal)
	if !normalized.Authenticated {
		return ErrUnauthenticated
	}
	if s.Allows(normalized, PermissionManagementAdmin) {
		return nil
	}
	for _, clientID := range normalized.ClientIDs {
		if s.repo().ClientOwnsHost(clientID, hostID) {
			return nil
		}
	}
	return ErrForbidden
}

func ResolveNodeAccessScope(principal Principal) NodeAccessScope {
	return ResolveNodeAccessScopeWithAuthorization(DefaultAuthorizationService{}, principal)
}

func ResolveNodeAccessScopeWithAuthorization(authz AuthorizationService, principal Principal) NodeAccessScope {
	context := resolvePrincipalContextWithAuthorization(authz, principal)
	normalized := context.Principal
	scope := NodeAccessScope{
		actorKind:        context.Kind,
		allowedClientIDs: make(map[int]struct{}),
		platformID:       context.PlatformID,
		serviceUserID:    context.ServiceUserID,
		userID:           context.UserID,
	}
	for _, clientID := range normalized.ClientIDs {
		if clientID > 0 {
			scope.allowedClientIDs[clientID] = struct{}{}
		}
	}
	if normalized.IsAdmin {
		scope.full = true
		return scope
	}
	if scope.actorKind == "platform_admin" {
		scope.accountWide = true
	}
	return scope
}

func (s NodeAccessScope) CanViewStatus() bool {
	return s.full || s.actorKind == "platform_admin" || s.actorKind == "platform_user"
}

func (s NodeAccessScope) IsFullAccess() bool {
	return s.full
}

// IsPlatformPrincipal reports whether the scope belongs to a management
// platform acting over the node API (machine-to-machine replication/recovery)
// rather than an interactive human operator. Platform replication streams must
// always carry real secret values, so human-facing export masking must not be
// applied to them.
func (s NodeAccessScope) IsPlatformPrincipal() bool {
	return s.actorKind == "platform_admin" || s.actorKind == "platform_user"
}

func (s NodeAccessScope) CanViewUsage() bool {
	return s.full || s.actorKind == "platform_admin" || s.actorKind == "platform_user" || s.actorKind == "user" || s.actorKind == "client"
}

func (s NodeAccessScope) CanExportConfig() bool {
	return s.full
}

func (s NodeAccessScope) CanSync() bool {
	return s.full
}

func (s NodeAccessScope) CanWriteTraffic() bool {
	return s.full
}

func (s NodeAccessScope) CanViewCallbackQueue() bool {
	return s.full || s.accountWide
}

func (s NodeAccessScope) CanManageCallbackQueue() bool {
	return s.full || s.accountWide
}

func (s NodeAccessScope) AllowsClient(client *file.Client) bool {
	if client == nil {
		return false
	}
	if s.full {
		return true
	}
	switch s.actorKind {
	case "platform_admin":
		return s.serviceUserID > 0 && client.OwnerID() == s.serviceUserID
	case "platform_user":
		if s.serviceUserID > 0 && client.OwnerID() != s.serviceUserID {
			return false
		}
		if len(s.allowedClientIDs) == 0 {
			return false
		}
		_, ok := s.allowedClientIDs[client.Id]
		return ok
	case "user":
		if s.userID > 0 {
			return client.CanBeManagedByUser(s.userID)
		}
		if len(s.allowedClientIDs) == 0 {
			return false
		}
		_, ok := s.allowedClientIDs[client.Id]
		return ok
	case "client":
		if len(s.allowedClientIDs) == 0 {
			return false
		}
		_, ok := s.allowedClientIDs[client.Id]
		return ok
	default:
		return false
	}
}

func (s NodeAccessScope) AllowsUser(user *file.User) bool {
	if user == nil {
		return false
	}
	if s.full {
		return true
	}
	switch s.actorKind {
	case "platform_admin", "platform_user":
		return s.serviceUserID > 0 && user.Id == s.serviceUserID
	case "user":
		return s.userID > 0 && user.Id == s.userID
	default:
		return false
	}
}

func (s NodeAccessScope) AllowsPlatform(platformID string) bool {
	platformID = strings.TrimSpace(platformID)
	if platformID == "" {
		return false
	}
	if s.full {
		return true
	}
	switch s.actorKind {
	case "platform_admin", "platform_user":
		return s.platformID != "" && s.platformID == platformID
	default:
		return false
	}
}

func ResolveProtectedActionAccess(authz AuthorizationService, input ProtectedActionAccessInput) (ProtectedActionAccessResult, error) {
	authz = authorizationOrDefault(authz)
	if permission := strings.TrimSpace(input.Permission); permission != "" {
		if err := authz.RequirePermission(input.Principal, permission); err != nil {
			return ProtectedActionAccessResult{}, err
		}
	}
	result := ProtectedActionAccessResult{}
	if input.ClientScope {
		resolvedClientID, err := authz.ResolveClient(input.Principal, input.RequestedClientID)
		if err != nil {
			return ProtectedActionAccessResult{}, err
		}
		result.ResolvedClientID = resolvedClientID
	}
	if input.ResourceID <= 0 {
		return result, nil
	}
	switch strings.ToLower(strings.TrimSpace(input.Ownership)) {
	case "client":
		if err := authz.RequireClient(input.Principal, input.ResourceID); err != nil {
			return ProtectedActionAccessResult{}, err
		}
	case "tunnel":
		if err := authz.RequireTunnel(input.Principal, input.ResourceID); err != nil {
			return ProtectedActionAccessResult{}, err
		}
	case "host":
		if err := authz.RequireHost(input.Principal, input.ResourceID); err != nil {
			return ProtectedActionAccessResult{}, err
		}
	}
	return result, nil
}

func (s DefaultAuthorizationService) canAccessClient(principal Principal, clientID int) bool {
	if clientID <= 0 {
		return false
	}
	if s.Allows(principal, PermissionManagementAdmin) {
		return true
	}
	for _, current := range principal.ClientIDs {
		if current == clientID {
			return true
		}
	}
	return false
}

func normalizePrincipalClientIDs(clientIDs []int) []int {
	normalized := make([]int, 0, len(clientIDs))
	visitor := newUniqueClientIDVisitor(len(clientIDs), func(clientID int) bool {
		normalized = append(normalized, clientID)
		return true
	})
	for _, clientID := range clientIDs {
		visitor.visit(clientID)
	}
	return normalized
}

func resolvePrincipalContext(principal Principal) principalContext {
	return resolvePrincipalContextWithAuthorization(DefaultAuthorizationService{}, principal)
}

func resolvePrincipalContextWithAuthorization(authz AuthorizationService, principal Principal) principalContext {
	authz = authorizationOrDefault(authz)
	normalized := authz.NormalizePrincipal(principal)
	return principalContext{
		Principal:       normalized,
		Kind:            strings.TrimSpace(normalized.Kind),
		PlatformID:      principalAttributeValue(normalized, "platform_id"),
		PlatformActorID: principalAttributeValue(normalized, "platform_actor_id"),
		UserID:          principalAttributeIntValue(normalized, "user_id"),
		ServiceUserID:   principalAttributeIntValue(normalized, "platform_service_user_id"),
		SourceType:      principalSourceType(normalized),
	}
}

func authorizationOrDefault(authz AuthorizationService) AuthorizationService {
	if isNilServiceValue(authz) {
		return DefaultAuthorizationService{}
	}
	return authz
}

func normalizePrincipalStrings(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func normalizePermissionSet(isAdmin bool, roles []string, explicit []string) []string {
	permissions := normalizePrincipalStrings(explicit)
	seen := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		seen[permission] = struct{}{}
	}
	for _, role := range roles {
		for _, permission := range DefaultRolePermissions(role) {
			permission = strings.TrimSpace(permission)
			if permission == "" {
				continue
			}
			if _, ok := seen[permission]; ok {
				continue
			}
			seen[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}
	if isAdmin {
		if _, ok := seen[PermissionAll]; !ok {
			seen[PermissionAll] = struct{}{}
			permissions = append(permissions, PermissionAll)
		}
	}
	return permissions
}

func principalSourceType(principal Principal) string {
	switch strings.TrimSpace(principal.Kind) {
	case "platform_admin":
		return "platform_admin"
	case "platform_user":
		return "platform_user"
	case "admin":
		return "node_admin"
	case "client":
		return "node_client"
	case "user":
		return "node_user"
	default:
		return strings.TrimSpace(principal.Kind)
	}
}

func DefaultRolePermissions(role string) []string {
	switch strings.TrimSpace(role) {
	case RoleAdmin:
		return []string{PermissionAll, PermissionManagementAdmin, PermissionGlobalManage}
	case RoleClient:
		return []string{
			PermissionClientsRead,
			PermissionTunnelsCreate,
			PermissionTunnelsRead,
			PermissionTunnelsUpdate,
			PermissionTunnelsDelete,
			PermissionTunnelsControl,
			PermissionHostsCreate,
			PermissionHostsRead,
			PermissionHostsUpdate,
			PermissionHostsDelete,
			PermissionHostsControl,
		}
	case RoleUser:
		return []string{
			PermissionClientsCreate,
			PermissionClientsRead,
			PermissionClientsUpdate,
			PermissionClientsDelete,
			PermissionClientsStatus,
			PermissionTunnelsCreate,
			PermissionTunnelsRead,
			PermissionTunnelsUpdate,
			PermissionTunnelsDelete,
			PermissionTunnelsControl,
			PermissionHostsCreate,
			PermissionHostsRead,
			PermissionHostsUpdate,
			PermissionHostsDelete,
			PermissionHostsControl,
		}
	default:
		return nil
	}
}

func permissionSetAllows(granted []string, required string) bool {
	required = strings.TrimSpace(required)
	if required == "" {
		return true
	}
	for _, permission := range granted {
		if matchPermission(permission, required) {
			return true
		}
	}
	return false
}

func matchPermission(granted, required string) bool {
	granted = strings.TrimSpace(granted)
	if granted == "" {
		return false
	}
	if granted == PermissionAll || granted == required {
		return true
	}
	if strings.HasSuffix(granted, "*") {
		prefix := strings.TrimSuffix(granted, "*")
		return strings.HasPrefix(required, prefix)
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func principalAttributeValue(principal Principal, key string) string {
	if principal.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(principal.Attributes[strings.TrimSpace(key)])
}

func principalAttributeIntValue(principal Principal, key string) int {
	value := principalAttributeValue(principal, key)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func (s DefaultAuthorizationService) resolver() PermissionResolver {
	if !isNilServiceValue(s.Resolver) {
		return s.Resolver
	}
	return DefaultPermissionResolver()
}

func (s DefaultAuthorizationService) repo() AuthorizationRepository {
	if !isNilServiceValue(s.Repo) {
		return s.Repo
	}
	if !isNilServiceValue(s.Backend.Repository) {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}
