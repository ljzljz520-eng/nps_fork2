package service

import (
	"sort"
	"strings"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/credential"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/servercfg"
)

type UserService interface {
	List(ListUsersInput) ListUsersResult
	Get(int) (*file.User, error)
	Add(AddUserInput) (UserMutation, error)
	Edit(EditUserInput) (UserMutation, error)
	ChangeStatus(id int, status bool) (UserMutation, error)
	Delete(id int) (UserMutation, error)
}

type DefaultUserService struct {
	ConfigProvider func() *servercfg.Snapshot
	Repo           UserRepository
	Runtime        UserRuntime
	Backend        Backend
}

type ListUsersInput struct {
	Offset int
	Limit  int
	Search string
	Sort   string
	Order  string
}

type ListUsersResult struct {
	Rows  []*UserListRow
	Total int
}

type UserMutation struct {
	ID   int
	User *file.User
}

type AddUserInput struct {
	ReservedAdminUsername string
	Username              string
	Password              string
	TOTPSecret            string
	Status                bool
	ExpireAt              string
	FlowLimit             int64
	MaxClients            int
	MaxTunnels            int
	MaxHosts              int
	MaxConnections        int
	RateLimit             int
	EntryACLMode          int
	EntryACLRules         string
	DestACLMode           int
	DestACLRules          string
}

type EditUserInput struct {
	ID                    int
	ReservedAdminUsername string
	ExpectedRevision      int64
	Username              string
	Password              string
	PasswordProvided      bool
	TOTPSecret            string
	TOTPSecretProvided    bool
	Status                bool
	StatusProvided        bool
	ExpireAt              string
	FlowLimit             int64
	MaxClients            int
	MaxTunnels            int
	MaxHosts              int
	MaxConnections        int
	RateLimit             int
	ResetFlow             bool
	EntryACLMode          int
	EntryACLRules         string
	DestACLMode           int
	DestACLRules          string
}

type UserListRow struct {
	*file.User
	ClientCount  int
	TunnelCount  int
	HostCount    int
	ExpireAtText string
}

type userDeletePlan struct {
	ownedClientIDs []int
	managerUpdates []*file.Client
}

func (s DefaultUserService) List(input ListUsersInput) ListUsersResult {
	repo := s.repo()
	clientCounts, tunnelCounts, hostCounts := collectOwnedResourceCounts(repo)

	rows := make([]*UserListRow, 0)
	search := strings.TrimSpace(input.Search)
	searchID := common.GetIntNoErrByStr(search)
	repo.RangeUsers(func(user *file.User) bool {
		if user == nil {
			return true
		}
		if user.Hidden {
			return true
		}
		if search != "" && user.Id != searchID && !common.ContainsFold(user.Username, search) {
			return true
		}
		snapshot := ensureDetachedUserSnapshot(repo, user)
		file.InitializeUserRuntime(snapshot)
		rows = append(rows, &UserListRow{
			User:         snapshot,
			ClientCount:  clientCounts[user.Id],
			TunnelCount:  tunnelCounts[user.Id],
			HostCount:    hostCounts[user.Id],
			ExpireAtText: formatUserExpireAt(snapshot.ExpireAt),
		})
		return true
	})

	sortUserRows(rows, input.Sort, input.Order)

	total := len(rows)
	return ListUsersResult{Rows: paginateUserRows(rows, input.Offset, input.Limit), Total: total}
}

func collectOwnedResourceCounts(repo UserRepository) (map[int]int, map[int]int, map[int]int) {
	return collectOwnedResourceCountMaps(repo)
}

func paginateUserRows(rows []*UserListRow, offset, limit int) []*UserListRow {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rows) {
		return nil
	}
	if limit <= 0 || offset+limit > len(rows) {
		limit = len(rows) - offset
	}
	return rows[offset : offset+limit]
}

func (s DefaultUserService) Get(id int) (*file.User, error) {
	repo := s.repo()
	user, err := repo.GetUser(id)
	if err != nil {
		return nil, mapUserServiceError(err)
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	if isManagedServiceUser(user) {
		return nil, ErrForbidden
	}
	return ensureDetachedUserSnapshot(repo, user), nil
}

func (s DefaultUserService) Add(input AddUserInput) (UserMutation, error) {
	username := strings.TrimSpace(input.Username)
	password := strings.TrimSpace(input.Password)
	totpSecret, err := normalizeUserTOTPSecret(input.TOTPSecret)
	if username == "" {
		return UserMutation{}, ErrUserUsernameRequired
	}
	if password == "" && totpSecret == "" {
		return UserMutation{}, ErrUserPasswordRequired
	}
	if err != nil {
		return UserMutation{}, err
	}
	storedPassword := ""
	if password != "" {
		storedPassword, err = credential.HashPassword(password)
		if err != nil {
			return UserMutation{}, err
		}
	}
	if username == strings.TrimSpace(input.ReservedAdminUsername) {
		return UserMutation{}, ErrReservedUsername
	}
	user := &file.User{
		Id:             s.repo().NextUserID(),
		Username:       username,
		Password:       storedPassword,
		TOTPSecret:     totpSecret,
		Kind:           "local",
		Status:         boolToUserStatus(input.Status),
		ExpireAt:       parseUserExpireAt(input.ExpireAt),
		FlowLimit:      normalizeUserFlowLimit(input.FlowLimit),
		TotalFlow:      &file.Flow{},
		MaxClients:     normalizeNonNegative(input.MaxClients),
		MaxTunnels:     normalizeNonNegative(input.MaxTunnels),
		MaxHosts:       normalizeNonNegative(input.MaxHosts),
		MaxConnections: normalizeNonNegative(input.MaxConnections),
		RateLimit:      normalizeNonNegative(input.RateLimit),
	}
	user.EntryAclMode, user.EntryAclRules = normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	user.DestAclMode, user.DestAclRules = normalizeDestinationACLInput(input.DestACLMode, input.DestACLRules)
	user.TouchMeta()
	if err := s.repo().CreateUser(user); err != nil {
		return UserMutation{}, err
	}
	return newUserMutationResult(user), nil
}

func (s DefaultUserService) Edit(input EditUserInput) (UserMutation, error) {
	repo := s.repo()
	user, err := repo.GetUser(input.ID)
	if err != nil {
		return UserMutation{}, mapUserServiceError(err)
	}
	if user == nil {
		return UserMutation{}, ErrUserNotFound
	}
	if isManagedServiceUser(user) {
		return UserMutation{}, ErrForbidden
	}
	working := ensureDetachedUserSnapshot(repo, user)
	username := strings.TrimSpace(input.Username)
	if username == "" {
		return UserMutation{}, ErrUserUsernameRequired
	}
	if username == strings.TrimSpace(input.ReservedAdminUsername) {
		return UserMutation{}, ErrReservedUsername
	}
	totpSecret, err := normalizeUserTOTPSecret(input.TOTPSecret)
	if err != nil {
		return UserMutation{}, err
	}
	passwordProvided := input.PasswordProvided || strings.TrimSpace(input.Password) != ""
	nextPassword := working.Password
	if passwordProvided {
		candidate := strings.TrimSpace(input.Password)
		if candidate == "" {
			nextPassword = ""
		} else {
			hashed, hashErr := credential.HashPassword(candidate)
			if hashErr != nil {
				return UserMutation{}, hashErr
			}
			nextPassword = hashed
		}
	}
	nextTOTPSecret := working.TOTPSecret
	totpSecretProvided := input.TOTPSecretProvided || strings.TrimSpace(input.TOTPSecret) != ""
	if totpSecretProvided {
		nextTOTPSecret = totpSecret
	}
	if nextPassword == "" && nextTOTPSecret == "" {
		return UserMutation{}, ErrUserPasswordRequired
	}
	nextStatus := working.Status != 0
	if input.StatusProvided || input.Status {
		nextStatus = input.Status
	}
	working.Username = username
	working.Password = nextPassword
	working.TOTPSecret = nextTOTPSecret
	working.Kind = "local"
	working.Hidden = false
	working.ExternalPlatformID = ""
	working.Status = boolToUserStatus(nextStatus)
	working.ExpireAt = parseUserExpireAt(input.ExpireAt)
	working.FlowLimit = normalizeUserFlowLimit(input.FlowLimit)
	working.MaxClients = normalizeNonNegative(input.MaxClients)
	working.MaxTunnels = normalizeNonNegative(input.MaxTunnels)
	working.MaxHosts = normalizeNonNegative(input.MaxHosts)
	working.MaxConnections = normalizeNonNegative(input.MaxConnections)
	working.RateLimit = normalizeNonNegative(input.RateLimit)
	working.EntryAclMode, working.EntryAclRules = normalizeEntryACLInput(input.EntryACLMode, input.EntryACLRules)
	working.DestAclMode, working.DestAclRules = normalizeDestinationACLInput(input.DestACLMode, input.DestACLRules)
	working.EnsureTotalFlow()
	if input.ResetFlow {
		working.ResetTotalTraffic()
	}
	working.TouchMeta()
	working.ExpectedRevision = input.ExpectedRevision
	if err := repo.SaveUser(working); err != nil {
		return UserMutation{}, mapUserServiceError(err)
	}
	if err := s.disconnectUserClientsIfLimited(working); err != nil {
		return UserMutation{}, err
	}
	return newUserMutationResult(working), nil
}

func normalizeUserTOTPSecret(secret string) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		return "", nil
	}
	if !crypt.IsValidTOTPSecret(secret) {
		return "", ErrInvalidTOTPSecret
	}
	return secret, nil
}

func (s DefaultUserService) ChangeStatus(id int, status bool) (UserMutation, error) {
	repo := s.repo()
	user, err := repo.GetUser(id)
	if err != nil {
		return UserMutation{}, mapUserServiceError(err)
	}
	if user == nil {
		return UserMutation{}, ErrUserNotFound
	}
	if isManagedServiceUser(user) {
		return UserMutation{}, ErrForbidden
	}
	working := ensureDetachedUserSnapshot(repo, user)
	working.Status = boolToUserStatus(status)
	working.TouchMeta()
	if err := repo.SaveUser(working); err != nil {
		return UserMutation{}, mapUserServiceError(err)
	}
	if !status {
		if err := s.disconnectUserClients(working.Id); err != nil {
			return UserMutation{}, err
		}
	}
	return newUserMutationResult(working), nil
}

func (s DefaultUserService) Delete(id int) (UserMutation, error) {
	if id <= 0 {
		return UserMutation{}, ErrUserNotFound
	}
	repo := s.repo()
	user, err := repo.GetUser(id)
	if err != nil {
		return UserMutation{}, mapUserServiceError(err)
	}
	if user == nil {
		return UserMutation{}, ErrUserNotFound
	}
	if isManagedServiceUser(user) {
		return UserMutation{}, ErrForbidden
	}
	working := ensureDetachedUserSnapshot(repo, user)
	plan, err := collectUserDeletePlan(repo, id)
	if err != nil {
		return UserMutation{}, err
	}
	if err := withDeferredPersistence(repo, func() error {
		if err := deleteOwnedUserClients(repo, s.runtime(), plan.ownedClientIDs); err != nil {
			return err
		}
		if err := saveUserDeleteManagerUpdates(repo, plan.managerUpdates); err != nil {
			return err
		}
		return mapUserServiceError(repo.DeleteUser(id))
	}); err != nil {
		return UserMutation{}, err
	}
	working.NowConn = 0
	return newUserMutationResult(working), nil
}

func (s DefaultUserService) repo() UserRepository {
	if !isNilServiceValue(s.Repo) {
		return s.Repo
	}
	if !isNilServiceValue(s.Backend.Repository) {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}

func (s DefaultUserService) runtime() UserRuntime {
	if !isNilServiceValue(s.Runtime) {
		return s.Runtime
	}
	if !isNilServiceValue(s.Backend.Runtime) {
		return s.Backend.Runtime
	}
	return DefaultBackend().Runtime
}

func sortUserRows(rows []*UserListRow, sortField, order string) {
	asc := strings.TrimSpace(order) == "" || strings.EqualFold(strings.TrimSpace(order), "asc")
	switch sortField {
	case "Username":
		sortUserRowsByString(rows, asc, func(row *UserListRow) string { return row.Username })
	case "Status":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.Status })
	case "ClientCount":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.ClientCount })
	case "TunnelCount":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.TunnelCount })
	case "HostCount":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.HostCount })
	case "ExpireAt":
		sortUserRowsByInt64(rows, asc, func(row *UserListRow) int64 { return row.ExpireAt })
	case "FlowLimit":
		sortUserRowsByInt64(rows, asc, func(row *UserListRow) int64 { return row.FlowLimit })
	case "RateLimit":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.RateLimit })
	case "MaxClients":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.MaxClients })
	case "MaxTunnels":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.MaxTunnels })
	case "MaxHosts":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.MaxHosts })
	case "MaxConnections":
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return row.MaxConnections })
	case "TotalFlow":
		sortUserRowsByInt64(rows, asc, func(row *UserListRow) int64 { return userTotalFlow(row.User) })
	case "Rate.NowRate", "NowRate":
		sortUserRowsByInt64(rows, asc, func(row *UserListRow) int64 { return userNowRate(row.User) })
	default:
		sortUserRowsByInt(rows, asc, func(row *UserListRow) int { return userRowID(row) })
	}
}

func sortUserRowsByString(rows []*UserListRow, asc bool, value func(*UserListRow) string) {
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		if leftValue, rightValue := value(left), value(right); leftValue != rightValue {
			if asc {
				return leftValue < rightValue
			}
			return leftValue > rightValue
		}
		return userRowID(left) < userRowID(right)
	})
}

func sortUserRowsByInt(rows []*UserListRow, asc bool, value func(*UserListRow) int) {
	sort.SliceStable(rows, func(i, j int) bool {
		if leftValue, rightValue := value(rows[i]), value(rows[j]); leftValue != rightValue {
			if asc {
				return leftValue < rightValue
			}
			return leftValue > rightValue
		}
		return userRowID(rows[i]) < userRowID(rows[j])
	})
}

func newUserMutationResult(user *file.User) UserMutation {
	if user == nil {
		return UserMutation{}
	}
	return UserMutation{
		ID:   user.Id,
		User: cloneUserForMutation(user),
	}
}

func sortUserRowsByInt64(rows []*UserListRow, asc bool, value func(*UserListRow) int64) {
	sort.SliceStable(rows, func(i, j int) bool {
		if leftValue, rightValue := value(rows[i]), value(rows[j]); leftValue != rightValue {
			if asc {
				return leftValue < rightValue
			}
			return leftValue > rightValue
		}
		return userRowID(rows[i]) < userRowID(rows[j])
	})
}

func userRowID(row *UserListRow) int {
	if row == nil || row.User == nil {
		return 0
	}
	return row.Id
}

func userTotalFlow(user *file.User) int64 {
	if user == nil {
		return 0
	}
	_, _, total := user.TotalTrafficTotals()
	return total
}

func userNowRate(user *file.User) int64 {
	if user == nil {
		return 0
	}
	_, _, total := user.TotalRateTotals()
	return total
}

func parseUserExpireAt(value string) int64 {
	expireAt := common.GetTimeNoErrByStr(strings.TrimSpace(value))
	if expireAt.IsZero() {
		return 0
	}
	return expireAt.Unix()
}

func formatUserExpireAt(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).Format("2006-01-02 15:04:05")
}

func boolToUserStatus(status bool) int {
	if status {
		return 1
	}
	return 0
}

func normalizeNonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func normalizeUserFlowLimit(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func (s DefaultUserService) disconnectUserClientsIfLimited(user *file.User) error {
	if !shouldDisconnectUserClientsNow(user, time.Now().Unix()) {
		return nil
	}
	return s.disconnectUserClients(user.Id)
}

func (s DefaultUserService) disconnectUserClients(userID int) error {
	if userID <= 0 {
		return nil
	}
	return rangeOwnedClientIDsByUser(s.repo(), userID, func(clientID int) bool {
		s.runtime().DisconnectClient(clientID)
		return true
	})
}

func shouldDisconnectUserClientsNow(user *file.User, now int64) bool {
	if user == nil {
		return false
	}
	if user.Status == 0 {
		return true
	}
	if user.ExpireAt > 0 && now >= user.ExpireAt {
		return true
	}
	if user.FlowLimit > 0 {
		_, _, total := user.TotalTrafficTotals()
		if total >= user.FlowLimit {
			return true
		}
	}
	return false
}

func isManagedServiceUser(user *file.User) bool {
	if user == nil {
		return false
	}
	user.NormalizeIdentity()
	return user.Hidden || user.Kind == "platform_service" || strings.TrimSpace(user.ExternalPlatformID) != ""
}

func pruneClientManagerUserID(client *file.Client, userID int) bool {
	if client == nil {
		return false
	}
	filtered, changed := filteredClientManagerUserIDs(client.ManagerUserIDs, userID)
	if !changed {
		return false
	}
	client.ManagerUserIDs = filtered
	return true
}

func collectUserDeletePlan(repo UserRepository, userID int) (userDeletePlan, error) {
	if repoDeletesUserClientRefs(repo) {
		clientIDs, err := collectOwnedClientIDsForUserDelete(repo, userID)
		if err != nil {
			return userDeletePlan{}, err
		}
		return userDeletePlan{ownedClientIDs: clientIDs}, nil
	}
	return collectManualUserDeletePlan(repo, userID)
}

func repoDeletesUserClientRefs(repo UserRepository) bool {
	if repo == nil {
		return false
	}
	cascadeRepo, ok := repo.(deleteUserCascadeClientRefsRepository)
	return ok && cascadeRepo.SupportsDeleteUserCascadeClientRefs()
}

func collectOwnedClientIDsForUserDelete(repo UserRepository, userID int) ([]int, error) {
	clientIDs := make([]int, 0)
	err := rangeOwnedClientIDsByUser(repo, userID, func(clientID int) bool {
		clientIDs = append(clientIDs, clientID)
		return true
	})
	return clientIDs, err
}

func collectManualUserDeletePlan(repo UserRepository, userID int) (userDeletePlan, error) {
	if repo == nil || userID <= 0 {
		return userDeletePlan{}, nil
	}
	if plan, ok, err := collectManualUserDeletePlanByManagedClientScope(repo, userID); ok {
		return plan, err
	}
	return collectManualUserDeletePlanByRange(repo, userID), nil
}

func collectManualUserDeletePlanByManagedClientScope(repo UserRepository, userID int) (userDeletePlan, bool, error) {
	if repo == nil || userID <= 0 {
		return userDeletePlan{}, true, nil
	}
	indexedRepo, ok := repo.(allManagedClientIDsByUserLookupRepository)
	if !ok || !indexedRepo.SupportsGetAllManagedClientIDsByUserID() {
		return userDeletePlan{}, false, nil
	}
	authoritativeRepo, ok := repo.(authoritativeAllManagedClientIDsByUserLookupRepository)
	if !ok || !authoritativeRepo.SupportsAuthoritativeAllManagedClientIDsByUserID() {
		return userDeletePlan{}, false, nil
	}
	clientIDs, err := indexedRepo.GetAllManagedClientIDsByUserID(userID)
	if err != nil {
		return userDeletePlan{}, true, err
	}
	plan := userDeletePlan{
		ownedClientIDs: make([]int, 0),
		managerUpdates: make([]*file.Client, 0),
	}
	err = rangeClientsByIDs(repo, clientIDs, func(client *file.Client) bool {
		if client == nil {
			return true
		}
		if client.OwnerID() == userID {
			plan.ownedClientIDs = append(plan.ownedClientIDs, client.Id)
			return true
		}
		filteredManagerIDs, changed := filteredClientManagerUserIDs(client.ManagerUserIDs, userID)
		if changed {
			working := ensureDetachedClientSnapshot(repo, client)
			working.ManagerUserIDs = filteredManagerIDs
			working.TouchMeta("", "", "")
			plan.managerUpdates = append(plan.managerUpdates, working)
		}
		return true
	})
	if err != nil {
		return userDeletePlan{}, true, err
	}
	return plan, true, nil
}

func collectManualUserDeletePlanByRange(repo UserRepository, userID int) userDeletePlan {
	plan := userDeletePlan{
		ownedClientIDs: make([]int, 0),
		managerUpdates: make([]*file.Client, 0),
	}
	ownedVisitor := newUniqueClientIDVisitor(0, func(clientID int) bool {
		plan.ownedClientIDs = append(plan.ownedClientIDs, clientID)
		return true
	})
	repo.RangeClients(func(client *file.Client) bool {
		if client == nil {
			return true
		}
		if client.OwnerID() == userID {
			return ownedVisitor.visit(client.Id)
		}
		filteredManagerIDs, changed := filteredClientManagerUserIDs(client.ManagerUserIDs, userID)
		if !changed {
			return true
		}
		working := ensureDetachedClientSnapshot(repo, client)
		working.ManagerUserIDs = filteredManagerIDs
		working.TouchMeta("", "", "")
		plan.managerUpdates = append(plan.managerUpdates, working)
		return true
	})
	return plan
}

func deleteOwnedUserClients(repo UserRepository, runtime UserRuntime, clientIDs []int) error {
	for _, clientID := range clientIDs {
		if clientID <= 0 {
			continue
		}
		if err := repo.DeleteClient(clientID); err != nil {
			return mapClientServiceError(err)
		}
		if runtime != nil {
			runtime.DisconnectClient(clientID)
			runtime.DeleteClientResources(clientID)
		}
	}
	return nil
}

func saveUserDeleteManagerUpdates(repo UserRepository, clients []*file.Client) error {
	for _, client := range clients {
		if client == nil {
			continue
		}
		if err := repo.SaveClient(client); err != nil {
			return mapClientServiceError(err)
		}
	}
	return nil
}

func filteredClientManagerUserIDs(managerUserIDs []int, userID int) ([]int, bool) {
	if userID <= 0 || len(managerUserIDs) == 0 {
		return nil, false
	}
	firstMatch := -1
	for index, current := range managerUserIDs {
		if current == userID {
			firstMatch = index
			break
		}
	}
	if firstMatch < 0 {
		return nil, false
	}
	filtered := make([]int, 0, len(managerUserIDs)-1)
	filtered = append(filtered, managerUserIDs[:firstMatch]...)
	for _, current := range managerUserIDs[firstMatch+1:] {
		if current != userID {
			filtered = append(filtered, current)
		}
	}
	return filtered, true
}
