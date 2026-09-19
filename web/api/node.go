package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server"
	webservice "github.com/djylb/nps/web/service"
)

type deferredPersistenceNodeStorage interface {
	WithDeferredPersistence(func() error) error
}

func resolveNodeAccessScope(actor *Actor) webservice.NodeAccessScope {
	return webservice.ResolveNodeAccessScope(normalizePrincipalWithAuthorization(PrincipalFromActor(actor), webservice.DefaultAuthorizationService{}))
}

func (a *App) resolveNodeAccessScope(actor *Actor) webservice.NodeAccessScope {
	return a.nodeActorAccess(actor).scope
}

type nodeActorAccess struct {
	actor     *Actor
	principal webservice.Principal
	scope     webservice.NodeAccessScope
}

func (a *App) nodeActorAccess(actor *Actor) nodeActorAccess {
	authz := webservice.AuthorizationService(webservice.DefaultAuthorizationService{})
	if a != nil {
		authz = a.authorization()
	}
	normalizedActor, principal := normalizeActorWithAuthorization(actor, authz)
	return nodeActorAccess{
		actor:     normalizedActor,
		principal: principal,
		scope:     webservice.ResolveNodeAccessScopeWithAuthorization(authz, principal),
	}
}

func (a *App) nodeActorAccessFromContext(c Context) nodeActorAccess {
	if c == nil {
		return a.nodeActorAccess(nil)
	}
	actor := c.Actor()
	if identity := currentSessionIdentityWithResolver(c, a.permissionResolver()); identity != nil {
		actor = ActorFromSessionIdentity(identity)
	}
	access := a.nodeActorAccess(actor)
	c.SetActor(access.actor)
	return access
}

func (access nodeActorAccess) visibility(a *App) (webservice.ClientVisibility, bool, error) {
	if a == nil {
		return webservice.ClientVisibility{}, false, nil
	}
	return a.nodeClientVisibility(access.actor, access.scope)
}

func (access nodeActorAccess) allows(a *App, permission string) bool {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return true
	}
	authz := webservice.AuthorizationService(webservice.DefaultAuthorizationService{})
	if a != nil {
		authz = a.authorization()
	}
	return authz.Allows(access.principal, permission)
}

func (access nodeActorAccess) authorize(a *App, c Context, input webservice.ProtectedActionAccessInput) (int, error) {
	if a == nil {
		return 0, webservice.ErrForbidden
	}
	input.Principal = access.principal
	return authorizeNodeProtectedAction(a, c, input)
}

type nodeReadContext struct {
	principal              webservice.Principal
	scope                  webservice.NodeAccessScope
	host                   string
	config                 *servercfg.Snapshot
	bootID                 string
	runtimeStartedAt       int64
	configEpoch            string
	operations             webservice.NodeOperationPayload
	idempotency            webservice.NodeIdempotencyPayload
	reverseStatus          func(string) webservice.ManagementPlatformReverseRuntimeStatus
	resolveServiceUsername func(string, string) string
}

type nodeGlobalResourcePayload struct {
	EntryACLMode  int    `json:"entry_acl_mode"`
	EntryACLRules string `json:"entry_acl_rules,omitempty"`
}

type nodeBanListMutationPayload struct {
	Action      string   `json:"action"`
	Key         string   `json:"key,omitempty"`
	RemovedKeys []string `json:"removed_keys,omitempty"`
	Total       int      `json:"total,omitempty"`
}

func (c nodeReadContext) statusInput(nodeID string) webservice.NodeStatusInput {
	return webservice.NodeStatusInput{
		NodeID:                 nodeID,
		Host:                   c.host,
		Scope:                  c.scope,
		Config:                 c.config,
		BootID:                 c.bootID,
		RuntimeStartedAt:       c.runtimeStartedAt,
		ConfigEpoch:            c.configEpoch,
		Operations:             c.operations,
		Idempotency:            c.idempotency,
		LiveOnlyEvents:         NodeLiveOnlyEvents(),
		ReverseStatus:          c.reverseStatus,
		ResolveServiceUsername: c.resolveServiceUsername,
	}
}

func (c nodeReadContext) registrationInput(nodeID string) webservice.NodeRegistrationInput {
	return webservice.NodeRegistrationInput{
		NodeID:                 nodeID,
		Host:                   c.host,
		Scope:                  c.scope,
		Config:                 c.config,
		BootID:                 c.bootID,
		RuntimeStartedAt:       c.runtimeStartedAt,
		ConfigEpoch:            c.configEpoch,
		Operations:             c.operations,
		Idempotency:            c.idempotency,
		LiveOnlyEvents:         NodeLiveOnlyEvents(),
		ReverseStatus:          c.reverseStatus,
		ResolveServiceUsername: c.resolveServiceUsername,
	}
}

func (c nodeReadContext) overviewInput(nodeID string, includeConfig bool, snapshot func() (interface{}, error)) webservice.NodeOverviewInput {
	return webservice.NodeOverviewInput{
		NodeID:                 nodeID,
		Host:                   c.host,
		Principal:              c.principal,
		Scope:                  c.scope,
		Config:                 c.config,
		BootID:                 c.bootID,
		RuntimeStartedAt:       c.runtimeStartedAt,
		ConfigEpoch:            c.configEpoch,
		Operations:             c.operations,
		Idempotency:            c.idempotency,
		LiveOnlyEvents:         NodeLiveOnlyEvents(),
		ReverseStatus:          c.reverseStatus,
		ResolveServiceUsername: c.resolveServiceUsername,
		IncludeConfig:          includeConfig,
		Snapshot:               snapshot,
	}
}

func (c nodeReadContext) dashboardInput() webservice.NodeDashboardInput {
	return webservice.NodeDashboardInput{
		Scope:       c.scope,
		ConfigEpoch: c.configEpoch,
	}
}

func (c nodeReadContext) usageSnapshotInput(nodeID string) webservice.NodeUsageSnapshotInput {
	return webservice.NodeUsageSnapshotInput{
		NodeID:      nodeID,
		Principal:   c.principal,
		Scope:       c.scope,
		Config:      c.config,
		ConfigEpoch: c.configEpoch,
	}
}

func (a *App) nodeReadContext(c Context) nodeReadContext {
	runtimeIdentity := a.runtimeIdentity()
	access := a.nodeActorAccessFromContext(c)
	return nodeReadContext{
		principal:              access.principal,
		scope:                  access.scope,
		host:                   c.Host(),
		config:                 a.currentConfig(),
		bootID:                 runtimeIdentity.BootID(),
		runtimeStartedAt:       runtimeIdentity.StartedAt(),
		configEpoch:            runtimeIdentity.ConfigEpoch(),
		operations:             a.runtimeStatus().Operations(),
		idempotency:            a.runtimeStatus().Idempotency(),
		reverseStatus:          a.managementPlatformRuntimeStatus().Status,
		resolveServiceUsername: a.managementPlatforms().ServiceUsername,
	}
}

func respondNodeControlData(c Context, payload interface{}, err error) bool {
	switch {
	case errors.Is(err, webservice.ErrForbidden), errors.Is(err, webservice.ErrUnauthenticated):
		respondManagementError(c, nodeAccessErrorStatus(err), err)
		return true
	case errors.Is(err, webservice.ErrSnapshotExportUnsupported):
		respondManagementError(c, http.StatusNotImplemented, err)
		return true
	case err != nil:
		respondManagementError(c, http.StatusInternalServerError, err)
		return true
	default:
		configEpoch := ""
		generatedAt := int64(0)
		switch value := payload.(type) {
		case webservice.NodeDashboardPayload:
			configEpoch = value.ConfigEpoch
			generatedAt = value.GeneratedAt
		case webservice.NodeUsageSnapshotPayload:
			configEpoch = value.ConfigEpoch
			generatedAt = value.GeneratedAt
		case webservice.NodeStatusPayload:
			configEpoch = value.ConfigEpoch
			generatedAt = value.Timestamp
		case webservice.NodeRegistrationPayload:
			configEpoch = value.ConfigEpoch
			generatedAt = value.Timestamp
		case webservice.NodeOverviewPayload:
			generatedAt = value.Timestamp
			if value.Registration != nil {
				configEpoch = value.Registration.ConfigEpoch
			} else if value.UsageSnapshot != nil {
				configEpoch = value.UsageSnapshot.ConfigEpoch
			}
		}
		respondManagementData(c, http.StatusOK, payload, managementResponseMeta(c, generatedAt, configEpoch))
		return true
	}
}

func (a *App) NodeKick(c Context) {
	var body nodeKickRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	access := a.nodeActorAccessFromContext(c)
	startedAt := time.Now()
	operationID := nodeOperationID(c)
	setNodeOperationHeader(c, operationID)
	storage := a.nodeStorage()
	var result webservice.NodeKickResult
	runKick := func(flushStore func() error) error {
		var kickErr error
		result, kickErr = a.nodeControl().Kick(webservice.NodeKickInput{
			Principal: access.principal,
			Target: webservice.NodeClientTarget{
				ClientID:  body.ClientID,
				VerifyKey: strings.TrimSpace(body.VerifyKey),
			},
			SourceType:       NodeActorSourceType(access.actor),
			SourcePlatformID: NodeActorPlatformID(access.actor),
			SourceActorID:    NodeActorID(access.actor),
			ResolveClient:    storage.ResolveClient,
			SaveClient:       storage.SaveClient,
			DisconnectClient: server.DelClientConnect,
			FlushStore:       flushStore,
		})
		return kickErr
	}
	var err error
	if deferredStorage, ok := storage.(deferredPersistenceNodeStorage); ok {
		err = deferredStorage.WithDeferredPersistence(func() error {
			return runKick(nil)
		})
	} else {
		err = runKick(storage.FlushRuntime)
	}
	if errors.Is(err, webservice.ErrForbidden) || errors.Is(err, webservice.ErrUnauthenticated) {
		a.runtimeStatus().NoteOperation("kick", err)
		a.recordNodeControlOperation(c, operationID, "kick", startedAt, 1, 0, 1)
		respondManagementError(c, nodeAccessErrorStatus(err), err)
		return
	}
	if err != nil {
		a.runtimeStatus().NoteOperation("kick", err)
		a.recordNodeControlOperation(c, operationID, "kick", startedAt, 1, 0, 1)
		respondManagementError(c, nodeControlMutationErrorStatus(err), err)
		return
	}
	a.runtimeStatus().NoteOperation("kick", nil)
	if a != nil && result.Client != nil {
		fields := mergeEventFieldMap(
			map[string]interface{}{
				"id": result.Client.Id,
			},
			clientEventFields(result.Client),
		)
		a.Emit(c, Event{
			Name:     "node.client.kicked",
			Resource: "client",
			Action:   "kick",
			Fields:   fields,
		})
	}
	a.recordNodeControlOperation(c, operationID, "kick", startedAt, 1, 1, 0)
	data := map[string]interface{}{"message": "kick success"}
	if result.Client != nil {
		data["client_id"] = result.Client.Id
	}
	respondManagementData(c, http.StatusOK, data, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func (a *App) NodeSync(c Context) {
	access := a.nodeActorAccessFromContext(c)
	startedAt := time.Now()
	operationID := nodeOperationID(c)
	setNodeOperationHeader(c, operationID)
	storage := a.nodeStorage()
	err := a.nodeControl().Sync(webservice.NodeSyncInput{
		Scope:             access.scope,
		StopRuntime:       server.StopManagedTasksPreserveStatus,
		FlushLocal:        storage.FlushLocal,
		FlushStore:        storage.FlushRuntime,
		ClearProxyCache:   server.ClearProxyCache,
		DisconnectOrphans: server.DisconnectOrphanClients,
		StartRuntime:      server.StartManagedTasksFromDB,
	})
	if errors.Is(err, webservice.ErrForbidden) || errors.Is(err, webservice.ErrUnauthenticated) {
		a.runtimeStatus().NoteOperation("sync", err)
		a.recordNodeControlOperation(c, operationID, "sync", startedAt, 1, 0, 1)
		respondManagementError(c, nodeAccessErrorStatus(err), err)
		return
	}
	if err != nil {
		a.runtimeStatus().NoteOperation("sync", err)
		a.recordNodeControlOperation(c, operationID, "sync", startedAt, 1, 0, 1)
		respondManagementError(c, http.StatusInternalServerError, err)
		return
	}
	a.runtimeStatus().NoteOperation("sync", nil)
	if a != nil {
		a.Emit(c, Event{
			Name:     "node.config.sync",
			Resource: "node",
			Action:   "sync",
		})
	}
	a.recordNodeControlOperation(c, operationID, "sync", startedAt, 1, 1, 0)
	respondManagementData(c, http.StatusOK, map[string]interface{}{"message": "sync success"}, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func (a *App) NodeGlobal(c Context) {
	global := a.Services.Globals.Get()
	payload := nodeGlobalResourcePayload{}
	if global != nil {
		payload.EntryACLMode = global.EntryAclMode
		payload.EntryACLRules = global.EntryAclRules
	}
	respondNodeResourceData(c, nodeResourceItemPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Item:        payload,
	}, nil)
}

func (a *App) NodeUpdateGlobal(c Context) {
	var body nodeGlobalUpdateRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if err := a.Services.Globals.Save(webservice.SaveGlobalInput{
		EntryACLMode:  body.EntryACLMode,
		EntryACLRules: body.EntryACLRules,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	global := a.Services.Globals.Get()
	payload := nodeGlobalResourcePayload{}
	if global != nil {
		payload.EntryACLMode = global.EntryAclMode
		payload.EntryACLRules = global.EntryAclRules
	}
	a.Emit(c, Event{
		Name:     "global.updated",
		Resource: "global",
		Action:   "update",
	})
	respondNodeMutationData(c, nodeResourceMutationPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Resource:    "global",
		Action:      "update",
		Item:        payload,
	}, nil)
}

func (a *App) NodeBanList(c Context) {
	items := a.Services.Globals.BanList()
	offset, limit, returned, hasMore := nodeListPagination(0, 0, len(items), len(items))
	respondNodeResourceData(c, nodeResourceListPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Offset:      offset,
		Limit:       limit,
		Returned:    returned,
		Total:       len(items),
		HasMore:     hasMore,
		Items:       items,
	}, nil)
}

func (a *App) NodeUnban(c Context) {
	var body nodeKeyActionRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if body.Key == "" {
		respondMissingRequestField(c, "key")
		return
	}
	if !a.Services.Globals.Unban(body.Key) {
		respondManagementErrorMessage(c, http.StatusNotFound, "ban_not_found", "not found", nil)
		return
	}
	a.Emit(c, Event{
		Name:     "banlist.unbanned",
		Resource: "global",
		Action:   "unban",
		Fields: map[string]interface{}{
			"key": body.Key,
		},
	})
	configEpoch := a.runtimeIdentity().ConfigEpoch()
	generatedAt := time.Now().Unix()
	respondManagementData(c, http.StatusOK, nodeBanListMutationPayload{
		Action: "unban",
		Key:    body.Key,
	}, managementResponseMeta(c, generatedAt, configEpoch))
}

func (a *App) NodeUnbanAll(c Context) {
	existing := a.Services.Globals.BanList()
	a.Services.Globals.UnbanAll()
	removedKeys := make([]string, 0, len(existing))
	for _, item := range existing {
		if item.Key != "" {
			removedKeys = append(removedKeys, item.Key)
		}
	}
	a.Emit(c, Event{
		Name:     "banlist.cleared",
		Resource: "global",
		Action:   "unban_all",
	})
	configEpoch := a.runtimeIdentity().ConfigEpoch()
	generatedAt := time.Now().Unix()
	respondManagementData(c, http.StatusOK, nodeBanListMutationPayload{
		Action:      "unban_all",
		RemovedKeys: removedKeys,
	}, managementResponseMeta(c, generatedAt, configEpoch))
}

func (a *App) NodeBanClean(c Context) {
	before := a.Services.Globals.BanList()
	a.Services.Globals.CleanBans()
	after := a.Services.Globals.BanList()
	remaining := make(map[string]struct{}, len(after))
	for _, item := range after {
		if item.Key != "" {
			remaining[item.Key] = struct{}{}
		}
	}
	removedKeys := make([]string, 0)
	for _, item := range before {
		if item.Key == "" {
			continue
		}
		if _, ok := remaining[item.Key]; ok {
			continue
		}
		removedKeys = append(removedKeys, item.Key)
	}
	a.Emit(c, Event{
		Name:     "banlist.cleaned",
		Resource: "global",
		Action:   "clean",
	})
	configEpoch := a.runtimeIdentity().ConfigEpoch()
	generatedAt := time.Now().Unix()
	respondManagementData(c, http.StatusOK, nodeBanListMutationPayload{
		Action:      "clean",
		RemovedKeys: removedKeys,
		Total:       len(after),
	}, managementResponseMeta(c, generatedAt, configEpoch))
}

func (a *App) NodeConfig(c Context) {
	access := a.nodeActorAccessFromContext(c)
	storage := a.nodeStorage()
	payload, err := a.nodeControl().ExportConfig(webservice.NodeConfigExportInput{
		Scope:    access.scope,
		Snapshot: storage.Snapshot,
	})
	if errors.Is(err, webservice.ErrForbidden) || errors.Is(err, webservice.ErrUnauthenticated) {
		respondManagementError(c, nodeAccessErrorStatus(err), err)
		return
	}
	if errors.Is(err, webservice.ErrSnapshotExportUnsupported) {
		respondManagementError(c, http.StatusNotImplemented, err)
		return
	}
	if err != nil {
		respondManagementError(c, http.StatusInternalServerError, err)
		return
	}
	// Human-facing exports are masked by default so a downloaded configuration
	// never discloses secrets. Management platforms (node token replication and
	// recovery) always receive real values; a full-access human operator may
	// additionally pass ?secrets=1 to obtain an unmasked backup for restore.
	if access.scope.IsFullAccess() && !access.scope.IsPlatformPrincipal() && !requestBoolValue(c, "secrets") {
		if snapshot, ok := payload.(*file.ConfigSnapshot); ok {
			payload = file.MaskConfigSnapshot(snapshot)
		}
	}
	respondManagementData(c, http.StatusOK, payload, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func (a *App) NodeStatus(c Context) {
	input := a.nodeReadContext(c)
	payload, err := a.nodeControl().Status(input.statusInput(a.NodeID))
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeRegistration(c Context) {
	input := a.nodeReadContext(c)
	payload, err := a.nodeControl().Registration(input.registrationInput(a.NodeID))
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeOverview(c Context) {
	input := a.nodeReadContext(c)
	storage := a.nodeStorage()
	payload, err := a.nodeControl().Overview(input.overviewInput(
		a.NodeID,
		requestBoolValue(c, "config"),
		storage.Snapshot,
	))
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeDashboard(c Context) {
	input := a.nodeReadContext(c)
	payload, err := a.nodeControl().Dashboard(input.dashboardInput())
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeOperations(c Context) {
	access := a.nodeActorAccessFromContext(c)
	payload, err := a.nodeControl().Operations(webservice.NodeOperationsInput{
		Scope:       access.scope,
		SubjectID:   NodeActorSubjectID(access.actor),
		OperationID: strings.TrimSpace(requestString(c, "operation_id")),
		Limit:       requestIntValue(c, "limit"),
		Store:       a.nodeOperations(),
	})
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeUsageSnapshot(c Context) {
	input := a.nodeReadContext(c)
	payload, err := a.nodeControl().UsageSnapshot(input.usageSnapshotInput(a.NodeID))
	respondNodeControlData(c, payload, err)
}

func (a *App) NodeTraffic(c Context) {
	access := a.nodeActorAccessFromContext(c)
	var body nodeTrafficRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	startedAt := time.Now()
	operationID := nodeOperationID(c)
	setNodeOperationHeader(c, operationID)
	items, err := decodeNodeTrafficItems(body)
	if err != nil {
		a.runtimeStatus().NoteOperation("traffic", err)
		a.recordNodeControlOperation(c, operationID, "traffic", startedAt, 1, 0, 1)
		respondManagementError(c, nodeControlMutationErrorStatus(err), err)
		return
	}
	storage := a.nodeStorage()
	var result webservice.NodeTrafficResult
	runTraffic := func(flushStore func() error) error {
		var applyErr error
		result, applyErr = a.nodeControl().ApplyTraffic(webservice.NodeTrafficInput{
			Scope:         access.scope,
			Items:         items,
			ResolveClient: storage.ResolveTrafficClient,
			ResolveUser:   storage.ResolveUser,
			SaveUser:      storage.SaveUser,
			SaveClient:    storage.SaveClient,
			FlushStore:    flushStore,
		})
		return applyErr
	}
	if deferredStorage, ok := storage.(deferredPersistenceNodeStorage); ok {
		err = deferredStorage.WithDeferredPersistence(func() error {
			return runTraffic(nil)
		})
	} else {
		err = runTraffic(storage.FlushRuntime)
	}
	if errors.Is(err, webservice.ErrForbidden) || errors.Is(err, webservice.ErrUnauthenticated) {
		a.runtimeStatus().NoteOperation("traffic", err)
		a.recordNodeControlOperation(c, operationID, "traffic", startedAt, len(items), 0, len(items))
		respondManagementError(c, nodeAccessErrorStatus(err), err)
		return
	}
	if err != nil {
		a.runtimeStatus().NoteOperation("traffic", err)
		a.recordNodeControlOperation(c, operationID, "traffic", startedAt, len(items), 0, len(items))
		respondManagementError(c, nodeControlErrorStatus(err), err)
		return
	}
	a.runtimeStatus().NoteOperation("traffic", nil)
	if a != nil {
		for _, item := range result.Clients {
			if item.Client == nil {
				continue
			}
			report, ok := a.nodeTrafficReporter().Observe(item.Client, item.InletDelta, item.ExportDelta)
			if !ok || report == nil || report.Client == nil {
				continue
			}
			fields := mergeEventFieldMap(map[string]interface{}{
				"id":                       report.Client.Id,
				"client_id":                report.Client.Id,
				"reported_at":              report.ReportedAt,
				"traffic_in":               report.DeltaIn,
				"traffic_out":              report.DeltaOut,
				"traffic_total_in":         report.TotalIn,
				"traffic_total_out":        report.TotalOut,
				"traffic_trigger":          report.Trigger,
				"traffic_interval_seconds": report.IntervalSeconds,
				"traffic_step_bytes":       report.StepBytes,
			}, clientEventFields(report.Client))
			a.Emit(c, Event{
				Name:     "client.traffic.reported",
				Resource: "client",
				Action:   "traffic",
				Fields:   fields,
			})
		}
		a.Emit(c, Event{
			Name:     "node.traffic.report",
			Resource: "node",
			Action:   "traffic",
			Fields: map[string]interface{}{
				"items": result.ItemCount,
			},
		})
	}
	a.recordNodeControlOperation(c, operationID, "traffic", startedAt, result.ItemCount, result.ItemCount, 0)
	respondManagementData(c, http.StatusOK, map[string]interface{}{
		"message":    "traffic accepted",
		"item_count": result.ItemCount,
	}, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func nodeControlErrorStatus(err error) int {
	switch {
	case errors.Is(err, webservice.ErrClientNotFound):
		return http.StatusNotFound
	case errors.Is(err, webservice.ErrClientIdentifierRequired):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrClientIdentifierConflict):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrInvalidTrafficItems):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficItemsEmpty):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficClientRequired):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficTargetRequired):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrSnapshotExportUnsupported):
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

func nodeAccessErrorStatus(err error) int {
	switch {
	case errors.Is(err, webservice.ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, webservice.ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func nodeControlMutationErrorStatus(err error) int {
	status := nodeControlErrorStatus(err)
	if status == http.StatusNotFound {
		return status
	}
	switch {
	case errors.Is(err, webservice.ErrClientIdentifierRequired):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrClientIdentifierConflict):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrInvalidTrafficItems):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficItemsEmpty):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficClientRequired):
		return http.StatusBadRequest
	case errors.Is(err, webservice.ErrTrafficTargetRequired):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func decodeNodeTrafficItems(body nodeTrafficRequest) ([]file.TrafficDelta, error) {
	if len(body.Items) > 0 {
		items := make([]file.TrafficDelta, 0, len(body.Items))
		for _, item := range body.Items {
			items = append(items, file.TrafficDelta{
				ClientID:  item.ClientID,
				VerifyKey: strings.TrimSpace(item.VerifyKey),
				In:        item.In,
				Out:       item.Out,
			})
		}
		if len(items) == 0 {
			return nil, webservice.ErrTrafficItemsEmpty
		}
		return items, nil
	}
	return webservice.DecodeNodeTrafficItems("", body.ClientID, strings.TrimSpace(body.VerifyKey), body.In, body.Out)
}

func nodeOperationID(c Context) string {
	if c == nil {
		return ""
	}
	if value := strings.TrimSpace(c.RequestHeader("X-Operation-ID")); value != "" {
		return value
	}
	if value := strings.TrimSpace(requestString(c, "operation_id")); value != "" {
		return value
	}
	return strings.TrimSpace(c.Metadata().RequestID)
}

func setNodeOperationHeader(c Context, operationID string) {
	if c == nil {
		return
	}
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return
	}
	c.SetResponseHeader("X-Operation-ID", operationID)
}

func (a *App) recordNodeControlOperation(c Context, operationID string, kind string, startedAt time.Time, count, successCount, errorCount int) {
	if a == nil {
		return
	}
	if c != nil && strings.Contains(strings.TrimSpace(c.Metadata().Source), ":batch") {
		return
	}
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return
	}
	access := a.nodeActorAccessFromContext(c)
	a.nodeOperations().Record(webservice.NodeOperationRecordPayload{
		OperationID:  operationID,
		Kind:         strings.TrimSpace(kind),
		RequestID:    strings.TrimSpace(c.Metadata().RequestID),
		Source:       strings.TrimSpace(c.Metadata().Source),
		Scope:        NodeOperationScope(access.actor),
		Actor:        NodeOperationActorPayload(access.actor),
		StartedAt:    startedAt.Unix(),
		FinishedAt:   time.Now().Unix(),
		DurationMs:   time.Since(startedAt).Milliseconds(),
		Count:        count,
		SuccessCount: successCount,
		ErrorCount:   errorCount,
		Paths:        []string{nodeOperationPath(kind)},
	})
}

func nodeOperationPath(kind string) string {
	switch strings.TrimSpace(kind) {
	case "kick":
		return "/api/clients/actions/kick"
	case "sync":
		return "/api/system/actions/sync"
	case "traffic":
		return "/api/traffic"
	default:
		return "/api/" + strings.TrimSpace(kind)
	}
}
