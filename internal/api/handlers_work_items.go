package api

// Work items (workitem/v1, docs/work-context-contract.md, mctl-api#349).
//
// Identity: the acting principal is ALWAYS derived from authentication
// (auth.UserFromContext). No body field names it. A body that tries to
// (actor, owner_principal, created_by, on_behalf_of, ...) is rejected with a
// typed 400 rather than silently ignored, the ApproveDevLoopWorkflow rule:
// a caller that believes it acted as someone else must find out it did not.
// A surface acting for one of its users needs the trusted surface-identity
// binding (mctl-api#350); until that exists a surface acts only as itself.
//
// Authorization is re-evaluated on every request: admins see everything; any
// other principal needs HasTenantAccess on the item's tenant, and a private
// item is visible only to its owner. An item the caller may not see answers
// 404, never 403, so its existence does not leak.
//
// Not in this slice: context snapshots, the approval projection and
// surface-identities (mctl-api#350).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// maxWorkItemBodyBytes bounds a request body: an intent is at most 8 KiB of
// text plus 8 KiB of params.
const maxWorkItemBodyBytes = 64 << 10

// defaultWorkItemSurface labels a request that names no surface.
const defaultWorkItemSurface = "api"

// Typed error codes a client can branch on.
const (
	wiCodeUnavailable      = "work_items_unavailable"
	wiCodeNotFound         = "work_item_not_found"
	wiCodeInvalid          = "invalid_request"
	wiCodeActorNotAccepted = "actor_not_accepted"
	wiCodeVersionConflict  = "state_version_conflict"
	wiCodeInvalidTransit   = "invalid_transition"
	wiCodeExecutionActive  = "execution_active"
	wiCodeKeyReused        = "idempotency_key_reused"
	wiCodeSecret           = "secret_in_text"
	wiCodeTenantForbidden  = "tenant_forbidden"
	wiCodeExternalKeyInUse = "external_key_in_use"
)

// forbiddenIdentityFields are body keys that would name who acts. None is
// ever accepted.
var forbiddenIdentityFields = []string{
	"actor", "actor_principal", "owner", "owner_principal", "created_by",
	"on_behalf_of", "subject", "delegated_actor", "user", "user_id",
}

// principalOf renders the authenticated caller as a principal string. The
// prefix records how the caller authenticated, so a Dex username that
// happens to equal a GitHub login never reads as that GitHub user.
func principalOf(u *auth.User) string {
	if u.IsService() {
		return "service:" + u.ID
	}
	if login, ok := u.GitHubLogin(); ok {
		return "github:" + login
	}
	return "oidc:" + u.ID
}

func canSeeWorkItem(u *auth.User, w *workitems.WorkItem) bool {
	if u.IsAdmin() {
		return true
	}
	if !u.HasTenantAccess(w.Tenant) {
		return false
	}
	return w.Visibility == workitems.VisibilityTenant || w.OwnerPrincipal == principalOf(u)
}

func (h *Handlers) workItemsUser(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "work-items store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

// visibleWorkItem loads {id} and answers 404 unless the caller may see it.
func (h *Handlers) visibleWorkItem(w http.ResponseWriter, r *http.Request, user *auth.User) (*workitems.WorkItem, bool) {
	id := chi.URLParam(r, "id")
	item, err := h.opts.WorkItems.Get(r.Context(), id)
	if err == nil && !canSeeWorkItem(user, item) {
		err = workitems.ErrNotFound
	}
	if err != nil {
		writeWorkItemError(w, err)
		return nil, false
	}
	return item, true
}

// writeWorkItemError maps store errors to one status and typed code each.
func writeWorkItemError(w http.ResponseWriter, err error) {
	var details map[string]interface{}
	var ce *workitems.ConflictError
	if errors.As(err, &ce) && ce.Current != nil {
		details = map[string]interface{}{"state": ce.Current.State, "state_version": ce.Current.StateVersion}
	}
	switch {
	case errors.Is(err, workitems.ErrNotFound):
		writeErrorCode(w, http.StatusNotFound, wiCodeNotFound, "work item not found", nil)
	case errors.Is(err, workitems.ErrVersionConflict):
		writeErrorCode(w, http.StatusConflict, wiCodeVersionConflict, err.Error(), details)
	case errors.Is(err, workitems.ErrInvalidTransition):
		writeErrorCode(w, http.StatusConflict, wiCodeInvalidTransit, err.Error(), details)
	case errors.Is(err, workitems.ErrExecutionActive):
		writeErrorCode(w, http.StatusConflict, wiCodeExecutionActive, err.Error(), details)
	case errors.Is(err, workitems.ErrIdempotencyKeyReuse):
		writeErrorCode(w, http.StatusConflict, wiCodeKeyReused, err.Error(), nil)
	case errors.Is(err, workitems.ErrExternalKeyInUse):
		writeErrorCode(w, http.StatusConflict, wiCodeExternalKeyInUse, err.Error(), nil)
	case errors.Is(err, workitems.ErrSecretInText):
		writeErrorCode(w, http.StatusBadRequest, wiCodeSecret, err.Error(), nil)
	case errors.Is(err, workitems.ErrInvalid):
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, err.Error(), nil)
	default:
		slog.Error("work-items store error", "error", err)
		writeError(w, http.StatusInternalServerError, "work-items store error")
	}
}

// decodeWorkItemBody decodes a strict JSON object into dst. A key that would
// name the actor is refused with its own code before anything else.
func decodeWorkItemBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWorkItemBodyBytes))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "request body too large or unreadable", nil)
		return false
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "body must be a JSON object", nil)
		return false
	}
	for _, k := range forbiddenIdentityFields {
		if _, present := keys[k]; present {
			writeErrorCode(w, http.StatusBadRequest, wiCodeActorNotAccepted,
				"the acting principal is taken from authentication; field "+strconv.Quote(k)+
					" is not accepted (a surface acting for a user needs mctl-api#350)", nil)
			return false
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "invalid JSON body: "+err.Error(), nil)
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "invalid JSON body: trailing data", nil)
		return false
	}
	return true
}

// mutationFor builds the store Mutation: actor from authentication, key from
// the Idempotency-Key header or the body (they must agree), and a hash of
// the request so a reused key is told apart from a retry.
func mutationFor(w http.ResponseWriter, r *http.Request, user *auth.User, op, itemID, surface, bodyKey string, body any) (workitems.Mutation, bool) {
	key := r.Header.Get("Idempotency-Key")
	if bodyKey != "" {
		if key != "" && key != bodyKey {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "Idempotency-Key header and idempotency_key differ", nil)
			return workitems.Mutation{}, false
		}
		key = bodyKey
	}
	// A relayed request speaks for its surface and no other.
	if relay, ok := user.RelaySurface(); ok {
		if surface != "" && surface != relay {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid,
				"a request relayed by surface:"+relay+" cannot claim surface "+strconv.Quote(surface), nil)
			return workitems.Mutation{}, false
		}
		surface = relay
	}
	if surface == "" {
		surface = defaultWorkItemSurface
	}
	m := workitems.Mutation{Actor: principalOf(user), ActingPrincipal: user.ActingPrincipal(), Surface: surface, IdempotencyKey: key}
	if meta, ok := ClientMetaFromContext(r.Context()); ok {
		m.RequestID = truncateRequestID(meta.RequestID)
	}
	if key != "" {
		// Hash the decoded request without its key, so a retry hashes the
		// same whether the key travels in the header or the body. Map keys
		// marshal sorted, so the digest is canonical.
		canonical, err := requestDigestInput(body)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "hash request")
			return workitems.Mutation{}, false
		}
		sum := sha256.Sum256(append([]byte(op+"\x00"+itemID+"\x00"), canonical...))
		m.RequestHash = "sha256:" + hex.EncodeToString(sum[:])
	}
	return m, true
}

func requestDigestInput(body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "idempotency_key")
	return json.Marshal(fields)
}

// auditWorkItem records ids only: never intent text, never surface external
// ids (contract "Retention and privacy").
func (h *Handlers) auditWorkItem(r *http.Request, user *auth.User, op, itemID, tenant string, extra map[string]string) {
	params := map[string]string{"work_item_id": itemID, "tenant": tenant, "actor": principalOf(user)}
	if acting := user.ActingPrincipal(); acting != "" {
		params["acting_principal"] = acting
	}
	for k, v := range extra {
		params[k] = v
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "succeeded",
		RiskLevel:  string(operations.RiskLow),
	})
}

type workItemView struct {
	SchemaVersion   string               `json:"schema_version"`
	WorkItem        *workitems.WorkItem  `json:"work_item"`
	StateVersion    int64                `json:"state_version"`
	LatestExecution *workitems.Execution `json:"latest_execution"`
}

func (h *Handlers) viewOf(r *http.Request, item *workitems.WorkItem) (workItemView, error) {
	execs, err := h.opts.WorkItems.Executions(r.Context(), item.ID)
	if err != nil {
		return workItemView{}, err
	}
	v := workItemView{SchemaVersion: workitems.SchemaVersion, WorkItem: item, StateVersion: item.StateVersion}
	if len(execs) > 0 {
		v.LatestExecution = &execs[len(execs)-1]
	}
	return v, nil
}

func (h *Handlers) writeView(w http.ResponseWriter, r *http.Request, status int, item *workitems.WorkItem) {
	v, err := h.viewOf(r, item)
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	writeJSON(w, status, v)
}

func createdStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

type createWorkItemBody struct {
	Tenant         string `json:"tenant"`
	Visibility     string `json:"visibility,omitempty"`
	OriginSurface  string `json:"origin_surface,omitempty"`
	Title          string `json:"title"`
	ExternalKey    string `json:"external_key,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// CreateWorkItem handles POST /api/v1/work-items: open a work item, or return
// the one this request (idempotency key) or its external_key already opened.
func (h *Handlers) CreateWorkItem(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	var body createWorkItemBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	if body.Tenant == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "tenant is required", nil)
		return
	}
	if !user.HasTenantAccess(body.Tenant) {
		writeErrorCode(w, http.StatusForbidden, wiCodeTenantForbidden, "no access to tenant "+strconv.Quote(body.Tenant), nil)
		return
	}
	if body.Visibility == "" {
		body.Visibility = workitems.VisibilityTenant
	}
	if body.OriginSurface == "" {
		// A relayed create originates on its surface; mutationFor refuses
		// any other it claims.
		if relay, ok := user.RelaySurface(); ok {
			body.OriginSurface = relay
		} else {
			body.OriginSurface = defaultWorkItemSurface
		}
	}
	m, ok := mutationFor(w, r, user, "create", body.Tenant, body.OriginSurface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	item, created, err := h.opts.WorkItems.Create(r.Context(), workitems.CreateInput{
		Mutation: m, Tenant: body.Tenant, Visibility: body.Visibility, OriginSurface: body.OriginSurface,
		Title: body.Title, ExternalKey: body.ExternalKey,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	if !canSeeWorkItem(user, item) {
		// The store binds keys to the principal and refuses a foreign
		// private item on external_key, so this is defence in depth: answer
		// without disclosing the item, naming what actually matched.
		if body.ExternalKey != "" {
			writeErrorCode(w, http.StatusConflict, wiCodeExternalKeyInUse, "external_key already names open work you cannot see", nil)
		} else {
			writeErrorCode(w, http.StatusConflict, wiCodeKeyReused, "idempotency key names work you cannot see", nil)
		}
		return
	}
	if created {
		h.auditWorkItem(r, user, "work_item.create", item.ID, item.Tenant, map[string]string{"origin_surface": item.OriginSurface})
	}
	h.writeView(w, r, createdStatus(created), item)
}

// GetWorkItem handles GET /api/v1/work-items/{id}.
func (h *Handlers) GetWorkItem(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	h.writeView(w, r, http.StatusOK, item)
}

// ListWorkItems handles GET /api/v1/work-items?tenant=&state=&owner=&limit=.
// Without state it lists open (non-terminal) work.
func (h *Handlers) ListWorkItems(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := workitems.ListFilter{State: q.Get("state"), Owner: q.Get("owner")}
	if limit := q.Get("limit"); limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil || n <= 0 || n > 500 {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "limit must be an integer from 1 to 500", nil)
			return
		}
		f.Limit = n
	}
	tenant := q.Get("tenant")
	switch {
	case tenant != "" && !user.HasTenantAccess(tenant):
		writeErrorCode(w, http.StatusForbidden, wiCodeTenantForbidden, "no access to tenant "+strconv.Quote(tenant), nil)
		return
	case tenant != "":
		f.Tenants = []string{tenant}
	case user.IsAdmin():
		f.AllTenants = true
	default:
		f.Tenants = user.Groups
	}
	if !user.IsAdmin() {
		f.Viewer = principalOf(user)
	}
	items, err := h.opts.WorkItems.List(r.Context(), f)
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "items": items})
}

type transitionWorkItemBody struct {
	Action               string `json:"action"`
	WaitingReason        string `json:"waiting_reason,omitempty"`
	SupersededBy         string `json:"superseded_by,omitempty"`
	ExpectedStateVersion int64  `json:"expected_state_version"`
	Surface              string `json:"surface,omitempty"`
	IdempotencyKey       string `json:"idempotency_key,omitempty"`
}

// TransitionWorkItem handles PATCH /api/v1/work-items/{id}: complete,
// archive, supersede or wait. Resume is its own route.
func (h *Handlers) TransitionWorkItem(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body transitionWorkItemBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	if body.SupersededBy != "" {
		// The successor must be visible to the caller too, or supersede
		// would confirm that an id it cannot see exists.
		next, err := h.opts.WorkItems.Get(r.Context(), body.SupersededBy)
		if err != nil || !canSeeWorkItem(user, next) {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "superseded_by is not a work item you can see", nil)
			return
		}
	}
	m, ok := mutationFor(w, r, user, "transition", item.ID, body.Surface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	updated, err := h.opts.WorkItems.Transition(r.Context(), workitems.TransitionInput{
		Mutation: m, WorkItemID: item.ID, Action: body.Action, WaitingReason: body.WaitingReason,
		SupersededBy: body.SupersededBy, ExpectedStateVersion: body.ExpectedStateVersion,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	h.auditWorkItem(r, user, "work_item.transition", item.ID, item.Tenant, map[string]string{"action": body.Action, "state": updated.State})
	h.writeView(w, r, http.StatusOK, updated)
}

type intentBody struct {
	Text           string          `json:"text"`
	Params         json.RawMessage `json:"params,omitempty"`
	Surface        string          `json:"surface,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
}

// AppendWorkItemIntent handles POST /api/v1/work-items/{id}/intents.
func (h *Handlers) AppendWorkItemIntent(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body intentBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	m, ok := mutationFor(w, r, user, "intent", item.ID, body.Surface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	intent, created, err := h.opts.WorkItems.AppendIntent(r.Context(), workitems.IntentInput{
		Mutation: m, WorkItemID: item.ID, Text: body.Text, Params: body.Params,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	if created {
		h.auditWorkItem(r, user, "work_item.intent", item.ID, item.Tenant, map[string]string{"intent_id": strconv.FormatInt(intent.ID, 10)})
	}
	writeJSON(w, createdStatus(created), map[string]any{"schema_version": workitems.SchemaVersion, "intent": intent})
}

// ListWorkItemExecutions handles GET /api/v1/work-items/{id}/executions.
func (h *Handlers) ListWorkItemExecutions(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	execs, err := h.opts.WorkItems.Executions(r.Context(), item.ID)
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "executions": execs})
}

type executionBody struct {
	Engine         string `json:"engine"`
	EngineRef      string `json:"engine_ref"`
	Phase          string `json:"phase,omitempty"`
	Surface        string `json:"surface,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// AttachWorkItemExecution handles POST /api/v1/work-items/{id}/executions:
// attach an engine run, or correlate a later phase of one already attached.
func (h *Handlers) AttachWorkItemExecution(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body executionBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	if body.Phase == "" {
		body.Phase = workitems.PhasePending
	}
	m, ok := mutationFor(w, r, user, "execution", item.ID, body.Surface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	exec, created, err := h.opts.WorkItems.AttachExecution(r.Context(), workitems.ExecutionInput{
		Mutation: m, WorkItemID: item.ID, Engine: body.Engine, EngineRef: body.EngineRef, Phase: body.Phase,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	h.auditWorkItem(r, user, "work_item.execution", item.ID, item.Tenant,
		map[string]string{"execution_id": exec.ID, "engine": exec.Engine, "phase": exec.Phase})
	writeJSON(w, createdStatus(created), map[string]any{"schema_version": workitems.SchemaVersion, "execution": exec})
}

type resumeBody struct {
	ExpectedStateVersion   int64  `json:"expected_state_version"`
	ResumedFromExecutionID string `json:"resumed_from_execution_id,omitempty"`
	Engine                 string `json:"engine"`
	EngineRef              string `json:"engine_ref"`
	Surface                string `json:"surface,omitempty"`
	IdempotencyKey         string `json:"idempotency_key,omitempty"`
}

// ResumeWorkItem handles POST /api/v1/work-items/{id}/resume: start a new
// execution continuing a prior one; a waiting item becomes active.
func (h *Handlers) ResumeWorkItem(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body resumeBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	m, ok := mutationFor(w, r, user, "resume", item.ID, body.Surface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	updated, exec, created, err := h.opts.WorkItems.Resume(r.Context(), workitems.ResumeInput{
		Mutation: m, WorkItemID: item.ID, ExpectedStateVersion: body.ExpectedStateVersion,
		ResumedFromExecutionID: body.ResumedFromExecutionID, Engine: body.Engine, EngineRef: body.EngineRef,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	if created {
		h.auditWorkItem(r, user, "work_item.resume", item.ID, item.Tenant, map[string]string{"execution_id": exec.ID})
	}
	// Built from what Resume returned: the resume is committed, so a second
	// read here could only turn a success into an error.
	writeJSON(w, createdStatus(created), map[string]any{
		"schema_version": workitems.SchemaVersion, "work_item": updated, "state_version": updated.StateVersion,
		"execution": exec,
	})
}

type surfaceRefBody struct {
	Surface         string `json:"surface"`
	ExternalID      string `json:"external_id"`
	ActorExternalID string `json:"actor_external_id,omitempty"`
}

// LinkWorkItemSurface handles POST /api/v1/work-items/{id}/surface-refs.
// actor_external_id is correlation metadata for reply routing: it is stored
// as given and never used as, or resolved to, the acting principal.
func (h *Handlers) LinkWorkItemSurface(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body surfaceRefBody
	if !decodeWorkItemBody(w, r, &body) {
		return
	}
	if body.Surface == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "surface is required", nil)
		return
	}
	if r.Header.Get("Idempotency-Key") != "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid,
			"this route is idempotent by (surface, external_id); Idempotency-Key is not used", nil)
		return
	}
	m, ok := mutationFor(w, r, user, "surface_ref", item.ID, body.Surface, "", body)
	if !ok {
		return
	}
	ref, created, err := h.opts.WorkItems.LinkSurface(r.Context(), workitems.SurfaceRefInput{
		Mutation: m, WorkItemID: item.ID, ExternalID: body.ExternalID, ActorExternalID: body.ActorExternalID,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	if created {
		h.auditWorkItem(r, user, "work_item.surface_linked", item.ID, item.Tenant, map[string]string{"surface": ref.Surface})
	}
	writeJSON(w, createdStatus(created), map[string]any{"schema_version": workitems.SchemaVersion, "surface_ref": ref})
}

// ListWorkItemEvents handles GET /api/v1/work-items/{id}/events.
func (h *Handlers) ListWorkItemEvents(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	events, err := h.opts.WorkItems.Events(r.Context(), item.ID)
	if err != nil {
		writeWorkItemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "events": events})
}

// truncateRequestID bounds the correlation id copied into history. chi's
// RequestID middleware takes an inbound X-Request-Id verbatim, so a long or
// non-UTF-8 trace id from a proxy must shorten, never fail the write.
func truncateRequestID(id string) string {
	id = strings.ToValidUTF8(id, "")
	for len(id) > workitems.MaxExternalIDBytes {
		_, size := utf8.DecodeLastRuneInString(id)
		id = id[:len(id)-size]
	}
	return id
}
