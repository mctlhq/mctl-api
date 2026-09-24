package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Action approval requests (mctl-api#366): the durable, single-use human
// approval of one hashed side effect of a runtime execution. mctl-api is the
// approval authority; a Temporal workflow only waits on it and re-reads it.
//
// Who may do what, always from authentication:
//   - create and consume: a service principal acting directly (never a
//     relayed surface). requested_by is the authenticated principal.
//   - decide: a human admin acting directly: never a service principal,
//     never a relayed surface, never the requester of the request.
//   - read: a human admin reads every request; a service principal reads
//     the requests it made. Anyone else is refused. A request the caller may
//     not read answers 404, so its existence does not leak.

// maxActionApprovalBodyBytes bounds a request body: the bound fields are at
// most a few KiB together.
const maxActionApprovalBodyBytes = 16 << 10

// Typed error codes a client can branch on.
const (
	aarCodeNotFound            = "approval_not_found"
	aarCodeIdempotencyConflict = "approval_idempotency_conflict"
	aarCodeIntentHashInvalid   = "intent_hash_mismatch"
	aarCodeAlreadyDecided      = "approval_already_decided"
	aarCodeSelfDecision        = "approval_self_decision"
	aarCodeNotApproved         = "approval_not_approved"
	aarCodeDenied              = "approval_denied"
	aarCodeExpired             = "approval_expired"
	aarCodeIntentMismatch      = "approval_intent_mismatch"
	aarCodeConsumed            = "approval_consumed"
	aarCodeRequesterForbidden  = "approval_requester_forbidden"
	aarCodeDeciderForbidden    = "approval_decider_forbidden"
	aarCodeReaderForbidden     = "approval_reader_forbidden"
)

// isDirectService is the service principal acting for itself.
func isDirectService(u *auth.User) bool {
	_, relayed := u.RelaySurface()
	return u.IsService() && !relayed
}

// isHumanAdmin is an admin person acting directly. The service principal
// carries the admins group, so IsAdmin alone would let it decide.
func isHumanAdmin(u *auth.User) bool {
	_, relayed := u.RelaySurface()
	_, surface := u.Surface()
	return u.IsAdmin() && !u.IsService() && !relayed && !surface
}

// canSeeActionApproval: a human admin sees every request, the requesting
// service its own.
func canSeeActionApproval(u *auth.User, a *workitems.ActionApprovalRequest) bool {
	if isHumanAdmin(u) {
		return true
	}
	return isDirectService(u) && a.RequestedBy == principalOf(u)
}

// actionApprovalRefusals maps each store refusal to its status and typed
// code, in match order.
var actionApprovalRefusals = []struct {
	err    error
	status int
	code   string
}{
	{workitems.ErrApprovalNotFound, http.StatusNotFound, aarCodeNotFound},
	{workitems.ErrApprovalIdempotencyConflict, http.StatusConflict, aarCodeIdempotencyConflict},
	{workitems.ErrApprovalIntentHash, http.StatusBadRequest, aarCodeIntentHashInvalid},
	{workitems.ErrApprovalAlreadyDecided, http.StatusConflict, aarCodeAlreadyDecided},
	{workitems.ErrApprovalSelfDecision, http.StatusForbidden, aarCodeSelfDecision},
	{workitems.ErrApprovalNotApproved, http.StatusConflict, aarCodeNotApproved},
	{workitems.ErrApprovalDenied, http.StatusConflict, aarCodeDenied},
	{workitems.ErrApprovalExpired, http.StatusConflict, aarCodeExpired},
	{workitems.ErrApprovalIntentMismatch, http.StatusConflict, aarCodeIntentMismatch},
	{workitems.ErrApprovalConsumed, http.StatusConflict, aarCodeConsumed},
}

// actionApprovalRefusalCode is the typed code of a store refusal, or "" for
// any other error.
func actionApprovalRefusalCode(err error) string {
	for _, r := range actionApprovalRefusals {
		if errors.Is(err, r.err) {
			return r.code
		}
	}
	return ""
}

func writeActionApprovalError(w http.ResponseWriter, err error) {
	for _, r := range actionApprovalRefusals {
		if errors.Is(err, r.err) {
			msg := err.Error()
			if r.code == aarCodeNotFound {
				msg = "action approval request not found"
			}
			writeErrorCode(w, r.status, r.code, msg, nil)
			return
		}
	}
	writeWorkItemError(w, err)
}

// visibleActionApproval loads {id} and answers 404 unless the caller may
// read it.
func (h *Handlers) visibleActionApproval(w http.ResponseWriter, r *http.Request, user *auth.User) (*workitems.ActionApprovalRequest, bool) {
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), chi.URLParam(r, "id"))
	if err == nil && !canSeeActionApproval(user, a) {
		err = workitems.ErrApprovalNotFound
	}
	if err != nil {
		writeActionApprovalError(w, err)
		return nil, false
	}
	return a, true
}

// auditActionApproval records ids, hashes and the decision: never args or
// the reason text.
func (h *Handlers) auditActionApproval(r *http.Request, user *auth.User, op string, a *workitems.ActionApprovalRequest, risk operations.RiskLevel) {
	params := map[string]string{
		"approval_id":    a.ID,
		"execution_id":   a.ExecutionID,
		"action_kind":    a.ActionKind,
		"policy_rule_id": a.PolicyRuleID,
		"intent_hash":    a.IntentHash,
		"state":          a.State,
		"requested_by":   a.RequestedBy,
		"actor":          principalOf(user),
	}
	if a.WorkItemID != "" {
		params["work_item_id"] = a.WorkItemID
	}
	if a.DecidedBy != "" {
		params["decided_by"] = a.DecidedBy
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "succeeded",
		RiskLevel:  string(risk),
	})
}

// auditActionApprovalRefusal records a refused decision or consume: the
// signatures of a replay, an intent swap or a confused deputy. Ids and the
// typed code only, never the reason text or a presented hash.
func (h *Handlers) auditActionApprovalRefusal(r *http.Request, user *auth.User, op, id, code string) {
	h.logAudit(r, audit.Entry{
		UserID:    user.ID,
		Operation: op,
		Parameters: map[string]string{
			"approval_id": id,
			"reason":      code,
			"actor":       principalOf(user),
		},
		Status:    "failed",
		RiskLevel: string(operations.RiskMedium),
	})
}

func writeActionApproval(w http.ResponseWriter, status int, a *workitems.ActionApprovalRequest) {
	writeJSON(w, status, map[string]any{"schema_version": workitems.ActionApprovalSchemaVersion, "approval": a})
}

type actionApprovalBody struct {
	ExecutionID    string    `json:"execution_id"`
	ActionKind     string    `json:"action_kind"`
	Target         string    `json:"target"`
	ArgsDigest     string    `json:"args_digest"`
	PolicyRuleID   string    `json:"policy_rule_id"`
	PolicyVersion  string    `json:"policy_version"`
	ArtifactHash   string    `json:"artifact_hash,omitempty"`
	WorkItemID     string    `json:"work_item_id,omitempty"`
	IdempotencyKey string    `json:"idempotency_key,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	IntentHash     string    `json:"intent_hash,omitempty"`
}

// CreateActionApproval handles POST /api/v1/action-approvals. 201 stores a
// new pending request; 200 returns the one this requester's idempotency key
// already names with the same intent; 409 approval_idempotency_conflict
// refuses the same key with a different intent.
func (h *Handlers) CreateActionApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if !isDirectService(user) {
		writeErrorCode(w, http.StatusForbidden, aarCodeRequesterForbidden,
			"only a service principal acting directly may request an action approval", nil)
		return
	}
	var body actionApprovalBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxActionApprovalBodyBytes) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	switch {
	case body.IdempotencyKey == "":
		body.IdempotencyKey = key
	case key != "" && key != body.IdempotencyKey:
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "Idempotency-Key header and idempotency_key differ", nil)
		return
	}
	a, created, err := h.opts.WorkItems.CreateActionApproval(r.Context(), workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID:   body.ExecutionID,
			ActionKind:    body.ActionKind,
			Target:        body.Target,
			ArgsDigest:    body.ArgsDigest,
			PolicyRuleID:  body.PolicyRuleID,
			PolicyVersion: body.PolicyVersion,
			ArtifactHash:  body.ArtifactHash,
			WorkItemID:    body.WorkItemID,
		},
		RequestedBy: principalOf(user),
		// Recorded only (mctl-api#373 phase 1).
		RequestedByPrincipalID: user.PrincipalID(),
		ViaPrincipalID:         user.ViaPrincipalID(),
		IdempotencyKey:         body.IdempotencyKey,
		ExpiresAt:              body.ExpiresAt,
		IntentHash:             body.IntentHash,
	})
	if err != nil {
		writeActionApprovalError(w, err)
		return
	}
	if created {
		h.auditActionApproval(r, user, "action_approval.create", a, operations.RiskLow)
	}
	writeActionApproval(w, createdStatus(created), a)
}

// GetActionApproval handles GET /api/v1/action-approvals/{id}. The state is
// the effective one: a pending or approved request past expires_at reads as
// expired.
func (h *Handlers) GetActionApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if !isHumanAdmin(user) && !isDirectService(user) {
		writeErrorCode(w, http.StatusForbidden, aarCodeReaderForbidden, "action approvals are read by admins and the requesting service", nil)
		return
	}
	a, ok := h.visibleActionApproval(w, r, user)
	if !ok {
		return
	}
	writeActionApproval(w, http.StatusOK, a)
}

// ListActionApprovals handles
// GET /api/v1/action-approvals?state=&execution_id=&limit=, newest first.
func (h *Handlers) ListActionApprovals(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	f := workitems.ActionApprovalFilter{}
	switch {
	case isHumanAdmin(user):
	case isDirectService(user):
		f.RequestedBy = principalOf(user)
	default:
		writeErrorCode(w, http.StatusForbidden, aarCodeReaderForbidden, "action approvals are read by admins and the requesting service", nil)
		return
	}
	q := r.URL.Query()
	f.State, f.ExecutionID = q.Get("state"), q.Get("execution_id")
	if f.State != "" && !workitems.ValidApprovalState(f.State) {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "state must be one of pending, approved, denied, consumed, expired", nil)
		return
	}
	if limit := q.Get("limit"); limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil || n <= 0 || n > workitems.MaxApprovalList {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "limit must be an integer from 1 to 500", nil)
			return
		}
		f.Limit = n
	}
	list, err := h.opts.WorkItems.ActionApprovals(r.Context(), f)
	if err != nil {
		writeActionApprovalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.ActionApprovalSchemaVersion, "approvals": list})
}

type actionDecisionBody struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// DecideActionApproval handles POST /api/v1/action-approvals/{id}/decision.
// Only a human admin acting directly decides, never the requester, and only
// a pending, unexpired request.
func (h *Handlers) DecideActionApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if !isHumanAdmin(user) {
		h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", chi.URLParam(r, "id"), aarCodeDeciderForbidden)
		writeErrorCode(w, http.StatusForbidden, aarCodeDeciderForbidden,
			"only a human admin acting directly may decide an action approval", nil)
		return
	}
	var body actionDecisionBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxActionApprovalBodyBytes) {
		return
	}
	a, err := h.opts.WorkItems.DecideActionApproval(r.Context(), workitems.ActionDecisionInput{
		ID: chi.URLParam(r, "id"), DecidedBy: principalOf(user), Decision: body.Decision, Reason: body.Reason,
		DecidedByPrincipalID: user.PrincipalID(), DecidedViaPrincipalID: user.ViaPrincipalID(),
	})
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", chi.URLParam(r, "id"), code)
		}
		writeActionApprovalError(w, err)
		return
	}
	h.auditActionApproval(r, user, "action_approval.decision", a, operations.RiskMedium)
	writeActionApproval(w, http.StatusOK, a)
}

type actionConsumeBody struct {
	IntentHash string `json:"intent_hash"`
}

// ConsumeActionApproval handles POST /api/v1/action-approvals/{id}/consume:
// spend an approved request exactly once, for exactly the approved intent.
func (h *Handlers) ConsumeActionApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if !isDirectService(user) {
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", chi.URLParam(r, "id"), aarCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, aarCodeRequesterForbidden,
			"only the requesting service may consume an action approval", nil)
		return
	}
	// Only the requester's own request: another's answers 404.
	cur, ok := h.visibleActionApproval(w, r, user)
	if !ok {
		return
	}
	var body actionConsumeBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxActionApprovalBodyBytes) {
		return
	}
	a, err := h.opts.WorkItems.ConsumeActionApproval(r.Context(), cur.ID, body.IntentHash)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", cur.ID, code)
		}
		writeActionApprovalError(w, err)
		return
	}
	h.auditActionApproval(r, user, "action_approval.consume", a, operations.RiskMedium)
	writeActionApproval(w, http.StatusOK, a)
}
