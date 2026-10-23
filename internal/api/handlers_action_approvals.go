package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Action approval requests (mctl-api#366): the durable, single-use human
// approval of one hashed side effect of a runtime execution. mctl-api is the
// approval authority; a Temporal workflow only waits on it and re-reads it.
//
// Who may do what, always from authentication:
//   - create, consume and mark executed: a service principal acting
//     directly (never a relayed surface). requested_by is the authenticated
//     principal; consume and mark executed act on its own requests only.
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
	aarCodeNotConsumed         = "approval_not_consumed"
	aarCodeExecuted            = "approval_executed"
	aarCodeTargetMismatch      = "approval_target_mismatch"
	aarCodeRequesterForbidden  = "approval_requester_forbidden"
	aarCodeDeciderForbidden    = "approval_decider_forbidden"
	aarCodeReaderForbidden     = "approval_reader_forbidden"
	aarCodeExecutionInvalid    = "approval_execution_invalid"
	aarCodeExecutionNotOpen    = "approval_execution_not_open"

	// Decision context and revalidation (mctl-api#700).
	aarCodeContextIncomplete    = "approval_context_incomplete"
	aarCodeContextInvalid       = "approval_context_invalid"
	aarCodeContextChanged       = "approval_context_changed"
	aarCodeStale                = "approval_stale"
	aarCodeAuthorityRevoked     = "approval_authority_revoked"
	aarCodeDeciderDisabled      = "approval_decider_disabled"
	aarCodeAuthorityUnavailable = "approval_authority_unavailable"
	aarCodePolicyDrift          = "approval_policy_drift"

	// Hardening (mctl-api#721).
	aarCodePolicyUnregistered = "approval_policy_unregistered"
	aarCodePolicyUnavailable  = "approval_policy_unavailable"
)

// devLoopApprovalKind is the action kind of a DevLoop's human approval gate
// (mctl-api#571): the grant later exercised on mctl-agents-approve.
const devLoopApprovalKind = "mctl-agents-approve"

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
//
// reapproval marks a refusal no retry can cure: the approval can never be
// spent, and details.reapproval_required=true tells the caller to ask for a
// new one. Callers should key on that flag, not on the code text.
var actionApprovalRefusals = []struct {
	err        error
	status     int
	code       string
	reapproval bool
}{
	{workitems.ErrApprovalNotFound, http.StatusNotFound, aarCodeNotFound, false},
	{workitems.ErrApprovalIdempotencyConflict, http.StatusConflict, aarCodeIdempotencyConflict, false},
	{workitems.ErrApprovalIntentHash, http.StatusBadRequest, aarCodeIntentHashInvalid, false},
	{workitems.ErrApprovalAlreadyDecided, http.StatusConflict, aarCodeAlreadyDecided, false},
	{workitems.ErrApprovalSelfDecision, http.StatusForbidden, aarCodeSelfDecision, false},
	{workitems.ErrApprovalNotApproved, http.StatusConflict, aarCodeNotApproved, false},
	{workitems.ErrApprovalDenied, http.StatusConflict, aarCodeDenied, false},
	{workitems.ErrApprovalExpired, http.StatusConflict, aarCodeExpired, true},
	{workitems.ErrApprovalIntentMismatch, http.StatusConflict, aarCodeIntentMismatch, false},
	{workitems.ErrApprovalConsumed, http.StatusConflict, aarCodeConsumed, false},
	{governance.ErrSpendContextIncomplete, http.StatusConflict, aarCodeContextIncomplete, true},
	{governance.ErrContextIncomplete, http.StatusUnprocessableEntity, aarCodeContextIncomplete, false},
	{governance.ErrContextInvalid, http.StatusBadRequest, aarCodeContextInvalid, false},
	{governance.ErrContextChanged, http.StatusConflict, aarCodeContextChanged, true},
	{governance.ErrApprovalStale, http.StatusConflict, aarCodeStale, true},
	{governance.ErrAuthorityRevoked, http.StatusConflict, aarCodeAuthorityRevoked, true},
	{governance.ErrDeciderDisabled, http.StatusConflict, aarCodeDeciderDisabled, true},
	{governance.ErrAuthorityUnavailable, http.StatusServiceUnavailable, aarCodeAuthorityUnavailable, false},
	{governance.ErrPolicyDrift, http.StatusConflict, aarCodePolicyDrift, true},
	{errCreatePolicyUnregistered, http.StatusUnprocessableEntity, aarCodePolicyUnregistered, false},
	{governance.ErrPolicyUnregistered, http.StatusConflict, aarCodePolicyUnregistered, true},
	{governance.ErrPolicyUnavailable, http.StatusServiceUnavailable, aarCodePolicyUnavailable, false},
	{workitems.ErrApprovalNotConsumed, http.StatusConflict, aarCodeNotConsumed, false},
	{workitems.ErrApprovalExecuted, http.StatusConflict, aarCodeExecuted, false},
	{workitems.ErrApprovalTargetMismatch, http.StatusConflict, aarCodeTargetMismatch, false},
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
			var details map[string]interface{}
			if r.reapproval {
				details = map[string]interface{}{"reapproval_required": true}
			}
			var inc *incompleteContextError
			if errors.As(err, &inc) {
				details = map[string]interface{}{"missing_fields": inc.missing}
			}
			var spend *governance.SpendContextIncompleteError
			if errors.As(err, &spend) {
				details = map[string]interface{}{"missing_fields": spend.Missing, "reapproval_required": true}
			}
			writeErrorCode(w, r.status, r.code, msg, details)
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
func (h *Handlers) auditActionApproval(r *http.Request, user *auth.User, op string, a *workitems.ActionApprovalRequest, risk operations.RiskLevel, extra ...map[string]string) {
	// The classified risk beats the call site's default once the row has one.
	if stored := governance.RiskOf(h.opts.Registry, a.ActionKind, a.RiskLevel); stored != "" {
		risk = operations.RiskLevel(stored)
	}
	params := map[string]string{
		"approval_id":    a.ID,
		"execution_id":   a.ExecutionID,
		"action_kind":    a.ActionKind,
		"target":         a.Target,
		"policy_rule_id": a.PolicyRuleID,
		"intent_hash":    a.IntentHash,
		"state":          a.State,
		"requested_by":   a.RequestedBy,
		"actor":          principalOf(user),
	}
	if a.WorkItemID != "" {
		params["work_item_id"] = a.WorkItemID
	}
	// The bound artifact -- for a DevLoop approval the proposal content
	// digest (mctl-agents#681) -- so what was decided is answerable from the
	// audit alone.
	if a.ArtifactHash != "" {
		params["artifact_hash"] = a.ArtifactHash
	}
	if a.DecidedBy != "" {
		params["decided_by"] = a.DecidedBy
	}
	params["policy_version"] = a.PolicyVersion
	if a.AuthorityBasis != "" {
		params["authority_basis"] = a.AuthorityBasis
	}
	if a.DecidedContextDigest != "" {
		params["context_digest"] = a.DecidedContextDigest
	}
	if a.FreshUntil != nil {
		params["fresh_until"] = a.FreshUntil.Format(time.RFC3339)
	}
	for _, m := range extra {
		for k, v := range m {
			params[k] = v
		}
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "succeeded",
		RiskLevel:  string(risk),
	})
}

// auditActionApprovalRefusal records a refused decision, consume or
// execution mark: the
// signatures of a replay, an intent swap or a confused deputy. Ids and the
// typed code only, never the reason text or a presented hash.
func (h *Handlers) auditActionApprovalRefusal(r *http.Request, user *auth.User, op, id, code string, extra ...map[string]string) {
	params := map[string]string{
		"approval_id": id,
		"reason":      code,
		"actor":       principalOf(user),
	}
	for _, m := range extra {
		for k, v := range m {
			params[k] = v
		}
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "failed",
		RiskLevel:  string(operations.RiskMedium),
	})
}

// errCreatePolicyUnregistered is the create-side refusal of an unregistered
// policy rule in strict mode: a 422 the client can fix, unlike the spend-side
// refusal, which requires a new approval.
var errCreatePolicyUnregistered = errors.New("the policy rule is not registered")

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

	// Decision context (mctl-api#700). All optional: risk_level is derived
	// from the operation registry for a registered action_kind, and the rest
	// default from the registered policy and the intent.
	RiskLevel      string   `json:"risk_level,omitempty"`
	SideEffect     string   `json:"side_effect,omitempty"`
	IntentSource   string   `json:"intent_source,omitempty"`
	PolicyDecision string   `json:"policy_decision,omitempty"`
	PolicyReasons  []string `json:"policy_reasons,omitempty"`
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
		h.auditActionApprovalRefusal(r, user, "action_approval.create_refused", "", aarCodeRequesterForbidden)
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
	if body.ActionKind == devLoopApprovalKind && !h.requireOpenExecution(w, r, user, body.ExecutionID) {
		return
	}
	actor, subject := actorAndSubject(user)
	intent := workitems.ActionIntent{
		ExecutionID:   body.ExecutionID,
		ActionKind:    body.ActionKind,
		Target:        body.Target,
		ArgsDigest:    body.ArgsDigest,
		PolicyRuleID:  body.PolicyRuleID,
		PolicyVersion: body.PolicyVersion,
		ArtifactHash:  body.ArtifactHash,
		WorkItemID:    body.WorkItemID,
	}
	in := workitems.ActionApprovalInput{
		ActionIntent:   intent,
		RiskLevel:      body.RiskLevel,
		SideEffect:     body.SideEffect,
		IntentSource:   body.IntentSource,
		PolicyDecision: body.PolicyDecision,
		PolicyReasons:  body.PolicyReasons,
		RequestedBy:    principalOf(user),
		// Recorded only (mctl-api#373 phase 1).
		RequestedByPrincipalID: user.PrincipalID(),
		ViaPrincipalID:         user.ViaPrincipalID(),
		// The requester as actor and subject (mctl-api#376 D2). Only a
		// direct service may create today (isDirectService above), so the
		// subject and agent_run_id stay empty until an agent run token may
		// request an approval (#376 slice C): an empty subject here means
		// "no caller can produce one yet", not "checked and not delegated".
		ActorKind:      actor.Kind,
		ActorName:      actor.Name,
		AgentRunID:     user.AgentRunID(),
		IdempotencyKey: body.IdempotencyKey,
		ExpiresAt:      body.ExpiresAt,
		IntentHash:     body.IntentHash,
	}
	// Precedence (mctl-api#721): structural and secret validation (400)
	// before governance completeness (422).
	if err := in.ValidateStructure(); err != nil {
		writeActionApprovalError(w, err)
		return
	}
	cc, err := governance.FillCreateContext(governance.CreateContext{
		RiskLevel: body.RiskLevel, SideEffect: body.SideEffect, IntentSource: body.IntentSource,
		PolicyDecision: body.PolicyDecision, PolicyReasons: body.PolicyReasons,
	}, intent, h.opts.Registry, h.approvalPolicies())
	if err != nil {
		h.auditActionApprovalRefusal(r, user, "action_approval.create_refused", "", aarCodeContextInvalid)
		writeActionApprovalError(w, err)
		return
	}
	// Refused here, where the client can still supply what is missing:
	// created incomplete, the request would only fail later at approve.
	if missing := cc.Missing(); len(missing) > 0 {
		h.auditActionApprovalRefusal(r, user, "action_approval.create_refused", "", aarCodeContextIncomplete)
		writeActionApprovalError(w, &incompleteContextError{missing: missing})
		return
	}
	policyStatus, perr := h.approvalPolicies().Admit(intent.PolicyRuleID, intent.PolicyVersion, h.opts.RequireRegisteredPolicy)
	if perr != nil {
		code := actionApprovalRefusalCode(perr)
		if errors.Is(perr, governance.ErrPolicyUnregistered) {
			perr = fmt.Errorf("%w: %q", errCreatePolicyUnregistered, intent.PolicyRuleID)
			code = aarCodePolicyUnregistered
		}
		h.auditActionApprovalRefusal(r, user, "action_approval.create_refused", "", code,
			map[string]string{"policy_status": policyStatus})
		writeActionApprovalError(w, perr)
		return
	}
	in.RiskLevel, in.SideEffect, in.IntentSource = cc.RiskLevel, cc.SideEffect, cc.IntentSource
	in.PolicyDecision, in.PolicyReasons = cc.PolicyDecision, cc.PolicyReasons
	if subject != nil {
		in.SubjectPrincipalID = subject.PrincipalID
		in.SubjectKind = subject.Kind
	}
	a, created, err := h.opts.WorkItems.CreateActionApproval(r.Context(), in)
	if err != nil {
		writeActionApprovalError(w, err)
		return
	}
	if created {
		h.auditActionApproval(r, user, "action_approval.create", a, operations.RiskLow,
			map[string]string{"policy_status": policyStatus})
	}
	h.writeApproval(w, createdStatus(created), a)
}

// requireOpenExecution admits a DevLoop approval only for an existing,
// non-terminal we_ execution (mctl-api#571 R2): the grant is bound to that
// execution later, so a free-form workflow id or a finished run would make
// a grant nothing can legitimately exercise. A failed read is a 503, never
// "no such execution".
func (h *Handlers) requireOpenExecution(w http.ResponseWriter, r *http.Request, user *auth.User, executionID string) bool {
	refuse := func(status int, code, msg string) bool {
		h.auditActionApprovalRefusal(r, user, "action_approval.create_refused", "", code)
		writeErrorCode(w, status, code, msg, nil)
		return false
	}
	exec, err := h.opts.WorkItems.ExecutionByID(r.Context(), executionID)
	switch {
	case errors.Is(err, workitems.ErrNotFound):
		return refuse(http.StatusBadRequest, aarCodeExecutionInvalid,
			"a "+devLoopApprovalKind+" approval must name an existing "+workitems.ExecutionIDPrefix+" execution")
	case err != nil:
		slog.Error("action approval: execution lookup failed", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "execution lookup failed", nil)
		return false
	case workitems.IsTerminalPhase(exec.Phase):
		return refuse(http.StatusConflict, aarCodeExecutionNotOpen, "execution "+exec.ID+" has finished ("+exec.Phase+")")
	}
	return true
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
	h.writeApproval(w, http.StatusOK, a)
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
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "state must be one of pending, approved, denied, consumed, executed, expired", nil)
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
	out := make([]approvalWithContext, len(list))
	for i := range list {
		out[i] = approvalWithContext{ActionApprovalRequest: &list[i], DecisionContext: h.decisionContext(&list[i])}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.ActionApprovalSchemaVersion, "approvals": out})
}

type actionDecisionBody struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	// ContextDigest, when sent, must equal the digest of the decision context
	// as it stands now (GET decision_context.context_digest): it proves the
	// reviewer approved what they were shown (mctl-api#700).
	ContextDigest string `json:"context_digest,omitempty"`
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
	// Precedence (mctl-api#721): a malformed decision is a 400 before any
	// governance refusal.
	if err := workitems.ValidateDecisionInput(body.Decision, body.Reason); err != nil {
		writeActionApprovalError(w, err)
		return
	}
	cur, err := h.opts.WorkItems.ActionApproval(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		// The pre-read refuses what the decide itself used to: audit it the
		// same way, so an unknown id still leaves a decision_refused entry.
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", chi.URLParam(r, "id"), code)
		}
		writeActionApprovalError(w, err)
		return
	}
	// The completeness gate applies only to a decision that could succeed;
	// terminal-state and self-decision refusals keep precedence.
	digest := ""
	if cur.State == workitems.ApprovalPending && cur.RequestedBy != principalOf(user) {
		var ok bool
		digest, ok = h.guardDecision(w, r, user, cur, body.Decision, body.ContextDigest)
		if !ok {
			return
		}
	}
	a, err := h.opts.WorkItems.DecideActionApproval(r.Context(), h.decisionCapture(workitems.ActionDecisionInput{
		ID: cur.ID, DecidedBy: principalOf(user), Decision: body.Decision, Reason: body.Reason,
		DecidedByPrincipalID: user.PrincipalID(), DecidedViaPrincipalID: user.ViaPrincipalID(),
	}, digest))
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", chi.URLParam(r, "id"), code)
		}
		writeActionApprovalError(w, err)
		return
	}
	h.auditActionApproval(r, user, "action_approval.decision", a, operations.RiskMedium,
		map[string]string{"policy_status": h.policyStatusOf(a)})
	h.writeApproval(w, http.StatusOK, a)
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
	// The state refusal comes first: a pending or spent request is not an
	// authority question, and answering one as approval_authority_revoked
	// (reapproval_required) would make a caller discard a live request.
	if err := workitems.ConsumeStateRefusal(cur); err != nil {
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", cur.ID, actionApprovalRefusalCode(err))
		writeActionApprovalError(w, err)
		return
	}
	reval, ok := h.revalidateApproval(w, r, user, cur)
	if !ok {
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
	h.auditActionApproval(r, user, "action_approval.consume", a, operations.RiskMedium,
		map[string]string{"revalidation": reval.Revalidation, "policy_status": reval.PolicyStatus})
	h.writeApproval(w, http.StatusOK, a)
}

type actionExecuteBody struct {
	Target       string `json:"target"`
	ArtifactHash string `json:"artifact_hash"`
}

// MarkActionApprovalExecuted handles
// POST /api/v1/action-approvals/{id}/execute: mark a consumed request
// executed exactly once, for exactly its bound target and artifact. Only
// the requesting service, on its own request, as for consume.
func (h *Handlers) MarkActionApprovalExecuted(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if !isDirectService(user) {
		h.auditActionApprovalRefusal(r, user, "action_approval.execute_refused", chi.URLParam(r, "id"), aarCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, aarCodeRequesterForbidden,
			"only the requesting service may mark an action approval executed", nil)
		return
	}
	// Only the requester's own request: another's answers 404.
	cur, ok := h.visibleActionApproval(w, r, user)
	if !ok {
		return
	}
	var body actionExecuteBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxActionApprovalBodyBytes) {
		return
	}
	if body.Target == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "target is required", nil)
		return
	}
	// Any non-empty value: the store compares it with the stored hash,
	// which must itself be non-empty, and bounds its length.
	if body.ArtifactHash == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "artifact_hash is required", nil)
		return
	}
	a, err := h.opts.WorkItems.MarkActionApprovalExecuted(r.Context(), cur.ID, body.Target, body.ArtifactHash, principalOf(user))
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.execute_refused", cur.ID, code)
		}
		writeActionApprovalError(w, err)
		return
	}
	h.auditActionApproval(r, user, "action_approval.execute", a, operations.RiskMedium)
	h.writeApproval(w, http.StatusOK, a)
}
