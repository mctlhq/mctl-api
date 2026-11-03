package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Owner actions on a DevLoop (mctl-api#900, Slice 2): request changes, defer
// and request cancel. None of them decides an aar_ grant -- approve and deny
// remain the only decisions -- and cancel stops future work, never rolls
// anything back. docs/decision-context-contract.md has the contract.

const (
	ownerActionCodeForbidden           = "owner_action_forbidden"
	ownerActionCodeIdempotencyConflict = "owner_action_idempotency_conflict"
	ownerActionCodeRunChanged          = "cancellation_run_changed"
	ownerActionCodeNotFound            = "owner_action_not_found"
)

// Outcomes of an owner action.
const (
	ownerOutcomeChangesRequested = "changes_requested"
	ownerOutcomeDeferred         = "deferred"
	// ownerOutcomeCancellationPending: abandon signalled, nothing known to
	// have been produced yet.
	ownerOutcomeCancellationPending = "cancellation_pending"
	// ownerOutcomeCancelled: the run is known stopped before implement.
	ownerOutcomeCancelled = "cancelled"
	// ownerOutcomeEffectsUnknown: the implement step may already have
	// produced effects that cannot be observed from here.
	ownerOutcomeEffectsUnknown = "cancellation_effects_unknown"
	ownerOutcomeAlreadyDone    = "already_finished"
)

const maxOwnerActionIdempotencyKeyBytes = 128

var ownerReasonCodeRE = regexp.MustCompile(`^[a-z0-9._:-]{1,64}$`)

// ownerActionRequest is the whole body: no free text.
type ownerActionRequest struct {
	Action         string           `json:"action"`
	IdempotencyKey string           `json:"idempotency_key"`
	Binding        *decisionBinding `json:"binding,omitempty"`
	ExpectedRunID  string           `json:"expected_run_id,omitempty"`
	ReasonCode     string           `json:"reason_code,omitempty"`
}

// validate returns the 400 message of a malformed body, or "".
func (b *ownerActionRequest) validate() string {
	switch b.Action {
	case workitems.OwnerActionRequestChanges, workitems.OwnerActionDefer, workitems.OwnerActionRequestCancel:
	default:
		return "action must be one of request_changes, defer, request_cancel"
	}
	if b.IdempotencyKey == "" || len(b.IdempotencyKey) > maxOwnerActionIdempotencyKeyBytes {
		return fmt.Sprintf("idempotency_key is required and at most %d bytes", maxOwnerActionIdempotencyKeyBytes)
	}
	if b.ReasonCode != "" && !ownerReasonCodeRE.MatchString(b.ReasonCode) {
		return "reason_code must match ^[a-z0-9._:-]{1,64}$"
	}
	if b.ExpectedRunID != "" {
		if b.Action != workitems.OwnerActionRequestCancel {
			return "expected_run_id applies to request_cancel only"
		}
		if !wellFormedBindingValue(b.ExpectedRunID) {
			return "expected_run_id is malformed"
		}
	}
	return ""
}

// contentDigest covers everything the caller chose, so a reused idempotency
// key with other content is told apart from a retry.
func (b *ownerActionRequest) contentDigest(workflowID string) string {
	canon, _ := json.Marshal(struct {
		Action        string           `json:"action"`
		WorkflowID    string           `json:"workflow_id"`
		Binding       *decisionBinding `json:"binding"`
		ExpectedRunID string           `json:"expected_run_id"`
		ReasonCode    string           `json:"reason_code"`
	}{b.Action, workflowID, b.Binding, b.ExpectedRunID, b.ReasonCode})
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ownerActionView is the response and audit shape: ids, codes and states.
func ownerActionView(o *workitems.OwnerAction, replayed bool) map[string]any {
	v := map[string]any{
		"id":          o.ID,
		"workflow_id": o.WorkflowID,
		"action":      o.Action,
		"state":       o.State,
		"outcome":     o.Outcome,
		"replayed":    replayed,
		"created_at":  o.CreatedAt,
		"updated_at":  o.UpdatedAt,
	}
	for k, s := range map[string]string{
		"run_id": o.RunID, "execution_id": o.ExecutionID, "approval_ref": o.ApprovalRef, "reason_code": o.ReasonCode,
	} {
		if s != "" {
			v[k] = s
		}
	}
	return v
}

func ownerActionAuditParams(o *workitems.OwnerAction, replayed bool) map[string]string {
	return map[string]string{
		"owner_action_id": o.ID, "action": o.Action, "workflow_id": o.WorkflowID, "run_id": o.RunID,
		"execution_id": o.ExecutionID, "approval_ref": o.ApprovalRef, "reason_code": o.ReasonCode,
		"outcome": o.Outcome, "replayed": fmt.Sprint(replayed),
	}
}

// ownerCancelSignalledOutcome is what a delivered abandon signal means. Only
// a grant that is pending or absent proves implement has not started; any
// other state may already have produced effects.
func ownerCancelSignalledOutcome(grant *workitems.ActionApprovalRequest) string {
	if grant == nil || grant.State == workitems.ApprovalPending {
		return ownerOutcomeCancellationPending
	}
	return ownerOutcomeEffectsUnknown
}

// ownerCancelFinishedOutcome reads how a run that is no longer running ended.
// status is the run's described status, or "" when it is not known (a stored
// run that a newer run has replaced). Anything unreadable is "effects
// unknown", never "stopped".
func (h *Handlers) ownerCancelFinishedOutcome(ctx context.Context, workflowID, runID, status string) string {
	if status != "" && status != devLoopStatusCompleted {
		// Failed, terminated, cancelled or timed out: no abandon result.
		return ownerOutcomeAlreadyDone
	}
	rctx, cancel := context.WithTimeout(ctx, devLoopResultReadTimeout)
	defer cancel()
	end, err := h.opts.TemporalClient.DevLoopEnded(rctx, workflowID, runID)
	switch {
	case err != nil:
		slog.Warn("owner cancel: could not read how the run ended", "workflow_id", workflowID, "run_id", runID, "error", err)
		return ownerOutcomeEffectsUnknown
	case !strings.HasPrefix(end.Ended, temporalclient.AbandonedEndedPrefix):
		return ownerOutcomeAlreadyDone
	case end.Implemented:
		return ownerOutcomeEffectsUnknown
	}
	return ownerOutcomeCancelled
}

// ownerActionBindingDigest is the context digest the grant's current state
// answers a binding with: the one recorded at decision when it has one,
// otherwise the live one.
func (h *Handlers) ownerActionBindingDigest(g *workitems.ActionApprovalRequest) string {
	if g.DecidedContextDigest != "" {
		return g.DecidedContextDigest
	}
	return h.decisionContext(g).ContextDigest
}

// RequestDevLoopOwnerAction handles
// POST /api/v1/agents/dev-loop/{workflow_id}/owner-actions.
func (h *Handlers) RequestDevLoopOwnerAction(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireTemporalAdmin(w, r)
	if !ok {
		return
	}
	workflowID := chi.URLParam(r, "workflow_id")
	// The direct-human check precedes every grant or run lookup, so the
	// absence of a grant never weakens who may act.
	if !isHumanAdmin(user) {
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-owner-action",
			WorkflowName: workflowID,
			Status:       "denied",
			RiskLevel:    string(operations.RiskMedium),
			Message:      ownerActionCodeForbidden + ": not a human admin acting directly",
		})
		writeErrorCode(w, http.StatusForbidden, ownerActionCodeForbidden,
			"owner actions on a DevLoop are admin-only and must be taken by a human acting directly", nil)
		return
	}
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "the work-item store is not configured", nil)
		return
	}
	if !refuseIdentityFields(w, r, maxExecutionRequestBodyBytes) {
		return
	}
	var body ownerActionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest,
			"invalid JSON: "+err.Error()+" (the body carries action, idempotency_key, binding, expected_run_id and reason_code; no free text)")
		return
	}
	if msg := body.validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	baseParams := map[string]string{"action": body.Action, "workflow_id": workflowID, "reason_code": body.ReasonCode}
	refuse := func(status int, code, msg string, details map[string]interface{}) {
		params := map[string]string{"reason": code}
		for k, v := range baseParams {
			params[k] = v
		}
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-owner-action",
			Parameters:   params,
			WorkflowName: workflowID,
			Status:       "failed",
			RiskLevel:    string(operations.RiskMedium),
			Message:      code,
		})
		writeErrorCode(w, status, code, msg, details)
	}

	ctx := r.Context()
	exec, grant, err := h.resolveDevLoopGrant(ctx, workflowID)
	var ambiguous *executionAmbiguousError
	switch {
	case errors.As(err, &ambiguous):
		refuse(http.StatusConflict, devLoopCodeExecutionAmbiguous,
			fmt.Sprintf("%d open work-item executions are attached for this workflow; resolve them first", ambiguous.count), nil)
		return
	case err != nil:
		slog.Error("dev-loop owner action: grant lookup failed", "workflow_id", workflowID, "error", err)
		refuse(http.StatusServiceUnavailable, wiCodeUnavailable, "could not read the DevLoop's approval grant", nil)
		return
	}
	if exec != nil {
		baseParams["execution_id"] = exec.ID
	}
	if grant != nil {
		baseParams["approval_ref"] = grant.ID
	}

	// The binding rules of the Slice 1 decision, applied before any write or
	// signal. A pre-grant cancel has nothing to bind to and is bound to the
	// run instead; request_changes and defer never get that exception.
	cancel := body.Action == workitems.OwnerActionRequestCancel
	if grant == nil && !cancel {
		refuse(http.StatusConflict, devLoopCodeGrantMissing, "the DevLoop has no "+devLoopApprovalKind+" approval to act on", nil)
		return
	}
	if grant == nil && body.Binding != nil {
		refuse(http.StatusConflict, devLoopCodeGrantMissing,
			"the action names "+body.Binding.ApprovalRef+" and there is no grant to bind it to", nil)
		return
	}
	if grant != nil {
		if missing := h.bindingGate(r, user, bindingRouteDevLoopOwnerAction, workflowID, body.Binding); missing != nil {
			h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", workflowID, aarCodeBindingMissing)
			writeActionApprovalError(w, &bindingMissingError{missing: missing})
			return
		}
		if body.Binding != nil && body.Binding.ApprovalRef != grant.ID {
			refuse(http.StatusConflict, aarCodeContextChanged, governance.ErrContextChanged.Error(),
				map[string]interface{}{"current_approval_ref": grant.ID, "reapproval_required": true})
			return
		}
	}
	if !cancel && grant.State != workitems.ApprovalPending {
		code := aarCodeNotApproved
		if grant.State == workitems.ApprovalApproved {
			code = aarCodeAlreadyDecided
		} else if c, ok := closedApprovalCodes[grant.State]; ok {
			code = c
		}
		refuse(http.StatusConflict, code, "the DevLoop's approval "+grant.ID+" is "+grant.State, nil)
		return
	}
	if grant != nil && body.Binding != nil && !bindingMatches(body.Binding, grant, h.ownerActionBindingDigest(grant)) {
		refuse(http.StatusConflict, aarCodeContextChanged, governance.ErrContextChanged.Error(),
			map[string]interface{}{"current_approval_ref": grant.ID, "reapproval_required": true})
		return
	}

	in := workitems.OwnerActionInput{
		WorkflowID: workflowID, Action: body.Action, ReasonCode: body.ReasonCode,
		RequestedBy: principalOf(user), PrincipalID: user.PrincipalID(),
		IdempotencyKey: body.IdempotencyKey, ContentDigest: body.contentDigest(workflowID),
	}
	if exec != nil {
		in.ExecutionID = exec.ID
	}
	if grant != nil {
		in.ApprovalRef = grant.ID
	}

	if !cancel {
		in.State = workitems.OwnerActionRecorded
		in.Outcome = ownerOutcomeChangesRequested
		if body.Action == workitems.OwnerActionDefer {
			in.Outcome = ownerOutcomeDeferred
		}
		row, replayed, err := h.opts.WorkItems.CreateOwnerAction(ctx, in)
		if err != nil {
			h.writeOwnerActionStoreError(w, refuse, err)
			return
		}
		h.finishOwnerAction(w, r, user, row, replayed)
		return
	}

	// request_cancel: bound to the exact run the server describes.
	described, fail := h.describeDevLoopRun(ctx, workflowID, "workflow not found")
	if fail != nil {
		refuse(fail.Status, "cancellation_describe_failed", fail.Client, nil)
		return
	}
	if body.ExpectedRunID != "" && body.ExpectedRunID != described.RunID {
		refuse(http.StatusConflict, ownerActionCodeRunChanged,
			"the run the card was rendered for ("+body.ExpectedRunID+") is not the current run ("+described.RunID+"); nothing was cancelled",
			map[string]interface{}{"current_run_id": described.RunID})
		return
	}
	in.RunID = described.RunID
	in.State = workitems.OwnerActionRequested
	row, replayed, err := h.opts.WorkItems.CreateOwnerAction(ctx, in)
	if err != nil {
		h.writeOwnerActionStoreError(w, refuse, err)
		return
	}
	if row.State != workitems.OwnerActionRequested {
		// Already signalled or finished: return it, signal nothing.
		h.finishOwnerAction(w, r, user, row, replayed)
		return
	}

	// A new row, or a replay whose signal never landed: (re)try against the
	// stored run only, never against whatever run holds the id now.
	var outcome, toState string
	if row.RunID != described.RunID {
		outcome, toState = h.ownerCancelFinishedOutcome(ctx, workflowID, row.RunID, ""), workitems.OwnerActionFinished
	} else {
		payload := map[string]string{"reason": "owner_action:" + row.ID, "abandoned_by": user.ID}
		if row.ReasonCode != "" {
			payload["reason"] += ":" + row.ReasonCode
		}
		res := h.abandonDevLoopRun(ctx, workflowID, payload, described)
		switch {
		case res.Fail != nil:
			status, code := res.Fail.Status, "cancellation_failed"
			switch {
			case res.Outcome == devLoopOutcomeRunChanged:
				code = ownerActionCodeRunChanged
			case errors.Is(res.Fail.Err, temporalclient.ErrUnavailable):
				status = http.StatusServiceUnavailable
			case status == http.StatusNotFound:
				code = "workflow_not_found"
			}
			// The row stays requested with no outcome: a replay with the same
			// key retries against the stored run.
			refuse(status, code, res.Fail.Client, nil)
			return
		case res.Outcome == devLoopOutcomeSignalled:
			outcome, toState = ownerCancelSignalledOutcome(grant), workitems.OwnerActionSignalled
		default:
			outcome, toState = h.ownerCancelFinishedOutcome(ctx, workflowID, res.Exec.RunID, res.Exec.Status), workitems.OwnerActionFinished
		}
	}
	marked, err := h.opts.WorkItems.MarkOwnerActionOutcome(ctx, row.ID, workitems.OwnerActionRequested, toState, outcome)
	if errors.Is(err, workitems.ErrOwnerActionStateChanged) {
		// A concurrent replay moved it first; report what it recorded.
		marked, err = h.opts.WorkItems.GetOwnerAction(ctx, row.ID)
	}
	if err != nil {
		slog.Error("dev-loop owner action: record outcome failed", "owner_action_id", row.ID, "error", err)
		refuse(http.StatusServiceUnavailable, wiCodeUnavailable, "could not record the cancellation outcome", nil)
		return
	}
	h.finishOwnerAction(w, r, user, marked, replayed)
}

func (h *Handlers) writeOwnerActionStoreError(w http.ResponseWriter, refuse func(int, string, string, map[string]interface{}), err error) {
	if errors.Is(err, workitems.ErrOwnerActionIdempotencyConflict) {
		refuse(http.StatusConflict, ownerActionCodeIdempotencyConflict,
			"the idempotency_key was already used with different content", nil)
		return
	}
	slog.Error("dev-loop owner action: store failed", "error", err)
	refuse(http.StatusServiceUnavailable, wiCodeUnavailable, "could not record the owner action", nil)
}

// finishOwnerAction audits and answers a successful owner action. It never
// writes an action_approval.decision entry: nothing was decided.
func (h *Handlers) finishOwnerAction(w http.ResponseWriter, r *http.Request, user *auth.User, row *workitems.OwnerAction, replayed bool) {
	h.logAudit(r, audit.Entry{
		UserID:       user.ID,
		Operation:    "dev-loop-owner-action",
		Parameters:   ownerActionAuditParams(row, replayed),
		WorkflowName: row.WorkflowID,
		Status:       "succeeded",
		RiskLevel:    string(operations.RiskMedium),
	})
	writeJSON(w, http.StatusOK, ownerActionView(row, replayed))
}

// ListDevLoopOwnerActions handles GET /api/v1/agents/dev-loop/{workflow_id}/owner-actions.
func (h *Handlers) ListDevLoopOwnerActions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireTemporalAdmin(w, r); !ok {
		return
	}
	workflowID := chi.URLParam(r, "workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "the work-item store is not configured", nil)
		return
	}
	rows, err := h.opts.WorkItems.ListOwnerActions(r.Context(), workflowID)
	if err != nil {
		slog.Error("dev-loop owner actions: list failed", "workflow_id", workflowID, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "could not read the owner actions", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, ownerActionView(&rows[i], false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"workflow_id": workflowID, "owner_actions": out})
}

// GetDevLoopOwnerAction handles GET /api/v1/agents/dev-loop/{workflow_id}/owner-actions/{id}.
// For a cancel whose signal was delivered it re-observes the run and records
// how it ended. It never signals.
func (h *Handlers) GetDevLoopOwnerAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireTemporalAdmin(w, r); !ok {
		return
	}
	workflowID := chi.URLParam(r, "workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "the work-item store is not configured", nil)
		return
	}
	ctx := r.Context()
	row, err := h.opts.WorkItems.GetOwnerAction(ctx, chi.URLParam(r, "id"))
	if err == nil && row.WorkflowID != workflowID {
		err = workitems.ErrOwnerActionNotFound
	}
	if errors.Is(err, workitems.ErrOwnerActionNotFound) {
		writeErrorCode(w, http.StatusNotFound, ownerActionCodeNotFound, "owner action not found", nil)
		return
	}
	if err != nil {
		slog.Error("dev-loop owner action: read failed", "workflow_id", workflowID, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "could not read the owner action", nil)
		return
	}
	if row.Action == workitems.OwnerActionRequestCancel && row.State == workitems.OwnerActionSignalled {
		// A failed describe leaves the stored outcome, which never claims
		// the run stopped.
		if exec, fail := h.describeDevLoopRun(ctx, workflowID, "workflow not found"); fail == nil &&
			(exec.RunID != row.RunID || exec.Status != devLoopStatusRunning) {
			status := ""
			if exec.RunID == row.RunID {
				status = exec.Status
			}
			outcome := h.ownerCancelFinishedOutcome(ctx, workflowID, row.RunID, status)
			marked, err := h.opts.WorkItems.MarkOwnerActionOutcome(ctx, row.ID, workitems.OwnerActionSignalled, workitems.OwnerActionFinished, outcome)
			if errors.Is(err, workitems.ErrOwnerActionStateChanged) {
				marked, err = h.opts.WorkItems.GetOwnerAction(ctx, row.ID)
			}
			if err == nil {
				row = marked
			}
		}
	}
	writeJSON(w, http.StatusOK, ownerActionView(row, false))
}
