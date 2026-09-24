package api

// Human-input responses (mctl-api#261). POST
// /api/v1/human-input/{request_id}/response turns an authenticated human's
// answer into one HumanInputResponse signal on the workflow that sealed the
// request.
//
// What this endpoint decides, and what it leaves to the workflow:
//   - The respondent is ALWAYS derived from authentication ("github:<login>").
//     The body has no respondent field, and the service principal cannot
//     answer at all: a human answer relayed by a machine credential could
//     not be told apart from the machine answering itself.
//   - Eligibility, request_hash, expiry and the typed value are checked here
//     so a caller gets a precise error. The workflow re-checks all of them
//     (validate_response) and has the final word.
//   - Pending comes from the workflow's human_input_state query, never from
//     a copy kept here.
//   - The delivery ledger (humaninput.Ledger) makes a submission idempotent
//     and makes delivery recoverable: the answer is recorded as
//     pending_delivery before the signal, so a Temporal outage leaves it
//     retryable instead of silently lost. It is the first claim per
//     request that wins, matching the workflow's first-valid-response rule.
//
// Delivery is at-least-once: two identical submissions racing each other can
// both signal. The workflow tolerates that by construction: it drains its
// queue first-valid-wins, and a payload arriving once it no longer waits is
// counted and dropped.
//
// An answer is information, not authorization. This endpoint never signals
// approve, and nothing it records is read by the approval path.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// maxHumanInputResponseBytes bounds the request body. Answers are short; a
// structured answer is a small object.
const maxHumanInputResponseBytes = 64 << 10

// Confirmation polling after the signal. The signal handler only queues the
// payload; the workflow validates it on its next task, normally well under
// a second. Past this window the response is reported pending_delivery and
// a resubmission of the same answer re-checks it. Variables so tests can
// shorten them.
var (
	humanInputConfirmAttempts = 8
	humanInputConfirmInterval = 250 * time.Millisecond
	humanInputConfirmBudget   = 5 * time.Second
)

// humanInputSurfacePattern: the surface is caller-declared provenance (which
// UI the answer was typed in), not a trust signal, so it is only shape-checked.
var humanInputSurfacePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// humanInputUnconfirmed is the one 202 detail: signalled, not yet confirmed.
const humanInputUnconfirmed = "delivered; not yet confirmed by the workflow, resubmit the same response to check again"

// Response statuses reported to the caller.
const (
	humanInputStatusAccepted = humaninput.DeliveryAccepted
	humanInputStatusPending  = humaninput.DeliveryPending
	humanInputStatusRejected = humaninput.DeliveryRejected
)

type humanInputResponseBody struct {
	RequestHash string          `json:"request_hash"`
	Value       json.RawMessage `json:"value"`
	Surface     string          `json:"surface"`
}

type humanInputResponseResult struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	State      string `json:"state,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Respondent string `json:"respondent,omitempty"`
	ReceivedAt string `json:"received_at,omitempty"`
}

// RespondHumanInput handles POST /api/v1/human-input/{request_id}/response.
func (h *Handlers) RespondHumanInput(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if user.IsService() {
		writeError(w, http.StatusForbidden, "a human-input response must come from the human answering, not the service principal")
		return
	}
	if h.opts.GitReader == nil || h.opts.TemporalClient == nil || h.opts.HumanInputLedger == nil {
		writeError(w, http.StatusServiceUnavailable, "human-input responses are not configured")
		return
	}
	id := chi.URLParam(r, "request_id")
	if !humanInputIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "request_id must look like hir-<16 hex>")
		return
	}
	body, value, err := decodeHumanInputResponse(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A relayed answer came through its surface and no other.
	if relay, ok := user.RelaySurface(); ok {
		if body.Surface != "" && body.Surface != relay {
			writeError(w, http.StatusBadRequest, "an answer relayed by surface:"+relay+" cannot claim surface "+body.Surface)
			return
		}
		body.Surface = relay
	}
	if body.Surface == "" {
		body.Surface = "api"
	}

	s, err := h.findHumanInput(id)
	if err != nil {
		slog.Error("human_input.respond failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read human-input requests")
		return
	}
	if s == nil || !canSeeHumanInput(user, s.req) {
		writeError(w, http.StatusNotFound, "human-input request not found: "+id)
		return
	}
	req := s.req
	// Only a GitHub login proven by authentication can answer; see
	// callerActorRef. Without one the caller has no respondent reference.
	ref, verified := callerActorRef(user)
	reject := func(code int, state, detail string) {
		msg := state + ": " + detail
		if state == "invalid_value" {
			// The validation error lists the question's options; the audit
			// row carries ids and the outcome only.
			msg = state
		}
		h.auditHumanInput(r, user, s, ref, "human_input.response_rejected", "failed", body.Surface, msg)
		writeJSON(w, code, humanInputResponseResult{RequestID: id, Status: humanInputStatusRejected, State: state, Detail: detail, Respondent: ref})
	}
	if !verified {
		reject(http.StatusForbidden, "not_eligible", "only a caller authenticated by GitHub can answer a human-input request")
		return
	}
	if !req.CanRespond(ref) {
		reject(http.StatusForbidden, "not_eligible", ref+" is not an eligible respondent for this request")
		return
	}
	// Retention: an answer that could not be delivered before its request
	// expired is dropped rather than kept indefinitely. Opportunistic (each
	// eligible submission sweeps; a partial index keeps it cheap) and
	// best-effort.
	if n, err := h.opts.HumanInputLedger.ClearExpiredValues(r.Context(), humanInputNow().UTC()); err != nil {
		slog.Warn("human_input.ledger_clear_expired_failed", "error", err)
	} else if n > 0 {
		slog.Info("human_input.ledger_cleared_expired_values", "count", n)
	}
	if body.RequestHash != req.RequestHash {
		reject(http.StatusConflict, "superseded", "request_hash does not match the current request")
		return
	}
	if err := humaninput.ValidateValue(*req.Response, value); err != nil {
		reject(http.StatusUnprocessableEntity, "invalid_value", err.Error())
		return
	}
	now := humanInputNow().UTC()
	if !now.Before(req.Expires()) {
		reject(http.StatusConflict, HumanInputExpired, "the request expired at "+req.ExpiresAt)
		return
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "value is not encodable")
		return
	}
	runID := ""
	if req.Execution.TemporalRunID != nil {
		runID = *req.Execution.TemporalRunID
	}
	sub := humaninput.Delivery{
		RequestID:   id,
		RequestHash: req.RequestHash,
		WorkflowID:  req.Execution.TemporalWorkflowID,
		RunID:       runID,
		Respondent:  ref,
		// Recorded only (mctl-api#373 phase 1).
		RespondentPrincipalID: user.PrincipalID(),
		ViaPrincipalID:        user.ViaPrincipalID(),
		Surface:               body.Surface,
		ValueHash:             humaninput.HashBytes(canonical),
		Value:                 canonical,
		ReceivedAt:            now,
		ExpiresAt:             req.Expires(),
	}

	ctx := r.Context()
	ledger := h.opts.HumanInputLedger
	existing, err := ledger.Get(ctx, id)
	if err != nil {
		slog.Error("human_input.respond ledger read failed", "request_id", id, "error", err)
		writeError(w, http.StatusServiceUnavailable, "human-input ledger unavailable")
		return
	}
	if existing != nil && existing.State != humaninput.DeliveryRejected {
		if code, res, done := h.settleExisting(ctx, r, user, s, existing, sub); done {
			writeJSON(w, code, res)
			return
		}
	}

	// No live delivery for this request: ask the workflow whether it is
	// waiting on it, and remember its resume_count as the baseline that
	// proves acceptance later.
	st, err := h.queryHumanInput(ctx, sub)
	if err != nil {
		if temporalclient.IsNotFound(err) {
			reject(http.StatusConflict, HumanInputNotPending, "owning workflow not found")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "owning workflow did not answer; nothing was recorded, retry later")
		return
	}
	if state, detail := deriveHumanInputState(st, req, now); state != HumanInputPending {
		reject(http.StatusConflict, state, detail)
		return
	}
	sub.BaselineResumeCount = st.ResumeCount

	cur, won, err := ledger.Claim(ctx, sub)
	if err != nil {
		slog.Error("human_input.respond ledger claim failed", "request_id", id, "error", err)
		writeError(w, http.StatusServiceUnavailable, "human-input ledger unavailable")
		return
	}
	if !won {
		// Lost a race. The winner is either this same answer delivered
		// twice (a surface retry), which is idempotent, or a competing one.
		if code, res, done := h.settleExisting(ctx, r, user, s, cur, sub); done {
			writeJSON(w, code, res)
			return
		}
		// The winner was rejected meanwhile, so the request is free again:
		// claim once more, as the path above does.
		cur, won, err = ledger.Claim(ctx, sub)
		if err != nil {
			slog.Error("human_input.respond ledger claim failed", "request_id", id, "error", err)
			writeError(w, http.StatusServiceUnavailable, "human-input ledger unavailable")
			return
		}
		if !won {
			code, res := h.refuseAnswered(r, user, s, sub, "another response was submitted concurrently")
			writeJSON(w, code, res)
			return
		}
	}
	code, res := h.deliverHumanInput(ctx, r, user, s, *cur)
	writeJSON(w, code, res)
}

// settleExisting handles a request that already has a live delivery. done
// is false only when that delivery turned out to be rejected, which frees
// the request for sub.
func (h *Handlers) settleExisting(ctx context.Context, r *http.Request, user *auth.User, s *sealedHumanInput, existing *humaninput.Delivery, sub humaninput.Delivery) (int, humanInputResponseResult, bool) {
	same := existing.SameSubmission(sub)
	if existing.State == humaninput.DeliveryAccepted {
		if same {
			return http.StatusOK, deliveryResult(*existing, humanInputStatusAccepted, "", "already accepted"), true
		}
		code, res := h.refuseAnswered(r, user, s, sub, "the request was already answered")
		return code, res, true
	}
	// Pending: push the recorded answer through first, whoever asked. This
	// is what makes delivery recoverable without a background worker.
	code, res := h.deliverHumanInput(ctx, r, user, s, *existing)
	if same {
		return code, res, true
	}
	if res.Status == humanInputStatusRejected {
		return 0, humanInputResponseResult{}, false
	}
	detail := "another response is being delivered"
	if res.Status == humanInputStatusAccepted {
		detail = "the request was already answered"
	}
	code, res = h.refuseAnswered(r, user, s, sub, detail)
	return code, res, true
}

// refuseAnswered refuses sub because another answer holds the request. It
// is audited like every other refusal: an attempt to override a recorded
// answer is exactly what an operator looks for afterwards.
func (h *Handlers) refuseAnswered(r *http.Request, user *auth.User, s *sealedHumanInput, sub humaninput.Delivery, detail string) (int, humanInputResponseResult) {
	h.auditHumanInput(r, user, s, sub.Respondent, "human_input.response_rejected", "failed", sub.Surface, "answered: "+detail)
	return http.StatusConflict, humanInputResponseResult{RequestID: sub.RequestID, Status: humanInputStatusRejected, State: "answered", Detail: detail, Respondent: sub.Respondent}
}

// deliverHumanInput signals the recorded delivery d and waits briefly for
// the workflow to accept or reject it.
func (h *Handlers) deliverHumanInput(ctx context.Context, r *http.Request, user *auth.User, s *sealedHumanInput, d humaninput.Delivery) (int, humanInputResponseResult) {
	ledger := h.opts.HumanInputLedger
	// Ledger writes that close or count a delivery must not depend on the
	// caller staying connected: a delivered answer left pending would keep
	// its raw value and look undelivered.
	ledgerCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), humanInputQueryTimeout)
	}
	resolve := func(state, reason string) {
		wctx, wcancel := ledgerCtx()
		defer wcancel()
		if err := ledger.Resolve(wctx, d, state); err != nil {
			if errors.Is(err, humaninput.ErrDeliveryNotPending) {
				// Another call closed this delivery and audited it.
				return
			}
			slog.Error("human_input.ledger_resolve_failed", "request_id", d.RequestID, "state", state, "error", err)
		}
		op, status := "human_input.response_accepted", "succeeded"
		if state == humaninput.DeliveryRejected {
			op, status = "human_input.response_rejected", "failed"
		}
		h.auditHumanInput(r, user, s, d.Respondent, op, status, d.Surface, reason)
	}

	pre, err := h.queryHumanInput(ctx, d)
	if err != nil {
		if temporalclient.IsNotFound(err) {
			resolve(humaninput.DeliveryRejected, "owning workflow not found")
			return http.StatusConflict, deliveryResult(d, humanInputStatusRejected, HumanInputNotPending, "owning workflow not found")
		}
		return http.StatusServiceUnavailable, deliveryResult(d, humanInputStatusPending, HumanInputUnknown, "owning workflow did not answer; the response is recorded, resubmit it to retry delivery")
	}
	// resume_count is per workflow: a rise proves THIS request was answered
	// only while the workflow still reports this request. A stale row whose
	// workflow has since moved on falls through to "not pending".
	if pre.ResumeCount > d.BaselineResumeCount && pre.RequestID == d.RequestID {
		resolve(humaninput.DeliveryAccepted, "")
		return http.StatusOK, deliveryResult(d, humanInputStatusAccepted, HumanInputResolved, "")
	}
	if state, detail := deriveHumanInputState(pre, s.req, humanInputNow().UTC()); state != HumanInputPending {
		resolve(humaninput.DeliveryRejected, state)
		return http.StatusConflict, deliveryResult(d, humanInputStatusRejected, state, detail)
	}

	var value any
	dec := json.NewDecoder(bytes.NewReader(d.Value))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		resolve(humaninput.DeliveryRejected, "recorded value unreadable")
		return http.StatusInternalServerError, deliveryResult(d, humanInputStatusRejected, HumanInputUnknown, "recorded value is unreadable")
	}
	actorType, actorID := splitActorRef(d.Respondent)
	doc := map[string]any{
		"api_version":  humaninput.APIVersion,
		"kind":         humaninput.ResponseKind,
		"request_id":   d.RequestID,
		"request_hash": d.RequestHash,
		"respondent":   map[string]any{"actor_type": actorType, "actor_id": actorID},
		"surface":      d.Surface,
		"value":        value,
		"received_at":  d.ReceivedAt.UTC().Format(time.RFC3339),
	}
	nctx, ncancel := ledgerCtx()
	err = ledger.NoteAttempt(nctx, d.RequestID)
	ncancel()
	if err != nil && !errors.Is(err, humaninput.ErrDeliveryNotPending) {
		slog.Warn("human_input.ledger_attempt_failed", "request_id", d.RequestID, "error", err)
	}
	sctx, cancel := context.WithTimeout(ctx, humanInputQueryTimeout)
	err = h.opts.TemporalClient.SignalHumanInputResponse(sctx, d.WorkflowID, d.RunID, doc)
	cancel()
	if err != nil {
		if temporalclient.IsNotFound(err) {
			resolve(humaninput.DeliveryRejected, "owning workflow not found")
			return http.StatusConflict, deliveryResult(d, humanInputStatusRejected, HumanInputNotPending, "owning workflow not found")
		}
		slog.Warn("human_input.signal_failed", "request_id", d.RequestID, "workflow_id", d.WorkflowID, "error", err)
		return http.StatusServiceUnavailable, deliveryResult(d, humanInputStatusPending, HumanInputUnknown, "the workflow could not be signalled; the response is recorded, resubmit it to retry delivery")
	}
	slog.Info("human_input.signal_sent", "request_id", d.RequestID, "workflow_id", d.WorkflowID, "work_item_id", s.req.WorkItemID)
	h.auditHumanInput(r, user, s, d.Respondent, "human_input.signal_sent", "submitted", d.Surface, "")

	// One budget for the whole confirmation, well inside the 30s route
	// timeout: past it the answer is recorded and delivered, only not yet
	// confirmed, and the caller is told so rather than cut off.
	cctx, ccancel := context.WithTimeout(ctx, humanInputConfirmBudget)
	defer ccancel()
	for i := 0; i < humanInputConfirmAttempts; i++ {
		if humanInputConfirmInterval > 0 {
			select {
			case <-cctx.Done():
				return http.StatusAccepted, deliveryResult(d, humanInputStatusPending, HumanInputPending, humanInputUnconfirmed)
			case <-time.After(humanInputConfirmInterval):
			}
		}
		st, err := h.queryHumanInput(cctx, d)
		if err != nil {
			slog.Debug("human_input.confirm_query_failed", "request_id", d.RequestID, "error", err)
			if cctx.Err() != nil {
				break
			}
			continue
		}
		if st.ResumeCount > d.BaselineResumeCount && st.RequestID == d.RequestID {
			resolve(humaninput.DeliveryAccepted, "")
			return http.StatusOK, deliveryResult(d, humanInputStatusAccepted, HumanInputResolved, "")
		}
		if st.RequestID == d.RequestID && st.State == temporalclient.HumanInputTimedOut {
			resolve(humaninput.DeliveryRejected, HumanInputTimedOut)
			return http.StatusConflict, deliveryResult(d, humanInputStatusRejected, HumanInputTimedOut, "")
		}
		// Rejections are counted per workflow, not per payload, so a rise
		// while it still waits on this request is this payload refused
		// (or a concurrent stray one; either way the workflow still
		// waits and a corrected answer may be submitted).
		if st.RequestID == d.RequestID && st.State == temporalclient.HumanInputWaitingForInput && st.RejectedCount > pre.RejectedCount {
			resolve(humaninput.DeliveryRejected, "refused by the workflow")
			return http.StatusConflict, deliveryResult(d, humanInputStatusRejected, HumanInputPending, "the workflow refused this response")
		}
	}
	return http.StatusAccepted, deliveryResult(d, humanInputStatusPending, HumanInputPending, humanInputUnconfirmed)
}

func (h *Handlers) queryHumanInput(ctx context.Context, d humaninput.Delivery) (*temporalclient.HumanInputState, error) {
	qctx, cancel := context.WithTimeout(ctx, humanInputQueryTimeout)
	defer cancel()
	st, err := h.opts.TemporalClient.QueryHumanInputState(qctx, d.WorkflowID, d.RunID)
	if err == nil && st == nil {
		return nil, errors.New("owning workflow returned no state")
	}
	return st, err
}

func deliveryResult(d humaninput.Delivery, status, state, detail string) humanInputResponseResult {
	return humanInputResponseResult{
		RequestID: d.RequestID, Status: status, State: state, Detail: detail,
		Respondent: d.Respondent, ReceivedAt: d.ReceivedAt.UTC().Format(time.RFC3339),
	}
}

// auditHumanInput records a lifecycle event. It carries ids only: never the
// question or the answer.
//
// respondent is whose answer the event is about. It differs from the caller
// (UserID, who triggered the event) when a submission redelivers an answer
// another eligible human recorded earlier.
func (h *Handlers) auditHumanInput(r *http.Request, user *auth.User, s *sealedHumanInput, respondent, op, status, surface, message string) {
	params := map[string]string{
		"request_id":   s.req.RequestID,
		"work_item_id": s.req.WorkItemID,
		"service":      s.file.Service,
		"proposal":     s.file.Proposal,
		"surface":      surface,
		"respondent":   respondent,
	}
	// A relayed answer keeps both: the human it is attributed to
	// (respondent) and the surface principal that carried it.
	if acting := user.ActingPrincipal(); acting != "" {
		params["acting_principal"] = acting
	}
	h.logAudit(r, audit.Entry{
		UserID:       user.ID,
		Operation:    op,
		Parameters:   params,
		WorkflowName: s.req.Execution.TemporalWorkflowID,
		Status:       status,
		RiskLevel:    string(operations.RiskLow),
		Message:      message,
	})
	slog.Info(op, "respondent", respondent, "request_id", s.req.RequestID, "workflow_id", s.req.Execution.TemporalWorkflowID, "work_item_id", s.req.WorkItemID, "user", user.ID, "detail", message)
}

func decodeHumanInputResponse(w http.ResponseWriter, r *http.Request) (humanInputResponseBody, any, error) {
	var body humanInputResponseBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHumanInputResponseBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return body, nil, errors.New("invalid JSON body (fields: request_hash, value, surface; the respondent is taken from authentication): " + err.Error())
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return body, nil, errors.New("invalid JSON body: trailing data")
	}
	if body.RequestHash == "" {
		return body, nil, errors.New("request_hash is required")
	}
	if len(body.Value) == 0 {
		return body, nil, errors.New("value is required")
	}
	if body.Surface != "" && !humanInputSurfacePattern.MatchString(body.Surface) {
		return body, nil, errors.New("surface must match " + humanInputSurfacePattern.String())
	}
	var value any
	vdec := json.NewDecoder(bytes.NewReader(body.Value))
	vdec.UseNumber()
	if err := vdec.Decode(&value); err != nil {
		return body, nil, errors.New("value is not valid JSON")
	}
	return body, value, nil
}

func splitActorRef(ref string) (string, string) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == ':' {
			return ref[:i], ref[i+1:]
		}
	}
	return ref, ""
}
