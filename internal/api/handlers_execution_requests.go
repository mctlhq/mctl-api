package api

import (
	"encoding/json"
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

// Execution requests (mctl-api#368).
//
// SURFACE REQUESTS EXECUTION; SURFACE DOES NOT DECLARE EXECUTION IDENTITY.
//
// Who may do what, always from authentication:
//   - create: a person acting directly, or a surface relaying for its linked
//     human (a relay route). Never the service principal: it must not
//     request work on a user's behalf. The body can name no engine, engine
//     run or execution id (400 execution_identity_not_accepted) and no actor
//     (400 actor_not_accepted).
//   - read: anyone who can see the work item (a relay route too).
//   - claim, fulfil, reject: the service principal acting directly, never a
//     person and never a relayed surface. Fulfil and reject also need the
//     caller's own unexpired claim, fenced by the claim token.

// maxExecutionRequestBodyBytes bounds a request body: every field is short,
// the longest a 1 KiB reject reason.
const maxExecutionRequestBodyBytes = 8 << 10

// Typed error codes a client can branch on.
const (
	xrCodeIdentityNotAccepted = "execution_identity_not_accepted"
	xrCodeOpen                = "execution_request_open"
	xrCodeNotFound            = "execution_request_not_found"
	xrCodeNotClaimed          = "execution_request_not_claimed"
	xrCodeClosed              = "execution_request_closed"
	xrCodeIntentNotFound      = "intent_not_found"
	xrCodeRequesterForbidden  = "execution_request_requester_forbidden"
	xrCodeClaimantForbidden   = "execution_request_claimant_forbidden"
)

// executionIdentityFields are body keys that would declare execution
// identity. Only the platform supplies these, at fulfil; a request that
// names one is refused rather than ignored, so a surface that believes it
// chose the run finds out it did not.
var executionIdentityFields = []string{"engine", "engine_ref", "execution_id"}

// refuseExecutionIdentity answers 400 when the raw body names any
// executionIdentityFields. It reads the body and puts it back for the
// strict decoder.
func refuseExecutionIdentity(w http.ResponseWriter, r *http.Request) bool {
	raw, ok := readWorkItemBody(w, r, maxExecutionRequestBodyBytes)
	if !ok {
		return false
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) == nil {
		for _, k := range executionIdentityFields {
			if _, present := keys[k]; present {
				writeErrorCode(w, http.StatusBadRequest, xrCodeIdentityNotAccepted,
					"execution identity is supplied by the execution platform when it fulfils the request; field "+
						strconv.Quote(k)+" is not accepted", nil)
				return false
			}
		}
	}
	restoreBody(r, raw)
	return true
}

func writeExecutionRequestError(w http.ResponseWriter, err error) {
	var open *workitems.OpenRequestError
	var closed *workitems.ClosedRequestError
	switch {
	case errors.As(err, &open):
		writeErrorCode(w, http.StatusConflict, xrCodeOpen, err.Error(), map[string]interface{}{
			"execution_request_id": open.Open.ID, "state": open.Open.State,
		})
	case errors.As(err, &closed):
		details := map[string]interface{}{"execution_request_id": closed.Request.ID, "state": closed.Request.State}
		if closed.Request.ExecutionID != "" {
			details["execution_id"] = closed.Request.ExecutionID
		}
		writeErrorCode(w, http.StatusConflict, xrCodeClosed, err.Error(), details)
	case errors.Is(err, workitems.ErrExecutionRequestNotFound):
		writeErrorCode(w, http.StatusNotFound, xrCodeNotFound, "execution request not found", nil)
	case errors.Is(err, workitems.ErrExecutionRequestNotClaimed):
		writeErrorCode(w, http.StatusConflict, xrCodeNotClaimed, err.Error(), nil)
	case errors.Is(err, workitems.ErrIntentNotFound):
		writeErrorCode(w, http.StatusNotFound, xrCodeIntentNotFound, "intent_id names no intent of this work item", nil)
	case errors.Is(err, workitems.ErrExecutionNotFound):
		writeErrorCode(w, http.StatusNotFound, wiCodeExecutionNotFound, "resumed_from_execution_id names no execution of this work item", nil)
	default:
		writeWorkItemError(w, err)
	}
}

// executionRequestRefusalCode is the typed code of a claim-holder refusal,
// or "" for any other error.
func executionRequestRefusalCode(err error) string {
	switch {
	case errors.Is(err, workitems.ErrExecutionRequestNotClaimed):
		return xrCodeNotClaimed
	case errors.Is(err, workitems.ErrExecutionRequestClosed):
		return xrCodeClosed
	}
	return ""
}

// auditExecutionRequest records ids only: never the reason text or the
// claim token. The human is the actor on create; the service on claim,
// fulfil and reject, with the requesting human kept as requested_by.
func (h *Handlers) auditExecutionRequest(r *http.Request, user *auth.User, op string, x *workitems.ExecutionRequest, tenant string, extra map[string]string) {
	params := map[string]string{
		"execution_request_id": x.ID, "kind": x.Kind, "state": x.State, "requested_by": x.RequestedBy,
	}
	if x.ExecutionID != "" {
		params["execution_id"] = x.ExecutionID
	}
	for k, v := range extra {
		params[k] = v
	}
	h.auditWorkItem(r, user, op, x.WorkItemID, tenant, params)
}

// auditExecutionRequestRefusal records a refused claim, fulfil or reject:
// the signature of a stale holder or a confused deputy.
func (h *Handlers) auditExecutionRequestRefusal(r *http.Request, user *auth.User, op, id, code string) {
	params := map[string]string{"execution_request_id": id, "reason": code, "actor": principalOf(user)}
	if acting := user.ActingPrincipal(); acting != "" {
		params["acting_principal"] = acting
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "failed",
		RiskLevel:  string(operations.RiskMedium),
	})
}

func writeExecutionRequest(w http.ResponseWriter, status int, x *workitems.ExecutionRequest, extra map[string]any) {
	body := map[string]any{"schema_version": workitems.SchemaVersion, "execution_request": x}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

type executionRequestBody struct {
	Kind                   string `json:"kind"`
	ExpectedStateVersion   int64  `json:"expected_state_version"`
	ResumedFromExecutionID string `json:"resumed_from_execution_id,omitempty"`
	IntentID               *int64 `json:"intent_id,omitempty"`
	Surface                string `json:"surface,omitempty"`
	IdempotencyKey         string `json:"idempotency_key,omitempty"`
}

// CreateExecutionRequest handles POST /api/v1/work-items/{id}/execution-requests:
// ask the platform to start or resume the item. 201 records a pending
// request; 200 is the replay of the same key and body.
func (h *Handlers) CreateExecutionRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	if user.IsService() {
		h.auditExecutionRequestRefusal(r, user, "work_item.execution_request_refused", "", xrCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, xrCodeRequesterForbidden,
			"the service principal fulfils execution requests; it cannot make one on a user's behalf", nil)
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	if !refuseExecutionIdentity(w, r) {
		return
	}
	var body executionRequestBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxExecutionRequestBodyBytes) {
		return
	}
	m, ok := mutationFor(w, r, user, "execution_request", item.ID, body.Surface, body.IdempotencyKey, body)
	if !ok {
		return
	}
	x, created, err := h.opts.WorkItems.CreateExecutionRequest(r.Context(), workitems.ExecutionRequestInput{
		Mutation: m, WorkItemID: item.ID, Kind: body.Kind, ExpectedStateVersion: body.ExpectedStateVersion,
		ResumedFromExecutionID: body.ResumedFromExecutionID, IntentID: body.IntentID,
	})
	if err != nil {
		writeExecutionRequestError(w, err)
		return
	}
	if created {
		h.auditExecutionRequest(r, user, "work_item.execution_request", x, item.Tenant, map[string]string{"surface": x.Surface})
	}
	writeExecutionRequest(w, createdStatus(created), x, nil)
}

// ListExecutionRequests handles GET /api/v1/work-items/{id}/execution-requests,
// newest first.
func (h *Handlers) ListExecutionRequests(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	list, err := h.opts.WorkItems.ExecutionRequests(r.Context(), item.ID)
	if err != nil {
		writeExecutionRequestError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "execution_requests": list})
}

// GetExecutionRequest handles
// GET /api/v1/work-items/{id}/execution-requests/{request_id}.
func (h *Handlers) GetExecutionRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	x, err := h.opts.WorkItems.ExecutionRequest(r.Context(), item.ID, chi.URLParam(r, "request_id"))
	if err != nil {
		writeExecutionRequestError(w, err)
		return
	}
	writeExecutionRequest(w, http.StatusOK, x, nil)
}

// executionPlatform admits the service principal acting directly, and
// refuses (and audits) everyone else.
func (h *Handlers) executionPlatform(w http.ResponseWriter, r *http.Request, op string) (*auth.User, bool) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return nil, false
	}
	if !isDirectService(user) {
		h.auditExecutionRequestRefusal(r, user, op, chi.URLParam(r, "request_id"), xrCodeClaimantForbidden)
		writeErrorCode(w, http.StatusForbidden, xrCodeClaimantForbidden,
			"only the execution platform (the service principal, acting directly) claims, fulfils or rejects execution requests", nil)
		return nil, false
	}
	return user, true
}

type claimBody struct {
	LeaseSeconds int `json:"lease_seconds,omitempty"`
}

// ClaimExecutionRequest handles POST /api/v1/execution-requests/claim: claim
// the oldest pending request, or one whose lease lapsed. 200 returns it with
// the claim_token fulfil and reject must present; 204 when none is
// claimable.
func (h *Handlers) ClaimExecutionRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := h.executionPlatform(w, r, "work_item.execution_request_claim_refused")
	if !ok {
		return
	}
	var body claimBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxExecutionRequestBodyBytes) {
		return
	}
	lease := workitems.DefaultClaimLease
	if body.LeaseSeconds != 0 {
		lease = time.Duration(body.LeaseSeconds) * time.Second
		if lease < workitems.MinClaimLease || lease > workitems.MaxClaimLease {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "lease_seconds must be from 5 to 900", nil)
			return
		}
	}
	m, ok := mutationFor(w, r, user, "execution_request_claim", "", "", "", body)
	if !ok {
		return
	}
	x, item, err := h.opts.WorkItems.ClaimExecutionRequest(r.Context(), workitems.ClaimInput{Mutation: m, Lease: lease})
	if err != nil {
		writeExecutionRequestError(w, err)
		return
	}
	if x == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.auditExecutionRequest(r, user, "work_item.execution_request_claimed", x, item.Tenant, nil)
	writeExecutionRequest(w, http.StatusOK, x, map[string]any{"claim_token": x.ClaimToken})
}

type fulfilBody struct {
	ClaimToken string `json:"claim_token"`
	Engine     string `json:"engine"`
	EngineRef  string `json:"engine_ref"`
}

// FulfilExecutionRequest handles
// POST /api/v1/execution-requests/{request_id}/fulfil: attach the canonical
// execution for the claimed request. 201 when attached now; 200 when the
// holder repeats the same engine run.
func (h *Handlers) FulfilExecutionRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := h.executionPlatform(w, r, "work_item.execution_request_fulfil_refused")
	if !ok {
		return
	}
	var body fulfilBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxExecutionRequestBodyBytes) {
		return
	}
	id := chi.URLParam(r, "request_id")
	m, ok := mutationFor(w, r, user, "execution_request_fulfil", id, "", "", body)
	if !ok {
		return
	}
	x, item, exec, created, err := h.opts.WorkItems.FulfilExecutionRequest(r.Context(), workitems.FulfilInput{
		ClaimRef: workitems.ClaimRef{Mutation: m, RequestID: id, ClaimToken: body.ClaimToken},
		Engine:   body.Engine, EngineRef: body.EngineRef,
	})
	if err != nil {
		if code := executionRequestRefusalCode(err); code != "" {
			h.auditExecutionRequestRefusal(r, user, "work_item.execution_request_fulfil_refused", id, code)
		}
		writeExecutionRequestError(w, err)
		return
	}
	if created {
		h.auditExecutionRequest(r, user, "work_item.execution_request_fulfilled", x, item.Tenant,
			map[string]string{"engine": exec.Engine, "attempt": strconv.Itoa(exec.Attempt)})
	}
	writeExecutionRequest(w, createdStatus(created), x, map[string]any{
		"execution": exec, "work_item": item, "state_version": item.StateVersion,
	})
}

type rejectBody struct {
	ClaimToken string `json:"claim_token"`
	Reason     string `json:"reason"`
}

// RejectExecutionRequest handles
// POST /api/v1/execution-requests/{request_id}/reject: close the claimed
// request without an execution.
func (h *Handlers) RejectExecutionRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := h.executionPlatform(w, r, "work_item.execution_request_reject_refused")
	if !ok {
		return
	}
	var body rejectBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxExecutionRequestBodyBytes) {
		return
	}
	id := chi.URLParam(r, "request_id")
	m, ok := mutationFor(w, r, user, "execution_request_reject", id, "", "", body)
	if !ok {
		return
	}
	x, item, rejected, err := h.opts.WorkItems.RejectExecutionRequest(r.Context(), workitems.RejectInput{
		ClaimRef: workitems.ClaimRef{Mutation: m, RequestID: id, ClaimToken: body.ClaimToken},
		Reason:   body.Reason,
	})
	if err != nil {
		if code := executionRequestRefusalCode(err); code != "" {
			h.auditExecutionRequestRefusal(r, user, "work_item.execution_request_reject_refused", id, code)
		}
		writeExecutionRequestError(w, err)
		return
	}
	if rejected {
		h.auditExecutionRequest(r, user, "work_item.execution_request_rejected", x, item.Tenant, nil)
	}
	writeExecutionRequest(w, http.StatusOK, x, nil)
}
