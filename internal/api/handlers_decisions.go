// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

// Durable decision records (mctl-api#701). See internal/decisions.
//
// Writes need evidence:write: the producer that seals execution evidence is
// the one that makes policy decisions and runs their attempts, so the
// evidence writer reaches these two append routes too (evidenceWriterGate).
// Every read is admin-only: a decision chain resolves approvals and
// evidence across work items.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/decisions"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// maxDecisionBodyBytes bounds a decision or attempt request; every field is
// a bounded id, code or digest.
const maxDecisionBodyBytes = 16 << 10

const decisionsRoute = "/api/v1/decisions"

// decisionWritesPerMinute is the decision routes' own budget. Every route
// also sits under globalRequestsPerMinute, which the evidence writer shares
// with evidence ingest (evidenceIngestPerMinute); 150 keeps the two
// buckets' sum under it, so a burst of decision writes cannot use up the
// global budget evidence ingest still has a right to.
const decisionWritesPerMinute = 150

// Typed error codes a client can branch on.
const (
	codeDecisionInvalid             = "decision_invalid"
	codeDecisionNotFound            = "decision_not_found"
	codeDecisionIdempotencyConflict = "decision_idempotency_conflict"
	codeDecisionApprovalBinding     = "decision_approval_binding"
	codeDecisionApprovalNotFound    = "decision_approval_not_found"
	codeDecisionUnobservable        = "decision_reference_unobservable"
	codeDecisionNotPermitted        = "decision_not_permitted"
	codeDecisionAlreadySucceeded    = "decision_already_succeeded"
	codeDecisionAttemptNotFound     = "decision_attempt_not_found"
	codeDecisionAttemptClosed       = "decision_attempt_closed"
	codeDecisionTooManyAttempts     = "decision_too_many_attempts"
	codeDecisionStoreUnavailable    = "decision_store_unavailable"
)

// isDecisionWriteRoute reports whether r is one of the two append routes:
// POST /api/v1/decisions and POST /api/v1/decisions/{id}/attempts.
func isDecisionWriteRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if r.URL.Path == decisionsRoute {
		return true
	}
	rest, ok := strings.CutPrefix(r.URL.Path, decisionsRoute+"/")
	if !ok {
		return false
	}
	id, ok := strings.CutSuffix(rest, "/attempts")
	return ok && id != "" && !strings.Contains(id, "/")
}

func (h *Handlers) requireDecisionWriter(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Decisions == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeDecisionStoreUnavailable, "decision store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.HasPermission(auth.PermissionEvidenceWrite) {
		writeErrorCode(w, http.StatusForbidden, "forbidden", "recording decisions requires "+auth.PermissionEvidenceWrite, nil)
		return nil, false
	}
	return user, true
}

// requireDecisionAdmin admits admin-only reads. A nil store is 503, never an
// empty result.
func (h *Handlers) requireDecisionAdmin(w http.ResponseWriter, r *http.Request) bool {
	if h.opts.Decisions == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeDecisionStoreUnavailable, "decision store not configured", nil)
		return false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "decision records are admin-only")
		return false
	}
	return true
}

func writeDecisionError(w http.ResponseWriter, err error) {
	for _, m := range []struct {
		target error
		status int
		code   string
	}{
		{decisions.ErrInvalid, http.StatusBadRequest, codeDecisionInvalid},
		{decisions.ErrNotFound, http.StatusNotFound, codeDecisionNotFound},
		{decisions.ErrIdempotencyConflict, http.StatusConflict, codeDecisionIdempotencyConflict},
		{decisions.ErrApprovalBinding, http.StatusUnprocessableEntity, codeDecisionApprovalBinding},
		{decisions.ErrApprovalNotFound, http.StatusUnprocessableEntity, codeDecisionApprovalNotFound},
		{decisions.ErrNotPermitted, http.StatusConflict, codeDecisionNotPermitted},
		{decisions.ErrAlreadySucceeded, http.StatusConflict, codeDecisionAlreadySucceeded},
		{decisions.ErrAttemptNotFound, http.StatusConflict, codeDecisionAttemptNotFound},
		{decisions.ErrAttemptClosed, http.StatusConflict, codeDecisionAttemptClosed},
		{decisions.ErrTooManyAttempts, http.StatusConflict, codeDecisionTooManyAttempts},
	} {
		if errors.Is(err, m.target) {
			writeErrorCode(w, m.status, m.code, err.Error(), nil)
			return
		}
	}
	// Could not observe a reference: the server cannot answer, which is
	// never the same as "absent". The cause may be a driver error, so it is
	// logged, not served.
	if errors.Is(err, decisions.ErrUnobservable) {
		slog.Error("decision reference unobservable", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, codeDecisionUnobservable,
			"a referenced approval or evidence record could not be read", nil)
		return
	}
	slog.Error("decision store error", "error", err)
	writeError(w, http.StatusInternalServerError, "decision store error")
}

// decodeDecisionBody decodes exactly one JSON object with no unknown keys.
func decodeDecisionBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxDecisionBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErrorCode(w, http.StatusBadRequest, codeDecisionInvalid, "invalid JSON body: "+err.Error(), nil)
		return false
	}
	if dec.More() {
		writeErrorCode(w, http.StatusBadRequest, codeDecisionInvalid, "trailing data after JSON object", nil)
		return false
	}
	return true
}

type recordDecisionRequest struct {
	ExecutionID    string    `json:"execution_id"`
	WorkItemID     string    `json:"work_item_id"`
	IntentSource   string    `json:"intent_source"`
	TraceID        string    `json:"trace_id"`
	PolicyVersion  string    `json:"policy_version"`
	RuleID         string    `json:"rule_id"`
	Verdict        string    `json:"verdict"`
	Code           string    `json:"code"`
	PolicyReasons  []string  `json:"policy_reasons"`
	Actor          string    `json:"actor"`
	PrincipalID    string    `json:"principal_id"`
	Tenant         string    `json:"tenant"`
	ApprovalID     string    `json:"approval_id"`
	AuthorityBasis string    `json:"authority_basis"`
	ActionKind     string    `json:"action_kind"`
	Operation      string    `json:"operation"`
	TargetDigest   string    `json:"target_digest"`
	ArgsDigest     string    `json:"args_digest"`
	ActionDigest   string    `json:"action_digest"`
	DecidedAt      time.Time `json:"decided_at"`
	IdempotencyKey string    `json:"idempotency_key"`
}

type decisionResponse struct {
	Decision *decisions.Decision `json:"decision"`
}

// RecordDecision handles POST /api/v1/decisions.
func (h *Handlers) RecordDecision(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireDecisionWriter(w, r)
	if !ok {
		return
	}
	var req recordDecisionRequest
	if !decodeDecisionBody(w, r, &req) {
		return
	}
	d, created, err := h.opts.Decisions.Record(r.Context(), decisions.DecisionInput{
		ExecutionID: req.ExecutionID, WorkItemID: req.WorkItemID, IntentSource: req.IntentSource,
		TraceID: req.TraceID, PolicyVersion: req.PolicyVersion, RuleID: req.RuleID,
		Verdict: req.Verdict, Code: req.Code, PolicyReasons: req.PolicyReasons,
		Actor: req.Actor, PrincipalID: req.PrincipalID, Tenant: req.Tenant,
		ApprovalID: req.ApprovalID, AuthorityBasis: req.AuthorityBasis,
		ActionKind: req.ActionKind, Operation: req.Operation, TargetDigest: req.TargetDigest,
		ArgsDigest: req.ArgsDigest, ActionDigest: req.ActionDigest, DecidedAt: req.DecidedAt,
		IdempotencyKey:        req.IdempotencyKey,
		RecordedBy:            user.ID,
		RecordedByPrincipalID: user.PrincipalID(),
	})
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if created {
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: "decision.record",
			Parameters: map[string]string{
				"decision_id":  d.ID,
				"execution_id": d.ExecutionID,
				"code":         d.Code,
				"approval_id":  d.ApprovalID,
			},
			Status:    "succeeded",
			RiskLevel: string(operations.RiskLow),
		})
	}
	writeJSON(w, createdStatus(created), decisionResponse{Decision: d})
}

type appendAttemptRequest struct {
	AttemptNo            int       `json:"attempt_no"`
	Phase                string    `json:"phase"`
	EvidenceID           string    `json:"evidence_id"`
	RuntimeExecutionID   string    `json:"runtime_execution_id"`
	CommerceInvocationID string    `json:"commerce_invocation_id"`
	ErrorCode            string    `json:"error_code"`
	ResultDigest         string    `json:"result_digest"`
	OccurredAt           time.Time `json:"occurred_at"`
	IdempotencyKey       string    `json:"idempotency_key"`
}

type attemptEventResponse struct {
	Event *decisions.AttemptEvent `json:"event"`
}

// AppendDecisionAttempt handles POST /api/v1/decisions/{id}/attempts.
func (h *Handlers) AppendDecisionAttempt(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireDecisionWriter(w, r)
	if !ok {
		return
	}
	var req appendAttemptRequest
	if !decodeDecisionBody(w, r, &req) {
		return
	}
	e, created, err := h.opts.Decisions.AppendAttempt(r.Context(), decisions.AttemptInput{
		DecisionID: chi.URLParam(r, "id"), AttemptNo: req.AttemptNo, Phase: req.Phase,
		EvidenceID: req.EvidenceID, RuntimeExecutionID: req.RuntimeExecutionID,
		CommerceInvocationID: req.CommerceInvocationID, ErrorCode: req.ErrorCode,
		ResultDigest: req.ResultDigest, OccurredAt: req.OccurredAt, IdempotencyKey: req.IdempotencyKey,
		RecordedBy:            user.ID,
		RecordedByPrincipalID: user.PrincipalID(),
	})
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if created {
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: "decision.attempt",
			Parameters: map[string]string{
				"decision_id": e.DecisionID,
				"attempt_no":  strconv.Itoa(e.AttemptNo),
				"phase":       e.Phase,
				"evidence_id": e.EvidenceID,
			},
			Status:    "succeeded",
			RiskLevel: string(operations.RiskLow),
		})
	}
	writeJSON(w, createdStatus(created), attemptEventResponse{Event: e})
}

// GetDecision handles GET /api/v1/decisions/{id}: the reconstructed chain.
// Admin-only. A reference that cannot be read is 503, never a partial chain.
func (h *Handlers) GetDecision(w http.ResponseWriter, r *http.Request) {
	if !h.requireDecisionAdmin(w, r) {
		return
	}
	c, err := h.opts.Decisions.Chain(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// ListDecisions handles GET /api/v1/decisions?execution_id=|work_item_id=|
// approval_id=. Admin-only. An unparseable limit is an error, not a default.
func (h *Handlers) ListDecisions(w http.ResponseWriter, r *http.Request) {
	if !h.requireDecisionAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	f := decisions.Filter{ExecutionID: q.Get("execution_id"), WorkItemID: q.Get("work_item_id"), ApprovalID: q.Get("approval_id")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErrorCode(w, http.StatusBadRequest, codeDecisionInvalid, "limit must be a positive integer", nil)
			return
		}
		f.Limit = n
	}
	res, err := h.opts.Decisions.List(r.Context(), f)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
