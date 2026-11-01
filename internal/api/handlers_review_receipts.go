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

// Durable review receipts (mctl-api#897, Tier B of the review-receipt
// contract). See internal/reviewstore and docs/review-receipts.md.
//
// Request ingest needs evidence:write (the producer that authored the
// subject registers the sealed request). A manual advisory receipt needs a
// direct human administrator. The worker receipt path is disabled until the
// authoritative execution -> attempt/lineage binding exists (mctl-api#896).
// Every read is admin-only and fails closed: a pool is complete or a typed
// 503, never a partial list.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/reviewstore"
)

// maxReviewBodyBytes bounds a review request or manual submission.
const maxReviewBodyBytes = 64 << 10

const reviewRequestsRoute = "/api/v1/review-requests"

// reviewWritesPerMinute is the review routes' own budget, sized so that
// evidence (120), decisions (150) and review (30) stay within the global
// 300/min per-principal limit.
const reviewWritesPerMinute = 30

// Typed error codes a client can branch on. The Tier A document codes
// (review_malformed, review_unknown_key, ...) come from reviewreceipts.
const (
	codeReviewUnsealed             = "review_unsealed"
	codeReviewNotPermitted         = "review_not_permitted"
	codeReviewRequestNotFound      = "review_request_not_found"
	codeReviewRequestClosed        = "review_request_closed"
	codeReviewBindingMismatch      = "review_binding_mismatch"
	codeReviewRequestModeWorker    = "review_request_mode_worker"
	codeReviewNonceReused          = "review_nonce_reused"
	codeReviewRequestConflict      = "review_request_conflict"
	codeReviewAuthoringUnresolved  = "review_authoring_unresolved"
	codeReviewTenantUnresolved     = "review_tenant_unresolved"
	codeReviewWorkerIngestDisabled = "review_worker_ingest_disabled"
	codeReviewStoreUnavailable     = "review_store_unavailable"
	codeReviewPoolTooLarge         = "review_pool_too_large"
	codeReviewEvidenceUnavailable  = "review_evidence_unavailable"
	codeReviewPrincipalUnavailable = "review_principal_unavailable"
)

// isReviewRequestWriteRoute reports whether r is POST /api/v1/review-requests,
// the one review route the evidence writer may call.
func isReviewRequestWriteRoute(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == reviewRequestsRoute
}

var reviewRefusals = []struct {
	target error
	status int
	code   string
}{
	{reviewstore.ErrUnsealed, http.StatusBadRequest, codeReviewUnsealed},
	{reviewstore.ErrRequestNotFound, http.StatusNotFound, codeReviewRequestNotFound},
	{reviewstore.ErrRequestClosed, http.StatusConflict, codeReviewRequestClosed},
	{reviewstore.ErrBindingMismatch, http.StatusConflict, codeReviewBindingMismatch},
	{reviewstore.ErrRequestModeWorker, http.StatusConflict, codeReviewRequestModeWorker},
	{reviewstore.ErrNonceReused, http.StatusConflict, codeReviewNonceReused},
	{reviewstore.ErrIdempotencyConflict, http.StatusConflict, codeReviewRequestConflict},
	{reviewstore.ErrAuthoringUnresolved, http.StatusUnprocessableEntity, codeReviewAuthoringUnresolved},
	{reviewstore.ErrTenantUnresolved, http.StatusUnprocessableEntity, codeReviewTenantUnresolved},
	{reviewstore.ErrPoolTooLarge, http.StatusServiceUnavailable, codeReviewPoolTooLarge},
}

func writeReviewError(w http.ResponseWriter, err error) {
	var docErr *reviewreceipts.Error
	if errors.As(err, &docErr) {
		writeErrorCode(w, http.StatusBadRequest, docErr.Code, docErr.Message, nil)
		return
	}
	for _, m := range reviewRefusals {
		if errors.Is(err, m.target) {
			writeErrorCode(w, m.status, m.code, err.Error(), nil)
			return
		}
	}
	if errors.Is(err, reviewstore.ErrEvidenceUnavailable) {
		slog.Error("review: evidence unavailable", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, codeReviewEvidenceUnavailable,
			"the authoring evidence could not be read", nil)
		return
	}
	// ErrStoreCorrupt and any driver error: the server cannot answer. The
	// cause is logged, not served.
	slog.Error("review store error", "error", err)
	writeErrorCode(w, http.StatusServiceUnavailable, codeReviewStoreUnavailable, "the review store could not answer", nil)
}

func (h *Handlers) reviewStoreOrUnavailable(w http.ResponseWriter) bool {
	if h.opts.ReviewStore == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeReviewStoreUnavailable, "review store not configured", nil)
		return false
	}
	return true
}

// requireReviewAdmin admits admin-only reads. A nil store is 503, never an
// empty result.
func (h *Handlers) requireReviewAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !h.reviewStoreOrUnavailable(w) {
		return false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "review records are admin-only")
		return false
	}
	return true
}

func readReviewBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReviewBodyBytes))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, reviewreceipts.CodeMalformed, "unreadable or oversized body", nil)
		return nil, false
	}
	return raw, true
}

func reviewActor(u *auth.User) reviewstore.Actor {
	return reviewstore.Actor{Name: principalOf(u), PrincipalID: u.PrincipalID()}
}

// IngestReviewRequest handles POST /api/v1/review-requests: the body is the
// sealed Tier A ReviewRequest document itself, stored verbatim.
func (h *Handlers) IngestReviewRequest(w http.ResponseWriter, r *http.Request) {
	if !h.reviewStoreOrUnavailable(w) {
		return
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.HasPermission(auth.PermissionEvidenceWrite) {
		writeErrorCode(w, http.StatusForbidden, "forbidden", "registering review requests requires "+auth.PermissionEvidenceWrite, nil)
		return
	}
	raw, ok := readReviewBody(w, r)
	if !ok {
		return
	}
	sr, replayed, err := h.opts.ReviewStore.IngestRequest(r.Context(), raw, reviewActor(user))
	if err != nil {
		writeReviewError(w, err)
		return
	}
	if !replayed {
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: "review.request_ingest",
			Parameters: map[string]string{
				"request_id": sr.Request.RequestID,
				"tenant":     sr.Tenant,
				"mode":       sr.Request.Mode,
			},
			Status:    "succeeded",
			RiskLevel: string(operations.RiskLow),
		})
	}
	writeJSON(w, createdStatus(!replayed), map[string]any{
		"request_id": sr.Request.RequestID,
		"tenant":     sr.Tenant,
		"replayed":   replayed,
	})
}

type manualReceiptBody struct {
	RequestID string          `json:"request_id"`
	Subject   json.RawMessage `json:"subject"`
	Outcome   string          `json:"outcome"`
	Criteria  []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"criteria"`
	FindingsRef struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		ContentHash string `json:"content_hash"`
	} `json:"findings_ref"`
}

// SubmitManualReview handles POST /api/v1/review-receipts/manual. Direct
// human administrators only; the receipt is always manual and advisory.
func (h *Handlers) SubmitManualReview(w http.ResponseWriter, r *http.Request) {
	if !h.reviewStoreOrUnavailable(w) {
		return
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !isHumanAdmin(user) {
		writeErrorCode(w, http.StatusForbidden, codeReviewNotPermitted,
			"a manual review assertion needs a direct human administrator", nil)
		return
	}
	if code, err := checkHumanPrincipal(r.Context(), h.opts.Principals, user.PrincipalID()); err != nil {
		if code != "" {
			writeErrorCode(w, http.StatusForbidden, codeReviewNotPermitted, "the caller is not an active human principal", nil)
			return
		}
		slog.Error("review: caller's principal could not be checked", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, codeReviewPrincipalUnavailable, "could not verify the caller's principal", nil)
		return
	}
	raw, ok := readReviewBody(w, r)
	if !ok {
		return
	}
	var body manualReceiptBody
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		code := reviewreceipts.CodeMalformed
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			code = reviewreceipts.CodeUnknownKey
		}
		writeErrorCode(w, http.StatusBadRequest, code, "invalid JSON body: "+err.Error(), nil)
		return
	}
	if dec.More() {
		writeErrorCode(w, http.StatusBadRequest, reviewreceipts.CodeMalformed, "trailing data after JSON object", nil)
		return
	}
	subject, err := reviewreceipts.ParseSubject(body.Subject)
	if err != nil {
		writeReviewError(w, err)
		return
	}
	in := reviewstore.ManualInput{
		RequestID: body.RequestID, Subject: subject, Outcome: body.Outcome,
		FindingsRef: reviewreceipts.ArtifactRef{
			Name: body.FindingsRef.Name, Kind: body.FindingsRef.Kind, ContentHash: body.FindingsRef.ContentHash,
		},
	}
	for _, c := range body.Criteria {
		in.Criteria = append(in.Criteria, reviewreceipts.Criterion{ID: c.ID, Status: c.Status})
	}
	rc, err := h.opts.ReviewStore.SubmitManual(r.Context(), in, reviewActor(user), time.Now())
	if err != nil {
		writeReviewError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID:    user.ID,
		Operation: "review.manual_submit",
		Parameters: map[string]string{
			"receipt_id": rc.Receipt.ReceiptID,
			"request_id": rc.Receipt.RequestID,
			"tenant":     rc.Tenant,
			"outcome":    rc.Receipt.Outcome,
		},
		Status:    "succeeded",
		RiskLevel: string(operations.RiskLow),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"receipt_id": rc.Receipt.ReceiptID,
		"request_id": rc.Receipt.RequestID,
		"mode":       rc.Receipt.Mode,
		"assurance":  rc.Receipt.Assurance,
		"tenant":     rc.Tenant,
		"receipt":    json.RawMessage(rc.Document),
	})
}

// SubmitWorkerReview handles POST /api/v1/review-receipts. Disabled until
// mctl-api#896 supplies an authoritative execution -> attempt/lineage
// binding; it reads no body.
func (h *Handlers) SubmitWorkerReview(w http.ResponseWriter, r *http.Request) {
	if user := auth.UserFromContext(r.Context()); user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeErrorCode(w, http.StatusNotImplemented, codeReviewWorkerIngestDisabled,
		"worker review receipts are disabled until the execution attempt and lineage binding exists (mctl-api#896)", nil)
}

// GetReviewRequest handles GET /api/v1/review-requests/{id}.
func (h *Handlers) GetReviewRequest(w http.ResponseWriter, r *http.Request) {
	if !h.requireReviewAdmin(w, r) {
		return
	}
	sr, err := h.opts.ReviewStore.Request(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeReviewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reviewRequestView(sr))
}

func reviewRequestView(sr *reviewstore.StoredRequest) map[string]any {
	out := map[string]any{
		"request":     json.RawMessage(sr.Document),
		"tenant":      sr.Tenant,
		"ingested_by": sr.IngestedBy,
		"ingested_at": sr.IngestedAt,
		"closed":      sr.Closed,
	}
	if sr.Closed {
		out["closed_reason"] = sr.ClosedReason
	}
	if sr.ClosedBy != "" {
		out["closed_by"] = sr.ClosedBy
	}
	return out
}

// ListReviewReceipts handles GET /api/v1/review-receipts: the complete pool
// in ingest order, or a typed 503.
func (h *Handlers) ListReviewReceipts(w http.ResponseWriter, r *http.Request) {
	if !h.requireReviewAdmin(w, r) {
		return
	}
	_, stored, err := h.opts.ReviewStore.Pool(r.Context())
	if err != nil {
		writeReviewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"receipts": reviewDocuments(stored),
		"count":    len(stored),
		"complete": true,
	})
}

func reviewDocuments(stored []reviewstore.StoredReceipt) []json.RawMessage {
	docs := make([]json.RawMessage, 0, len(stored))
	for i := range stored {
		docs = append(docs, json.RawMessage(stored[i].Document))
	}
	return docs
}

var reviewSubjectQueryKeys = []string{
	"kind", "repository", "report_root", "report_path", "source_sha", "base_sha", "head_sha",
	"inventory_digest", "digest_version", "service", "slug", "gitops_commit", "content_digest", "approval_ref",
}

func reviewSubjectFromQuery(q url.Values) (reviewreceipts.ReviewSubject, error) {
	m := map[string]string{}
	for _, k := range reviewSubjectQueryKeys {
		if v := q.Get(k); v != "" {
			m[k] = v
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return reviewreceipts.ReviewSubject{}, err
	}
	return reviewreceipts.ParseSubject(raw)
}

// GetReviewGate handles GET /api/v1/review-gate: the Tier A gate verdict
// plus the full input it was computed from, so Tier A can re-run it.
func (h *Handlers) GetReviewGate(w http.ResponseWriter, r *http.Request) {
	if !h.requireReviewAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	required := q.Get("required_assurance")
	if required == "" {
		required = reviewreceipts.AssuranceIndependent
	}
	if required != reviewreceipts.AssuranceIndependent && required != reviewreceipts.AssuranceAny {
		writeErrorCode(w, http.StatusBadRequest, reviewreceipts.CodeMalformed, "required_assurance must be independent or any", nil)
		return
	}
	live, err := reviewSubjectFromQuery(q)
	if err != nil {
		writeReviewError(w, err)
		return
	}
	sr, pool, err := h.opts.ReviewStore.GateInput(r.Context(), live)
	if err != nil {
		writeReviewError(w, err)
		return
	}
	var reqPtr *reviewreceipts.ReviewRequest
	var reqDoc = json.RawMessage("null")
	closed := false
	if sr != nil {
		reqPtr = &sr.Request
		reqDoc = json.RawMessage(sr.Document)
		closed = sr.Closed
	}
	verdict, err := reviewreceipts.EvaluateReviewGate(&live, reqPtr, pool, required)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, reviewreceipts.CodeMalformed, err.Error(), nil)
		return
	}
	docs := make([]json.RawMessage, 0, len(pool))
	for i := range pool {
		b, merr := json.Marshal(pool[i].Dict())
		if merr != nil {
			writeReviewError(w, merr)
			return
		}
		docs = append(docs, b)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verdict":            verdict,
		"required_assurance": required,
		"live_subject":       live.Dict(),
		"request":            reqDoc,
		"request_closed":     closed,
		"pool":               docs,
		"pool_count":         len(docs),
		"complete":           true,
	})
}
