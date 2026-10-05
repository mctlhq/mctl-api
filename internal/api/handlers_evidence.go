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

// Durable execution-evidence storage and retrieval (mctl-api#409, Tier B of
// evidence.mctl.ai/v1alpha1, ADR 018 and its Amendment 1). See
// internal/evidence for the storage layer and docs/execution-evidence.md
// for the contract.
//
// Authorization mirrors the usage ledger's shape one-for-one: ingest needs
// evidence:write (the evidence writer, or an admin); every read is
// admin-only EXCEPT the one work-item-scoped read, which reuses
// visibleWorkItem/canSeeWorkItem so an evidence record's existence never
// leaks past what the caller could already see on the work item.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// maxEvidenceBodyBytes bounds an ingest request: the base64 of at most
// evidence.MaxEvidenceBytes plus a small margin for the wrapper's own
// framing, the same maxSnapshotBodyBytes shape.
const maxEvidenceBodyBytes = (evidence.MaxEvidenceBytes/3+1)*4 + 16<<10

// evidenceWriterRoute is the one route the evidence-writer principal may
// call.
const evidenceWriterRoute = "/api/v1/evidence/records"

// Typed error codes a client can branch on.
const (
	codeEvidenceUnsupportedAPIVersion = "evidence_unsupported_api_version"
	codeEvidenceInvalid               = "evidence_invalid"
	codeEvidenceHashMismatch          = "evidence_hash_mismatch"
	codeEvidenceDivergence            = "evidence_divergence"
	codeEvidenceExecutionRefInvalid   = "evidence_execution_ref_invalid"
	codeEvidenceTooLarge              = "evidence_too_large"
	codeEvidenceNotFound              = "evidence_not_found"
	codeEvidenceStoreUnavailable      = "evidence_store_unavailable"
	codeEvidenceWriterForbidden       = "evidence_writer_route_not_allowed"
	// ADR 018 Amendment 2.
	codeEvidenceSupersedesInvalid   = "evidence_supersedes_invalid"
	codeEvidenceQueryInvalid        = "evidence_query_invalid"
	codeEvidenceCurrentPoolTooLarge = "evidence_current_pool_too_large"
	codeEvidenceCurrentNotVisible   = "evidence_current_not_visible"
)

// evidenceWriterGate confines the evidence-writer principal (mctl-api#409)
// to appending evidence records. Everything else answers 403 before any
// handler runs, mirroring usageWriterGate exactly.
func evidenceWriterGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsEvidenceWriter() &&
			(r.Method != http.MethodPost || r.URL.Path != evidenceWriterRoute) {
			writeErrorCode(w, http.StatusForbidden, codeEvidenceWriterForbidden,
				"the evidence writer may only call POST "+evidenceWriterRoute, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireEvidenceWriter admits callers holding evidence:write: the
// evidence writer, and admins.
func (h *Handlers) requireEvidenceWriter(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Evidence == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeEvidenceStoreUnavailable, "evidence store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.HasPermission(auth.PermissionEvidenceWrite) {
		writeErrorCode(w, http.StatusForbidden, "forbidden", "appending evidence records requires "+auth.PermissionEvidenceWrite, nil)
		return nil, false
	}
	return user, true
}

// requireEvidenceAdmin admits admin-only reads. A nil store is 503, not an
// empty result: "the store is not configured" and "no evidence was ever
// produced" must never be the same answer (requirements.md "Availability,
// gaps and retention").
func (h *Handlers) requireEvidenceAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Evidence == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeEvidenceStoreUnavailable, "evidence store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "evidence is admin-only outside its work item's own visibility")
		return nil, false
	}
	return user, true
}

// writeEvidenceError maps evidence sentinel errors to one status and typed
// code each.
func writeEvidenceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, evidence.ErrUnsupportedAPIVersion):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceUnsupportedAPIVersion, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceHashMismatch):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceHashMismatch, err.Error(), nil)
	case errors.Is(err, evidence.ErrInvalidExecutionRef):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceExecutionRefInvalid, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceTooLarge):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceTooLarge, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceInvalid):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceInvalid, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceSecret):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceInvalid, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceDivergence):
		writeErrorCode(w, http.StatusConflict, codeEvidenceDivergence, err.Error(), nil)
	case errors.Is(err, evidence.ErrEvidenceNotFound):
		writeErrorCode(w, http.StatusNotFound, codeEvidenceNotFound, "evidence not found", nil)
	case errors.Is(err, evidence.ErrEvidenceSupersedesInvalid):
		writeErrorCode(w, http.StatusUnprocessableEntity, codeEvidenceSupersedesInvalid, err.Error(), nil)
	case errors.Is(err, evidence.ErrCurrentQueryInvalid):
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceQueryInvalid, err.Error(), nil)
	case errors.Is(err, evidence.ErrCurrentPoolTooLarge):
		// Never a truncated no_evidence: the complete pool could not be
		// loaded, so the server cannot answer.
		writeErrorCode(w, http.StatusInternalServerError, codeEvidenceCurrentPoolTooLarge, err.Error(), nil)
	case errors.Is(err, evidence.ErrCurrentNotVisible):
		writeErrorCode(w, http.StatusForbidden, codeEvidenceCurrentNotVisible,
			"the current evidence for this subject depends on evidence outside this work item", nil)
	default:
		slog.Error("evidence store error", "error", err)
		writeError(w, http.StatusInternalServerError, "evidence store error")
	}
}

type ingestEvidenceRequest struct {
	// EnvelopeB64 is the base64 of the sealed Tier A envelope JSON,
	// verbatim. The envelope carries its own api_version, evidence_id and
	// content_hash; all three are verified server-side, so the wrapper
	// repeats none of them (design.md section 7).
	EnvelopeB64 string `json:"envelope_b64"`
}

type ingestEvidenceResponse struct {
	Evidence *evidence.Evidence `json:"evidence"`
}

// IngestEvidence handles POST /api/v1/evidence/records: validate, recompute
// identity, store the received bytes verbatim (or return the record already
// sealed with this content), and audit the accepted write.
func (h *Handlers) IngestEvidence(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireEvidenceWriter(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEvidenceBodyBytes)
	var req ingestEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// An over-large body surfaces from MaxBytesReader as a decode error;
		// answer with the documented evidence_too_large code, not
		// evidence_invalid.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorCode(w, http.StatusBadRequest, codeEvidenceTooLarge, "request body exceeds the evidence size limit", nil)
			return
		}
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceInvalid, "invalid JSON body", nil)
		return
	}
	envelopeBytes, err := base64.StdEncoding.Strict().DecodeString(req.EnvelopeB64)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceInvalid, "envelope_b64 is not standard base64", nil)
		return
	}
	if pattern, found := secretscan.Scan(envelopeBytes); found {
		writeErrorCode(w, http.StatusBadRequest, codeEvidenceInvalid, "envelope matches a secret pattern ("+pattern+")", nil)
		return
	}
	rec, created, err := h.opts.Evidence.Ingest(r.Context(), evidence.IngestInput{
		EnvelopeBytes:         envelopeBytes,
		IngestedBy:            user.ID,
		IngestedByPrincipalID: user.PrincipalID(),
	})
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	if created {
		kind, id := rec.PrimaryExecutionRef()
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: "evidence.ingest",
			Parameters: map[string]string{
				"evidence_id":      rec.ID,
				"primary_ref_kind": kind,
				"primary_ref_id":   id,
				"ingested_by":      user.ID,
			},
			Status:    "succeeded",
			RiskLevel: string(operations.RiskLow),
		})
	}
	writeJSON(w, createdStatus(created), ingestEvidenceResponse{Evidence: rec})
}

// GetEvidence handles GET /api/v1/evidence/{id}. Admin-only.
func (h *Handlers) GetEvidence(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireEvidenceAdmin(w, r); !ok {
		return
	}
	rec, err := h.opts.Evidence.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ingestEvidenceResponse{Evidence: rec})
}

// evidenceFilterFromQuery builds a Filter from query parameters. An
// unparseable issue/pr number is an error, matching usageFilterFromQuery's
// reasoning: a silently dropped filter would return a much larger answer
// than the one asked for.
func evidenceFilterFromQuery(r *http.Request) (evidence.Filter, error) {
	q := r.URL.Query()
	f := evidence.Filter{
		ExecutionID:        q.Get("execution_id"),
		RuntimeExecutionID: q.Get("runtime_execution_id"),
		TraceID:            q.Get("trace_id"),
		WorkItemID:         q.Get("work_item_id"),
		Engine:             q.Get("engine"),
		EngineRef:          q.Get("engine_ref"),
		Repository:         q.Get("repository"),
	}
	if err := subjectFilterFromQuery(r, &f); err != nil {
		return f, err
	}
	parseInt := func(key string) (*int64, error) {
		raw := q.Get(key)
		if raw == "" {
			return nil, nil
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, errors.New("invalid " + key)
		}
		return &v, nil
	}
	var err error
	if f.IssueNumber, err = parseInt("issue"); err != nil {
		return f, err
	}
	if f.PRNumber, err = parseInt("pr"); err != nil {
		return f, err
	}
	if (f.IssueNumber != nil || f.PRNumber != nil) && f.Repository == "" {
		return f, errors.New("issue and pr require repository")
	}
	if raw := q.Get("limit"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil || v <= 0 {
			return f, errors.New("invalid limit")
		}
		if v > evidence.MaxQueryLimit {
			return f, errors.New("limit exceeds " + strconv.Itoa(evidence.MaxQueryLimit))
		}
		f.Limit = v
	}
	return f, nil
}

// subjectFilterFromQuery reads the ADR 018 Amendment 2 subject filters
// (subject_kind, subject_repository, subject_ref, subject_revision). An
// unknown subject_kind is an error rather than a filter that silently
// matches nothing.
func subjectFilterFromQuery(r *http.Request, f *evidence.Filter) error {
	q := r.URL.Query()
	f.SubjectKind = q.Get("subject_kind")
	f.SubjectRepository = q.Get("subject_repository")
	f.SubjectRef = q.Get("subject_ref")
	f.SubjectRevision = q.Get("subject_revision")
	if f.SubjectKind != "" && !evidence.IsSubjectKind(f.SubjectKind) {
		return fmt.Errorf("%w: invalid subject_kind", evidence.ErrCurrentQueryInvalid)
	}
	return nil
}

// writeFilterError answers a rejected list filter: a subject-filter
// rejection carries the typed evidence_query_invalid code (the same one
// the current read uses), every older filter error keeps its plain 400.
func writeFilterError(w http.ResponseWriter, err error) {
	if errors.Is(err, evidence.ErrCurrentQueryInvalid) {
		writeEvidenceError(w, err)
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

// ListEvidence handles GET /api/v1/evidence with any combination of the
// supported filters. Admin-only. The response shape does not depend on
// which filters were supplied.
func (h *Handlers) ListEvidence(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireEvidenceAdmin(w, r); !ok {
		return
	}
	f, err := evidenceFilterFromQuery(r)
	if err != nil {
		writeFilterError(w, err)
		return
	}
	res, err := h.opts.Evidence.List(r.Context(), f)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ListWorkItemEvidence handles GET /api/v1/work-items/{id}/evidence. The
// caller must already be able to see the work item (visibleWorkItem
// answers 404, not 403, for one it may not) -- evidence never leaks past
// that.
func (h *Handlers) ListWorkItemEvidence(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	if h.opts.Evidence == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeEvidenceStoreUnavailable, "evidence store not configured", nil)
		return
	}
	var f evidence.Filter
	if err := subjectFilterFromQuery(r, &f); err != nil {
		writeFilterError(w, err)
		return
	}
	res, err := h.opts.Evidence.ByWorkItem(r.Context(), item.ID, f)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// currentQuery reads GET .../evidence/current's parameters. Validation is
// the store's (ValidateSubjectQuery): a malformed value answers 400
// evidence_query_invalid, never no_evidence. A repeated parameter is
// malformed too, rather than silently first-wins, and so is an unknown one:
// the list routes spell the same filters subject_ref/subject_revision, and
// a misspelled revision silently dropped would resolve at the wrong
// revision.
func currentQuery(r *http.Request) (evidence.SubjectQuery, error) {
	q := r.URL.Query()
	for key, values := range q {
		if !currentQueryKeys[key] {
			return evidence.SubjectQuery{}, fmt.Errorf("%w: unknown parameter %q (expected subject_kind, repository, ref, revision)",
				evidence.ErrCurrentQueryInvalid, key)
		}
		if len(values) > 1 {
			return evidence.SubjectQuery{}, fmt.Errorf("%w: %s given more than once", evidence.ErrCurrentQueryInvalid, key)
		}
	}
	return evidence.SubjectQuery{
		Kind:       q.Get("subject_kind"),
		Repository: q.Get("repository"),
		Ref:        q.Get("ref"),
		Revision:   q.Get("revision"),
	}, nil
}

var currentQueryKeys = map[string]bool{"subject_kind": true, "repository": true, "ref": true, "revision": true}

// CurrentEvidence handles GET /api/v1/evidence/current
// (?subject_kind=&repository=&ref=&revision=): ADR 018 Amendment 2's
// resolve_current over the complete stored pool, answering {state,
// evidence}. Admin-only, like GET /api/v1/evidence.
func (h *Handlers) CurrentEvidence(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireEvidenceAdmin(w, r); !ok {
		return
	}
	q, err := currentQuery(r)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	res, err := h.opts.Evidence.Current(r.Context(), q)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// CurrentWorkItemEvidence handles GET
// /api/v1/work-items/{id}/evidence/current: the work-item-scoped variant,
// behind visibleWorkItem (404 for an item the caller may not see). It
// resolves over the same complete pool as CurrentEvidence and answers only
// when every record that answer depends on is attached to this work item
// (403 evidence_current_not_visible otherwise) — evidence never leaks past
// the work item, and a partial pool is never resolved.
func (h *Handlers) CurrentWorkItemEvidence(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	if h.opts.Evidence == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeEvidenceStoreUnavailable, "evidence store not configured", nil)
		return
	}
	q, err := currentQuery(r)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	res, err := h.opts.Evidence.CurrentForWorkItem(r.Context(), q, item.ID)
	if err != nil {
		writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
