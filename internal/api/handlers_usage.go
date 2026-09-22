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

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/usage"
)

// Model usage ledger endpoints (mctl-api#266), implementing ADR-012.
//
// The ledger is a financial read model. It answers "what did this DevLoop
// cost", "what did investigator versus implementer spend", "what did repo X
// spend this week" — and it must keep answering them after trace data has aged
// out, which is why it is mctl-owned storage rather than a query over a
// tracing backend.
//
// Authorization is admin-only on both the write and the read side, matching the
// lifecycle and agent-registry surfaces. The read side is admin-only for a
// reason specific to this data: aggregate spend per repository and per agent is
// commercially sensitive in a way that a workflow status is not.

const usageMaxBodyBytes = 1 << 20 // 1 MiB — a batch of records, never a payload.

// maxIngestBatch bounds one request. A producer with more records sends more
// requests; the deterministic id makes a split batch safe to retry.
const maxIngestBatch = 500

// requireUsageAdmin mirrors requireLifecycleAdmin.
//
// A nil store is 503, not 404 or an empty result: "the ledger is not
// configured" and "this DevLoop cost nothing" must never be the same answer.
// An operator reading zero spend from an unconfigured ledger would conclude the
// opposite of the truth.
func (h *Handlers) requireUsageAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Usage == nil {
		writeError(w, http.StatusServiceUnavailable, "usage ledger not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "usage ledger is admin-only")
		return nil, false
	}
	return user, true
}

type ingestUsageRequest struct {
	Records []*usage.Record `json:"records"`
}

type ingestUsageResponse struct {
	Accepted int      `json:"accepted"`
	Deduped  int      `json:"deduped"`
	IDs      []string `json:"ids"`
}

// IngestUsageRecords accepts a batch of usage records idempotently.
//
// POST /api/v1/usage/records
//
// Re-delivery is a success, not an error: the response reports how many records
// were already present so a producer can tell a genuine no-op from a lost
// write, and neither outcome asks it to retry.
func (h *Handlers) IngestUsageRecords(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireUsageAdmin(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, usageMaxBodyBytes)
	var req ingestUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Records) == 0 {
		writeError(w, http.StatusBadRequest, "records must not be empty")
		return
	}
	if len(req.Records) > maxIngestBatch {
		writeError(w, http.StatusRequestEntityTooLarge, "batch exceeds "+strconv.Itoa(maxIngestBatch)+" records")
		return
	}
	res, err := h.opts.Usage.Ingest(r.Context(), req.Records)
	if err != nil {
		switch {
		case errors.Is(err, usage.ErrUnsupportedSchema), errors.Is(err, usage.ErrInvalidRecord):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			// The error may name a session id but never any model content —
			// the record type has no field of that shape.
			slog.Error("usage ingest failed", "error", err, "actor", user.ID)
			writeError(w, http.StatusInternalServerError, "failed to record usage")
		}
		return
	}
	writeJSON(w, http.StatusOK, ingestUsageResponse{
		Accepted: len(res.Accepted),
		Deduped:  len(res.Deduped),
		IDs:      append(append([]string{}, res.Accepted...), res.Deduped...),
	})
}

// usageFilterFromQuery builds a Filter from query parameters.
//
// An unparseable number is an error rather than a silently dropped filter: a
// caller asking for one issue's spend and receiving the whole repository's
// would read a much larger number as that issue's cost.
func usageFilterFromQuery(r *http.Request) (usage.Filter, error) {
	q := r.URL.Query()
	f := usage.Filter{
		TemporalWorkflowID: q.Get("workflow_id"),
		WorkItemID:         q.Get("work_item_id"),
		TargetRepo:         q.Get("repository"),
		Agent:              q.Get("agent"),
		DevLoopStage:       q.Get("stage"),
		Provider:           q.Get("provider"),
		CanonicalModel:     q.Get("model"),
		Outcome:            q.Get("outcome"),
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
	parseTime := func(key string) (*time.Time, error) {
		raw := q.Get(key)
		if raw == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, errors.New("invalid " + key + ": want RFC3339")
		}
		return &t, nil
	}
	if f.Since, err = parseTime("since"); err != nil {
		return f, err
	}
	if f.Until, err = parseTime("until"); err != nil {
		return f, err
	}
	if raw := q.Get("limit"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil || v <= 0 {
			return f, errors.New("invalid limit")
		}
		f.Limit = v
	}
	return f, nil
}

// ListUsageRecords returns matching ledger rows, newest first.
//
// GET /api/v1/usage/records
func (h *Handlers) ListUsageRecords(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireUsageAdmin(w, r); !ok {
		return
	}
	f, err := usageFilterFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	records, err := h.opts.Usage.List(r.Context(), f)
	if err != nil {
		slog.Error("usage list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read usage records")
		return
	}
	if records == nil {
		records = []*usage.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"records": records,
		"count":   len(records),
	})
}

// GetUsageSummary aggregates matching rows over one dimension.
//
// GET /api/v1/usage/summary?group_by=agent
//
// The response keeps provider_reported, calculated and invoice_reconciled cost
// apart rather than returning one total. Summing them would produce a number
// that is neither an estimate nor an invoice, and whoever read it could not
// tell which.
func (h *Handlers) GetUsageSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireUsageAdmin(w, r); !ok {
		return
	}
	f, err := usageFilterFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw := r.URL.Query().Get("group_by")
	if raw == "" {
		raw = string(usage.GroupByAgent)
	}
	by, ok := usage.ParseGroupBy(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown group_by")
		return
	}
	buckets, err := h.opts.Usage.Summary(r.Context(), f, by)
	if err != nil {
		slog.Error("usage summary failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to summarize usage")
		return
	}
	if buckets == nil {
		buckets = []*usage.Bucket{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"group_by": string(by),
		"buckets":  buckets,
	})
}
