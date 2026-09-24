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
// Authorization: the read side is admin-only, matching the lifecycle and
// agent-registry surfaces, for a reason specific to this data: aggregate spend
// per repository and per agent is commercially sensitive in a way that a
// workflow status is not. The write side needs usage:write, which admins hold
// and the dedicated usage-writer principal (mctlhq/.github#50) holds alone;
// every row records who ingested it.

const usageMaxBodyBytes = 1 << 20 // 1 MiB — a batch of records, never a payload.

// maxIngestBatch bounds one request. A producer with more records sends more
// requests; the deterministic id makes a split batch safe to retry.
const maxIngestBatch = 500

// The handler rejects an over-large limit rather than letting the store clamp
// it invisibly, and takes the ceiling FROM the store so the two cannot drift —
// a duplicated constant would eventually turn valid limits into 400s.

// usageWriterRoute is the one route the usage-writer principal may call.
const usageWriterRoute = "/api/v1/usage/records"

// usageWriterGate confines the usage-writer principal (mctlhq/.github#50)
// to appending usage records. Everything else, including the ledger's own
// reads and every admin route, answers 403 before any handler runs: the
// credential is a single capability, not an API key. Its reads stay
// admin-only because per-repository spend is commercially sensitive.
func usageWriterGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsUsageWriter() &&
			(r.Method != http.MethodPost || r.URL.Path != usageWriterRoute) {
			writeErrorCode(w, http.StatusForbidden, "usage_writer_route_not_allowed",
				"the usage writer may only call POST "+usageWriterRoute, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireUsageWriter admits the callers allowed to append records: those
// holding usage:write, which is the usage writer and, as before, admins.
func (h *Handlers) requireUsageWriter(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Usage == nil {
		writeError(w, http.StatusServiceUnavailable, "usage ledger not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.HasPermission(auth.PermissionUsageWrite) {
		writeError(w, http.StatusForbidden, "appending usage records requires "+auth.PermissionUsageWrite)
		return nil, false
	}
	return user, true
}

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

// listUsageResponse and summaryUsageResponse embed the store's result rather
// than copying its fields into a map.
//
// The hand-built map is what let `truncated_by` be set on the result, promised
// in the docs, and never reach a client: adding a field to the result did not
// add it to the response. Embedding makes that class of drift impossible —
// the wire shape follows the type.
type listUsageResponse struct {
	*usage.ListResult
	// Count is the size of THIS page, not the number of matching records.
	Count int `json:"count"`
}

type summaryUsageResponse struct {
	GroupBy string `json:"group_by"`
	*usage.SummaryResult
}

// ingestUsageResponse embeds the store result for the same reason the read
// responses do, and because flattening cost information: Accepted and Deduped
// arrive as two distinct lists, and concatenating them into one `ids` told a
// producer that two of five collided without saying WHICH two.
type ingestUsageResponse struct {
	*usage.IngestResult
	AcceptedCount int `json:"accepted_count"`
	DedupedCount  int `json:"deduped_count"`
}

// IngestUsageRecords accepts a batch of usage records idempotently.
//
// POST /api/v1/usage/records
//
// Re-delivery is a success, not an error: the response reports how many records
// were already present so a producer can tell a genuine no-op from a lost
// write, and neither outcome asks it to retry.
func (h *Handlers) IngestUsageRecords(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireUsageWriter(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, usageMaxBodyBytes)
	var req ingestUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// A batch over the byte cap must not read as malformed JSON: the
		// producer needs to tell "do not retry this" from "split and retry",
		// and the record-count cap below already answers 413.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge,
				"batch exceeds "+strconv.FormatInt(usageMaxBodyBytes, 10)+" bytes")
			return
		}
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
	res, err := h.opts.Usage.IngestAs(r.Context(), usage.Ingester{ID: user.ID, PrincipalID: user.PrincipalID()}, req.Records)
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
		IngestResult:  res,
		AcceptedCount: len(res.Accepted),
		DedupedCount:  len(res.Deduped),
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
		if v > usage.MaxQueryLimit {
			// Same rule as every other filter here: an out-of-range argument
			// is an error, never a quietly different answer. Returning a
			// smaller page than was asked for would have a caller summing
			// costs believe they had seen everything.
			return f, errors.New("limit exceeds " + strconv.Itoa(usage.MaxQueryLimit))
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
	res, err := h.opts.Usage.List(r.Context(), f)
	if err != nil {
		slog.Error("usage list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read usage records")
		return
	}
	// count travels with truncated: without that, a caller summing
	// calculated_cost over a busy week reads a clipped page as the complete
	// answer and understates real spend.
	writeJSON(w, http.StatusOK, listUsageResponse{ListResult: res, Count: len(res.Records)})
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
	res, err := h.opts.Usage.Summary(r.Context(), f, by)
	if err != nil {
		slog.Error("usage summary failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to summarize usage")
		return
	}
	writeJSON(w, http.StatusOK, summaryUsageResponse{GroupBy: string(by), SummaryResult: res})
}
