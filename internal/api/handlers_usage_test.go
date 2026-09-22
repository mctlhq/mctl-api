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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/usage"
)

func newTestUsageStore(t *testing.T) (*usage.Store, string) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed usage handler test")
	}
	ctx := context.Background()
	cat, err := usage.NewCatalog([]usage.Pricing{{
		Version: "handler-v1", CanonicalModel: "test-model",
		EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InputPerMTok:  10, OutputPerMTok: 50,
	}})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	s, err := usage.NewStore(ctx, connStr, cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	prefix := fmt.Sprintf("apitest-%s-%d", t.Name(), time.Now().UnixNano())
	// Cleanup is scoped to this test's own session prefix, for the same reason
	// the lifecycle handler tests scope theirs: the job runs
	// `go test -p 1 ./...` because packages sharing this database were wiping
	// each other's rows, and an unscoped DELETE would recreate that.
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM model_usage_records WHERE session_id LIKE $1`, prefix+"%")
		pool.Close()
		s.Close()
	})
	return s, prefix
}

func usageRecordBody(prefix, session string) map[string]any {
	return map[string]any{
		"session_id": prefix + "-" + session, "result_uuid": prefix + "-" + session + "-uuid",
		"model_key": "test-model", "canonical_model": "test-model", "provider": "firstParty",
		"temporal_workflow_id": prefix + "-wf", "agent": "implementer", "devloop_stage": "implement",
		"target_repo": "mctlhq/mctl-api", "issue_number": 266,
		"input_tokens": 1000000, "output_tokens": 100000,
		"outcome": "success", "num_turns": 3,
		"recorded_at": "2026-06-01T12:00:00Z",
	}
}

func postUsage(t *testing.T, h *Handlers, body map[string]any, admin bool) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/v1/usage/records", bytes.NewReader(raw))
	if admin {
		req = adminCtx(req)
	}
	rec := httptest.NewRecorder()
	h.IngestUsageRecords(rec, req)
	return rec
}

// A nil ledger must be 503 on every endpoint. An operator asking what a DevLoop
// cost and receiving an empty, 200 answer from an unconfigured store would read
// "nothing was spent", which is the opposite of "we do not know".
func TestUsageHandlers_NilStoreIs503NotEmpty(t *testing.T) {
	h := &Handlers{opts: Options{}} // Usage left nil

	for name, fn := range map[string]http.HandlerFunc{
		"list":    h.ListUsageRecords,
		"summary": h.GetUsageSummary,
		"ingest":  h.IngestUsageRecords,
	} {
		req := adminCtx(httptest.NewRequest("GET", "/api/v1/usage/records", nil))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with nil store: want 503, got %d (body %s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestUsageHandlers_AuthBoundary(t *testing.T) {
	store, _ := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	for name, fn := range map[string]http.HandlerFunc{
		"list":    h.ListUsageRecords,
		"summary": h.GetUsageSummary,
		"ingest":  h.IngestUsageRecords,
	} {
		req := httptest.NewRequest("GET", "/api/v1/usage/records", nil)
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: want 401, got %d", name, rec.Code)
		}

		req = httptest.NewRequest("GET", "/api/v1/usage/records", nil)
		req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "t", Groups: []string{"some-tenant"}}))
		rec = httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s non-admin: want 403, got %d", name, rec.Code)
		}
	}
}

// Re-delivery is reported as deduped, not as an error and not as a second
// accepted record. A producer must be able to tell "already recorded" from
// "lost", and neither answer may ask it to retry into a double count.
func TestUsageHandlers_IngestIsIdempotentOverHTTP(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}
	body := map[string]any{"records": []any{usageRecordBody(prefix, "a")}}

	rec := postUsage(t, h, body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("first ingest: %d %s", rec.Code, rec.Body.String())
	}
	var first ingestUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.Accepted != 1 || first.Deduped != 0 {
		t.Fatalf("first: accepted=%d deduped=%d, want 1/0", first.Accepted, first.Deduped)
	}

	rec = postUsage(t, h, body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
	var second ingestUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if second.Accepted != 0 || second.Deduped != 1 {
		t.Fatalf("replay: accepted=%d deduped=%d, want 0/1 — a paid invocation was counted twice",
			second.Accepted, second.Deduped)
	}
}

// A calculated cost with no pricing version is a 400 with a reason, not a 500
// from a constraint violation.
func TestUsageHandlers_RejectsUnreproducibleCost(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	rec := usageRecordBody(prefix, "bad")
	rec["calculated_cost"] = 1.23
	// pricing_version deliberately omitted.
	resp := postUsage(t, h, map[string]any{"records": []any{rec}}, true)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", resp.Code, resp.Body.String())
	}
}

func TestUsageHandlers_RejectsEmptyAndOversizedBatch(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	if resp := postUsage(t, h, map[string]any{"records": []any{}}, true); resp.Code != http.StatusBadRequest {
		t.Errorf("empty batch: want 400, got %d", resp.Code)
	}
	big := make([]any, maxIngestBatch+1)
	for i := range big {
		big[i] = usageRecordBody(prefix, fmt.Sprintf("s%d", i))
	}
	if resp := postUsage(t, h, map[string]any{"records": big}, true); resp.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized batch: want 413, got %d", resp.Code)
	}
}

// An unparseable filter is an error, never a silently dropped predicate: a
// caller asking for one issue's spend and receiving the repository's total
// would read a much larger number as that issue's cost.
func TestUsageHandlers_BadFilterIsRejectedNotIgnored(t *testing.T) {
	store, _ := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	for _, q := range []string{"issue=not-a-number", "pr=x", "since=yesterday", "limit=0", "limit=-3"} {
		req := adminCtx(httptest.NewRequest("GET", "/api/v1/usage/records?"+q, nil))
		rec := httptest.NewRecorder()
		h.ListUsageRecords(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", q, rec.Code)
		}
	}
	// An unknown group_by is refused rather than defaulted, so a typo cannot
	// silently answer a different question.
	req := adminCtx(httptest.NewRequest("GET", "/api/v1/usage/summary?group_by=nonsense", nil))
	rec := httptest.NewRecorder()
	h.GetUsageSummary(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown group_by: want 400, got %d", rec.Code)
	}
}

// The end-to-end operator question from mctl-api#266: what did this DevLoop
// cost, broken down by agent?
func TestUsageHandlers_SummaryAnswersOperatorQuestion(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	impl := usageRecordBody(prefix, "impl")
	inv := usageRecordBody(prefix, "inv")
	inv["agent"] = "investigator"
	if resp := postUsage(t, h, map[string]any{"records": []any{impl, inv}}, true); resp.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", resp.Code, resp.Body.String())
	}

	req := adminCtx(httptest.NewRequest("GET",
		"/api/v1/usage/summary?group_by=agent&workflow_id="+prefix+"-wf", nil))
	rec := httptest.NewRecorder()
	h.GetUsageSummary(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		GroupBy   string          `json:"group_by"`
		Buckets   []*usage.Bucket `json:"buckets"`
		Truncated bool            `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Buckets) != 2 {
		t.Fatalf("buckets = %d, want 2", len(out.Buckets))
	}
	for _, b := range out.Buckets {
		if b.CalculatedCost == nil {
			t.Errorf("bucket %q has no calculated cost", b.Key)
		}
		if b.ProviderReportedCost != nil {
			t.Errorf("bucket %q reports a provider cost; an estimate must not read as invoice truth", b.Key)
		}
	}

	// The response must never carry model content — the type has no field for
	// it, and this guards the JSON shape a future change could widen.
	for _, banned := range []string{"prompt", "completion", "\"text\"", "\"content\""} {
		if strings.Contains(rec.Body.String(), banned) {
			t.Errorf("summary response contains %q", banned)
		}
	}
}

// Every other test in this file calls the handler directly, which is exactly
// how a missing route stayed invisible in the lifecycle work (see
// TestLifecycleRoutesAreRegistered). A handler with no route is an endpoint
// that does not exist.
func TestUsageRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, want := range []string{
		"POST /api/v1/usage/records",
		"GET /api/v1/usage/records",
		"GET /api/v1/usage/summary",
	} {
		if !found[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}

// Review round 1, claude P2: a client-chosen id must not reach the store. Over
// HTTP this is the path that matters — `id` is a plain JSON field, so nothing
// stopped a producer from sending one before.
func TestUsageHandlers_ClientSuppliedIDIsRejected(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	body := usageRecordBody(prefix, "spoof")
	body["id"] = "client-chosen-id"
	resp := postUsage(t, h, map[string]any{"records": []any{body}}, true)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a client-chosen id, got %d (%s)", resp.Code, resp.Body.String())
	}
}

// Review round 1, agy finding 1: {"records":[null]} panicked the process.
func TestUsageHandlers_NullRecordIsRejectedNotPanicked(t *testing.T) {
	store, _ := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("a null record panicked the handler: %v", rec)
		}
	}()
	resp := postUsage(t, h, map[string]any{"records": []any{nil}}, true)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a null record, got %d (%s)", resp.Code, resp.Body.String())
	}
}

// Review round 1, claude P2: an over-large limit is an error, not a quietly
// smaller page — the same rule the rest of the filters already follow.
func TestUsageHandlers_OverLargeLimitIsRejected(t *testing.T) {
	store, _ := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	req := adminCtx(httptest.NewRequest("GET", "/api/v1/usage/records?limit=5000", nil))
	rec := httptest.NewRecorder()
	h.ListUsageRecords(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("limit=5000: want 400, got %d", rec.Code)
	}
}

// Review round 1, claude P3: a batch over the byte cap read as "invalid JSON
// body", so a producer could not tell "do not retry" from "split and retry".
func TestUsageHandlers_OversizedBodyIs413NotMalformedJSON(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	body := usageRecordBody(prefix, "big")
	body["work_item_id"] = strings.Repeat("x", int(usageMaxBodyBytes)+1)
	raw, err := json.Marshal(map[string]any{"records": []any{body}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := adminCtx(httptest.NewRequest("POST", "/api/v1/usage/records", bytes.NewReader(raw)))
	rec := httptest.NewRecorder()
	h.IngestUsageRecords(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: want 413, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// Review round 1, agy finding 5: the list success path had no coverage.
func TestUsageHandlers_ListReturnsIngestedRecords(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}

	if resp := postUsage(t, h, map[string]any{"records": []any{usageRecordBody(prefix, "listed")}}, true); resp.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", resp.Code, resp.Body.String())
	}
	req := adminCtx(httptest.NewRequest("GET", "/api/v1/usage/records?workflow_id="+prefix+"-wf", nil))
	rec := httptest.NewRecorder()
	h.ListUsageRecords(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Records []*usage.Record `json:"records"`
		Count   int             `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 1 || len(out.Records) != 1 {
		t.Fatalf("count = %d, records = %d, want 1/1", out.Count, len(out.Records))
	}
	got := out.Records[0]
	if got.SessionID != prefix+"-listed" {
		t.Errorf("session_id = %q", got.SessionID)
	}
	if got.InputTokens == nil || *got.InputTokens != 1_000_000 {
		t.Errorf("input tokens = %v", got.InputTokens)
	}
	// The ledger's own derived cost must come back with the version that made it.
	if got.CalculatedCost == nil || got.PricingVersion != "handler-v1" {
		t.Errorf("cost = %v, pricing version = %q", got.CalculatedCost, got.PricingVersion)
	}
}
