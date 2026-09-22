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

package usage

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestStore connects to the Postgres that .github/workflows/validate.yml
// runs as a service for the `test` job (image postgres:16, TEST_DATABASE_URL
// exported). The skip fires on a developer laptop, NOT in CI.
//
// These belong against a real database rather than a mock for the same reason
// the lifecycle store's do: the idempotency guarantee here IS the primary key.
// A mocked pool could only show that the code handles a conflict, never that
// the database produces one.
//
// Cleanup is scoped to the session prefix each test creates. The job runs
// `go test -p 1 ./...` because packages sharing this database were wiping each
// other's rows; an unscoped DELETE would recreate that from a new direction.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed usage ledger test")
	}
	ctx := context.Background()
	cat, err := NewCatalog([]Pricing{{
		Version: "test-v1", CanonicalModel: "test-model",
		EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InputPerMTok:  10, OutputPerMTok: 50,
	}})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	s, err := NewStore(ctx, connStr, cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	prefix := fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM model_usage_records WHERE session_id LIKE $1`, prefix+"%")
		s.Close()
	})
	return s, prefix
}

func testRecord(prefix, model string, at time.Time) *Record {
	return &Record{
		SessionID: prefix + "-session", ResultUUID: prefix + "-uuid",
		ModelKey: model, CanonicalModel: model, Provider: ProviderFirstParty,
		TemporalWorkflowID: prefix + "-wf", Agent: "implementer", DevLoopStage: "implement",
		TargetRepo: "mctlhq/mctl-api", IssueNumber: i64(266),
		InputTokens: i64(1_000_000), OutputTokens: i64(100_000),
		Outcome: OutcomeSuccess, NumTurns: i64(3), RecordedAt: at,
	}
}

// ADR-012 invariant 3: recording the same ResultMessage twice leaves exactly
// one row. This is the guarantee the whole ledger rests on — without it a
// Temporal retry double-counts a paid invocation.
func TestIngestIsIdempotent(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	first, err := s.Ingest(ctx, []*Record{testRecord(prefix, "test-model", at)})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if len(first.Accepted) != 1 || len(first.Deduped) != 0 {
		t.Fatalf("first ingest: accepted=%d deduped=%d, want 1/0", len(first.Accepted), len(first.Deduped))
	}
	second, err := s.Ingest(ctx, []*Record{testRecord(prefix, "test-model", at)})
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if len(second.Accepted) != 0 || len(second.Deduped) != 1 {
		t.Fatalf("replay: accepted=%d deduped=%d, want 0/1 — a paid invocation was counted twice",
			len(second.Accepted), len(second.Deduped))
	}
	got, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows after replay = %d, want 1", len(got))
	}
}

// ADR-012 invariant 2: a run spanning two models produces two records sharing
// a workflow id and differing in model.
func TestRunSpanningTwoModelsProducesTwoRows(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	res, err := s.Ingest(ctx, []*Record{
		testRecord(prefix, "test-model", at),
		testRecord(prefix, "other-model", at),
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(res.Accepted) != 2 {
		t.Fatalf("accepted = %d, want 2", len(res.Accepted))
	}
	got, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
}

// ADR-012 invariant 9: absent and zero survive a round-trip as different
// facts. This is the one a NOT NULL DEFAULT 0 column would silently destroy.
func TestAbsentAndZeroSurviveRoundTrip(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	absent := testRecord(prefix, "test-model", at)
	absent.SessionID = prefix + "-absent"
	absent.ResultUUID = prefix + "-absent-uuid"
	absent.CacheReadTokens = nil

	zero := testRecord(prefix, "test-model", at)
	zero.SessionID = prefix + "-zero"
	zero.ResultUUID = prefix + "-zero-uuid"
	zero.CacheReadTokens = i64(0)

	if _, err := s.Ingest(ctx, []*Record{absent, zero}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	rows, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var sawAbsent, sawZero bool
	for _, r := range rows {
		switch r.SessionID {
		case prefix + "-absent":
			sawAbsent = true
			if r.CacheReadTokens != nil {
				t.Errorf("unreported cache tokens came back as %d; 'not measured' became 'nothing spent'", *r.CacheReadTokens)
			}
		case prefix + "-zero":
			sawZero = true
			if r.CacheReadTokens == nil {
				t.Error("a reported zero came back as absent")
			} else if *r.CacheReadTokens != 0 {
				t.Errorf("reported zero came back as %d", *r.CacheReadTokens)
			}
		}
	}
	if !sawAbsent || !sawZero {
		t.Fatalf("missing rows: absent=%v zero=%v", sawAbsent, sawZero)
	}
}

// ADR-012 invariant 7, end to end: a later rate card does not reach back and
// change a stored cost.
func TestStoredCostSurvivesAPriceChange(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	if _, err := s.Ingest(ctx, []*Record{testRecord(prefix, "test-model", at)}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	before, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil || len(before) != 1 {
		t.Fatalf("List: %v (rows %d)", err, len(before))
	}
	if before[0].CalculatedCost == nil {
		t.Fatal("no calculated cost was stored")
	}
	original := *before[0].CalculatedCost
	if before[0].PricingVersion != "test-v1" {
		t.Fatalf("pricing version = %q, want test-v1", before[0].PricingVersion)
	}

	// The price doubles from July.
	newCat, err := NewCatalog([]Pricing{
		{Version: "test-v1", CanonicalModel: "test-model",
			EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), InputPerMTok: 10, OutputPerMTok: 50},
		{Version: "test-v2", CanonicalModel: "test-model",
			EffectiveFrom: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), InputPerMTok: 20, OutputPerMTok: 100},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	s.catalog = newCat

	after, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if *after[0].CalculatedCost != original {
		t.Errorf("stored cost changed from %v to %v after a price change", original, *after[0].CalculatedCost)
	}
	if after[0].PricingVersion != "test-v1" {
		t.Errorf("pricing version changed to %q", after[0].PricingVersion)
	}
}

// The ledger must answer the operator questions in mctl-api#266: by repo/issue,
// by agent stage, by model, over a window.
func TestSummaryAggregatesOverDimensions(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	investigator := testRecord(prefix, "test-model", at)
	investigator.SessionID = prefix + "-inv"
	investigator.ResultUUID = prefix + "-inv-uuid"
	investigator.Agent = "investigator"

	if _, err := s.Ingest(ctx, []*Record{testRecord(prefix, "test-model", at), investigator}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	buckets, err := s.Summary(ctx, Filter{TemporalWorkflowID: prefix + "-wf"}, GroupByAgent)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(buckets) != 2 {
		t.Fatalf("buckets = %d, want 2 (investigator, implementer)", len(buckets))
	}
	for _, b := range buckets {
		if b.Count != 1 {
			t.Errorf("bucket %q count = %d, want 1", b.Key, b.Count)
		}
		if b.InputTokens == nil || *b.InputTokens != 1_000_000 {
			t.Errorf("bucket %q input tokens = %v", b.Key, b.InputTokens)
		}
		// Under the subscription decision no record carries a provider cost,
		// and the summary must not invent one by folding in the estimate.
		if b.ProviderReportedCost != nil {
			t.Errorf("bucket %q reported a provider cost of %v; estimates must not read as invoice truth", b.Key, *b.ProviderReportedCost)
		}
	}
}

// Historical usage stays queryable independently of any trace backend: the
// rows are the ledger's own, keyed by correlation ids rather than by a live
// trace lookup.
func TestRecordsRemainQueryableByCorrelationWithoutTraceData(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	r := testRecord(prefix, "test-model", at)
	r.TraceID = ""
	r.SpanID = ""
	if _, err := s.Ingest(ctx, []*Record{r}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	issue := int64(266)
	got, err := s.List(ctx, Filter{TargetRepo: "mctlhq/mctl-api", IssueNumber: &issue})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, rec := range got {
		if rec.SessionID == r.SessionID {
			found = true
		}
	}
	if !found {
		t.Error("a record with no trace id could not be found by repo and issue")
	}
}

// The CHECK constraint is defence in depth: Ingest already rejects this via
// Validate, so this test writes straight to the table to prove the claim the
// schema comment makes. A future writer that does not go through Ingest — a
// backfill script, a reconciliation job — still cannot store an estimate whose
// rates are unknowable.
func TestDatabaseRefusesCalculatedCostWithoutPricingVersion(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()

	_, err := s.pool.Exec(ctx, `
INSERT INTO model_usage_records (id, schema_version, session_id, model_key, calculated_cost, pricing_version, recorded_at)
VALUES ($1, $2, $3, 'm', 1.23, '', NOW())`,
		prefix+"-bad", SchemaVersion, prefix+"-direct")
	if err == nil {
		t.Fatal("the database stored a calculated cost with no pricing version; it can never be reproduced")
	}
	if !strings.Contains(err.Error(), "calculated_cost_requires_version") {
		t.Fatalf("insert failed for the wrong reason: %v", err)
	}

	// The same row with a version is accepted, so the constraint is not just
	// rejecting everything.
	if _, err := s.pool.Exec(ctx, `
INSERT INTO model_usage_records (id, schema_version, session_id, model_key, calculated_cost, pricing_version, recorded_at)
VALUES ($1, $2, $3, 'm', 1.23, 'test-v1', NOW())`,
		prefix+"-good", SchemaVersion, prefix+"-direct"); err != nil {
		t.Fatalf("a priced row with a version was rejected: %v", err)
	}
}
