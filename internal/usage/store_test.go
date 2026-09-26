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
	"errors"
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

	first, err := s.IngestAs(ctx, Ingester{}, []*Record{testRecord(prefix, "test-model", at)})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if len(first.Accepted) != 1 || len(first.Deduped) != 0 {
		t.Fatalf("first ingest: accepted=%d deduped=%d, want 1/0", len(first.Accepted), len(first.Deduped))
	}
	second, err := s.IngestAs(ctx, Ingester{}, []*Record{testRecord(prefix, "test-model", at)})
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
	if len(got.Records) != 1 {
		t.Fatalf("rows after replay = %d, want 1", len(got.Records))
	}
}

// ADR-012 invariant 2: a run spanning two models produces two records sharing
// a workflow id and differing in model.
func TestRunSpanningTwoModelsProducesTwoRows(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	res, err := s.IngestAs(ctx, Ingester{}, []*Record{
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
	if len(got.Records) != 2 {
		t.Fatalf("rows = %d, want 2", len(got.Records))
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

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{absent, zero}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	rows, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var sawAbsent, sawZero bool
	for _, r := range rows.Records {
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

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{testRecord(prefix, "test-model", at)}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	before, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil || len(before.Records) != 1 {
		t.Fatalf("List: %v (rows %d)", err, len(before.Records))
	}
	if before.Records[0].CalculatedCost == nil {
		t.Fatal("no calculated cost was stored")
	}
	original := *before.Records[0].CalculatedCost
	if before.Records[0].PricingVersion != "test-v1" {
		t.Fatalf("pricing version = %q, want test-v1", before.Records[0].PricingVersion)
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
	if *after.Records[0].CalculatedCost != original {
		t.Errorf("stored cost changed from %v to %v after a price change", original, *after.Records[0].CalculatedCost)
	}
	if after.Records[0].PricingVersion != "test-v1" {
		t.Errorf("pricing version changed to %q", after.Records[0].PricingVersion)
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

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{testRecord(prefix, "test-model", at), investigator}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	res, err := s.Summary(ctx, Filter{TemporalWorkflowID: prefix + "-wf"}, GroupByAgent)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(res.Buckets) != 2 {
		t.Fatalf("buckets = %d, want 2 (investigator, implementer)", len(res.Buckets))
	}
	if res.Truncated {
		t.Error("a two-bucket summary reported itself truncated")
	}
	for _, b := range res.Buckets {
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
	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{r}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	issue := int64(266)
	got, err := s.List(ctx, Filter{TargetRepo: "mctlhq/mctl-api", IssueNumber: &issue})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, rec := range got.Records {
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

// Review round 1, agy finding 3: a producer that reports only model_key leaves
// canonical_model empty, and a filter on canonical_model alone omitted those
// rows — so a repository's spend read lower than it actually was.
func TestModelFilterMatchesRecordsWithoutCanonicalModel(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	bare := testRecord(prefix, "test-model", at)
	bare.SessionID = prefix + "-bare"
	bare.ResultUUID = prefix + "-bare-uuid"
	bare.CanonicalModel = "" // only model_key reported

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{bare}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	got, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf", CanonicalModel: "test-model"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, r := range got.Records {
		if r.SessionID == prefix+"-bare" {
			found = true
		}
	}
	if !found {
		t.Error("a record reported with model_key only was invisible to a model filter; spend would read low")
	}
}

// Review round 1, claude P2 (store.go:429): Summary had no LIMIT, so an
// unfiltered group-by on a high-cardinality dimension returned one bucket per
// workflow that ever ran.
func TestSummaryIsBoundedAndSaysSo(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	var batch []*Record
	for i := 0; i < 5; i++ {
		r := testRecord(prefix, "test-model", at)
		r.SessionID = fmt.Sprintf("%s-s%d", prefix, i)
		r.ResultUUID = fmt.Sprintf("%s-u%d", prefix, i)
		r.TemporalWorkflowID = fmt.Sprintf("%s-wf-%d", prefix, i)
		batch = append(batch, r)
	}
	if _, err := s.IngestAs(ctx, Ingester{}, batch); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	res, err := s.Summary(ctx, Filter{TargetRepo: "mctlhq/mctl-api", Limit: 2}, GroupByWorkflow)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(res.Buckets) != 2 {
		t.Fatalf("buckets = %d, want 2 (the limit)", len(res.Buckets))
	}
	if !res.Truncated {
		t.Error("a clipped bucket list did not report itself truncated; it reads as the whole breakdown")
	}
	if res.Limit != 2 {
		t.Errorf("limit = %d, want 2", res.Limit)
	}
}

// Review round 1, claude P2 (store.go:315): asking for more than the ceiling
// silently returned the DEFAULT page, i.e. fewer rows than asking for the
// ceiling, with nothing in the response saying so.
//
// Round 2 note: the first version of this test used three records, which
// cannot distinguish a clamp to 1000 from a reset to 200 — it passed against
// the unfixed code and locked in nothing. It needs more rows than the default
// page to discriminate, so it inserts 201 and asserts all 201 come back.
func TestOverLargeLimitClampsRatherThanShrinks(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	const rows = DefaultQueryLimit + 1
	var batch []*Record
	for i := 0; i < rows; i++ {
		r := testRecord(prefix, "test-model", at)
		r.SessionID = fmt.Sprintf("%s-c%d", prefix, i)
		r.ResultUUID = fmt.Sprintf("%s-cu%d", prefix, i)
		batch = append(batch, r)
	}
	if _, err := s.IngestAs(ctx, Ingester{}, batch); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	huge, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf", Limit: 50000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(huge.Records) != rows {
		t.Errorf("rows = %d, want %d; an over-large limit did not clamp to the ceiling (a reset to the %d default returns fewer than asking for the ceiling)",
			len(huge.Records), rows, DefaultQueryLimit)
	}
	if huge.Truncated {
		t.Error("a complete result reported itself truncated")
	}

	// And the default page truncates visibly rather than silently.
	def, err := s.List(ctx, Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(def.Records) != DefaultQueryLimit {
		t.Errorf("default page = %d rows, want %d", len(def.Records), DefaultQueryLimit)
	}
	if !def.Truncated {
		t.Error("a clipped page did not report itself truncated; it reads as the complete answer")
	}
}

// Review round 1, agy finding 1, at the boundary a client can actually reach.
func TestIngestRejectsNilRecordInBatch(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	_, err := s.IngestAs(ctx, Ingester{}, []*Record{testRecord(prefix, "test-model", at), nil})
	if err == nil {
		t.Fatal("a batch containing a null record was accepted")
	}
	if !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("error = %v, want ErrInvalidRecord (a 400, not a panic or a 500)", err)
	}
	if !strings.Contains(err.Error(), "record 1") {
		t.Errorf("error does not name the offending index: %v", err)
	}
}

// Review round 2, claude P3: the filter learned the model_key fallback in
// round 1 but group_by=canonical_model did not, so a per-model breakdown
// showed those records' spend under "" rather than under the model that
// incurred it.
func TestSummaryByModelUsesTheModelKeyFallback(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	bare := testRecord(prefix, "test-model", at)
	bare.SessionID = prefix + "-bare"
	bare.ResultUUID = prefix + "-bare-uuid"
	bare.CanonicalModel = "" // only model_key reported

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{bare}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	res, err := s.Summary(ctx, Filter{TemporalWorkflowID: prefix + "-wf"}, GroupByModel)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	for _, b := range res.Buckets {
		if b.Key == "" {
			t.Error("a model_key-only record was bucketed under the empty string instead of its model")
		}
		if b.Key != "test-model" {
			t.Errorf("bucket key = %q, want test-model", b.Key)
		}
	}
	if len(res.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(res.Buckets))
	}
}

// mctl-agents#499: a DevLoop's usage is queryable by its execution and by its
// pull request, not only by workflow name, and the execution survives the
// round trip.
func TestRecordsAreQueryableByExecutionAndPullRequest(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	inv := testRecord(prefix+"-inv", "test-model", at)
	inv.Agent, inv.ExecutionID = "investigator", prefix+"-we-1"
	impl := testRecord(prefix+"-impl", "test-model", at)
	impl.ExecutionID, impl.PRNumber = prefix+"-ex-2", i64(9001)
	other := testRecord(prefix+"-other", "test-model", at)
	other.TargetRepo, other.PRNumber, other.ExecutionID = "mctlhq/elsewhere", i64(9001), prefix+"-we-3"
	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{inv, impl, other}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	sessions := func(f Filter) []string {
		t.Helper()
		got, err := s.List(ctx, f)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var out []string
		for _, r := range got.Records {
			if strings.HasPrefix(r.SessionID, prefix) {
				out = append(out, r.SessionID)
			}
		}
		return out
	}

	byExec := sessions(Filter{ExecutionID: prefix + "-we-1"})
	if len(byExec) != 1 || byExec[0] != inv.SessionID {
		t.Errorf("execution filter: got %v, want only the investigator's row", byExec)
	}
	pr := int64(9001)
	byPR := sessions(Filter{TargetRepo: "mctlhq/mctl-api", PRNumber: &pr})
	if len(byPR) != 1 || byPR[0] != impl.SessionID {
		t.Errorf("repo+pr filter: got %v, want only mctl-api's PR 9001 row (not elsewhere's)", byPR)
	}

	got, err := s.List(ctx, Filter{ExecutionID: prefix + "-ex-2"})
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("List by execution: %v, %d rows", err, len(got.Records))
	}
	if got.Records[0].ExecutionID != prefix+"-ex-2" {
		t.Errorf("execution_id did not round-trip: %q", got.Records[0].ExecutionID)
	}

	sum, err := s.Summary(ctx, Filter{Since: &at}, GroupByExecution)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	seen := map[string]bool{}
	for _, b := range sum.Buckets {
		seen[b.Key] = true
	}
	for _, want := range []string{prefix + "-we-1", prefix + "-ex-2", prefix + "-we-3"} {
		if !seen[want] {
			t.Errorf("group_by=execution_id has no bucket %q", want)
		}
	}
}

// TestTemporalRunIDRoundTrips covers T1/T2: a record carrying a run id is
// queryable by it and round-trips byte-identical; a record with no run id is
// accepted and reads back as "".
func TestTemporalRunIDRoundTrips(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	withRun := testRecord(prefix+"-with-run", "test-model", at)
	withRun.TemporalRunID = "018f6e2a-6e2a-7e2a-8e2a-9e2a6e2a6e2a"
	otherRun := testRecord(prefix+"-other-run", "test-model", at)
	otherRun.TemporalRunID = "018f6e2a-0000-0000-0000-000000000000"
	noRun := testRecord(prefix+"-no-run", "test-model", at)

	if _, err := s.IngestAs(ctx, Ingester{}, []*Record{withRun, otherRun, noRun}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	got, err := s.List(ctx, Filter{TemporalRunID: withRun.TemporalRunID})
	if err != nil {
		t.Fatalf("List by run id: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("run id filter: got %d rows, want 1", len(got.Records))
	}
	if got.Records[0].TemporalRunID != withRun.TemporalRunID {
		t.Errorf("temporal_run_id did not round-trip: got %q, want %q",
			got.Records[0].TemporalRunID, withRun.TemporalRunID)
	}
	if got.Records[0].SessionID != withRun.SessionID {
		t.Errorf("run id filter matched the wrong row: %q", got.Records[0].SessionID)
	}

	noRunGot, err := s.List(ctx, Filter{TemporalWorkflowID: noRun.TemporalWorkflowID})
	if err != nil {
		t.Fatalf("List no-run record: %v", err)
	}
	if len(noRunGot.Records) != 1 {
		t.Fatalf("no-run record: got %d rows, want 1", len(noRunGot.Records))
	}
	if noRunGot.Records[0].TemporalRunID != "" {
		t.Errorf("no-run record: temporal_run_id = %q, want empty", noRunGot.Records[0].TemporalRunID)
	}
}

// TestTemporalRunIDDedupeKeepsFirstWrite covers T4: a replay carrying a
// different run id must not create a second row, and the surviving row keeps
// the first write's run id — ON CONFLICT DO NOTHING, same as ingested_by.
func TestTemporalRunIDDedupeKeepsFirstWrite(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	first := testRecord(prefix, "test-model", at)
	first.TemporalRunID = "018f6e2a-1111-1111-1111-111111111111"
	firstRes, err := s.IngestAs(ctx, Ingester{}, []*Record{first})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if len(firstRes.Accepted) != 1 {
		t.Fatalf("first ingest: accepted=%d, want 1", len(firstRes.Accepted))
	}

	replay := testRecord(prefix, "test-model", at)
	replay.TemporalRunID = "018f6e2a-2222-2222-2222-222222222222"
	replayRes, err := s.IngestAs(ctx, Ingester{}, []*Record{replay})
	if err != nil {
		t.Fatalf("replay ingest: %v", err)
	}
	if len(replayRes.Accepted) != 0 || len(replayRes.Deduped) != 1 {
		t.Fatalf("replay: accepted=%d deduped=%d, want 0/1", len(replayRes.Accepted), len(replayRes.Deduped))
	}

	got, err := s.List(ctx, Filter{TemporalWorkflowID: first.TemporalWorkflowID})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("rows after replay = %d, want 1", len(got.Records))
	}
	if got.Records[0].TemporalRunID != first.TemporalRunID {
		t.Errorf("dedupe overwrote the run id: got %q, want the first write's %q",
			got.Records[0].TemporalRunID, first.TemporalRunID)
	}
}

// TestTemporalRunIDSchemaIsAdditiveAndIdempotent covers T6: pre-existing rows
// (inserted before the column existed) stay readable with TemporalRunID == "",
// and re-applying usageSchema is a no-op.
func TestTemporalRunIDSchemaIsAdditiveAndIdempotent(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Simulate a row written before temporal_run_id existed, by inserting
	// through raw SQL naming only pre-change columns. The column's
	// NOT NULL DEFAULT '' makes this legal without naming it.
	sessionID := prefix + "-legacy-session"
	_, err := s.pool.Exec(ctx, `
INSERT INTO model_usage_records (
    id, schema_version, session_id, result_uuid, model_key, recorded_at
) VALUES ($1, $2, $3, $4, $5, $6)`,
		prefix+"-legacy-id", SchemaVersion, sessionID, prefix+"-legacy-uuid", "test-model", at)
	if err != nil {
		t.Fatalf("legacy insert: %v", err)
	}

	var runID string
	row := s.pool.QueryRow(ctx, `SELECT temporal_run_id FROM model_usage_records WHERE session_id = $1`, sessionID)
	if err := row.Scan(&runID); err != nil {
		t.Fatalf("scanning legacy row: %v", err)
	}
	if runID != "" {
		t.Errorf("legacy row: temporal_run_id = %q, want empty", runID)
	}

	// Applying the schema a second time must be a no-op.
	if _, err := s.pool.Exec(ctx, usageSchema); err != nil {
		t.Fatalf("re-applying usageSchema: %v", err)
	}
	if _, err := s.pool.Exec(ctx, usageSchema); err != nil {
		t.Fatalf("re-applying usageSchema a third time: %v", err)
	}
}
