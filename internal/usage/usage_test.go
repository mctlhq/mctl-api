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
	"reflect"
	"strings"
	"testing"
	"time"
)

func i64(v int64) *int64 { return &v }

// ADR-012 invariant 8: the record has no field that can hold prompt or
// completion text.
//
// This is asserted over the struct rather than over a redaction helper on
// purpose. A redaction test proves that one code path scrubs a field; this
// proves there is no field to scrub, which is the actual guarantee and the one
// that survives a future producer written by someone who never read the ADR.
func TestRecordHasNoFreeTextContentField(t *testing.T) {
	forbidden := []string{"prompt", "completion", "message", "content", "text", "body", "response", "input_text", "output_text"}
	rt := reflect.TypeOf(Record{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, bad := range forbidden {
			if name == bad {
				t.Errorf("Record has field %q, which can carry model content; ADR-012 invariant 8 forbids it", rt.Field(i).Name)
			}
		}
	}
}

// ADR-012: the dedupe key is deterministic, so a replay lands on the same id.
func TestDeterministicIDIsStableAndScoped(t *testing.T) {
	a := DeterministicID("sess-1", "uuid-1", "claude-opus-5", i64(3))
	b := DeterministicID("sess-1", "uuid-1", "claude-opus-5", i64(3))
	if a != b {
		t.Fatalf("id is not deterministic: %s vs %s", a, b)
	}
	// Invariant 2: a run spanning two models produces two records.
	if c := DeterministicID("sess-1", "uuid-1", "claude-haiku-4-5", i64(3)); c == a {
		t.Error("two models in one run collapsed onto one id")
	}
	// A different session is a different paid invocation.
	if c := DeterministicID("sess-2", "uuid-1", "claude-opus-5", i64(3)); c == a {
		t.Error("two sessions collapsed onto one id")
	}
}

// ADR-012: result_uuid is nullable on older CLIs; the fallback keeps two
// results for one model in one session apart.
func TestDeterministicIDFallsBackWithoutResultUUID(t *testing.T) {
	a := DeterministicID("sess-1", "", "claude-opus-5", i64(3))
	b := DeterministicID("sess-1", "", "claude-opus-5", i64(3))
	if a != b {
		t.Fatal("fallback id is not deterministic")
	}
	if c := DeterministicID("sess-1", "", "claude-opus-5", i64(4)); c == a {
		t.Error("num_turns does not separate two results for one model in one session")
	}
	if c := DeterministicID("sess-1", "uuid-1", "claude-opus-5", i64(3)); c == a {
		t.Error("fallback id collides with the uuid-based id")
	}
}

// ADR-012 invariant 4: a retry that RE-RUNS the model is a new invocation with
// a real new charge, and must not be deduped. retry_attempt is deliberately
// absent from the key — the new session_id is what separates them.
func TestRetryThatRerunsTheModelIsNotDeduped(t *testing.T) {
	first := DeterministicID("sess-attempt-1", "uuid-a", "claude-opus-5", i64(2))
	second := DeterministicID("sess-attempt-2", "uuid-b", "claude-opus-5", i64(2))
	if first == second {
		t.Fatal("a re-run of the model collapsed onto the first attempt's id; the charge would be lost")
	}
}

// ADR-012 invariant 6, at the layer that rejects before the database has to.
func TestCalculatedCostRequiresPricingVersion(t *testing.T) {
	cost := 1.25
	r := &Record{SessionID: "s", ModelKey: "m", CalculatedCost: &cost}
	if err := r.EnsureID(); err != nil {
		t.Fatalf("EnsureID: %v", err)
	}
	if err := r.Validate(); err == nil {
		t.Fatal("a calculated cost with no pricing version was accepted; it can never be reproduced")
	}
	r.PricingVersion = "2026-09-01"
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate with a pricing version: %v", err)
	}
}

func TestEnsureIDRejectsUnknownSchemaVersion(t *testing.T) {
	r := &Record{SchemaVersion: 99, SessionID: "s", ModelKey: "m"}
	if err := r.EnsureID(); err == nil {
		t.Fatal("a record from a future schema was accepted, so it would be misread rather than refused")
	}
}

// ADR-012 invariant 7: a price-table change must not alter a stored cost. The
// catalog resolves by the instant of the invocation, never by "latest".
func TestCatalogResolvesByInstantNotLatest(t *testing.T) {
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	oct := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cat, err := NewCatalog([]Pricing{
		{Version: "v-oct", CanonicalModel: "m", EffectiveFrom: oct, InputPerMTok: 20},
		{Version: "v-sep", CanonicalModel: "m", EffectiveFrom: sep, InputPerMTok: 10},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	r := &Record{
		SessionID: "s", ModelKey: "m", CanonicalModel: "m",
		RecordedAt:  time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
		InputTokens: i64(1_000_000),
	}
	if err := cat.Calculate(r); err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if r.PricingVersion != "v-sep" {
		t.Errorf("pricing version = %q, want v-sep: a September run was priced with a later card", r.PricingVersion)
	}
	switch {
	case r.CalculatedCost == nil:
		t.Error("calculated cost is absent, want 10")
	case *r.CalculatedCost != 10:
		t.Errorf("calculated cost = %v, want 10", *r.CalculatedCost)
	}
	// A run before any card has no price rather than a wrong one.
	early := &Record{SessionID: "s", ModelKey: "m", CanonicalModel: "m",
		RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), InputTokens: i64(1_000_000)}
	if err := cat.Calculate(early); err == nil {
		t.Error("a run predating every rate card was priced anyway")
	}
}

// ADR-012: absent is not zero. An unreported dimension contributes nothing to
// the cost AND stays absent on the record.
func TestCalculateTreatsAbsentAsUnmeasuredNotZero(t *testing.T) {
	cat, err := NewCatalog([]Pricing{{
		Version: "v1", CanonicalModel: "m",
		EffectiveFrom:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InputPerMTok:     10,
		CacheReadPerMTok: 1,
	}})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	unreported := &Record{SessionID: "s", ModelKey: "m", CanonicalModel: "m",
		RecordedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), InputTokens: i64(1_000_000)}
	reportedZero := &Record{SessionID: "s2", ModelKey: "m", CanonicalModel: "m",
		RecordedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), InputTokens: i64(1_000_000), CacheReadTokens: i64(0)}
	for _, r := range []*Record{unreported, reportedZero} {
		if err := cat.Calculate(r); err != nil {
			t.Fatalf("Calculate: %v", err)
		}
	}
	if *unreported.CalculatedCost != *reportedZero.CalculatedCost {
		t.Error("an unreported dimension and a reported zero produced different costs")
	}
	if unreported.CacheReadTokens != nil {
		t.Error("Calculate invented a zero for an unreported dimension")
	}
	if reportedZero.CacheReadTokens == nil {
		t.Error("Calculate erased a reported zero")
	}
}

// ADR-012: a provider-reported cost is never overwritten by an estimate.
func TestCalculateDoesNotOverwriteProviderReportedCost(t *testing.T) {
	cat, err := NewCatalog([]Pricing{{
		Version: "v1", CanonicalModel: "m",
		EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), InputPerMTok: 10,
	}})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	reported := 4.2
	r := &Record{SessionID: "s", ModelKey: "m", CanonicalModel: "m",
		RecordedAt:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		InputTokens: i64(1_000_000), ProviderReportedCost: &reported}
	if err := cat.Calculate(r); err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if r.CalculatedCost != nil {
		t.Error("an estimate was written over a provider-reported cost")
	}
	if *r.ProviderReportedCost != 4.2 {
		t.Error("the provider-reported cost was modified")
	}
}

func TestParseGroupByRejectsUnknownDimension(t *testing.T) {
	if _, ok := ParseGroupBy("agent"); !ok {
		t.Error("agent should be a known dimension")
	}
	// The set is closed so that a query parameter can never reach SQL.
	if _, ok := ParseGroupBy("target_repo; DROP TABLE model_usage_records"); ok {
		t.Error("an arbitrary string was accepted as a group-by dimension")
	}
}

// Review round 1, claude P2 (types.go:181): the id was only derived when the
// producer did not send one, which made the central idempotency guarantee
// opt-out. A producer emitting a fresh uuid per delivery would get a new row
// per retry and double-count a paid invocation.
func TestSuppliedIDCannotBypassTheDedupeKey(t *testing.T) {
	derived := DeterministicID("sess-1", "uuid-1", "model-a", i64(2))

	r := &Record{SessionID: "sess-1", ResultUUID: "uuid-1", ModelKey: "model-a", NumTurns: i64(2),
		ID: "00000000-client-chosen-0000"}
	if err := r.EnsureID(); err == nil {
		t.Fatal("a client-chosen id was accepted; every retry would create a new row")
	}

	// A producer that computes the key correctly is not penalised.
	ok := &Record{SessionID: "sess-1", ResultUUID: "uuid-1", ModelKey: "model-a", NumTurns: i64(2), ID: derived}
	if err := ok.EnsureID(); err != nil {
		t.Fatalf("a correctly derived id was rejected: %v", err)
	}
	if ok.ID != derived {
		t.Errorf("id = %q, want %q", ok.ID, derived)
	}
}

// Review round 1, claude P3 (types.go:162): an unescaped separator let
// distinct field tuples hash alike. A collision is not a bad read — it is a
// paid invocation that ON CONFLICT DO NOTHING discards.
func TestDeterministicIDResistsDelimiterInjection(t *testing.T) {
	if DeterministicID("a", "b|c", "d", nil) == DeterministicID("a", "b", "c|d", nil) {
		t.Error("delimiter injection: two different field tuples share a digest")
	}
	// The fallback shape must not collide with the uuid shape.
	if DeterministicID("s", "X", "3", nil) == DeterministicID("s", "", "X", i64(3)) {
		t.Error("the no-result fallback collides with the uuid form")
	}
}

// Review round 1, claude P2 + agy finding 2 (pricing.go): Provider was parsed,
// documented and never consulted, so a Bedrock card priced a firstParty
// invocation. Those rates genuinely differ — this is wrong money, not untidy
// code.
func TestPricingIsResolvedPerProvider(t *testing.T) {
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cat, err := NewCatalog([]Pricing{
		{Version: "first-jan", CanonicalModel: "m", Provider: ProviderFirstParty, EffectiveFrom: jan, InputPerMTok: 10},
		{Version: "bedrock-sep", CanonicalModel: "m", Provider: ProviderBedrock, EffectiveFrom: sep, InputPerMTok: 20},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	first := &Record{SessionID: "s", ModelKey: "m", CanonicalModel: "m", Provider: ProviderFirstParty,
		RecordedAt: at, InputTokens: i64(1_000_000)}
	if err := cat.Calculate(first); err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if first.PricingVersion != "first-jan" || *first.CalculatedCost != 10 {
		t.Errorf("firstParty priced with %q at %v; the later Bedrock card leaked across providers",
			first.PricingVersion, *first.CalculatedCost)
	}

	bedrock := &Record{SessionID: "s2", ModelKey: "m", CanonicalModel: "m", Provider: ProviderBedrock,
		RecordedAt: at, InputTokens: i64(1_000_000)}
	if err := cat.Calculate(bedrock); err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if bedrock.PricingVersion != "bedrock-sep" || *bedrock.CalculatedCost != 20 {
		t.Errorf("bedrock priced with %q at %v", bedrock.PricingVersion, *bedrock.CalculatedCost)
	}
}

// A card with no provider is a wildcard, so a single-rate catalog keeps
// working without naming every provider.
func TestProviderlessCardIsAWildcard(t *testing.T) {
	cat, err := NewCatalog([]Pricing{
		{Version: "any", CanonicalModel: "m", EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), InputPerMTok: 7},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	r := &Record{SessionID: "s", ModelKey: "m", CanonicalModel: "m", Provider: ProviderVertex,
		RecordedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), InputTokens: i64(1_000_000)}
	if err := cat.Calculate(r); err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if *r.CalculatedCost != 7 {
		t.Errorf("wildcard card did not apply: cost = %v", *r.CalculatedCost)
	}
}

// Two cards in force at the same instant have no correct answer. Resolving it
// by sort order would price identical records differently between restarts,
// which is invariant 7 broken by a different route.
func TestCatalogRejectsTwoCardsEffectiveAtTheSameInstant(t *testing.T) {
	at := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := NewCatalog([]Pricing{
		{Version: "a", CanonicalModel: "m", Provider: ProviderFirstParty, EffectiveFrom: at, InputPerMTok: 10},
		{Version: "b", CanonicalModel: "m", Provider: ProviderFirstParty, EffectiveFrom: at, InputPerMTok: 20},
	})
	if err == nil {
		t.Fatal("a catalog with two cards effective at the same instant was accepted")
	}
}

// Review round 1, agy finding 1: {"records":[null]} decoded to a nil element
// and the ingest loop dereferenced it, panicking the process.
func TestNilRecordIsRejectedNotPanicked(t *testing.T) {
	r := (*Record)(nil)
	if err := r.EnsureID(); err == nil {
		t.Error("EnsureID accepted a nil record")
	}
	if err := r.Validate(); err == nil {
		t.Error("Validate accepted a nil record")
	}
}

// Review round 1, agy finding 4: the catalog loader had no test at all.
func TestParseCatalogReadsARateCardDocument(t *testing.T) {
	cat, err := ParseCatalog([]byte(`[
	  {"version":"2026-09-01","canonical_model":"m","provider":"firstParty",
	   "effective_from":"2026-09-01T00:00:00Z","input_per_mtok":3,"output_per_mtok":15}
	]`))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	p, ok := cat.At("m", ProviderFirstParty, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("the parsed card did not resolve")
	}
	if p.Version != "2026-09-01" || p.InputPerMTok != 3 {
		t.Errorf("parsed card = %+v", p)
	}
	if _, err := ParseCatalog([]byte(`{"not":"an array"}`)); err == nil {
		t.Error("a malformed catalog document was accepted")
	}
	if _, err := ParseCatalog([]byte(`[{"canonical_model":"m","effective_from":"2026-09-01T00:00:00Z"}]`)); err == nil {
		t.Error("a card with no version was accepted; its cost could never be reproduced")
	}
}
