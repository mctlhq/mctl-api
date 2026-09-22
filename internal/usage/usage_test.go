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
