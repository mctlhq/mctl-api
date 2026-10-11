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

package commerce

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		// Rows are keyed by the test's own capability prefix; the FK order is
		// transitions, invocations, quotes, terms.
		_, _ = s.pool.Exec(ctx, `DELETE FROM commerce_invocation_transitions WHERE invocation_id IN
			(SELECT invocation_id FROM commerce_invocations WHERE capability_id LIKE 'mctl://test-commerce/%')`)
		_, _ = s.pool.Exec(ctx, `DELETE FROM commerce_invocations WHERE capability_id LIKE 'mctl://test-commerce/%'`)
		_, _ = s.pool.Exec(ctx, `DELETE FROM commerce_quotes WHERE capability_id LIKE 'mctl://test-commerce/%'`)
		_, _ = s.pool.Exec(ctx, `DELETE FROM commerce_terms WHERE capability_id LIKE 'mctl://test-commerce/%'`)
		s.Close()
	})
	return s
}

var schemaHash = "sha256:" + strings.Repeat("ab", 32)

func testCapability(t *testing.T) string {
	return "mctl://test-commerce/" + strings.ToLower(t.Name()) + "/" + newULID(time.Now())
}

func publish(t *testing.T, s *Store, cap string, mode string, amount int64) *Terms {
	t.Helper()
	terms, err := s.PublishTerms(context.Background(), PublishTermsInput{
		CapabilityID:    cap,
		InputSchemaHash: schemaHash,
		ProviderID:      "pilot-provider",
		PriceMode:       mode,
		Price:           Money{Currency: "EUR", AmountMinor: amount},
		FundsMode:       FundsModeSimulated,
		QuoteTTLSeconds: 300,
		EffectiveFrom:   time.Now().Add(-time.Minute),
		PublishedBy:     "prn_admin",
	})
	if err != nil {
		t.Fatalf("PublishTerms: %v", err)
	}
	return terms
}

func ids(tenant string) Identities {
	return Identities{
		TenantID:           tenant,
		PrincipalID:        "prn_01JZ8Q0000000000000000000A",
		SubjectPrincipalID: "prn_01JZ8Q0000000000000000000A",
		PayerAccountID:     "acct_tenant_" + tenant,
		ExecutionID:        "we_01JZ8Q0000000000000000000C",
	}
}

func mint(t *testing.T, s *Store, cap string, id Identities) *Quote {
	t.Helper()
	q, err := s.MintQuote(context.Background(), MintQuoteInput{
		CapabilityID: cap, InputSchemaHash: schemaHash, Identities: id, ArgsDigest: goldenArgsDigest,
	})
	if err != nil {
		t.Fatalf("MintQuote: %v", err)
	}
	return q
}

func accept(t *testing.T, s *Store, q *Quote, key string) *AcceptResult {
	t.Helper()
	res, err := s.AcceptInvocation(context.Background(), AcceptInvocationInput{
		QuoteID: q.QuoteID, QuoteDigest: q.QuoteDigest, IdempotencyKey: key,
		Identities: q.Identities, ArgsDigest: q.ArgsDigest,
	})
	if err != nil {
		t.Fatalf("AcceptInvocation: %v", err)
	}
	return res
}

func TestTermsAreImmutableAndVersioned(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	v1 := publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	if v1.TermsVersion != 1 || !strings.HasPrefix(v1.TermsID, TermsIDPrefix) || v1.Meter != MeterInvocation {
		t.Fatalf("v1 = %+v", v1)
	}
	v2 := publish(t, s, cap, PriceModePerSuccessfulCall, 15)
	if v2.TermsID != v1.TermsID || v2.TermsVersion != 2 {
		t.Fatalf("v2 = %+v", v2)
	}
	cur, err := s.CurrentTerms(ctx, cap, schemaHash)
	if err != nil || cur.TermsVersion != 2 || cur.Price.AmountMinor != 15 {
		t.Fatalf("CurrentTerms = %+v, %v", cur, err)
	}
	old, err := s.GetTerms(ctx, v1.TermsID, 1)
	if err != nil || old.Price.AmountMinor != 12 {
		t.Fatalf("v1 changed: %+v, %v", old, err)
	}
	// A second terms id for the same capability is refused.
	_, err = s.PublishTerms(ctx, PublishTermsInput{
		TermsID: "ctm_01JZ8PZ0000000000000000000", CapabilityID: cap, InputSchemaHash: schemaHash,
		ProviderID: "p", PriceMode: PriceModePerCall, Price: Money{Currency: "EUR", AmountMinor: 1},
		FundsMode: FundsModeSimulated, QuoteTTLSeconds: 60, EffectiveFrom: time.Now(), PublishedBy: "prn_admin",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("second terms id accepted: %v", err)
	}
	// An unknown capability is not free.
	if _, err := s.CurrentTerms(ctx, cap+"/missing", schemaHash); !errors.Is(err, ErrTermsNotFound) {
		t.Fatalf("missing terms: %v", err)
	}
	// A different input schema hash is a different capability version.
	if _, err := s.CurrentTerms(ctx, cap, "sha256:"+strings.Repeat("cd", 32)); !errors.Is(err, ErrTermsNotFound) {
		t.Fatalf("other schema hash resolved: %v", err)
	}
	list, err := s.ListTerms(ctx, cap)
	if err != nil || len(list) != 2 || list[0].TermsVersion != 2 {
		t.Fatalf("ListTerms = %+v, %v", list, err)
	}
}

func TestMintQuoteBindsIdentitiesAndDigest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	terms := publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	id := ids("acme")
	q := mint(t, s, cap, id)
	if q.TermsID != terms.TermsID || q.TermsVersion != 1 || q.Price.AmountMinor != 12 || q.Identities != id {
		t.Fatalf("quote = %+v", q)
	}
	if QuoteDigest(*q) != q.QuoteDigest {
		t.Fatal("stored digest does not recompute")
	}
	ttl := time.Until(q.ExpiresAt)
	if ttl < 290*time.Second || ttl > 300*time.Second {
		t.Fatalf("ttl = %s", ttl)
	}
	if q.ExpiresAt.Nanosecond() != 0 {
		t.Fatal("expires_at must be second precision")
	}
	got, err := s.GetQuote(ctx, "acme", q.QuoteID)
	if err != nil || got.QuoteDigest != q.QuoteDigest {
		t.Fatalf("GetQuote = %+v, %v", got, err)
	}
	if _, err := s.GetQuote(ctx, "other", q.QuoteID); !errors.Is(err, ErrQuoteNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	bad := MintQuoteInput{CapabilityID: cap, InputSchemaHash: schemaHash, Identities: id, ArgsDigest: goldenArgsDigest}
	bad.SubjectPrincipalID = "prn_01JZ8Q0000000000000000000B"
	if _, err := s.MintQuote(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delegated subject without grant accepted: %v", err)
	}
	bad.ExecutionID = ""
	bad.SubjectPrincipalID = id.PrincipalID
	if _, err := s.MintQuote(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing execution_id accepted: %v", err)
	}
}

func TestAcceptIsIdempotentWithinScopeAndConflictsOnChange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	id := ids("acme")
	q := mint(t, s, cap, id)

	first := accept(t, s, q, "key-1")
	if first.Replayed || first.Invocation.Phase != PhaseAccepted || first.Invocation.PaymentStatus != PaymentNone ||
		first.Invocation.ChargeStatus != ChargeNone || first.Invocation.ExecutionOutcome != OutcomeNotDispatched {
		t.Fatalf("first = %+v", first.Invocation)
	}
	if first.Invocation.ProviderOpKey != "mctl-op/v1:"+first.Invocation.InvocationID {
		t.Fatalf("op key = %s", first.Invocation.ProviderOpKey)
	}
	if !first.Invocation.QuoteExpiresAt.Equal(q.ExpiresAt) {
		t.Fatalf("quote_expires_at = %s, want %s", first.Invocation.QuoteExpiresAt, q.ExpiresAt)
	}

	// Same key, same digest: the original row, no second row.
	again := accept(t, s, q, "key-1")
	if !again.Replayed || again.Invocation.InvocationID != first.Invocation.InvocationID {
		t.Fatalf("replay = %+v", again)
	}

	// Same key, different payload: conflict, never a fresh row.
	q2 := mint(t, s, cap, id)
	_, err := s.AcceptInvocation(ctx, AcceptInvocationInput{
		QuoteID: q2.QuoteID, QuoteDigest: q2.QuoteDigest, IdempotencyKey: "key-1",
		Identities: id, ArgsDigest: q2.ArgsDigest,
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed payload under same key: %v", err)
	}

	// Same key in another tenant is a different scope.
	other := ids("beta")
	q3 := mint(t, s, cap, other)
	third := accept(t, s, q3, "key-1")
	if third.Replayed || third.Invocation.InvocationID == first.Invocation.InvocationID {
		t.Fatalf("scope leaked across tenants: %+v", third)
	}

	// A quote binds exactly one invocation.
	_, err = s.AcceptInvocation(ctx, AcceptInvocationInput{
		QuoteID: q.QuoteID, QuoteDigest: q.QuoteDigest, IdempotencyKey: "key-2",
		Identities: id, ArgsDigest: q.ArgsDigest,
	})
	if !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("quote reused under a new key: %v", err)
	}

	list, err := s.ListInvocations(ctx, ListFilter{TenantID: "acme"})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListInvocations acme = %d, %v", len(list), err)
	}
	hist, err := s.ListTransitions(ctx, "acme", first.Invocation.InvocationID)
	if err != nil || len(hist) != 1 || hist[0].ToPhase != PhaseAccepted || hist[0].FromPhase != "" {
		t.Fatalf("history = %+v, %v", hist, err)
	}
}

func TestAcceptRefusesTamperedExpiredStaleAndForeignQuotes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	terms := publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	id := ids("acme")
	q := mint(t, s, cap, id)
	base := AcceptInvocationInput{QuoteID: q.QuoteID, QuoteDigest: q.QuoteDigest, IdempotencyKey: "k",
		Identities: id, ArgsDigest: q.ArgsDigest}

	in := base
	in.QuoteDigest = "sha256:" + strings.Repeat("00", 32)
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("wrong digest: %v", err)
	}
	in = base
	in.ArgsDigest = "sha256:" + strings.Repeat("00", 32)
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("wrong args: %v", err)
	}
	in = base
	in.Identities.PayerAccountID = "acct_other"
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("other payer: %v", err)
	}
	in = base
	in.Identities.TenantID = "beta"
	in.Identities.PayerAccountID = "acct_tenant_beta"
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteNotFound) {
		t.Fatalf("cross-tenant accept: %v", err)
	}
	in = base
	in.TermsBinding = "sha256:" + strings.Repeat("11", 32)
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("wrong terms binding: %v", err)
	}
	in = base
	in.TermsBinding = TermsBinding(*terms, id.TenantID, id.PayerAccountID)
	if _, err := s.AcceptInvocation(ctx, in); err != nil {
		t.Fatalf("correct terms binding refused: %v", err)
	}

	// Tampering with the stored row is caught by recomputation.
	q4 := mint(t, s, cap, id)
	if _, err := s.pool.Exec(ctx, `UPDATE commerce_quotes SET amount_minor = 1 WHERE quote_id = $1`, q4.QuoteID); err != nil {
		t.Fatal(err)
	}
	in = base
	in.QuoteID, in.QuoteDigest, in.IdempotencyKey = q4.QuoteID, q4.QuoteDigest, "k4"
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteMismatch) {
		t.Fatalf("tampered row accepted: %v", err)
	}

	// Terms superseded after minting: stale.
	q2 := mint(t, s, cap, id)
	publish(t, s, cap, PriceModePerSuccessfulCall, 13)
	in = base
	in.QuoteID, in.QuoteDigest, in.IdempotencyKey = q2.QuoteID, q2.QuoteDigest, "k2"
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteStale) {
		t.Fatalf("stale quote: %v", err)
	}

	// Expired: the store clock is moved past expires_at.
	q3 := mint(t, s, cap, id)
	s.now = func() time.Time { return q3.ExpiresAt }
	in = base
	in.QuoteID, in.QuoteDigest, in.IdempotencyKey = q3.QuoteID, q3.QuoteDigest, "k3"
	if _, err := s.AcceptInvocation(ctx, in); !errors.Is(err, ErrQuoteExpired) {
		t.Fatalf("expired quote: %v", err)
	}
}

func TestFreeTermsNeedNoPayment(t *testing.T) {
	s := newTestStore(t)
	cap := testCapability(t)
	publish(t, s, cap, PriceModeFree, 0)
	q := mint(t, s, cap, ids("acme"))
	res := accept(t, s, q, "free")
	if res.Invocation.PaymentStatus != PaymentNotRequired || res.Invocation.Price.AmountMinor != 0 {
		t.Fatalf("free invocation = %+v", res.Invocation)
	}
}

func TestTransitionsAreCheckedAndAppendOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	id := ids("acme")
	inv := accept(t, s, mint(t, s, cap, id), "t").Invocation

	// Wrong expected phase is a conflict, not a blind write.
	_, err := s.Transition(ctx, "acme", TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseReserved,
		ToPhase: PhaseDispatching, Actor: "prn_api"})
	if !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("wrong expected phase: %v", err)
	}
	// Another tenant cannot move it.
	_, err = s.Transition(ctx, "beta", TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseAccepted,
		ToPhase: PhaseRefused, ReasonCode: ReasonBudgetExhausted, Actor: "prn_api"})
	if !errors.Is(err, ErrInvocationNotFound) {
		t.Fatalf("cross-tenant transition: %v", err)
	}

	deadline := time.Now().Add(15 * time.Minute)
	steps := []TransitionInput{
		{ExpectedPhase: PhaseAccepted, ToPhase: PhaseReserved, ChargeStatus: ChargeReserved, PaymentStatus: PaymentAuthorized, ReservationDeadline: &deadline},
		{ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching},
		{ExpectedPhase: PhaseDispatching, ToPhase: PhaseDispatched},
		{ExpectedPhase: PhaseDispatched, ToPhase: PhaseOutcomeUnknown, ReasonCode: ReasonOutcomeUnknown},
	}
	var cur *Invocation
	for i, st := range steps {
		st.InvocationID, st.Actor = inv.InvocationID, "prn_api"
		cur, err = s.Transition(ctx, "acme", st)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if cur.Phase != st.ToPhase || cur.Version != int64(i+2) {
			t.Fatalf("step %d = %+v", i, cur)
		}
	}
	if cur.ExecutionOutcome != OutcomeUnknown || cur.ChargeStatus != ChargeReserved || cur.PaymentStatus != PaymentAuthorized {
		t.Fatalf("unknown liability not held: %+v", cur)
	}
	if cur.ReservationDeadline == nil || cur.FinalizedAt != nil {
		t.Fatalf("deadlines = %+v", cur)
	}
	// Time passing does not release unknown liability: the row is listed as
	// overdue, and unchanged.
	s.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	overdue, err := s.ListOverdue(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range overdue {
		if o.InvocationID == inv.InvocationID {
			found = true
			if o.Phase != PhaseOutcomeUnknown || o.ChargeStatus != ChargeReserved {
				t.Fatalf("overdue row changed: %+v", o)
			}
		}
	}
	if !found {
		t.Fatal("overdue row not listed")
	}
	s.now = func() time.Time { return time.Now().UTC() }

	qty := int64(1)
	cur, err = s.Transition(ctx, "acme", TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseOutcomeUnknown,
		ToPhase: PhaseFinalized, ExecutionOutcome: OutcomeSucceeded, ChargeStatus: ChargeCaptured, PaymentStatus: PaymentCaptured,
		UsageQuantity: &qty, Actor: "prn_reconciler", Note: "outcome(key) definitive"})
	if err != nil || cur.Phase != PhaseFinalized || cur.FinalizedAt == nil || cur.UsageQuantity == nil || *cur.UsageQuantity != 1 {
		t.Fatalf("finalize = %+v, %v", cur, err)
	}
	// Terminal rows never move again, whatever the expected phase says: a
	// caller that believes the row is still dispatched gets ErrTerminal,
	// not a plain phase conflict.
	_, err = s.Transition(ctx, "acme", TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseDispatched,
		ToPhase: PhaseOutcomeUnknown, Actor: "prn_api"})
	if !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal moved: %v", err)
	}
	hist, err := s.ListTransitions(ctx, "acme", inv.InvocationID)
	if err != nil || len(hist) != 6 {
		t.Fatalf("history = %d rows, %v", len(hist), err)
	}
	for i := 1; i < len(hist); i++ {
		if hist[i].FromPhase != hist[i-1].ToPhase || hist[i].Seq <= hist[i-1].Seq {
			t.Fatalf("history not contiguous at %d: %+v", i, hist)
		}
	}
	if hist[5].Actor != "prn_reconciler" || hist[5].Note == "" {
		t.Fatalf("last row = %+v", hist[5])
	}

	// A release from reserved flips charge_status itself.
	inv2 := accept(t, s, mint(t, s, cap, id), "t2").Invocation
	if _, err := s.Transition(ctx, "acme", TransitionInput{InvocationID: inv2.InvocationID, ExpectedPhase: PhaseAccepted,
		ToPhase: PhaseReserved, ChargeStatus: ChargeReserved, PaymentStatus: PaymentAuthorized, ReservationDeadline: &deadline, Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	rel, err := s.Transition(ctx, "acme", TransitionInput{InvocationID: inv2.InvocationID, ExpectedPhase: PhaseReserved,
		ToPhase: PhaseReleased, ReasonCode: ReasonPaymentDenied, PaymentStatus: PaymentVoided, Actor: "a"})
	if err != nil || rel.ChargeStatus != ChargeReleased || rel.ExecutionOutcome != OutcomeNotDispatched {
		t.Fatalf("release = %+v, %v", rel, err)
	}
}

func TestConcurrentAcceptsOfOneKeyYieldOneRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 5)
	id := ids("acme")
	q := mint(t, s, cap, id)
	const n = 12
	var wg sync.WaitGroup
	results := make([]*AcceptResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.AcceptInvocation(ctx, AcceptInvocationInput{
				QuoteID: q.QuoteID, QuoteDigest: q.QuoteDigest, IdempotencyKey: "race",
				Identities: id, ArgsDigest: q.ArgsDigest,
			})
		}(i)
	}
	wg.Wait()
	seen := map[string]int{}
	replays := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		seen[results[i].Invocation.InvocationID]++
		if results[i].Replayed {
			replays++
		}
	}
	if len(seen) != 1 || replays != n-1 {
		t.Fatalf("rows=%d replays=%d", len(seen), replays)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM commerce_invocations WHERE quote_id = $1`, q.QuoteID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count = %d, %v", count, err)
	}
}

func TestListFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 5)
	id := ids("acme")
	for i := 0; i < 3; i++ {
		accept(t, s, mint(t, s, cap, id), fmt.Sprintf("k%d", i))
	}
	got, err := s.ListInvocations(ctx, ListFilter{TenantID: "acme", CapabilityID: cap, Phase: PhaseAccepted, Limit: 2})
	if err != nil || len(got) != 2 {
		t.Fatalf("filtered = %d, %v", len(got), err)
	}
	got, err = s.ListInvocations(ctx, ListFilter{TenantID: "acme", CapabilityID: cap, Phase: PhaseFinalized})
	if err != nil || len(got) != 0 {
		t.Fatalf("phase filter = %d, %v", len(got), err)
	}
	got, err = s.ListInvocations(ctx, ListFilter{TenantID: "acme", CapabilityID: cap, Until: time.Now().Add(-time.Hour)})
	if err != nil || len(got) != 0 {
		t.Fatalf("until filter = %d, %v", len(got), err)
	}
}
