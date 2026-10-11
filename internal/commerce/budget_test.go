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
	"strings"
	"sync"
	"testing"
	"time"
)

// testTenant mints a tenant id the cleanup in newTestStore recognises.
func testTenant(t *testing.T) string {
	t.Helper()
	id, err := newULID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return "tc-" + strings.ToLower(id)
}

func setBudget(t *testing.T, s *Store, tenant string, monthly, perRequest int64) *Budget {
	t.Helper()
	b, err := s.SetBudget(context.Background(), SetBudgetInput{
		TenantID: tenant, PayerAccountID: "acct_tenant_" + tenant, Currency: "EUR",
		MonthlyLimitMinor: monthly, PerRequestMaxMinor: perRequest, Actor: "prn_admin", Reason: "test",
	})
	if err != nil {
		t.Fatalf("SetBudget: %v", err)
	}
	return b
}

// acceptOne mints and accepts one invocation for the tenant under its own
// idempotency key.
func acceptOne(t *testing.T, s *Store, cap, tenant, key string) *Invocation {
	t.Helper()
	return accept(t, s, mint(t, s, cap, ids(tenant)), key).Invocation
}

func reserve(t *testing.T, s *Store, tenant, id string) *ReserveResult {
	t.Helper()
	res, err := s.Reserve(context.Background(), ReserveInput{TenantID: tenant, InvocationID: id, Actor: "prn_gateway"})
	if err != nil {
		t.Fatalf("Reserve %s: %v", id, err)
	}
	return res
}

func dispatch(t *testing.T, s *Store, tenant, id string) {
	t.Helper()
	ctx := context.Background()
	for _, step := range [][2]string{{PhaseReserved, PhaseDispatching}, {PhaseDispatching, PhaseDispatched}} {
		if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: id, ExpectedPhase: step[0], ToPhase: step[1], Actor: "prn_gateway"}); err != nil {
			t.Fatalf("%s -> %s: %v", step[0], step[1], err)
		}
	}
}

func balance(t *testing.T, s *Store, tenant string) *Balance {
	t.Helper()
	b, err := s.GetBalance(context.Background(), tenant, "acct_tenant_"+tenant)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	return b
}

func TestBudgetIsAuditedAndCurrencyBound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	payer := "acct_tenant_" + tenant

	if _, err := s.GetBalance(ctx, tenant, payer); !errors.Is(err, ErrBudgetNotFound) {
		t.Fatalf("balance without budget: %v", err)
	}
	b := setBudget(t, s, tenant, 100, 50)
	if b.FundsMode != FundsModeSimulated || b.Version != 1 || b.Currency != "EUR" {
		t.Fatalf("budget = %+v", b)
	}
	b2 := setBudget(t, s, tenant, 200, 50)
	if b2.Version != 2 || b2.MonthlyLimitMinor != 200 {
		t.Fatalf("budget v2 = %+v", b2)
	}
	changes, err := s.ListBudgetChanges(ctx, tenant, payer)
	if err != nil || len(changes) != 2 {
		t.Fatalf("changes = %+v, %v", changes, err)
	}
	if changes[0].OldMonthlyLimitMinor != nil || changes[1].OldMonthlyLimitMinor == nil || *changes[1].OldMonthlyLimitMinor != 100 ||
		changes[1].Actor != "prn_admin" || changes[1].Reason != "test" {
		t.Fatalf("history = %+v", changes)
	}
	for name, in := range map[string]SetBudgetInput{
		"no reason":      {TenantID: tenant, PayerAccountID: payer, Currency: "EUR", MonthlyLimitMinor: 1, PerRequestMaxMinor: 1, Actor: "prn_admin"},
		"no actor":       {TenantID: tenant, PayerAccountID: payer, Currency: "EUR", MonthlyLimitMinor: 1, PerRequestMaxMinor: 1, Reason: "r"},
		"zero per req":   {TenantID: tenant, PayerAccountID: payer, Currency: "EUR", MonthlyLimitMinor: 1, PerRequestMaxMinor: 0, Actor: "a", Reason: "r"},
		"negative limit": {TenantID: tenant, PayerAccountID: payer, Currency: "EUR", MonthlyLimitMinor: -1, PerRequestMaxMinor: 1, Actor: "a", Reason: "r"},
		"bad currency":   {TenantID: tenant, PayerAccountID: payer, Currency: "XXX", MonthlyLimitMinor: 1, PerRequestMaxMinor: 1, Actor: "a", Reason: "r"},
	} {
		if _, err := s.SetBudget(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A currency change is allowed while nothing was ever reserved...
	if _, err := s.SetBudget(ctx, SetBudgetInput{TenantID: tenant, PayerAccountID: payer, Currency: "USD",
		MonthlyLimitMinor: 200, PerRequestMaxMinor: 50, Actor: "prn_admin", Reason: "switch"}); err != nil {
		t.Fatalf("currency switch on an empty account: %v", err)
	}
	setBudget(t, s, tenant, 200, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	reserve(t, s, tenant, acceptOne(t, s, cap, tenant, "k1").InvocationID)
	// ...and refused once the account has a reservation.
	if _, err := s.SetBudget(ctx, SetBudgetInput{TenantID: tenant, PayerAccountID: payer, Currency: "USD",
		MonthlyLimitMinor: 200, PerRequestMaxMinor: 50, Actor: "prn_admin", Reason: "switch"}); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("currency switch with reservations: %v", err)
	}
}

func TestReserveAuthorizesAtomicallyAndReplays(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	inv := acceptOne(t, s, cap, tenant, "k1")

	res := reserve(t, s, tenant, inv.InvocationID)
	if res.Replayed || res.Invocation.Phase != PhaseReserved || res.Invocation.ChargeStatus != ChargeReserved ||
		res.Invocation.PaymentStatus != PaymentAuthorized || res.Invocation.ReservationDeadline == nil {
		t.Fatalf("reserved = %+v", res.Invocation)
	}
	if res.Reservation.Status != ReservationHeld || res.Reservation.AmountMinor != 12 || res.Reservation.Period != Period(time.Now()) ||
		!strings.HasPrefix(res.Reservation.AuthorizationID, "sauth_") {
		t.Fatalf("reservation = %+v", res.Reservation)
	}
	st, err := s.auth.Status(ctx, s.pool, PaymentOperationKey(inv.InvocationID, PaymentOpAuthorize))
	if err != nil || st.Result != PaymentResultAuthorized || st.ID != res.Reservation.AuthorizationID {
		t.Fatalf("status = %+v, %v", st, err)
	}
	again := reserve(t, s, tenant, inv.InvocationID)
	if !again.Replayed || again.Reservation.ReservationID != res.Reservation.ReservationID {
		t.Fatalf("second reserve = %+v", again)
	}
	bal := balance(t, s, tenant)
	if bal.ReservedMinor != 12 || bal.CommittedMinor != 0 || bal.AvailableMinor != 88 {
		t.Fatalf("balance = %+v", bal)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM commerce_reservations WHERE invocation_id = $1`, inv.InvocationID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("reservations = %d, %v", n, err)
	}
}

func TestReserveDeniesAndHoldsNothing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 60)

	t.Run("no budget", func(t *testing.T) {
		tenant := testTenant(t)
		inv := acceptOne(t, s, cap, tenant, "k")
		res, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"})
		if !errors.Is(err, ErrBudgetExhausted) || res == nil || res.Invocation.Phase != PhaseRefused || res.Invocation.ReasonCode != ReasonBudgetExhausted {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
	})
	t.Run("per-request maximum", func(t *testing.T) {
		tenant := testTenant(t)
		setBudget(t, s, tenant, 1000, 50)
		inv := acceptOne(t, s, cap, tenant, "k")
		_, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"})
		if !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("err = %v", err)
		}
		got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID)
		if got.Phase != PhaseRefused || got.ChargeStatus != ChargeNone || got.PaymentStatus != PaymentNone {
			t.Fatalf("row = %+v", got)
		}
		// The refusal is durable: a retry answers the same thing.
		if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"}); !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("retry = %v", err)
		}
		if bal := balance(t, s, tenant); bal.ReservedMinor != 0 || bal.AvailableMinor != 1000 {
			t.Fatalf("balance after denial = %+v", bal)
		}
	})
	t.Run("currency", func(t *testing.T) {
		tenant := testTenant(t)
		if _, err := s.SetBudget(ctx, SetBudgetInput{TenantID: tenant, PayerAccountID: "acct_tenant_" + tenant, Currency: "USD",
			MonthlyLimitMinor: 1000, PerRequestMaxMinor: 100, Actor: "prn_admin", Reason: "usd"}); err != nil {
			t.Fatal(err)
		}
		inv := acceptOne(t, s, cap, tenant, "k")
		_, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"})
		if !errors.Is(err, ErrCurrencyMismatch) {
			t.Fatalf("err = %v", err)
		}
		got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID)
		if got.Phase != PhaseRefused || got.ReasonCode != ReasonCurrencyMismatch {
			t.Fatalf("row = %+v", got)
		}
	})
	t.Run("quote expired", func(t *testing.T) {
		tenant := testTenant(t)
		setBudget(t, s, tenant, 1000, 100)
		inv := acceptOne(t, s, cap, tenant, "k")
		s.now = func() time.Time { return inv.QuoteExpiresAt }
		defer func() { s.now = func() time.Time { return time.Now().UTC() } }()
		_, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"})
		if !errors.Is(err, ErrQuoteExpired) {
			t.Fatalf("err = %v", err)
		}
		got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID)
		if got.Phase != PhaseRefused || got.ReasonCode != ReasonQuoteExpired {
			t.Fatalf("row = %+v", got)
		}
	})
	t.Run("wrong phase", func(t *testing.T) {
		tenant := testTenant(t)
		setBudget(t, s, tenant, 1000, 100)
		inv := acceptOne(t, s, cap, tenant, "k")
		if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseAccepted,
			ToPhase: PhaseRefused, ReasonCode: "policy-denied", Actor: "a"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "a"}); !errors.Is(err, ErrTerminal) {
			t.Fatalf("err = %v", err)
		}
	})
}

// ADR 020 invariant 11: EUR 0.12 per_successful_call under a EUR 1.00 budget
// admits at most 8 concurrent reservations and refuses the rest.
func TestConcurrentReservesNeverOverspend(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerSuccessfulCall, 12)
	const n = 12
	invs := make([]*Invocation, n)
	for i := range invs {
		invs[i] = acceptOne(t, s, cap, tenant, fmt.Sprintf("k%d", i))
	}
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := range invs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: invs[i].InvocationID, Actor: "a"})
		}(i)
	}
	wg.Wait()
	reserved, refused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			reserved++
		case errors.Is(err, ErrBudgetExhausted):
			refused++
		default:
			t.Fatalf("unexpected: %v", err)
		}
	}
	if reserved != 8 || refused != 4 {
		t.Fatalf("reserved %d, refused %d", reserved, refused)
	}
	bal := balance(t, s, tenant)
	if bal.ReservedMinor != 96 || bal.AvailableMinor != 4 {
		t.Fatalf("balance = %+v", bal)
	}
	// The ninth, accepted after the burst, is refused too.
	ninth := acceptOne(t, s, cap, tenant, "k-ninth")
	if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: ninth.InvocationID, Actor: "a"}); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("ninth = %v", err)
	}
}

func TestFinalizeCapturesOrReleasesExactlyOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 1000, 100)
	perSuccess := testCapability(t) + "/success"
	perCall := testCapability(t) + "/call"
	free := testCapability(t) + "/free"
	publish(t, s, perSuccess, PriceModePerSuccessfulCall, 12)
	publish(t, s, perCall, PriceModePerCall, 7)
	publish(t, s, free, PriceModeFree, 0)

	finalize := func(id, outcome string) (*FinalizeResult, error) {
		return s.Finalize(ctx, FinalizeInput{TenantID: tenant, InvocationID: id, Actor: "prn_gateway", ExecutionOutcome: outcome})
	}
	// per_successful_call, succeeded: captured, settled.
	a := acceptOne(t, s, perSuccess, tenant, "a")
	reserve(t, s, tenant, a.InvocationID)
	dispatch(t, s, tenant, a.InvocationID)
	res, err := finalize(a.InvocationID, OutcomeSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	if inv := res.Invocation; inv.Phase != PhaseFinalized || inv.ChargeStatus != ChargeCaptured || inv.PaymentStatus != PaymentCaptured ||
		inv.SettlementStatus != SettlementSettled || inv.UsageQuantity == nil || *inv.UsageQuantity != 1 || inv.FinalizedAt == nil {
		t.Fatalf("captured = %+v", inv)
	}
	if res.Reservation.Status != ReservationCaptured || !strings.HasPrefix(res.Reservation.CaptureID, "scap_") {
		t.Fatalf("reservation = %+v", res.Reservation)
	}
	// Replay with the same outcome returns the same thing; another outcome conflicts.
	again, err := finalize(a.InvocationID, OutcomeSucceeded)
	if err != nil || !again.Replayed || again.Reservation.CaptureID != res.Reservation.CaptureID {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	if _, err := finalize(a.InvocationID, OutcomeFailed); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("contradicting replay: %v", err)
	}
	var captures int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM commerce_payment_operations WHERE invocation_id = $1 AND operation = 'capture'`,
		a.InvocationID).Scan(&captures); err != nil || captures != 1 {
		t.Fatalf("captures = %d, %v", captures, err)
	}

	// per_successful_call, failed: released, voided, no charge.
	b := acceptOne(t, s, perSuccess, tenant, "b")
	reserve(t, s, tenant, b.InvocationID)
	dispatch(t, s, tenant, b.InvocationID)
	res, err = finalize(b.InvocationID, OutcomeFailed)
	if err != nil {
		t.Fatal(err)
	}
	if inv := res.Invocation; inv.Phase != PhaseFinalized || inv.ChargeStatus != ChargeReleased || inv.PaymentStatus != PaymentVoided ||
		inv.ExecutionOutcome != OutcomeFailed || res.Reservation.Status != ReservationReleased {
		t.Fatalf("released = %+v / %+v", inv, res.Reservation)
	}

	// per_call, failed: still captured.
	c := acceptOne(t, s, perCall, tenant, "c")
	reserve(t, s, tenant, c.InvocationID)
	dispatch(t, s, tenant, c.InvocationID)
	res, err = finalize(c.InvocationID, OutcomeFailed)
	if err != nil || res.Invocation.ChargeStatus != ChargeCaptured || res.Reservation.AmountMinor != 7 {
		t.Fatalf("per_call failed = %+v, %v", res, err)
	}

	// free: a zero hold, captured, payment never required.
	d := acceptOne(t, s, free, tenant, "d")
	rd := reserve(t, s, tenant, d.InvocationID)
	if rd.Invocation.PaymentStatus != PaymentNotRequired || rd.Reservation.AmountMinor != 0 || rd.Reservation.AuthorizationID != "" {
		t.Fatalf("free reserve = %+v / %+v", rd.Invocation, rd.Reservation)
	}
	dispatch(t, s, tenant, d.InvocationID)
	res, err = finalize(d.InvocationID, OutcomeSucceeded)
	if err != nil || res.Invocation.ChargeStatus != ChargeCaptured || res.Invocation.PaymentStatus != PaymentNotRequired ||
		res.Invocation.SettlementStatus != SettlementNotApplicable {
		t.Fatalf("free finalize = %+v, %v", res, err)
	}

	// Committed is the sum of captures this period: 12 + 7 + 0.
	if bal := balance(t, s, tenant); bal.CommittedMinor != 19 || bal.ReservedMinor != 0 || bal.AvailableMinor != 981 {
		t.Fatalf("balance = %+v", bal)
	}

	// Finalize needs a dispatched or outcome_unknown row.
	e := acceptOne(t, s, perCall, tenant, "e")
	if _, err := finalize(e.InvocationID, OutcomeSucceeded); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("finalize accepted: %v", err)
	}
	reserve(t, s, tenant, e.InvocationID)
	if _, err := finalize(e.InvocationID, OutcomeSucceeded); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("finalize reserved: %v", err)
	}
	if _, err := s.Finalize(ctx, FinalizeInput{TenantID: tenant, InvocationID: e.InvocationID, Actor: "a", ExecutionOutcome: OutcomeUnknown}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finalize with unknown outcome: %v", err)
	}
}

func TestReleaseBeforeDispatchAndNotAfter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 1000, 100)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)
	release := func(id string) (*FinalizeResult, error) {
		return s.Release(ctx, ReleaseInput{TenantID: tenant, InvocationID: id, Actor: "prn_gateway", ReasonCode: "provider-unavailable"})
	}

	a := acceptOne(t, s, cap, tenant, "a")
	reserve(t, s, tenant, a.InvocationID)
	res, err := release(a.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if inv := res.Invocation; inv.Phase != PhaseReleased || inv.ChargeStatus != ChargeReleased || inv.PaymentStatus != PaymentVoided ||
		inv.ExecutionOutcome != OutcomeNotDispatched || inv.ReasonCode != "provider-unavailable" || res.Reservation.Status != ReservationReleased {
		t.Fatalf("released = %+v / %+v", inv, res.Reservation)
	}
	again, err := release(a.InvocationID)
	if err != nil || !again.Replayed {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	if bal := balance(t, s, tenant); bal.ReservedMinor != 0 || bal.CommittedMinor != 0 {
		t.Fatalf("balance = %+v", bal)
	}

	// dispatching can still be released (failure before the provider accepts).
	b := acceptOne(t, s, cap, tenant, "b")
	reserve(t, s, tenant, b.InvocationID)
	if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: b.InvocationID, ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching, Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := release(b.InvocationID); err != nil {
		t.Fatalf("release dispatching: %v", err)
	}

	// dispatched cannot: the outcome must be observed.
	c := acceptOne(t, s, cap, tenant, "c")
	reserve(t, s, tenant, c.InvocationID)
	dispatch(t, s, tenant, c.InvocationID)
	if _, err := release(c.InvocationID); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("release dispatched: %v", err)
	}
	// Neither can an accepted row: there is nothing held.
	d := acceptOne(t, s, cap, tenant, "d")
	if _, err := release(d.InvocationID); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("release accepted: %v", err)
	}
	if _, err := s.Release(ctx, ReleaseInput{TenantID: tenant, InvocationID: c.InvocationID, Actor: "a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("release without reason: %v", err)
	}
}

// ADR 020 invariant 13 and sec. 11 recovery table: the reconciler refuses
// an expired accepted row and releases an expired reserved one, and never
// touches a row past dispatch, whatever its age.
func TestExpireStaleNeverReleasesUnknownLiability(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 1000, 100)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)

	accepted := acceptOne(t, s, cap, tenant, "accepted")
	reserved := acceptOne(t, s, cap, tenant, "reserved")
	reserve(t, s, tenant, reserved.InvocationID)
	dispatching := acceptOne(t, s, cap, tenant, "dispatching")
	reserve(t, s, tenant, dispatching.InvocationID)
	if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: dispatching.InvocationID, ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching, Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	dispatched := acceptOne(t, s, cap, tenant, "dispatched")
	reserve(t, s, tenant, dispatched.InvocationID)
	dispatch(t, s, tenant, dispatched.InvocationID)
	unknown := acceptOne(t, s, cap, tenant, "unknown")
	reserve(t, s, tenant, unknown.InvocationID)
	dispatch(t, s, tenant, unknown.InvocationID)
	if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: unknown.InvocationID, ExpectedPhase: PhaseDispatched, ToPhase: PhaseOutcomeUnknown, Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	before := balance(t, s, tenant)
	if before.ReservedMinor != 30 || before.PendingLiabilityMinor != 10 || before.AvailableMinor != 960 {
		t.Fatalf("balance before = %+v", before)
	}

	// Two days later: every quote, reservation and reconciliation deadline
	// has passed.
	s.now = func() time.Time { return time.Now().UTC().Add(48 * time.Hour) }
	defer func() { s.now = func() time.Time { return time.Now().UTC() } }()
	res, err := s.ExpireStale(ctx, "prn_reconciler", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refused) < 1 || len(res.Released) < 1 {
		t.Fatalf("result = %+v", res)
	}
	want := map[string]string{
		accepted.InvocationID: PhaseRefused, reserved.InvocationID: PhaseReleased,
		dispatching.InvocationID: PhaseDispatching, dispatched.InvocationID: PhaseDispatched, unknown.InvocationID: PhaseOutcomeUnknown,
	}
	for id, phase := range want {
		got, err := s.GetInvocation(ctx, tenant, id)
		if err != nil || got.Phase != phase {
			t.Errorf("%s: phase %s, want %s (%v)", id, got.Phase, phase, err)
		}
	}
	got, _ := s.GetInvocation(ctx, tenant, reserved.InvocationID)
	if got.ReasonCode != ReasonReservationExpired || got.PaymentStatus != PaymentVoided {
		t.Fatalf("expired reservation = %+v", got)
	}
	after := balance(t, s, tenant)
	// Liability past dispatch is still held, and it is still held in a new
	// period: nothing became spendable because time passed.
	if after.ReservedMinor != 20 || after.PendingLiabilityMinor != 10 || after.Period == before.Period && after.AvailableMinor != 970 {
		t.Fatalf("balance after = %+v", after)
	}
	overdue, err := s.ListOverdue(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, v := range overdue {
		ids[v.InvocationID] = true
	}
	for _, id := range []string{dispatching.InvocationID, dispatched.InvocationID, unknown.InvocationID} {
		if !ids[id] {
			t.Errorf("%s is not listed overdue for the operator", id)
		}
	}
}

func TestMonthRolloverKeepsHoldsAndAttributesCaptures(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 40)

	jan := time.Date(2027, 1, 20, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return jan }
	defer func() { s.now = func() time.Time { return time.Now().UTC() } }()
	captured := acceptOne(t, s, cap, tenant, "captured")
	reserve(t, s, tenant, captured.InvocationID)
	dispatch(t, s, tenant, captured.InvocationID)
	held := acceptOne(t, s, cap, tenant, "held")
	reserve(t, s, tenant, held.InvocationID)
	dispatch(t, s, tenant, held.InvocationID)
	if bal := balance(t, s, tenant); bal.Period != "2027-01" || bal.ReservedMinor != 80 || bal.AvailableMinor != 20 {
		t.Fatalf("january = %+v", bal)
	}

	// February: the January hold still counts, so only 60 is available,
	// and a capture of a January hold lands in January, not February.
	feb := time.Date(2027, 2, 2, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return feb }
	if bal := balance(t, s, tenant); bal.Period != "2027-02" || bal.ReservedMinor != 80 || bal.CommittedMinor != 0 || bal.AvailableMinor != 20 {
		t.Fatalf("february before capture = %+v", bal)
	}
	res, err := s.Finalize(ctx, FinalizeInput{TenantID: tenant, InvocationID: captured.InvocationID, Actor: "a", ExecutionOutcome: OutcomeSucceeded})
	if err != nil || res.Reservation.Period != "2027-01" {
		t.Fatalf("capture = %+v, %v", res, err)
	}
	bal := balance(t, s, tenant)
	if bal.CommittedMinor != 0 || bal.ReservedMinor != 40 || bal.AvailableMinor != 60 {
		t.Fatalf("february after capture = %+v", bal)
	}
	// February's own limit admits a 40 now, and a second one does not: the
	// January hold is still counted.
	third := acceptOne(t, s, cap, tenant, "third")
	reserve(t, s, tenant, third.InvocationID)
	fourth := acceptOne(t, s, cap, tenant, "fourth")
	if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: fourth.InvocationID, Actor: "a"}); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("fourth = %v", err)
	}
	pre, err := s.Precheck(ctx, tenant, "acct_tenant_"+tenant, Money{Currency: "EUR", AmountMinor: 40})
	if err != nil || pre.Sufficient || pre.ReasonCode != ReasonBudgetExhausted || pre.Balance.AvailableMinor != 20 {
		t.Fatalf("precheck = %+v, %v", pre, err)
	}
	pre, err = s.Precheck(ctx, tenant, "acct_tenant_"+tenant, Money{Currency: "EUR", AmountMinor: 20})
	if err != nil || !pre.Sufficient {
		t.Fatalf("precheck 20 = %+v, %v", pre, err)
	}
	if _, err := s.Precheck(ctx, tenant, "acct_tenant_"+tenant, Money{Currency: "USD", AmountMinor: 1}); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("precheck usd = %v", err)
	}
}

// unknownOnce wraps the simulated adapter and answers unknown to the first
// authorize, like a rail whose response was lost.
type unknownOnce struct {
	SimulatedAuthorizer
	mu   sync.Mutex
	hits int
}

func (u *unknownOnce) Authorize(ctx context.Context, q querier, req PaymentRequest) (PaymentResult, error) {
	u.mu.Lock()
	u.hits++
	first := u.hits == 1
	u.mu.Unlock()
	if first {
		return PaymentResult{Operation: PaymentOpAuthorize, Result: PaymentResultUnknown}, nil
	}
	return u.SimulatedAuthorizer.Authorize(ctx, q, req)
}

func TestUnknownAuthorizationIsNeverDenied(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UseAuthorizer(&unknownOnce{}); err != nil {
		t.Fatal(err)
	}
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)
	inv := acceptOne(t, s, cap, tenant, "k")
	res := reserve(t, s, tenant, inv.InvocationID)
	if res.Invocation.Phase != PhaseReserved || res.Invocation.PaymentStatus != PaymentUnknown || res.Reservation.Status != ReservationHeld {
		t.Fatalf("unknown authorize = %+v / %+v", res.Invocation, res.Reservation)
	}
	if bal := balance(t, s, tenant); bal.ReservedMinor != 10 {
		t.Fatalf("hold not counted: %+v", bal)
	}
	// Time passing does not free it: the reconciler releases only a reserved
	// row past its deadline, and this one is, so it is voided through the
	// adapter, never silently dropped.
	s.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	defer func() { s.now = func() time.Time { return time.Now().UTC() } }()
	exp, err := s.ExpireStale(ctx, "prn_reconciler", 10)
	if err != nil {
		t.Fatalf("expire = %v", err)
	}
	if len(exp.Released) != 0 || len(exp.Unresolved) != 1 || exp.Unresolved[0] != inv.InvocationID {
		t.Fatalf("an unknown authorization must stay held and be reported: %+v", exp)
	}
	got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID)
	if got.Phase != PhaseReserved || got.PaymentStatus != PaymentUnknown {
		t.Fatalf("row = %+v", got)
	}
	// Once the rail records the authorization, status finds it and the void
	// goes through against that id.
	a := SimulatedAuthorizer{}
	if _, err := a.Authorize(ctx, s.pool, PaymentRequest{Key: PaymentOperationKey(inv.InvocationID, PaymentOpAuthorize),
		InvocationID: inv.InvocationID, TenantID: tenant, PayerAccountID: inv.PayerAccountID, Money: inv.Price,
		FundsMode: inv.FundsMode, QuoteDigest: inv.QuoteDigest}); err != nil {
		t.Fatal(err)
	}
	exp, err = s.ExpireStale(ctx, "prn_reconciler", 10)
	if err != nil || len(exp.Released) != 1 {
		t.Fatalf("expire after status resolved = %+v, %v", exp, err)
	}
	got, _ = s.GetInvocation(ctx, tenant, inv.InvocationID)
	rsv, _ := s.GetReservation(ctx, tenant, inv.InvocationID)
	if got.Phase != PhaseReleased || got.PaymentStatus != PaymentVoided || rsv.Status != ReservationReleased || rsv.AuthorizationID == "" {
		t.Fatalf("row = %+v / %+v", got, rsv)
	}
}

func TestAdapterNegotiation(t *testing.T) {
	s := &Store{}
	for name, info := range map[string]AdapterInfo{
		"no void":       {AdapterID: "x", AdapterVersion: "1", FundsModes: []string{FundsModeSimulated}, Features: []string{FeatureAuthCapture, FeatureStatusLookup}},
		"no status":     {AdapterID: "x", AdapterVersion: "1", FundsModes: []string{FundsModeSimulated}, Features: []string{FeatureAuthCapture, FeatureVoid}},
		"no simulation": {AdapterID: "x", AdapterVersion: "1", FundsModes: []string{FundsModeLive}, Features: []string{FeatureAuthCapture, FeatureVoid, FeatureStatusLookup}},
		"no id":         {AdapterVersion: "1", FundsModes: []string{FundsModeSimulated}, Features: []string{FeatureAuthCapture, FeatureVoid, FeatureStatusLookup}},
	} {
		if err := s.UseAuthorizer(fakeAdapter{info}); !errors.Is(err, ErrAdapterIneligible) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.UseAuthorizer(SimulatedAuthorizer{}); err != nil {
		t.Fatalf("simulated adapter refused: %v", err)
	}
	if err := s.UseAuthorizer(nil); !errors.Is(err, ErrAdapterIneligible) {
		t.Fatalf("nil adapter: %v", err)
	}
}

type fakeAdapter struct{ info AdapterInfo }

func (f fakeAdapter) Adapter() AdapterInfo { return f.info }
func (fakeAdapter) Authorize(context.Context, querier, PaymentRequest) (PaymentResult, error) {
	return PaymentResult{}, nil
}
func (fakeAdapter) Capture(context.Context, querier, string, string, Money) (PaymentResult, error) {
	return PaymentResult{}, nil
}
func (fakeAdapter) Void(context.Context, querier, string, string) (PaymentResult, error) {
	return PaymentResult{}, nil
}
func (fakeAdapter) Status(context.Context, querier, string) (PaymentResult, error) {
	return PaymentResult{}, nil
}

func TestPaymentKeyWithDifferentParametersConflicts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := SimulatedAuthorizer{}
	key := "mctl-pay/v1:inv_test_conflict:" + PaymentOpAuthorize
	defer func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM commerce_payment_operations WHERE invocation_id = 'inv_test_conflict'`)
	}()
	req := PaymentRequest{Key: key, InvocationID: "inv_test_conflict", TenantID: "t", PayerAccountID: "p",
		Money: Money{Currency: "EUR", AmountMinor: 5}, FundsMode: FundsModeSimulated, QuoteDigest: goldenQuoteDigest}
	first, err := a.Authorize(ctx, s.pool, req)
	if err != nil || first.Result != PaymentResultAuthorized {
		t.Fatalf("first = %+v, %v", first, err)
	}
	same, err := a.Authorize(ctx, s.pool, req)
	if err != nil || same.ID != first.ID {
		t.Fatalf("replay = %+v, %v", same, err)
	}
	changed := req
	changed.Money.AmountMinor = 6
	if _, err := a.Authorize(ctx, s.pool, changed); !errors.Is(err, ErrPaymentConflict) {
		t.Fatalf("changed amount: %v", err)
	}
	live := req
	live.Key += ":live"
	live.InvocationID = "inv_test_conflict"
	live.FundsMode = FundsModeLive
	denied, err := a.Authorize(ctx, s.pool, live)
	if err != nil || denied.Result != PaymentResultDenied || denied.Reason != ReasonFundsModeUnavailable {
		t.Fatalf("live = %+v, %v", denied, err)
	}
	// A capture above the authorized amount fails; one at it is settled.
	over, err := a.Capture(ctx, s.pool, "mctl-pay/v1:inv_test_conflict:capture-over", first.ID, Money{Currency: "EUR", AmountMinor: 6})
	if err != nil || over.Result != PaymentResultFailed {
		t.Fatalf("over-capture = %+v, %v", over, err)
	}
	cap, err := a.Capture(ctx, s.pool, "mctl-pay/v1:inv_test_conflict:capture", first.ID, Money{Currency: "EUR", AmountMinor: 5})
	if err != nil || cap.Result != PaymentResultCaptured || cap.Settlement != SettlementSettled {
		t.Fatalf("capture = %+v, %v", cap, err)
	}
	st, err := a.Status(ctx, s.pool, "mctl-pay/v1:inv_test_conflict:nothing")
	if err != nil || st.Result != PaymentResultNotFound {
		t.Fatalf("status of nothing = %+v, %v", st, err)
	}
}

func TestReserveNeverReplaysASettledHold(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)

	// A live hold replays through dispatch, a settled one answers conflict.
	done := acceptOne(t, s, cap, tenant, "k-finalized")
	reserve(t, s, tenant, done.InvocationID)
	dispatch(t, s, tenant, done.InvocationID)
	if again := reserve(t, s, tenant, done.InvocationID); !again.Replayed || again.Reservation.Status != ReservationHeld {
		t.Fatalf("dispatched row must replay its live hold: %+v", again)
	}
	if _, err := s.Finalize(ctx, FinalizeInput{TenantID: tenant, InvocationID: done.InvocationID, Actor: "prn_gateway", ExecutionOutcome: OutcomeSucceeded}); err != nil {
		t.Fatal(err)
	}
	res, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: done.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrPhaseConflict) || res != nil {
		t.Fatalf("reserve on a finalized row: res = %+v, err = %v, want phase-conflict", res, err)
	}

	gone := acceptOne(t, s, cap, tenant, "k-released")
	reserve(t, s, tenant, gone.InvocationID)
	if _, err := s.Release(ctx, ReleaseInput{TenantID: tenant, InvocationID: gone.InvocationID, Actor: "prn_gateway", ReasonCode: "cancelled"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: gone.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("reserve on a released row: err = %v, want phase-conflict", err)
	}

	// A refused row answers its refusal again, with the row.
	setBudget(t, s, tenant, 5, 50)
	no := acceptOne(t, s, cap, tenant, "k-refused")
	if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: no.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("first: %v", err)
	}
	res, err = s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: no.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrBudgetExhausted) || res == nil || res.Invocation == nil || res.Invocation.Phase != PhaseRefused {
		t.Fatalf("retry on a refused row: res = %+v, err = %v", res, err)
	}
}

// statusAdapter answers unknown to every authorize and lets the test decide
// what a later status lookup of the authorize key says, like a rail whose
// response was lost and is settled out of band.
type statusAdapter struct {
	SimulatedAuthorizer
	mu     sync.Mutex
	status map[string]PaymentResult
}

func (a *statusAdapter) Authorize(context.Context, querier, PaymentRequest) (PaymentResult, error) {
	return PaymentResult{Operation: PaymentOpAuthorize, Result: PaymentResultUnknown}, nil
}

func (a *statusAdapter) Status(ctx context.Context, q querier, key string) (PaymentResult, error) {
	a.mu.Lock()
	st, ok := a.status[key]
	a.mu.Unlock()
	if ok {
		return st, nil
	}
	if strings.HasSuffix(key, ":"+PaymentOpAuthorize) {
		return PaymentResult{Operation: PaymentOpAuthorize, Result: PaymentResultUnknown}, nil
	}
	return a.SimulatedAuthorizer.Status(ctx, q, key)
}

func (a *statusAdapter) resolve(id, result, authID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status[PaymentOperationKey(id, PaymentOpAuthorize)] = PaymentResult{Operation: PaymentOpAuthorize, Result: result, ID: authID}
}

func TestUnknownHoldCannotDispatchUntilResolved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	adapter := &statusAdapter{status: map[string]PaymentResult{}}
	if err := s.UseAuthorizer(adapter); err != nil {
		t.Fatal(err)
	}
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)
	toDispatching := func(id string) error {
		_, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: id, ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching, Actor: "prn_gateway"})
		return err
	}

	// 1. Unknown: held, counted, not dispatchable, and a retry says unknown.
	a := acceptOne(t, s, cap, tenant, "k-authorized")
	if res := reserve(t, s, tenant, a.InvocationID); res.Invocation.PaymentStatus != PaymentUnknown {
		t.Fatalf("reserve = %+v", res.Invocation)
	}
	if err := toDispatching(a.InvocationID); !errors.Is(err, ErrPaymentUnknown) {
		t.Fatalf("dispatching an unknown hold: err = %v, want payment-unknown", err)
	}
	if _, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: a.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPaymentUnknown) {
		t.Fatalf("retry while unknown: err = %v", err)
	}
	if bal := balance(t, s, tenant); bal.ReservedMinor != 10 {
		t.Fatalf("hold must stay counted: %+v", bal)
	}

	// 2. The rail settles it as authorized: the retry records it and the
	// row may now be dispatched.
	adapter.resolve(a.InvocationID, PaymentResultAuthorized, "rail_auth_1")
	res := reserve(t, s, tenant, a.InvocationID)
	if !res.Replayed || res.Invocation.PaymentStatus != PaymentAuthorized || res.Reservation.AuthorizationID != "rail_auth_1" || res.Reservation.Status != ReservationHeld {
		t.Fatalf("resolved authorized = %+v / %+v", res.Invocation, res.Reservation)
	}
	if err := toDispatching(a.InvocationID); err != nil {
		t.Fatalf("dispatch after resolution: %v", err)
	}

	// 3. The rail settles another as denied: the retry releases the hold
	// with nothing to void and reports the denial.
	d := acceptOne(t, s, cap, tenant, "k-denied")
	reserve(t, s, tenant, d.InvocationID)
	adapter.resolve(d.InvocationID, PaymentResultDenied, "")
	res, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: d.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrPaymentDenied) || res == nil || res.Invocation.Phase != PhaseReleased ||
		res.Invocation.ChargeStatus != ChargeReleased || res.Invocation.PaymentStatus != PaymentDenied || res.Reservation.Status != ReservationReleased {
		t.Fatalf("resolved denied: res = %+v, err = %v", res, err)
	}
	if bal := balance(t, s, tenant); bal.ReservedMinor != 10 || bal.AvailableMinor != 90 {
		t.Fatalf("denied hold must be freed: %+v", bal)
	}

	// 4. A late denial after dispatch (only reachable if the guard above is
	// bypassed; forced here) finalizes the row with the hold released
	// instead of erroring forever.
	l := acceptOne(t, s, cap, tenant, "k-late")
	reserve(t, s, tenant, l.InvocationID)
	if _, err := s.pool.Exec(ctx, `UPDATE commerce_invocations SET phase = $2 WHERE invocation_id = $1`, l.InvocationID, PhaseDispatched); err != nil {
		t.Fatal(err)
	}
	adapter.resolve(l.InvocationID, PaymentResultDenied, "")
	fin, err := s.Finalize(ctx, FinalizeInput{TenantID: tenant, InvocationID: l.InvocationID, Actor: "prn_gateway", ExecutionOutcome: OutcomeSucceeded})
	if err != nil || fin.Invocation.Phase != PhaseFinalized || fin.Invocation.ChargeStatus != ChargeReleased ||
		fin.Invocation.PaymentStatus != PaymentDenied || fin.Reservation.Status != ReservationReleased {
		t.Fatalf("finalize after late denial: res = %+v, err = %v", fin, err)
	}
	if bal := balance(t, s, tenant); bal.ReservedMinor != 10 || bal.CommittedMinor != 0 {
		t.Fatalf("late-denied hold must not stay held: %+v", bal)
	}
}
