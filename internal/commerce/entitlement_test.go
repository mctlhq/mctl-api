// Copyright 2026 MCTL Authors
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
	"testing"
	"time"
)

func TestEntitlementInputValidation(t *testing.T) {
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	for name, in := range map[string]GrantEntitlementInput{
		"missing tenant":       {TenantID: "", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing capability":   {TenantID: "t1", CapabilityID: "", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"zero units":           {TenantID: "t1", CapabilityID: "cap", Units: 0, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"negative units":       {TenantID: "t1", CapabilityID: "cap", Units: -5, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing invoice":      {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "", ExpiresAt: expires, Actor: "prn_admin"},
		"missing actor":        {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: ""},
		"zero expiry":          {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: time.Time{}, Actor: "prn_admin"},
		"past expiry":          {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: now.Add(-1 * time.Hour), Actor: "prn_admin"},
		"expiry over 10 years": {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: now.AddDate(11, 0, 0), Actor: "prn_admin"},
	} {
		if err := in.validate(now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	valid := GrantEntitlementInput{TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"}
	if err := valid.validate(now); err != nil {
		t.Fatalf("valid.validate: %v", err)
	}
}

func TestEntitlementGrantAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	capID := testCapability(t) + "/grant"
	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	// Unknown capability fails with ErrTermsNotFound
	_, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        50,
		InvoiceRef:   "INV-2026-TEST",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
	})
	if !errors.Is(err, ErrTermsNotFound) {
		t.Fatalf("grant without terms: want ErrTermsNotFound, got %v", err)
	}

	publish(t, s, capID, PriceModePerCall, 10)

	// Valid grant
	ent, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        50,
		InvoiceRef:   "INV-2026-TEST",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
		Reason:       "Paid Capability Alpha pilot",
	})
	if err != nil {
		t.Fatalf("GrantEntitlement: %v", err)
	}
	if ent.TotalUnits != 50 || ent.RemainingUnits != 50 || ent.ReservedUnits != 0 || ent.Status != EntitlementStatusActive {
		t.Fatalf("units/status mismatch: %+v", ent)
	}
	if ent.PaymentStatus != "paid" || ent.InvoiceRef != "INV-2026-TEST" || ent.GrantedBy != "prn_admin" || ent.Reason != "Paid Capability Alpha pilot" {
		t.Fatalf("metadata mismatch: %+v", ent)
	}

	// Duplicate invoice returns conflict
	_, err = s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        20,
		InvoiceRef:   "INV-2026-TEST",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
	})
	if !errors.Is(err, ErrEntitlementConflict) {
		t.Fatalf("duplicate invoice: want ErrEntitlementConflict, got %v", err)
	}

	// Get entitlement
	got, err := s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if got.EntitlementID != ent.EntitlementID || got.RemainingUnits != 50 || got.GrantedBy != "prn_admin" || got.Reason != "Paid Capability Alpha pilot" {
		t.Fatalf("got = %+v", got)
	}

	// List entitlements
	list, err := s.ListEntitlements(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListEntitlements: %v, len=%d", err, len(list))
	}
	if list[0].EntitlementID != ent.EntitlementID {
		t.Fatalf("list item mismatch: %+v", list[0])
	}

	// Non-existent entitlement
	if _, err := s.GetEntitlement(ctx, tenant, "ent_nonexistent"); !errors.Is(err, ErrEntitlementNotFound) {
		t.Fatalf("want ErrEntitlementNotFound, got %v", err)
	}
}

func TestEntitlementLifecycleWithInvocation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	capID := testCapability(t) + "/alpha"
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	// Publish terms and set budget
	publish(t, s, capID, PriceModePerSuccessfulCall, 10)
	setBudget(t, s, tenant, 100, 50)

	// Grant 2 units for this capability
	ent, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        2,
		InvoiceRef:   "INV-ALPHA-01",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
		Reason:       "2-call test package",
	})
	if err != nil {
		t.Fatalf("GrantEntitlement: %v", err)
	}

	// 1. Invocation 1: Reserved -> Finalized (Captured)
	inv1 := acceptOne(t, s, capID, tenant, "key-ent-1")
	reserve(t, s, tenant, inv1.InvocationID)

	// Check that 1 unit is held
	curEnt, err := s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if curEnt.RemainingUnits != 1 || curEnt.ReservedUnits != 1 {
		t.Fatalf("after reserve: remaining=%d, reserved=%d (want 1, 1)", curEnt.RemainingUnits, curEnt.ReservedUnits)
	}

	// Assert independent budget ledger: price mode was PriceModePerSuccessfulCall (10 minor)
	bal := balance(t, s, tenant)
	if bal.ReservedMinor != 10 || bal.CommittedMinor != 0 || bal.AvailableMinor != 90 {
		t.Fatalf("balance after reserve 1: %+v", bal)
	}

	dispatch(t, s, tenant, inv1.InvocationID)

	// Finalize invocation 1 as succeeded
	_, err = s.Finalize(ctx, FinalizeInput{
		TenantID:         tenant,
		InvocationID:     inv1.InvocationID,
		ExecutionOutcome: OutcomeSucceeded,
		Actor:            "prn_gateway",
	})
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Check that unit is captured and released from reservation
	curEnt, err = s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if curEnt.RemainingUnits != 1 || curEnt.ReservedUnits != 0 {
		t.Fatalf("after finalize success: remaining=%d, reserved=%d (want 1, 0)", curEnt.RemainingUnits, curEnt.ReservedUnits)
	}

	// Assert budget balance after finalize: captured 10 minor
	bal = balance(t, s, tenant)
	if bal.ReservedMinor != 0 || bal.CommittedMinor != 10 || bal.AvailableMinor != 90 {
		t.Fatalf("balance after finalize 1: %+v", bal)
	}

	// 2. Invocation 2: Reserved -> Released (Failed / Cancelled)
	inv2 := acceptOne(t, s, capID, tenant, "key-ent-2")
	reserve(t, s, tenant, inv2.InvocationID)

	curEnt, err = s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if curEnt.RemainingUnits != 0 || curEnt.ReservedUnits != 1 {
		t.Fatalf("after reserve 2: remaining=%d, reserved=%d (want 0, 1)", curEnt.RemainingUnits, curEnt.ReservedUnits)
	}

	// Budget holds 10 minor again
	bal = balance(t, s, tenant)
	if bal.ReservedMinor != 10 || bal.CommittedMinor != 10 || bal.AvailableMinor != 80 {
		t.Fatalf("balance after reserve 2: %+v", bal)
	}

	// Release invocation 2 before dispatch
	_, err = s.Release(ctx, ReleaseInput{
		TenantID:     tenant,
		InvocationID: inv2.InvocationID,
		Actor:        "prn_gateway",
		ReasonCode:   "client-cancelled",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Check that unit was restored to remaining_units
	curEnt, err = s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if curEnt.RemainingUnits != 1 || curEnt.ReservedUnits != 0 {
		t.Fatalf("after release: remaining=%d, reserved=%d (want 1, 0)", curEnt.RemainingUnits, curEnt.ReservedUnits)
	}

	// Budget reservation is restored
	bal = balance(t, s, tenant)
	if bal.ReservedMinor != 0 || bal.CommittedMinor != 10 || bal.AvailableMinor != 90 {
		t.Fatalf("balance after release 2: %+v", bal)
	}
}

func TestEntitlementGatingExhaustedAndExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	capID := testCapability(t) + "/gated"
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	publish(t, s, capID, PriceModePerCall, 10)
	setBudget(t, s, tenant, 100, 50)

	// 1. Grant 1 unit
	_, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        1,
		InvoiceRef:   "INV-GATE-01",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
	})
	if err != nil {
		t.Fatalf("GrantEntitlement: %v", err)
	}

	// Reserve 1: consumes the only unit
	inv1 := acceptOne(t, s, capID, tenant, "k1")
	reserve(t, s, tenant, inv1.InvocationID)

	// Reserve 2: tenant has an entitlement for this capability, but units are exhausted
	inv2 := acceptOne(t, s, capID, tenant, "k2")
	res, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv2.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrEntitlementExhausted) {
		t.Fatalf("reserve on exhausted: want ErrEntitlementExhausted, got %v", err)
	}
	if res.Invocation.ReasonCode != ReasonEntitlementExhausted {
		t.Fatalf("reason code: want %s, got %s", ReasonEntitlementExhausted, res.Invocation.ReasonCode)
	}

	// 2. Test Expired Gating: update entitlement expires_at to the past
	_, err = s.pool.Exec(ctx, `UPDATE commerce_entitlements SET expires_at = $1 WHERE tenant_id = $2 AND capability_id = $3`,
		time.Now().Add(-1*time.Hour), tenant, capID)
	if err != nil {
		t.Fatal(err)
	}
	// Restore 1 unit so remaining_units > 0 but expired
	_, err = s.pool.Exec(ctx, `UPDATE commerce_entitlements SET remaining_units = 1 WHERE tenant_id = $1 AND capability_id = $2`,
		tenant, capID)
	if err != nil {
		t.Fatal(err)
	}

	inv3 := acceptOne(t, s, capID, tenant, "k3")
	res, err = s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv3.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrEntitlementExpired) {
		t.Fatalf("reserve on expired: want ErrEntitlementExpired, got %v", err)
	}
	if res.Invocation.ReasonCode != ReasonEntitlementExpired {
		t.Fatalf("reason code: want %s, got %s", ReasonEntitlementExpired, res.Invocation.ReasonCode)
	}

	// 3. Retry on refused invocations preserves the refusal error (ADR 020 replay invariant)
	retryExhausted, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv2.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrEntitlementExhausted) {
		t.Fatalf("retry on exhausted: want ErrEntitlementExhausted, got %v", err)
	}
	if retryExhausted.Invocation.ReasonCode != ReasonEntitlementExhausted {
		t.Fatalf("retry reason code: want %s, got %s", ReasonEntitlementExhausted, retryExhausted.Invocation.ReasonCode)
	}

	retryExpired, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv3.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrEntitlementExpired) {
		t.Fatalf("retry on expired: want ErrEntitlementExpired, got %v", err)
	}
	if retryExpired.Invocation.ReasonCode != ReasonEntitlementExpired {
		t.Fatalf("retry reason code: want %s, got %s", ReasonEntitlementExpired, retryExpired.Invocation.ReasonCode)
	}
}

func TestEntitlementUnknownHoldDeniedRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	adapter := &statusAdapter{status: map[string]PaymentResult{}}
	if err := s.UseAuthorizer(adapter); err != nil {
		t.Fatal(err)
	}
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	capID := testCapability(t) + "/unknown-deny"
	publish(t, s, capID, PriceModePerCall, 10)
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	ent, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        1,
		InvoiceRef:   "INV-UNKNOWN-01",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
	})
	if err != nil {
		t.Fatalf("GrantEntitlement: %v", err)
	}

	d := acceptOne(t, s, capID, tenant, "k-denied-ent")
	// Reserve enters unknown status: holds unit
	res := reserve(t, s, tenant, d.InvocationID)
	if res.Invocation.PaymentStatus != PaymentUnknown {
		t.Fatalf("payment status = %s, want unknown", res.Invocation.PaymentStatus)
	}

	curEnt, err := s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil || curEnt.RemainingUnits != 0 || curEnt.ReservedUnits != 1 {
		t.Fatalf("during unknown hold: %+v", curEnt)
	}

	// Adapter resolves to denied
	adapter.resolve(d.InvocationID, PaymentResultDenied, "")

	// Retry reserve resolves unknown hold to denied via resolveUnknownHold
	resDeny, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: d.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrPaymentDenied) || resDeny == nil || resDeny.Invocation.Phase != PhaseReleased {
		t.Fatalf("resDeny = %+v, err = %v", resDeny, err)
	}

	// Verify entitlement unit is RESTORED! (P1 fix verification)
	curEnt, err = s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil || curEnt.RemainingUnits != 1 || curEnt.ReservedUnits != 0 {
		t.Fatalf("after denied resolution: remaining=%d, reserved=%d (want 1, 0)", curEnt.RemainingUnits, curEnt.ReservedUnits)
	}
}

func TestEntitlementRetire(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	otherTenant := testTenant(t) + "-other"
	capID := testCapability(t) + "/retire"
	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	publish(t, s, capID, PriceModePerCall, 10)

	ent, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        10,
		InvoiceRef:   "INV-RETIRE-01",
		ExpiresAt:    expires,
		Actor:        "prn_admin",
	})
	if err != nil {
		t.Fatalf("GrantEntitlement: %v", err)
	}
	if ent.Status != EntitlementStatusActive {
		t.Fatalf("status: want active, got %s", ent.Status)
	}

	// Retire entitlement
	retired, err := s.RetireEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("RetireEntitlement: %v", err)
	}
	if retired.Status != EntitlementStatusRetired {
		t.Fatalf("retired status: want retired, got %s", retired.Status)
	}

	// Idempotent retire
	retiredAgain, err := s.RetireEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("RetireEntitlement retry: %v", err)
	}
	if retiredAgain.Status != EntitlementStatusRetired {
		t.Fatalf("retired retry status: want retired, got %s", retiredAgain.Status)
	}

	// Cross-tenant retire returns not found
	_, err = s.RetireEntitlement(ctx, otherTenant, ent.EntitlementID)
	if !errors.Is(err, ErrEntitlementNotFound) {
		t.Fatalf("cross-tenant retire: want ErrEntitlementNotFound, got %v", err)
	}

	// Unknown entitlement returns not found
	_, err = s.RetireEntitlement(ctx, tenant, "ent_00000000000000000000000000")
	if !errors.Is(err, ErrEntitlementNotFound) {
		t.Fatalf("unknown retire: want ErrEntitlementNotFound, got %v", err)
	}
}

func TestEntitlementMultiPackageFIFODepletion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	capID := testCapability(t) + "/multi-pkg"
	publish(t, s, capID, PriceModePerCall, 10)
	setBudget(t, s, tenant, 100, 50)

	finalize := func(invID string) {
		dispatch(t, s, tenant, invID)
		_, err := s.Finalize(ctx, FinalizeInput{
			TenantID:         tenant,
			InvocationID:     invID,
			ExecutionOutcome: OutcomeSucceeded,
			Actor:            "prn_gateway",
		})
		if err != nil {
			t.Fatalf("finalize %s: %v", invID, err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	// Package 1: 2 units, earlier expiry (+10h)
	pkg1, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        2,
		InvoiceRef:   "INV-PKG-1",
		ExpiresAt:    now.Add(10 * time.Hour),
		Actor:        "prn_admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Package 2: 3 units, later expiry (+20h)
	pkg2, err := s.GrantEntitlement(ctx, GrantEntitlementInput{
		TenantID:     tenant,
		CapabilityID: capID,
		Units:        3,
		InvoiceRef:   "INV-PKG-2",
		ExpiresAt:    now.Add(20 * time.Hour),
		Actor:        "prn_admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Consume 2 units: should both come from Package 1 (FIFO by expires_at)
	inv1 := acceptOne(t, s, capID, tenant, "k1")
	reserve(t, s, tenant, inv1.InvocationID)
	inv2 := acceptOne(t, s, capID, tenant, "k2")
	reserve(t, s, tenant, inv2.InvocationID)

	p1, _ := s.GetEntitlement(ctx, tenant, pkg1.EntitlementID)
	p2, _ := s.GetEntitlement(ctx, tenant, pkg2.EntitlementID)
	if p1.RemainingUnits != 0 || p1.ReservedUnits != 2 {
		t.Fatalf("pkg1 after 2 reserves: %+v", p1)
	}
	if p2.RemainingUnits != 3 || p2.ReservedUnits != 0 {
		t.Fatalf("pkg2 untouched: %+v", p2)
	}

	// Finalize both to free reservations
	finalize(inv1.InvocationID)
	finalize(inv2.InvocationID)

	// 2. Consume 3rd unit: Package 1 is exhausted, should roll over to Package 2 seamlessly
	inv3 := acceptOne(t, s, capID, tenant, "k3")
	reserve(t, s, tenant, inv3.InvocationID)

	p1, _ = s.GetEntitlement(ctx, tenant, pkg1.EntitlementID)
	p2, _ = s.GetEntitlement(ctx, tenant, pkg2.EntitlementID)
	if p1.RemainingUnits != 0 || p1.ReservedUnits != 0 {
		t.Fatalf("pkg1 after rollover: %+v", p1)
	}
	if p2.RemainingUnits != 2 || p2.ReservedUnits != 1 {
		t.Fatalf("pkg2 drawn: %+v", p2)
	}
	finalize(inv3.InvocationID)

	// 3. Consume remaining 2 units of Package 2
	inv4 := acceptOne(t, s, capID, tenant, "k4")
	reserve(t, s, tenant, inv4.InvocationID)
	inv5 := acceptOne(t, s, capID, tenant, "k5")
	reserve(t, s, tenant, inv5.InvocationID)
	finalize(inv4.InvocationID)
	finalize(inv5.InvocationID)

	// 4. Both packages exhausted: next reservation refused
	inv6 := acceptOne(t, s, capID, tenant, "k6")
	res6, err := s.Reserve(ctx, ReserveInput{TenantID: tenant, InvocationID: inv6.InvocationID, Actor: "prn_gateway"})
	if !errors.Is(err, ErrEntitlementExhausted) {
		t.Fatalf("want ErrEntitlementExhausted, got %v", err)
	}
	if res6.Invocation.ReasonCode != ReasonEntitlementExhausted {
		t.Fatalf("reason code: want %s, got %s", ReasonEntitlementExhausted, res6.Invocation.ReasonCode)
	}

	// 5. Admin retires both exhausted packages: tenant seamlessly falls back to standard currency budget
	_, err = s.RetireEntitlement(ctx, tenant, pkg1.EntitlementID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RetireEntitlement(ctx, tenant, pkg2.EntitlementID)
	if err != nil {
		t.Fatal(err)
	}

	// Next reservation succeeds under standard budget
	inv7 := acceptOne(t, s, capID, tenant, "k7")
	res7 := reserve(t, s, tenant, inv7.InvocationID)
	if res7.Reservation == nil || res7.Reservation.AmountMinor != 10 {
		t.Fatalf("fallback reservation under budget: %+v", res7)
	}
}
