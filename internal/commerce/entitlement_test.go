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
	expires := time.Now().Add(24 * time.Hour)
	for name, in := range map[string]GrantEntitlementInput{
		"missing tenant":     {TenantID: "", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing capability": {TenantID: "t1", CapabilityID: "", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"zero units":         {TenantID: "t1", CapabilityID: "cap", Units: 0, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"negative units":     {TenantID: "t1", CapabilityID: "cap", Units: -5, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing invoice":    {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "", ExpiresAt: expires, Actor: "prn_admin"},
		"missing actor":      {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: ""},
		"zero expiry":        {TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: time.Time{}, Actor: "prn_admin"},
	} {
		if err := in.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	valid := GrantEntitlementInput{TenantID: "t1", CapabilityID: "cap", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid.validate: %v", err)
	}
}

func TestEntitlementGrantAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	capID := "mctl://projects/projects_search"
	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	// Validation tests
	for name, in := range map[string]GrantEntitlementInput{
		"missing tenant":     {TenantID: "", CapabilityID: capID, Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing capability": {TenantID: tenant, CapabilityID: "", Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"zero units":         {TenantID: tenant, CapabilityID: capID, Units: 0, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"negative units":     {TenantID: tenant, CapabilityID: capID, Units: -5, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: "prn_admin"},
		"missing invoice":    {TenantID: tenant, CapabilityID: capID, Units: 10, InvoiceRef: "", ExpiresAt: expires, Actor: "prn_admin"},
		"missing actor":      {TenantID: tenant, CapabilityID: capID, Units: 10, InvoiceRef: "INV-001", ExpiresAt: expires, Actor: ""},
		"zero expiry":        {TenantID: tenant, CapabilityID: capID, Units: 10, InvoiceRef: "INV-001", ExpiresAt: time.Time{}, Actor: "prn_admin"},
	} {
		if _, err := s.GrantEntitlement(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}

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
	if ent.TotalUnits != 50 || ent.RemainingUnits != 50 || ent.ReservedUnits != 0 {
		t.Fatalf("units mismatch: %+v", ent)
	}
	if ent.PaymentStatus != "paid" || ent.InvoiceRef != "INV-2026-TEST" {
		t.Fatalf("metadata mismatch: %+v", ent)
	}

	// Get entitlement
	got, err := s.GetEntitlement(ctx, tenant, ent.EntitlementID)
	if err != nil {
		t.Fatalf("GetEntitlement: %v", err)
	}
	if got.EntitlementID != ent.EntitlementID || got.RemainingUnits != 50 {
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
	capID := "mctl://projects/projects_search"
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
}
