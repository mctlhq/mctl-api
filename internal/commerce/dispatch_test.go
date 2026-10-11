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
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSeed is a fixed seed so the golden signature below is reproducible in
// the Python verifier (mctl-agents orchestrator/commerce.py).
var testSeed = []byte(strings.Repeat("\x07", ed25519.SeedSize))

func testSigner(t *testing.T) *DispatchSigner {
	t.Helper()
	sig, err := NewDispatchSigner("kid-test-1", testSeed)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func reservedInvocation(t *testing.T, s *Store, priceMode string, amount int64) (tenant string, inv *Invocation) {
	t.Helper()
	tenant = testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, priceMode, amount)
	inv = acceptOne(t, s, cap, tenant, "k")
	reserve(t, s, tenant, inv.InvocationID)
	return tenant, inv
}

// TestDispatchAuthorizationGoldenVector pins the signed encoding so the
// Python verifier can reproduce it byte for byte.
func TestDispatchAuthorizationGoldenVector(t *testing.T) {
	sig := testSigner(t)
	a := sig.sign(DispatchAuthorization{
		InvocationID:         "inv_01JZ8Q0000000000000000000D",
		ProviderOperationKey: "mctl-op/v1:inv_01JZ8Q0000000000000000000D",
		ProviderID:           "pilot-provider",
		CapabilityID:         "mctl://mcp-local/pilot-provider/lookup_status",
		InputSchemaHash:      schemaHash,
		ArgsDigest:           goldenArgsDigest,
		TenantID:             "acme",
		DispatchDeadline:     "2026-10-11T12:06:00Z",
	})
	if got := base64.RawURLEncoding.EncodeToString(sig.PublicKey()); got != goldenDispatchPublicKey {
		t.Fatalf("public key = %s", got)
	}
	if got := digestOf(string(a.SigningMessage())); got != goldenDispatchMessageDigest {
		t.Fatalf("signing message digest = %s", got)
	}
	if a.Signature != goldenDispatchSignature {
		t.Fatalf("signature = %s", a.Signature)
	}
	if err := VerifyDispatchAuthorization(sig.PublicKey(), a); err != nil {
		t.Fatalf("verify = %v", err)
	}
}

// The golden dispatch authorization, reproduced by the Python verifier in
// mctl-agents. Ed25519 is deterministic, so the signature is pinned too.
const (
	goldenDispatchPublicKey     = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
	goldenDispatchMessageDigest = "sha256:e613ea26797144af17eb98f8206279a1c764bcf16e72a3463a47e5366df89174"
	goldenDispatchSignature     = "QUdLuG4SYxJQUVeRJygWNAeh24OKUVb_mV9AJBl8e0Nql7BTHEdtdqRCeslo3x5yKP0pQcvemUh3AUfco-LtBQ"
)

func TestDispatchSignsAFencedAuthorizationAndReplaysIt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sig := testSigner(t)
	s.UseDispatchSigner(sig)
	tenant, inv := reservedInvocation(t, s, PriceModePerSuccessfulCall, 12)

	before := time.Now().UTC().Truncate(time.Second)
	res, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.Replayed || res.Invocation.Phase != PhaseDispatching || res.Invocation.DispatchDeadline == nil {
		t.Fatalf("first dispatch = %+v", res.Invocation)
	}
	d := *res.Invocation.DispatchDeadline
	if d.Before(before.Add(DefaultDispatchWindow)) || d.After(time.Now().UTC().Add(DefaultDispatchWindow)) || !d.Equal(d.Truncate(time.Second)) {
		t.Fatalf("dispatch deadline %s outside the window", d)
	}
	a := res.Authorization
	if err := VerifyDispatchAuthorization(sig.PublicKey(), a); err != nil {
		t.Fatalf("verify = %v", err)
	}
	want := DispatchAuthorization{
		SchemaVersion: SchemaVersion, KeyID: "kid-test-1", InvocationID: inv.InvocationID,
		ProviderOperationKey: ProviderOperationKey(inv.InvocationID), ProviderID: "pilot-provider",
		CapabilityID: inv.CapabilityID, InputSchemaHash: schemaHash, ArgsDigest: inv.ArgsDigest,
		TenantID: tenant, DispatchDeadline: HashedTime(d), Signature: a.Signature,
	}
	if a != want {
		t.Fatalf("authorization = %+v, want %+v", a, want)
	}

	// The retry is handed the identical authorization and nothing changes:
	// no later deadline is ever minted for this row.
	s.now = func() time.Time { return time.Now().UTC().Add(30 * time.Second) }
	defer func() { s.now = func() time.Time { return time.Now().UTC() } }()
	again, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"})
	if err != nil || !again.Replayed || again.Authorization != a || again.Invocation.Version != res.Invocation.Version {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	hist, _ := s.ListTransitions(ctx, tenant, inv.InvocationID)
	if n := countTo(hist, PhaseDispatching); n != 1 {
		t.Fatalf("dispatching entered %d times", n)
	}
}

func countTo(hist []Transition, phase string) int {
	n := 0
	for i := range hist {
		if hist[i].ToPhase == phase {
			n++
		}
	}
	return n
}

func TestDispatchAuthorizationTamperingFailsVerification(t *testing.T) {
	sig := testSigner(t)
	a := sig.sign(DispatchAuthorization{
		InvocationID: "inv_X", ProviderOperationKey: ProviderOperationKey("inv_X"), ProviderID: "p",
		CapabilityID: "mctl://mcp-local/p/t", InputSchemaHash: schemaHash, ArgsDigest: goldenArgsDigest,
		TenantID: "acme", DispatchDeadline: "2026-10-11T12:06:00Z",
	})
	if err := VerifyDispatchAuthorization(sig.PublicKey(), a); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*DispatchAuthorization){
		"key_id":            func(x *DispatchAuthorization) { x.KeyID = "kid-other" },
		"provider_id":       func(x *DispatchAuthorization) { x.ProviderID = "other" },
		"capability_id":     func(x *DispatchAuthorization) { x.CapabilityID = "mctl://mcp-local/p/other" },
		"input_schema_hash": func(x *DispatchAuthorization) { x.InputSchemaHash = "sha256:" + strings.Repeat("cd", 32) },
		"args_digest":       func(x *DispatchAuthorization) { x.ArgsDigest = "sha256:" + strings.Repeat("00", 32) },
		"tenant_id":         func(x *DispatchAuthorization) { x.TenantID = "other" },
		"dispatch_deadline": func(x *DispatchAuthorization) { x.DispatchDeadline = "2026-10-11T13:06:00Z" },
		"invocation_id": func(x *DispatchAuthorization) {
			x.InvocationID, x.ProviderOperationKey = "inv_Y", ProviderOperationKey("inv_Y")
		},
		"operation_key":  func(x *DispatchAuthorization) { x.ProviderOperationKey = ProviderOperationKey("inv_Y") },
		"schema_version": func(x *DispatchAuthorization) { x.SchemaVersion = 2 },
		"signature":      func(x *DispatchAuthorization) { x.Signature = x.Signature[:len(x.Signature)-2] + "AA" },
		"bad_deadline":   func(x *DispatchAuthorization) { x.DispatchDeadline = "2026-10-11T12:06:00+00:00" },
	}
	for name, mutate := range mutations {
		x := a
		mutate(&x)
		if err := VerifyDispatchAuthorization(sig.PublicKey(), x); !errors.Is(err, ErrBadAuthorization) {
			t.Errorf("%s: err = %v, want ErrBadAuthorization", name, err)
		}
	}
	other, _ := NewDispatchSigner("kid-test-1", []byte(strings.Repeat("\x08", ed25519.SeedSize)))
	if err := VerifyDispatchAuthorization(other.PublicKey(), a); !errors.Is(err, ErrBadAuthorization) {
		t.Fatalf("another key verified it: %v", err)
	}
}

func TestDispatchOnlyFromReserved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.UseDispatchSigner(testSigner(t))
	tenant := testTenant(t)
	setBudget(t, s, tenant, 100, 50)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)

	accepted := acceptOne(t, s, cap, tenant, "k-accepted")
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: accepted.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("dispatch of accepted: %v", err)
	}

	inv := acceptOne(t, s, cap, tenant, "k-dispatched")
	reserve(t, s, tenant, inv.InvocationID)
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: inv.InvocationID, ExpectedPhase: PhaseDispatching, ToPhase: PhaseDispatched, Actor: "prn_gateway"}); err != nil {
		t.Fatal(err)
	}
	// Past dispatching only the outcome lookup is safe: no authorization.
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("dispatch of dispatched: %v", err)
	}

	// A dispatching row without a fence was moved behind the API and gets
	// no authorization.
	unfenced := acceptOne(t, s, cap, tenant, "k-unfenced")
	reserve(t, s, tenant, unfenced.InvocationID)
	if _, err := s.Transition(ctx, tenant, TransitionInput{InvocationID: unfenced.InvocationID, ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching, Actor: "prn_gateway"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: unfenced.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("dispatch of an unfenced dispatching row: %v", err)
	}

	// A reserved row that already carries a fence was written behind the
	// API: the fence is written once and never moved, so no authorization
	// is minted over a deadline the provider may already have seen.
	prefenced := acceptOne(t, s, cap, tenant, "k-prefenced")
	reserve(t, s, tenant, prefenced.InvocationID)
	stale := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.pool.Exec(ctx, `UPDATE commerce_invocations SET dispatch_deadline = $2 WHERE invocation_id = $1`, prefenced.InvocationID, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: prefenced.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("dispatch over an existing fence: %v", err)
	}
	got, err := s.GetInvocation(ctx, tenant, prefenced.InvocationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != PhaseReserved || got.DispatchDeadline == nil || !got.DispatchDeadline.Equal(stale) {
		t.Fatalf("a refused dispatch must leave the row as it was: %+v", got)
	}

	// Another tenant's invocation is not found, the same as a missing one.
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: testTenant(t), InvocationID: inv.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrInvocationNotFound) {
		t.Fatalf("cross-tenant dispatch: %v", err)
	}
}

func TestDispatchRefusesExpiredReservationAndUnknownAuthorization(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.UseDispatchSigner(testSigner(t))
	tenant, inv := reservedInvocation(t, s, PriceModePerCall, 10)
	s.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	_, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"})
	s.now = func() time.Time { return time.Now().UTC() }
	if !errors.Is(err, ErrPhaseConflict) {
		t.Fatalf("dispatch past the reservation deadline: %v", err)
	}
	if got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID); got.Phase != PhaseReserved || got.DispatchDeadline != nil {
		t.Fatalf("refused dispatch changed the row: %+v", got)
	}

	if err := s.UseAuthorizer(&unknownOnce{}); err != nil {
		t.Fatal(err)
	}
	u, uinv := reservedInvocation(t, s, PriceModePerCall, 10)
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: u, InvocationID: uinv.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrPaymentUnknown) {
		t.Fatalf("dispatch of an unknown authorization: %v", err)
	}
}

func TestDispatchWithoutSignerIsUnavailable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, inv := reservedInvocation(t, s, PriceModePerCall, 10)
	if _, err := s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"}); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("dispatch without signer: %v", err)
	}
	if _, err := s.DispatchKeys(); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("keys without signer: %v", err)
	}
	if got, _ := s.GetInvocation(ctx, tenant, inv.InvocationID); got.Phase != PhaseReserved {
		t.Fatalf("row moved: %+v", got)
	}
}

func TestConcurrentDispatchMintsOneFence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.UseDispatchSigner(testSigner(t))
	tenant, inv := reservedInvocation(t, s, PriceModePerSuccessfulCall, 12)
	const n = 10
	var wg sync.WaitGroup
	results := make([]*DispatchResult, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.Dispatch(ctx, DispatchInput{TenantID: tenant, InvocationID: inv.InvocationID, Actor: "prn_gateway"})
		}(i)
	}
	wg.Wait()
	fresh := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("dispatch %d: %v", i, errs[i])
		}
		if !results[i].Replayed {
			fresh++
		}
		if results[i].Authorization != results[0].Authorization {
			t.Fatalf("dispatch %d got a different authorization", i)
		}
	}
	if fresh != 1 {
		t.Fatalf("%d dispatchers entered dispatching, want 1", fresh)
	}
}

func TestApprovalBindsOneInvocation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)
	approval := "aar_" + strings.ToLower(t.Name())

	q1 := mint(t, s, cap, ids(tenant))
	first, err := s.AcceptInvocation(ctx, AcceptInvocationInput{QuoteID: q1.QuoteID, QuoteDigest: q1.QuoteDigest,
		IdempotencyKey: "k1", Identities: q1.Identities, ArgsDigest: q1.ArgsDigest, ApprovalID: approval})
	if err != nil || first.Invocation.ApprovalID != approval {
		t.Fatalf("first accept = %+v, %v", first, err)
	}
	q2 := mint(t, s, cap, ids(tenant))
	if _, err := s.AcceptInvocation(ctx, AcceptInvocationInput{QuoteID: q2.QuoteID, QuoteDigest: q2.QuoteDigest,
		IdempotencyKey: "k2", Identities: q2.Identities, ArgsDigest: q2.ArgsDigest, ApprovalID: approval}); !errors.Is(err, ErrApprovalBound) {
		t.Fatalf("second invocation on one approval: err = %v, want ErrApprovalBound", err)
	}
	// The original keeps its approval, and its own retry still replays.
	again, err := s.AcceptInvocation(ctx, AcceptInvocationInput{QuoteID: q1.QuoteID, QuoteDigest: q1.QuoteDigest,
		IdempotencyKey: "k1", Identities: q1.Identities, ArgsDigest: q1.ArgsDigest, ApprovalID: approval})
	if err != nil || !again.Replayed || again.Invocation.InvocationID != first.Invocation.InvocationID {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	// Invocations without an approval never collide with each other.
	acceptOne(t, s, cap, tenant, "k3")
	acceptOne(t, s, cap, tenant, "k4")

	// The binding is per tenant: approval_id is caller input, so another
	// tenant naming the same id neither collides with it nor learns it exists.
	other := testTenant(t)
	q3 := mint(t, s, cap, ids(other))
	if _, err := s.AcceptInvocation(ctx, AcceptInvocationInput{QuoteID: q3.QuoteID, QuoteDigest: q3.QuoteDigest,
		IdempotencyKey: "k1", Identities: q3.Identities, ArgsDigest: q3.ArgsDigest, ApprovalID: approval}); err != nil {
		t.Fatalf("another tenant naming the same approval id: %v", err)
	}
}

func TestListFindsAnInvocationByItsIdempotencyScope(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant := testTenant(t)
	cap := testCapability(t)
	publish(t, s, cap, PriceModePerCall, 10)
	inv := acceptOne(t, s, cap, tenant, "gw:key-1")
	acceptOne(t, s, cap, tenant, "gw:key-2")
	principal := ids(tenant).PrincipalID

	got, err := s.ListInvocations(ctx, ListFilter{TenantID: tenant, PrincipalID: principal, IdempotencyKey: "gw:key-1"})
	if err != nil || len(got) != 1 || got[0].InvocationID != inv.InvocationID {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	if got, err := s.ListInvocations(ctx, ListFilter{TenantID: tenant, PrincipalID: "prn_someone_else", IdempotencyKey: "gw:key-1"}); err != nil || len(got) != 0 {
		t.Fatalf("another principal's key must find nothing: %+v, %v", got, err)
	}
	if got, err := s.ListInvocations(ctx, ListFilter{TenantID: testTenant(t), PrincipalID: principal, IdempotencyKey: "gw:key-1"}); err != nil || len(got) != 0 {
		t.Fatalf("another tenant must find nothing: %+v, %v", got, err)
	}
	// A principal without a key scopes the listing too.
	if got, err := s.ListInvocations(ctx, ListFilter{TenantID: tenant, PrincipalID: principal}); err != nil || len(got) != 2 {
		t.Fatalf("principal-only listing = %d rows, %v", len(got), err)
	}
	if got, err := s.ListInvocations(ctx, ListFilter{TenantID: tenant, PrincipalID: "prn_someone_else"}); err != nil || len(got) != 0 {
		t.Fatalf("principal-only listing for another principal = %+v, %v", got, err)
	}
	if _, err := s.ListInvocations(ctx, ListFilter{TenantID: tenant, IdempotencyKey: "gw:key-1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("key without principal: %v", err)
	}
}

// mctlhq/mctl-agents#626 item 7: installing the signer while requests read
// it is not a data race (run with -race; CI's validate does not, so this
// is the guard for anyone who does).
func TestUseDispatchSignerIsSafeWhileServing(t *testing.T) {
	s := &Store{}
	sig := testSigner(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			s.UseDispatchSigner(sig)
			s.UseDispatchSigner(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if keys, err := s.DispatchKeys(); err == nil && keys[0].KeyID != "kid-test-1" {
				t.Errorf("key id %q", keys[0].KeyID)
			}
		}
	}()
	wg.Wait()
	s.UseDispatchSigner(sig)
	if keys, err := s.DispatchKeys(); err != nil || len(keys) != 1 {
		t.Fatalf("installed signer not served: %v %v", keys, err)
	}
}
