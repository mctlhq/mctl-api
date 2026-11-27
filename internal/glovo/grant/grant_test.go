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

package grant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	tTenant   = "team-alpha"
	tOwner    = "prn_OWNERAAAAAAAAAAAAAAAAAAAAA"
	tConn     = "gconn_SYNTHETIC0001"
	tBasket   = "gbk_ABCDEFGHJKMNPQRSTVWXYZ0123"
	tFP       = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	tPrices   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	tPrices2  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	tCartV    = "cartv-7"
	tApproval = "aar_00000000000000000000000000000001"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func approved(now time.Time) (*workitems.ActionApprovalRequest, *workitems.GlovoBasketBinding) {
	a := &workitems.ActionApprovalRequest{ID: tApproval, ActionKind: workitems.ActionKindGlovoBasketApproval,
		State: workitems.ApprovalApproved, ExpiresAt: now.Add(time.Hour), DecidedByPrincipalID: tOwner,
		AuthorityBasis: workitems.GlovoAuthorityBasis}
	b := &workitems.GlovoBasketBinding{ApprovalID: tApproval, Tenant: tTenant, OwnerPrincipalID: tOwner,
		BasketID: tBasket, Revision: 3, BasketFingerprint: tFP}
	return a, b
}

type env struct {
	svc   *Service
	store *memStore
	now   *time.Time
	g     *Grant
}

// setup mints one grant at t0.
func setup(t *testing.T) *env {
	t.Helper()
	now := t0
	st := newMemStore()
	n := 0
	svc := &Service{Store: st, Now: func() time.Time { return now },
		NewID: func() (string, error) { n++; return IDPrefix + strings.Repeat("0", 31) + fmt.Sprint(n), nil }}
	a, b := approved(now)
	d, err := DecisionFromApproval(a, b, now)
	if err != nil {
		t.Fatal(err)
	}
	g, err := svc.Mint(context.Background(), MintInput{Decision: d, ConnectionID: tConn, ConnectionRevision: 5,
		ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, TTL: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, store: st, now: &now, g: g}
}

func (e *env) req() ConsumeRequest {
	return ConsumeRequest{GrantID: e.g.ID, Tenant: tTenant, OwnerPrincipalID: tOwner, ConnectionID: tConn,
		BasketID: tBasket, BasketRevision: 3, BasketFingerprint: tFP,
		Live: Live{ConnectionRevision: 5, ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices}}
}

func code(t *testing.T, err error) glovo.Code {
	t.Helper()
	var ge *glovo.Error
	if !errors.As(err, &ge) {
		t.Fatalf("want a glovo refusal, got %v", err)
	}
	return ge.Code
}

func TestFingerprintGoldenAndSensitive(t *testing.T) {
	b := Binding{Tenant: tTenant, OwnerPrincipalID: tOwner, ConnectionID: tConn, ConnectionRevision: 5, BasketID: tBasket,
		BasketRevision: 3, BasketFingerprint: tFP, ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices,
		ExpiresAt: t0.Add(10 * time.Minute)}
	got, err := b.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	// Computed independently (Python json sort_keys, compact separators).
	const golden = "sha256:28af62d760c6c42a9093c9870a900b51029879ddb642ca39c734b4fc9672a2b2"
	if got != golden {
		t.Fatalf("fingerprint %s, golden %s", got, golden)
	}
	// Every bound field must move the digest.
	mut := map[string]func(*Binding){
		"tenant":     func(b *Binding) { b.Tenant = "team-beta" },
		"owner":      func(b *Binding) { b.OwnerPrincipalID = "prn_OTHEROTHEROTHEROTHEROTHER" },
		"connection": func(b *Binding) { b.ConnectionID = "gconn_SYNTHETIC0002" },
		"conn rev":   func(b *Binding) { b.ConnectionRevision++ },
		"basket":     func(b *Binding) { b.BasketID = "gbk_ZZZZZZZZZZZZZZZZZZZZZZZZZZ" },
		"basket rev": func(b *Binding) { b.BasketRevision++ },
		"basket fp":  func(b *Binding) { b.BasketFingerprint = tPrices },
		"cart ver":   func(b *Binding) { b.ProviderCartVersion = "cartv-8" },
		"prices":     func(b *Binding) { b.PriceSnapshotDigest = tPrices2 },
		"expiry":     func(b *Binding) { b.ExpiresAt = b.ExpiresAt.Add(time.Microsecond) },
	}
	for name, f := range mut {
		c := b
		f(&c)
		other, err := c.Fingerprint()
		if err != nil || other == got {
			t.Errorf("%s does not move the fingerprint (err %v)", name, err)
		}
	}
	// Time zone spelling does not.
	c := b
	c.ExpiresAt = b.ExpiresAt.In(time.FixedZone("x", 3600))
	if same, _ := c.Fingerprint(); same != got {
		t.Error("time zone changed the fingerprint")
	}
}

func TestBindingValidateRefusesEveryMissingField(t *testing.T) {
	ok := Binding{Tenant: tTenant, OwnerPrincipalID: tOwner, ConnectionID: tConn, ConnectionRevision: 5, BasketID: tBasket,
		BasketRevision: 3, BasketFingerprint: tFP, ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, ExpiresAt: t0}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*Binding){
		"tenant": func(b *Binding) { b.Tenant = "" }, "owner": func(b *Binding) { b.OwnerPrincipalID = "usr_x" },
		"conn": func(b *Binding) { b.ConnectionID = "" }, "connrev": func(b *Binding) { b.ConnectionRevision = 0 },
		"basket": func(b *Binding) { b.BasketID = "x" }, "rev": func(b *Binding) { b.BasketRevision = 0 },
		"fp": func(b *Binding) { b.BasketFingerprint = "" }, "cart": func(b *Binding) { b.ProviderCartVersion = "" },
		"prices": func(b *Binding) { b.PriceSnapshotDigest = "" }, "exp": func(b *Binding) { b.ExpiresAt = time.Time{} },
	} {
		c := ok
		f(&c)
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestDecisionOnlyFromAnApprovedOwnerDecision(t *testing.T) {
	cases := map[string]func(a *workitems.ActionApprovalRequest, b *workitems.GlovoBasketBinding){
		"pending": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) {
			a.State = workitems.ApprovalPending
		},
		"denied": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) {
			a.State = workitems.ApprovalDenied
		},
		"other kind": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) { a.ActionKind = "deploy" },
		"not owner": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) {
			a.DecidedByPrincipalID = "prn_OTHER"
		},
		"no decider":  func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) { a.DecidedByPrincipalID = "" },
		"admin basis": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) { a.AuthorityBasis = "admin" },
		"id mismatch": func(_ *workitems.ActionApprovalRequest, b *workitems.GlovoBasketBinding) { b.ApprovalID = "aar_other" },
		"empty owner": func(a *workitems.ActionApprovalRequest, b *workitems.GlovoBasketBinding) {
			b.OwnerPrincipalID, a.DecidedByPrincipalID = "", ""
		},
		"expired": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) { a.ExpiresAt = t0 },
		"fresh passed": func(a *workitems.ActionApprovalRequest, _ *workitems.GlovoBasketBinding) {
			f := t0.Add(-time.Second)
			a.FreshUntil = &f
		},
	}
	for name, f := range cases {
		a, b := approved(t0)
		f(a, b)
		if _, err := DecisionFromApproval(a, b, t0); err == nil {
			t.Errorf("%s: a decision was built", name)
		}
	}
	if _, err := DecisionFromApproval(nil, nil, t0); err == nil {
		t.Error("nil rows built a decision")
	}
}

func TestMintRefusesAForgedZeroDecision(t *testing.T) {
	st := newMemStore()
	svc := &Service{Store: st, Now: func() time.Time { return t0 }}
	_, err := svc.Mint(context.Background(), MintInput{Decision: HumanDecision{}, ConnectionID: tConn, ConnectionRevision: 5,
		ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, TTL: time.Minute})
	if code(t, err) != glovo.CodeApprovalInvalid || len(st.byID) != 0 {
		t.Fatalf("zero decision minted: %v", err)
	}
}

func TestMintBindsDecisionAndCapsExpiry(t *testing.T) {
	e := setup(t)
	if e.g.Binding.BasketID != tBasket || e.g.Binding.BasketRevision != 3 || e.g.Binding.Tenant != tTenant || e.g.Binding.OwnerPrincipalID != tOwner {
		t.Fatalf("binding does not come from the decision: %+v", e.g.Binding)
	}
	if !e.g.Binding.ExpiresAt.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("expiry %v", e.g.Binding.ExpiresAt)
	}
	// The decision's own earlier expiry wins over the TTL.
	a, b := approved(t0)
	a.ExpiresAt = t0.Add(2 * time.Minute)
	d, _ := DecisionFromApproval(a, b, t0)
	e.svc.Store = newMemStore()
	g, err := e.svc.Mint(context.Background(), MintInput{Decision: d, ConnectionID: tConn, ConnectionRevision: 5,
		ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, TTL: 10 * time.Minute})
	if err != nil || !g.Binding.ExpiresAt.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("cap: %v %+v", err, g)
	}
	for _, ttl := range []time.Duration{0, -time.Second, MaxGrantTTL + time.Second} {
		if _, err := e.svc.Mint(context.Background(), MintInput{Decision: d, ConnectionID: tConn, ConnectionRevision: 5,
			ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, TTL: ttl}); !errors.Is(err, ErrInvalid) {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
}

func TestMintIsIdempotentPerApproval(t *testing.T) {
	e := setup(t)
	a, b := approved(t0)
	d, _ := DecisionFromApproval(a, b, t0)
	in := MintInput{Decision: d, ConnectionID: tConn, ConnectionRevision: 5, ProviderCartVersion: tCartV, PriceSnapshotDigest: tPrices, TTL: 10 * time.Minute}
	*e.now = t0.Add(time.Minute) // a retry at a later clock
	g2, err := e.svc.Mint(context.Background(), in)
	if err != nil || g2.ID != e.g.ID {
		t.Fatalf("retry: %v %v", err, g2)
	}
	in.PriceSnapshotDigest = tPrices2 // a different plan for the same approval
	if _, err := e.svc.Mint(context.Background(), in); code(t, err) != glovo.CodeApprovalReplayed {
		t.Fatalf("second grant for one approval: %v", err)
	}
}

func TestConsumeHappyPathThenReplay(t *testing.T) {
	e := setup(t)
	c, err := e.svc.VerifyAndConsume(context.Background(), e.req())
	if err != nil {
		t.Fatal(err)
	}
	if c.IdempotencyKey != e.g.IdempotencyKey || c.GrantID != e.g.ID || c.ConsumedAt.IsZero() {
		t.Fatalf("consumed %+v", c)
	}
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); code(t, err) != glovo.CodeApprovalReplayed {
		t.Fatalf("replay: %v", err)
	}
}

func TestConsumeForeignScopeIsNotFoundAndDoesNotConsume(t *testing.T) {
	for name, f := range map[string]func(*ConsumeRequest){
		"tenant":     func(r *ConsumeRequest) { r.Tenant = "team-beta" },
		"owner":      func(r *ConsumeRequest) { r.OwnerPrincipalID = "prn_OTHER" },
		"connection": func(r *ConsumeRequest) { r.ConnectionID = "gconn_OTHER" },
		"basket":     func(r *ConsumeRequest) { r.BasketID = "gbk_ZZZZZZZZZZZZZZZZZZZZZZZZZZ" },
		"revision":   func(r *ConsumeRequest) { r.BasketRevision = 4 },
		"fp":         func(r *ConsumeRequest) { r.BasketFingerprint = tPrices },
		"unknown id": func(r *ConsumeRequest) { r.GrantID = IDPrefix + strings.Repeat("a", 32) },
	} {
		e := setup(t)
		r := e.req()
		f(&r)
		if _, err := e.svc.VerifyAndConsume(context.Background(), r); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("%s: want not_found, got %v", name, err)
		}
		if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); err != nil {
			t.Errorf("%s: the grant was spent by the foreign attempt: %v", name, err)
		}
	}
}

func TestConsumeExpired(t *testing.T) {
	e := setup(t)
	*e.now = e.g.Binding.ExpiresAt // exactly at expiry is expired
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); code(t, err) != glovo.CodeApprovalExpired {
		t.Fatalf("%v", err)
	}
}

func TestConsumeDriftIsStaleAndLeavesGrantUnconsumed(t *testing.T) {
	for name, f := range map[string]struct {
		mut  func(*ConsumeRequest)
		want string
	}{
		"price or fee": {func(r *ConsumeRequest) { r.Live.PriceSnapshotDigest = tPrices2 }, "price_snapshot"},
		"cart version": {func(r *ConsumeRequest) { r.Live.ProviderCartVersion = "cartv-8" }, "provider_cart_version"},
		"connection":   {func(r *ConsumeRequest) { r.Live.ConnectionRevision = 6 }, "connection_revision"},
	} {
		e := setup(t)
		r := e.req()
		f.mut(&r)
		_, err := e.svc.VerifyAndConsume(context.Background(), r)
		var se *StaleError
		if !errors.As(err, &se) || len(se.Drifted) != 1 || se.Drifted[0] != f.want || !IsStale(err) {
			t.Fatalf("%s: %v", name, err)
		}
		if g, _ := e.store.Get(context.Background(), e.g.ID); g.ConsumedAt != nil {
			t.Fatalf("%s: a stale attempt consumed the grant", name)
		}
		if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); err != nil {
			t.Fatalf("%s: grant unusable after a stale attempt: %v", name, err)
		}
	}
}

func TestConsumeRequiresEveryLiveObservation(t *testing.T) {
	for name, f := range map[string]func(*ConsumeRequest){
		"no cart version": func(r *ConsumeRequest) { r.Live.ProviderCartVersion = "" },
		"no prices":       func(r *ConsumeRequest) { r.Live.PriceSnapshotDigest = "" },
		"no conn rev":     func(r *ConsumeRequest) { r.Live.ConnectionRevision = 0 },
		"bad grant id":    func(r *ConsumeRequest) { r.GrantID = "x" },
		"no tenant":       func(r *ConsumeRequest) { r.Tenant = "" },
	} {
		e := setup(t)
		r := e.req()
		f(&r)
		if _, err := e.svc.VerifyAndConsume(context.Background(), r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConsumeRefusesAStoredRowThatDoesNotReproduce(t *testing.T) {
	e := setup(t)
	e.store.tamper(e.g.ID, func(g *Grant) { g.Binding.ProviderCartVersion = "cartv-8" })
	r := e.req()
	r.Live.ProviderCartVersion = "cartv-8"
	if _, err := e.svc.VerifyAndConsume(context.Background(), r); code(t, err) != glovo.CodeFingerprintChanged {
		t.Fatalf("%v", err)
	}
}

func TestConsumeAFailedReadIsAnErrorNotNotFound(t *testing.T) {
	e := setup(t)
	boom := errors.New("db down")
	e.store.failRead = boom
	_, err := e.svc.VerifyAndConsume(context.Background(), e.req())
	if !errors.Is(err, boom) || errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestConsumeOnlyOneOfManyConcurrentCallsWins(t *testing.T) {
	e := setup(t)
	var ok, replayed int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.VerifyAndConsume(context.Background(), e.req())
			var ge *glovo.Error
			switch {
			case err == nil:
				atomic.AddInt32(&ok, 1)
			case errors.As(err, &ge) && ge.Code == glovo.CodeApprovalReplayed:
				atomic.AddInt32(&replayed, 1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || replayed != 63 {
		t.Fatalf("ok=%d replayed=%d", ok, replayed)
	}
}

func TestServiceWithoutStoreFailsClosed(t *testing.T) {
	var s *Service
	if _, err := s.VerifyAndConsume(context.Background(), ConsumeRequest{}); code(t, err) != glovo.CodeNotReady {
		t.Fatal(err)
	}
	if _, err := (&Service{}).Mint(context.Background(), MintInput{}); code(t, err) != glovo.CodeNotReady {
		t.Fatal(err)
	}
}

// lenientStore is a Store whose Consume enforces nothing, so the tests below
// prove that VerifyAndConsume refuses a replayed or expired grant by itself
// and does not lean on the store's compare-and-set alone.
type lenientStore struct{ *memStore }

func (l lenientStore) Consume(_ context.Context, id string, at time.Time) (Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.byID[id]
	g.ConsumedAt = &at
	l.byID[id] = g
	return g, nil
}

func TestServiceRefusesReplayAndExpiryWithoutTheStoresHelp(t *testing.T) {
	e := setup(t)
	e.svc.Store = lenientStore{e.store}
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); code(t, err) != glovo.CodeApprovalReplayed {
		t.Fatalf("replay: %v", err)
	}
	e = setup(t)
	e.svc.Store = lenientStore{e.store}
	*e.now = e.g.Binding.ExpiresAt.Add(time.Second)
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); code(t, err) != glovo.CodeApprovalExpired {
		t.Fatalf("expired: %v", err)
	}
}

// A store that consumed a grant a moment earlier than the service's read
// (a lost race) is still a refusal.
func TestLostRaceAtTheStoreIsReplayed(t *testing.T) {
	e := setup(t)
	e.svc.Store = racingStore{e.store}
	if _, err := e.svc.VerifyAndConsume(context.Background(), e.req()); code(t, err) != glovo.CodeApprovalReplayed {
		t.Fatalf("%v", err)
	}
}

// racingStore consumes the grant between the service's Get and its Consume.
type racingStore struct{ *memStore }

func (r racingStore) Consume(ctx context.Context, id string, at time.Time) (Grant, error) {
	if _, err := r.memStore.Consume(ctx, id, at); err != nil {
		return Grant{}, err
	}
	return r.memStore.Consume(ctx, id, at)
}
