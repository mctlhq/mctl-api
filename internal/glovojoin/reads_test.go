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

package glovojoin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

// recBridge is a ReadBridge double that records every request and serves a
// canned payload per kind. It never touches a provider.
type recBridge struct {
	mu      sync.Mutex
	payload map[bridge.ReadKind][]byte
	err     error
	calls   []bridge.ReadRequest
}

func (b *recBridge) Read(_ context.Context, r bridge.ReadRequest) (*bridge.ReadResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, r)
	if b.err != nil {
		return nil, b.err
	}
	d, ok := b.payload[r.Kind]
	if !ok {
		return nil, bridge.ErrReadUnavailable
	}
	return &bridge.ReadResult{Kind: r.Kind, ResultRef: "rres_test", Digest: PayloadHash(d), Data: d, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (b *recBridge) n() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

func (s *stack) reader(b ReadBridge) *Reader {
	return &Reader{DB: s.rp, Conns: s.conns, Order: s.orders, Bridge: b}
}

func (s *stack) subject() Subject {
	return Subject{PrincipalID: stackOwner, Tenant: stackTenant, InstallID: s.installID, InstallRevision: s.installRev,
		Scopes: []string{ScopeRead, ScopeBasketPrepare}}
}

func (s *stack) bridgeWith(t *testing.T) *recBridge {
	return &recBridge{payload: map[bridge.ReadKind][]byte{
		bridge.ReadHistory: fixturePayload(t, "read-result.history.valid.json"),
		bridge.ReadPreview: fixturePayload(t, "read-result.preview.valid.json"),
		bridge.ReadBasket:  fixturePayload(t, "read-result.basket.valid.json"),
	}}
}

// History, then preview of an issued ref, then prepare of that preview: the
// whole read-to-write path on the real stores, with exactly the reads made.
func TestReadsFeedPrepareEndToEnd(t *testing.T) {
	s := newStack(t)
	s.activate("k-e2e")
	b := s.bridgeWith(t)
	rd := s.reader(b)
	ctx := context.Background()
	h, rf := rd.History(ctx, s.subject(), 0, "")
	if rf != nil {
		t.Fatal(rf)
	}
	if len(h.Orders) != 2 || h.NextCursor == "" {
		t.Fatalf("history = %+v", h)
	}
	pv, rf := rd.Preview(ctx, s.subject(), h.Orders[0].OrderRef)
	if rf != nil {
		t.Fatal(rf)
	}
	if pv.Fingerprint == "" || len(pv.Items) != 2 || len(pv.Unavailable) != 1 || !pv.ExpiresAt.After(time.Now()) {
		t.Fatalf("preview = %+v", pv)
	}
	if got := b.n(); got != 2 {
		t.Fatalf("bridge reads = %d, want 2 (history, preview)", got)
	}
	// The command carries the refs, the revision and the verified scopes.
	c := b.calls[1]
	if c.Kind != bridge.ReadPreview || c.TenantRef == "" || c.PrincipalRef == "" || c.InstallRevisionRef == "" || c.ConnectionRef != s.connID ||
		len(c.Scopes) != 2 || c.Tenant != stackTenant || c.OwnerPrincipalID != stackOwner {
		t.Fatalf("read request = %+v", c)
	}
	res, rf := s.prepare.Prepare(ctx, PrepareRequest{Tenant: stackTenant, PrincipalID: stackOwner, PreviewID: pv.PreviewID, Key: "e2e-key"})
	if rf != nil {
		t.Fatalf("prepare: %v", rf)
	}
	if res.Fingerprint != pv.Fingerprint {
		t.Fatalf("prepare fingerprint %s != preview %s", res.Fingerprint, pv.Fingerprint)
	}
	if got := b.n(); got != 2 {
		t.Fatalf("prepare made a read: %d calls", got)
	}
	if w := s.writes(); w[5] != 0 {
		t.Fatalf("bridge_commands = %d after the whole path", w[5])
	}
}

// A12: a pho_ or cursor no history read issued to this subject is 404 with
// zero commands.
func TestReadsRefuseRefsNobodyIssued(t *testing.T) {
	s := newStack(t)
	s.activate("k-a12")
	b := s.bridgeWith(t)
	rd := s.reader(b)
	ctx := context.Background()
	_, rf := rd.Preview(ctx, s.subject(), "pho_00000000000000000009")
	wantCode(t, rf, glovo.CodeNotFound, "read_ref_not_issued")
	_, rf = rd.History(ctx, s.subject(), 5, "Zm9yZ2VkLWN1cnNvcg")
	wantCode(t, rf, glovo.CodeNotFound, "read_ref_not_issued")
	_, rf = rd.Preview(ctx, s.subject(), "not-a-pho")
	wantCode(t, rf, glovo.CodeInvalidRequest, "pho_shape")
	if got := b.n(); got != 0 {
		t.Fatalf("%d bridge reads for refs nobody issued", got)
	}
	// After a history read the issued cursor is accepted and forwarded.
	h, rf := rd.History(ctx, s.subject(), 5, "")
	if rf != nil {
		t.Fatal(rf)
	}
	if _, rf = rd.History(ctx, s.subject(), 5, h.NextCursor); rf != nil {
		t.Fatalf("issued cursor refused: %v", rf)
	}
	if string(b.calls[1].Params) != `{"cursor":"`+h.NextCursor+`","limit":5}` {
		t.Fatalf("params = %s", b.calls[1].Params)
	}
	_, rf = rd.History(ctx, s.subject(), 21, "")
	wantCode(t, rf, glovo.CodeInvalidRequest, "history_limit")
}

// An unparsable provider payload is unavailable, and records nothing: a ref the
// client never received must not become usable.
func TestReadsDoNotRecordRefsOfABadPayload(t *testing.T) {
	s := newStack(t)
	s.activate("k-bad")
	b := &recBridge{payload: map[bridge.ReadKind][]byte{bridge.ReadHistory: []byte(`{"orders":[{"history_order_ref":"pho_00000000000000000000"}]}`)}}
	_, rf := s.reader(b).History(context.Background(), s.subject(), 0, "")
	wantCode(t, rf, glovo.CodeUnavailable, "read:history_payload")
	if n := s.count(`SELECT count(*) FROM glovo.join_read_refs`); n != 0 {
		t.Fatalf("%d refs recorded for a rejected payload", n)
	}
}

func TestReadErrorsMapToTheJoinCodes(t *testing.T) {
	s := newStack(t)
	s.activate("k-err")
	ctx := context.Background()
	for _, c := range []struct {
		err  error
		code glovo.Code
	}{
		{bridge.ErrReadNotAuthorized, glovo.CodeScopeUnsupported},
		{bridge.ErrReadUnavailable, glovo.CodeUnavailable},
		{errors.New("boom"), glovo.CodeUnavailable},
		{context.DeadlineExceeded, glovo.CodeUnavailable},
	} {
		b := s.bridgeWith(t)
		b.err = c.err
		_, rf := s.reader(b).Basket(ctx, s.subject())
		wantCode(t, rf, c.code, "")
	}
	_, rf := (&Reader{DB: s.rp, Conns: s.conns, Order: s.orders}).Basket(ctx, s.subject())
	wantCode(t, rf, glovo.CodeNotReady, "read_bridge_absent")
	_, rf = s.reader(NotReadyBridge{}).Basket(ctx, s.subject())
	wantCode(t, rf, glovo.CodeNotReady, "")
}

func TestReadsReReadTheConnection(t *testing.T) {
	s := newStack(t)
	s.activate("k-rev")
	b := s.bridgeWith(t)
	if _, err := s.conns.Revoke(context.Background(), stackOf, stackUser, s.connID, "user_revoked"); err != nil {
		t.Fatal(err)
	}
	_, rf := s.reader(b).Basket(context.Background(), s.subject())
	wantCode(t, rf, glovo.CodeConnectionRevoked, "")
	if b.n() != 0 {
		t.Fatalf("read on a revoked connection: %d", b.n())
	}
	stale := s.subject()
	stale.InstallRevision++
	if _, rf = s.reader(b).Basket(context.Background(), stale); rf == nil {
		t.Fatal("a stale install revision read")
	}
}

func TestEmptyPreviewCannotBePrepared(t *testing.T) {
	s := newStack(t)
	s.activate("k-empty")
	b := s.bridgeWith(t)
	b.payload[bridge.ReadPreview] = fixturePayload(t, "read-result.preview.empty.valid.json")
	rd := s.reader(b)
	ctx := context.Background()
	h, rf := rd.History(ctx, s.subject(), 0, "")
	if rf != nil {
		t.Fatal(rf)
	}
	pv, rf := rd.Preview(ctx, s.subject(), h.Orders[0].OrderRef)
	if rf != nil {
		t.Fatal(rf)
	}
	if pv.Fingerprint != "" || len(pv.Items) != 0 {
		t.Fatalf("empty preview = %+v", pv)
	}
	_, rf = s.prepare.Prepare(ctx, PrepareRequest{Tenant: stackTenant, PrincipalID: stackOwner, PreviewID: pv.PreviewID, Key: "empty-key"})
	wantCode(t, rf, glovo.CodeInvalidRequest, "basket_empty")
}

// A7: the refs sent to the provider side carry no tenant name, principal id or
// order id, and the same principal in two tenants gets two different prr_.
func TestJoinRefsAreOpaqueAndPerTenant(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	mint := func(tenant string) string {
		tx, err := s.rp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		ref, err := s.orders.MintJoinRefTx(ctx, tx, orders.JoinPrincipal, tenant, stackOwner, stackOwner)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	a, b := mint("acme-tenant"), mint("other-tenant")
	if a == b || !strings.HasPrefix(a, "prr_") || !strings.HasPrefix(b, "prr_") {
		t.Fatalf("refs %q %q", a, b)
	}
	for _, ref := range []string{a, b} {
		for _, leak := range []string{"acme", "other", "tenant", "prn_", "pord_", stackOwner} {
			if strings.Contains(ref, leak) {
				t.Fatalf("ref %q leaks %q", ref, leak)
			}
		}
	}
	if mint("acme-tenant") != a {
		t.Fatal("a second mint of the same (tenant, principal) gave another ref")
	}
}
