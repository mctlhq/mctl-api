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
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
)

// party is one (tenant, owner) with an active connection on the shared stack.
type party struct {
	tenant, owner, installID, connID string
	rev                              int64
}

// join installs the tenant if needed and gives the owner an active connection,
// the way the #961 worker does.
func (s *stack) join(tenant, owner, key string) party {
	s.t.Helper()
	ctx := context.Background()
	of := glovo.Owner{TenantID: tenant, PrincipalID: owner}
	inst, err := s.conns.Install(ctx, tenant, stackAdmin)
	if err != nil {
		s.t.Fatalf("Install %s: %v", tenant, err)
	}
	r, err := s.conns.Connect(ctx, glovo.ConnectInput{Owner: of, ExpectedInstallRevision: inst.InstallRevision, IdempotencyKey: key,
		Actor: glovo.Actor{PrincipalID: owner, Kind: glovo.ActorUser}})
	if err != nil {
		s.t.Fatalf("Connect %s/%s: %v", tenant, owner, err)
	}
	tx, err := s.rp.Begin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := s.conns.ActivateTx(ctx, tx, glovo.ActivateInput{Owner: of, ConnectionID: r.Connection.ConnectionID, ExpectedVersion: r.Connection.Version,
		ExpectedInstallRevision: inst.InstallRevision, ExpiresIn: time.Hour, Actor: stackWorker})
	if err != nil {
		s.t.Fatalf("ActivateTx %s/%s: %v", tenant, owner, err)
	}
	if err := tx.Commit(ctx); err != nil {
		s.t.Fatal(err)
	}
	return party{tenant: tenant, owner: owner, installID: inst.InstallID, rev: inst.InstallRevision, connID: a.ConnectionID}
}

func (pt party) preview(s *stack, payload string) Preview {
	s.t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	p := Preview{Tenant: pt.tenant, PrincipalID: pt.owner, ConnectionID: pt.connID, InstallID: pt.installID, InstallRevision: pt.rev,
		PayloadHash: PayloadHash([]byte(payload)), CreatedAt: now, ExpiresAt: now.Add(PreviewTTL)}
	var err error
	if p.ID, err = NewPreviewID(); err != nil {
		s.t.Fatal(err)
	}
	_, canonical, perr := basket.Parse([]byte(payload))
	if perr != nil {
		s.t.Fatal(perr)
	}
	p.Approval, p.Fingerprint = canonical, basket.Fingerprint(canonical)
	if err := InsertPreview(context.Background(), s.rp, p); err != nil {
		s.t.Fatal(err)
	}
	return p
}

func (pt party) req(p Preview, key string) PrepareRequest {
	return PrepareRequest{Tenant: pt.tenant, PrincipalID: pt.owner, PreviewID: p.ID, Key: key, InstallID: pt.installID, InstallRevision: pt.rev}
}

const (
	matrixOwner2 = "prn_OWNER00000000000000000002"
	matrixOwner3 = "prn_OWNER00000000000000000003"
)

func (s *stack) statusReader() *StatusReader {
	return &StatusReader{DB: s.rp, Orders: s.orders, Approvals: s.work}
}

// T6: the two-tenant, two-owner matrix on the real stores. Every pair that
// must not see each other is checked in both directions, on the order, the
// status, the preview and the idempotency key.
func TestJoinNegativeMatrixAcrossTenantsAndOwners(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	a1 := s.join("acme", stackOwner, "m-a1")
	a2 := s.join("acme", matrixOwner2, "m-a2")
	b1 := s.join("beta", stackOwner, "m-b1") // the same principal id in another tenant
	b3 := s.join("beta", matrixOwner3, "m-b3")

	// Two owners of one tenant and two tenants all use the SAME idempotency key:
	// each gets its own order, none replays another's.
	const key = "shared-key-0001"
	var orders [4]string
	for i, pt := range []party{a1, a2, b1, b3} {
		p := pt.preview(s, stackBasket)
		res, rf := s.prepare.Prepare(ctx, pt.req(p, key))
		if rf != nil || res.Replayed {
			t.Fatalf("party %d: %+v, %v", i, res, rf)
		}
		orders[i] = res.OrderID
	}
	seen := map[string]bool{}
	for _, o := range orders {
		if seen[o] {
			t.Fatalf("two owners received the same order %s", o)
		}
		seen[o] = true
	}
	if got := s.count(`SELECT count(*) FROM glovo.orders`); got != 4 {
		t.Fatalf("%d orders for four parties on one key, want 4", got)
	}
	if got := s.count(`SELECT count(DISTINCT consumed_order_ref) FROM glovo.join_previews WHERE consumed_order_ref IS NOT NULL`); got != 4 {
		t.Fatalf("%d claimed previews, want 4", got)
	}

	// Status: only the owner, in the tenant, reads the order. The non-empty
	// principal is what separates two owners of one tenant.
	st := s.statusReader()
	parties := []party{a1, a2, b1, b3}
	for i, pt := range parties {
		for j, o := range orders {
			state, _, rf := st.Status(ctx, pt.tenant, pt.owner, o)
			if i == j {
				if rf != nil || state != "awaiting_approval" {
					t.Errorf("owner %d reads own order: %q %v", i, state, rf)
				}
				continue
			}
			wantCode(t, rf, glovo.CodeNotFound, "order_not_found")
		}
	}

	// The same principal id in the other tenant is another owner.
	if _, _, rf := st.Status(ctx, "beta", a1.owner, orders[0]); rf == nil {
		t.Error("the owner's id in another tenant read the order")
	}
	// An empty principal never matches an owner.
	if _, _, rf := st.Status(ctx, "acme", "", orders[0]); rf == nil {
		t.Error("an empty principal read an order")
	}

	// A preview of one owner is not loadable, claimable or preparable by another.
	pa := a1.preview(s, stackBasket)
	for _, other := range []party{a2, b1, b3} {
		if got, rf := LoadPreview(ctx, s.rp, pa.ID, other.tenant, other.owner, time.Now()); got != nil || rf == nil {
			t.Errorf("%s/%s loaded a preview of acme/%s", other.tenant, other.owner, a1.owner)
		}
		if ok, err := ClaimPreview(ctx, s.rp, pa.ID, other.tenant, other.owner, "ordr_x"); err != nil || ok {
			t.Errorf("%s/%s claimed a preview of acme/%s: %v %v", other.tenant, other.owner, a1.owner, ok, err)
		}
		_, rf := s.prepare.Prepare(ctx, other.req(pa, "cross-"+other.owner))
		wantCode(t, rf, glovo.CodeNotFound, "preview_not_found")
	}
	if got := s.count(`SELECT count(*) FROM glovo.orders`); got != 4 {
		t.Fatalf("a cross-owner prepare wrote an order: %d", got)
	}
	if got := s.count(`SELECT count(*) FROM glovo.join_previews WHERE id = $1 AND consumed_order_ref IS NULL`, pa.ID); got != 1 {
		t.Fatal("a cross-owner attempt spent the preview")
	}

	// The owner still prepares it, and a retry of the same request replays.
	res, rf := s.prepare.Prepare(ctx, a1.req(pa, "owner-key"))
	if rf != nil || res.Replayed {
		t.Fatalf("owner prepare after the attempts: %+v %v", res, rf)
	}
	if again, rf := s.prepare.Prepare(ctx, a1.req(pa, "owner-key")); rf != nil || !again.Replayed || again.OrderID != res.OrderID {
		t.Fatalf("replay: %+v %v", again, rf)
	}
	// The same key with another preview is a conflict, not a second order.
	pb := a1.preview(s, stackBasket)
	_, rf = s.prepare.Prepare(ctx, a1.req(pb, "owner-key"))
	if rf == nil || !errors.Is(rf, glovo.Refuse(glovo.CodeIdempotencyReused)) {
		t.Fatalf("a reused key with another preview: %v", rf)
	}
}

// T6: stale install and wrong connection at the join level, with the real
// stores: another owner's connection id on a preview, and an install revision
// that moved after the preview was issued.
func TestJoinStaleInstallAndWrongConnection(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	a1 := s.join("acme", stackOwner, "m-a1")
	a2 := s.join("acme", matrixOwner2, "m-a2")

	// A preview of owner 1 that names owner 2's connection.
	p := a1.preview(s, stackBasket)
	if _, err := s.mp.Exec(ctx, `UPDATE glovo.join_previews SET connection_id = $2 WHERE id = $1`, p.ID, a2.connID); err != nil {
		t.Fatal(err)
	}
	_, rf := s.prepare.Prepare(ctx, a1.req(p, "wrong-conn"))
	wantCode(t, rf, glovo.CodeStaleInstall, "preview_connection_changed")

	// The subject's install moved on: the same preview is refused with the old
	// revision and writes nothing.
	p2 := a1.preview(s, stackBasket)
	old := a1.req(p2, "stale-rev")
	old.InstallRevision = a1.rev + 1
	_, rf = s.prepare.Prepare(ctx, old)
	wantCode(t, rf, glovo.CodeStaleInstall, "subject_install_stale")
	if got := s.count(`SELECT count(*) FROM glovo.orders`); got != 0 {
		t.Fatalf("a refused prepare wrote %d orders", got)
	}
}
