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
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	stackTenant = "acme"
	stackOwner  = "prn_OWNER00000000000000000001"
	stackBasket = `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR",
"lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],
"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`
)

// lazyOrders breaks the construction cycle between the work-items store (it
// binds the approval through the order store) and the order store (it reads
// the execution binding through the work-items store).
type lazyOrders struct{ s *orders.Store }

func (l *lazyOrders) BindApproval(ctx context.Context, tx pgx.Tx, sc orders.Scope, a orders.Actor, orderRef, approvalRef string) error {
	return l.s.BindApproval(ctx, tx, sc, a, orderRef, approvalRef)
}

// stack is the real #959/#988/#989/#986 stack on one scratch database with
// the three roles of the owner-confirmed model.
type stack struct {
	t           *testing.T
	base, db    string
	mig, wi, rt string
	mp, rp      *pgxpool.Pool
	conns       *glovo.Store
	orders      *orders.Store
	work        *workitems.Store
	installID   string
	installRev  int64
	connID      string
	prepare     *Preparer
}

func (s *stack) url(user string) string {
	u, err := url.Parse(s.base)
	if err != nil {
		s.t.Fatal(err)
	}
	u.User = url.UserPassword(user, testPassword)
	u.Path = "/" + s.db
	return u.String()
}

func newStack(t *testing.T) *stack {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	sfx := randHex(6)
	s := &stack{t: t, base: base, db: "j957sdb_" + sfx, mig: "j957smig_" + sfx, wi: "j957swi_" + sfx, rt: "j957srt_" + sfx}
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = root.Close(ctx) }()
	var stmts []string
	for _, r := range []string{s.mig, s.wi, s.rt} {
		stmts = append(stmts, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, testPassword))
	}
	stmts = append(stmts, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, s.db, s.mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, s.db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, s.db, s.wi, s.rt))
	for _, q := range stmts {
		if _, err := root.Exec(ctx, q); err != nil {
			t.Fatalf("setup %q: %v", q, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, s.db))
		for _, r := range []string{s.rt, s.wi, s.mig} {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	migURL := s.url(s.mig)
	if err := glovo.ApplySchema(ctx, migURL, s.rt); err != nil {
		t.Fatalf("glovo.ApplySchema: %v", err)
	}
	if err := ApplySchema(ctx, migURL, s.rt); err != nil {
		t.Fatalf("glovojoin.ApplySchema: %v", err)
	}
	if err := orders.ApplySchema(ctx, migURL, s.rt); err != nil {
		t.Fatalf("orders.ApplySchema: %v", err)
	}
	if err := workitems.ApplyGlovoApprovalSchema(ctx, migURL, s.rt, workitems.WithWorkItemsRole(s.wi)); err != nil {
		t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
	}
	if err := bridge.ApplySchema(ctx, migURL, s.rt, bridge.WithWorkItemsRole(s.wi)); err != nil {
		t.Fatalf("bridge.ApplySchema: %v", err)
	}
	s.mp = s.pool(migURL)
	s.rp = s.pool(s.url(s.rt))
	lazy := &lazyOrders{}
	s.work, err = workitems.NewStore(ctx, s.url(s.wi), workitems.WithGlovoOrders(lazy))
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	t.Cleanup(s.work.Close)
	s.conns, err = glovo.NewStore(ctx, s.rp, s.rt, s.mig, glovo.WithExplicitURL(true),
		glovo.WithRevocationHook(bridge.CancelOpenForConnections), glovo.WithLockTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("glovo.NewStore: %v", err)
	}
	s.orders, err = orders.NewStore(ctx, s.rp, s.rt, s.mig, s.conns, s.work)
	if err != nil {
		t.Fatalf("orders.NewStore: %v", err)
	}
	lazy.s = s.orders
	s.prepare = &Preparer{DB: s.rp, Conns: s.conns, Order: s.orders, Work: s.work}
	return s
}

func (s *stack) pool(u string) *pgxpool.Pool {
	s.t.Helper()
	p, err := pgxpool.New(context.Background(), u)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(p.Close)
	return p
}

var (
	stackAdmin  = glovo.Actor{PrincipalID: "prn_ADMIN00000000000000000001", Kind: glovo.ActorAdmin}
	stackUser   = glovo.Actor{PrincipalID: stackOwner, Kind: glovo.ActorUser}
	stackWorker = glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker}
	stackOf     = glovo.Owner{TenantID: stackTenant, PrincipalID: stackOwner}
)

// activate installs the tenant and makes the owner an active connection the
// way the #961 worker does: Connect then ActivateTx.
func (s *stack) activate(key string) {
	s.t.Helper()
	ctx := context.Background()
	inst, err := s.conns.Install(ctx, stackTenant, stackAdmin)
	if err != nil {
		s.t.Fatalf("Install: %v", err)
	}
	r, err := s.conns.Connect(ctx, glovo.ConnectInput{Owner: stackOf, ExpectedInstallRevision: inst.InstallRevision, IdempotencyKey: key, Actor: stackUser})
	if err != nil {
		s.t.Fatalf("Connect: %v", err)
	}
	tx, err := s.rp.Begin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := s.conns.ActivateTx(ctx, tx, glovo.ActivateInput{Owner: stackOf, ConnectionID: r.Connection.ConnectionID, ExpectedVersion: r.Connection.Version,
		ExpectedInstallRevision: inst.InstallRevision, ExpiresIn: time.Hour, Actor: stackWorker})
	if err != nil {
		s.t.Fatalf("ActivateTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		s.t.Fatal(err)
	}
	s.installID, s.installRev, s.connID = inst.InstallID, inst.InstallRevision, a.ConnectionID
}

// preview inserts a valid preview row bound to the live connection.
func (s *stack) preview(payload string) Preview {
	s.t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	p := Preview{Tenant: stackTenant, PrincipalID: stackOwner, ConnectionID: s.connID, InstallID: s.installID, InstallRevision: s.installRev,
		PayloadHash: PayloadHash([]byte(payload)), CreatedAt: now, ExpiresAt: now.Add(PreviewTTL)}
	var err error
	if p.ID, err = NewPreviewID(); err != nil {
		s.t.Fatal(err)
	}
	if payload != "" {
		_, canonical, perr := basket.Parse([]byte(payload))
		if perr != nil {
			s.t.Fatal(perr)
		}
		p.Approval, p.Fingerprint = canonical, basket.Fingerprint(canonical)
	}
	if err := InsertPreview(context.Background(), s.rp, p); err != nil {
		s.t.Fatal(err)
	}
	return p
}

func (s *stack) count(sql string, args ...any) int {
	s.t.Helper()
	var n int
	if err := s.mp.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		s.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (s *stack) req(p Preview, key string) PrepareRequest {
	return PrepareRequest{Tenant: stackTenant, PrincipalID: stackOwner, PreviewID: p.ID, Key: key, InstallID: s.installID, InstallRevision: s.installRev}
}
