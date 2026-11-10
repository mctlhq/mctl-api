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

package control

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// proofEnv is the production shape: every slice's schema applied by the one
// migration role, one shared runtime-role pool for the bridge and the Glovo
// store, and a separate work-items pool.
type proofEnv struct {
	*env
	gs  *glovo.Store
	bs  *bridge.Store
	wip *pgxpool.Pool
}

func newProofEnv(t *testing.T) *proofEnv {
	t.Helper()
	e := newBase(t)
	ctx := context.Background()
	// The slices apply in a fixed order; a map would not keep it.
	steps := []struct {
		name  string
		apply func() error
	}{
		{"glovo", func() error { return glovo.ApplySchema(ctx, e.migURL, e.rt) }},
		{"join", func() error { return glovojoin.ApplySchema(ctx, e.migURL, e.rt) }},
		{"orders", func() error { return orders.ApplySchema(ctx, e.migURL, e.rt) }},
		{"approvals", func() error {
			return workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, workitems.WithWorkItemsRole(e.wi))
		}},
		{"bridge", func() error { return bridge.ApplySchema(ctx, e.migURL, e.rt, bridge.WithWorkItemsRole(e.wi)) }},
	}
	for _, s := range steps {
		if err := s.apply(); err != nil {
			t.Fatalf("apply %s: %v", s.name, err)
		}
	}
	e.mp = e.pool(e.migURL)
	e.rtp = e.pool(e.rtURL)
	p := &proofEnv{env: e, wip: e.pool(e.url(e.wi))}
	var err error
	if p.bs, err = bridge.NewRuntimeStore(ctx, e.rtp); err != nil {
		t.Fatalf("NewRuntimeStore: %v", err)
	}
	p.gs, err = glovo.NewStore(ctx, e.rtp, e.rt, e.mig, glovo.WithExplicitURL(true), glovo.WithRevocationHook(bridge.CancelOpenForConnections))
	if err != nil {
		t.Fatalf("glovo.NewStore: %v", err)
	}
	return p
}

func (p *proofEnv) prove() error { return ProveOneDatabase(context.Background(), p.bs, p.gs, p.wip) }

func (p *proofEnv) superExec(db string, stmts ...string) {
	p.t.Helper()
	u, err := url.Parse(p.base)
	if err != nil {
		p.t.Fatal(err)
	}
	u.Path = "/" + db
	ctx := context.Background()
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		p.t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	for _, s := range stmts {
		if _, err := c.Exec(ctx, s); err != nil {
			p.t.Fatalf("%s: %v", s, err)
		}
	}
}

func (p *proofEnv) wantFail(substr string) {
	p.t.Helper()
	err := p.prove()
	if err == nil {
		p.t.Fatalf("the proof passed, want a failure containing %q", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		p.t.Fatalf("the proof failed with %q, want it to contain %q", err, substr)
	}
	if n := p.count(`SELECT count(*) FROM bridge_colocation_probe`); n != 0 {
		p.t.Fatalf("%d nonce rows survived a failed proof", n)
	}
}

func TestProveOneDatabase(t *testing.T) {
	t.Run("passes on the converged production shape and leaves no nonce", func(t *testing.T) {
		p := newProofEnv(t)
		if err := p.prove(); err != nil {
			t.Fatalf("the proof failed on a converged input: %v", err)
		}
		if n := p.count(`SELECT count(*) FROM bridge_colocation_probe`); n != 0 {
			t.Fatalf("%d nonce rows survived", n)
		}
	})
	t.Run("nil collaborators", func(t *testing.T) {
		p := newProofEnv(t)
		ctx := context.Background()
		if err := ProveOneDatabase(ctx, nil, p.gs, p.wip); err == nil {
			t.Fatal("nil bridge store passed")
		}
		if err := ProveOneDatabase(ctx, p.bs, nil, p.wip); err == nil {
			t.Fatal("nil glovo store passed")
		}
		if err := ProveOneDatabase(ctx, p.bs, p.gs, nil); err == nil {
			t.Fatal("nil work-items pool passed")
		}
	})
	t.Run("the stores must share one pool", func(t *testing.T) {
		p := newProofEnv(t)
		other := p.pool(p.rtURL)
		gs, err := glovo.NewStore(context.Background(), other, p.rt, p.mig, glovo.WithExplicitURL(true), glovo.WithRevocationHook(bridge.CancelOpenForConnections))
		if err != nil {
			t.Fatal(err)
		}
		err = ProveOneDatabase(context.Background(), p.bs, gs, p.wip)
		if err == nil || !strings.Contains(err.Error(), "share one pool") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the work-items pool is not the shared pool", func(t *testing.T) {
		p := newProofEnv(t)
		err := ProveOneDatabase(context.Background(), p.bs, p.gs, p.rtp)
		if err == nil || !strings.Contains(err.Error(), "is the shared pool") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a work-items pool on another database is not one database", func(t *testing.T) {
		p := newProofEnv(t)
		root, err := pgx.Connect(context.Background(), p.base)
		if err != nil {
			t.Fatal(err)
		}
		other := p.db + "_other"
		if _, err := root.Exec(context.Background(), fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, other, p.mig)); err != nil {
			t.Fatal(err)
		}
		_ = root.Close(context.Background())
		t.Cleanup(func() {
			c, err := pgx.Connect(context.Background(), p.base)
			if err != nil {
				return
			}
			defer func() { _ = c.Close(context.Background()) }()
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, other))
		})
		p.superExec(other, `CREATE TABLE public.bridge_colocation_probe (nonce text)`,
			fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, other, p.wi), fmt.Sprintf(`GRANT SELECT ON public.bridge_colocation_probe TO %s`, p.wi))
		u, _ := url.Parse(p.url(p.wi))
		u.Path = "/" + other
		wip := p.pool(u.String())
		err = ProveOneDatabase(context.Background(), p.bs, p.gs, wip)
		if err == nil || !strings.Contains(err.Error(), "not one database") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a work-items pool that cannot read the probe fails", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, fmt.Sprintf(`REVOKE SELECT ON bridge_colocation_probe FROM %s`, p.wi))
		p.wantFail("read nonce on the work-items pool")
	})
	t.Run("a nonce that cannot be written fails", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, fmt.Sprintf(`REVOKE INSERT ON bridge_colocation_probe FROM %s`, p.rt))
		err := p.prove()
		if err == nil || !strings.Contains(err.Error(), "write nonce") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a missing relation fails", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, `ALTER TABLE glovo.control_starts RENAME TO control_starts_x`)
		p.wantFail("glovo.control_starts is missing")
	})
	t.Run("drifted bridge grants fail", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, fmt.Sprintf(`GRANT DELETE ON bridge_commands TO %s`, p.rt))
		p.wantFail("bridge grants")
	})
	t.Run("a disabled guard trigger fails", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, `ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`)
		p.wantFail("guard trigger")
	})
	t.Run("a work-items role with USAGE on schema glovo fails", func(t *testing.T) {
		p := newProofEnv(t)
		p.superExec(p.db, fmt.Sprintf(`GRANT USAGE ON SCHEMA glovo TO %s`, p.wi))
		p.wantFail("USAGE on schema glovo")
	})
	t.Run("a work-items pool on the shared role fails", func(t *testing.T) {
		p := newProofEnv(t)
		sameRole := p.pool(p.rtURL)
		err := ProveOneDatabase(context.Background(), p.bs, p.gs, sameRole)
		if err == nil || !strings.Contains(err.Error(), "uses the shared role") {
			t.Fatalf("got %v", err)
		}
	})
}

// proveRole and proveTriggers are checked on their own: the stores' own Ready
// checks reject some of the same drift earlier, so the proof alone would not
// show that these two functions can fail.
func TestProveRoleAndTriggers(t *testing.T) {
	p := newProofEnv(t)
	ctx := context.Background()
	if err := proveRole(ctx, p.rtp); err != nil {
		t.Fatalf("the runtime role: %v", err)
	}
	if err := proveTriggers(ctx, p.rtp); err != nil {
		t.Fatalf("converged triggers: %v", err)
	}
	// The owner owns every relation.
	if err := proveRole(ctx, p.mp); err == nil {
		t.Fatal("the migration role passed as a runtime role")
	}
	for _, attr := range []string{"CREATEROLE", "CREATEDB", "BYPASSRLS"} {
		role := "c985x_" + rnd(4)
		p.superExec(p.db, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' %s`, role, pw, attr),
			fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, p.db, role))
		t.Cleanup(func() {
			p.superExec("postgres", fmt.Sprintf(`DROP OWNED BY %s`, role), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role))
		})
		if err := proveRole(ctx, p.pool(p.url(role))); err == nil {
			t.Fatalf("a role with %s passed", attr)
		}
	}
	// A member of the owner role owns what it owns.
	member := "c985m_" + rnd(4)
	p.superExec(p.db, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, member, pw), fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, p.db, member),
		fmt.Sprintf(`GRANT %s TO %s`, p.mig, member))
	t.Cleanup(func() {
		p.superExec("postgres", fmt.Sprintf(`DROP OWNED BY %s`, member), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, member))
	})
	if err := proveRole(ctx, p.pool(p.url(member))); err == nil {
		t.Fatal("a member of the owner role passed")
	}
	// A failed read is an error, never a pass.
	closed := p.pool(p.rtURL)
	closed.Close()
	if err := proveRole(ctx, closed); err == nil {
		t.Fatal("proveRole passed on a closed pool")
	}
	if err := proveTriggers(ctx, closed); err == nil {
		t.Fatal("proveTriggers passed on a closed pool")
	}
	p.superExec(p.db, `ALTER TABLE glovo.orders DISABLE TRIGGER USER`)
	if err := proveTriggers(ctx, p.rtp); err == nil {
		t.Fatal("a disabled glovo trigger passed")
	}
}

func TestProofIsSticky(t *testing.T) {
	var nilProof *Proof
	wantCode(t, nilProof.Err(), glovo.CodeNotReady)
	var p Proof
	wantCode(t, p.Err(), glovo.CodeNotReady)
	calls := 0
	if err := p.Run(func() error { calls++; return errors.New("boom") }); err == nil {
		t.Fatal("a failed run returned nil")
	}
	// A failure is never retried into a pass.
	if err := p.Run(func() error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatalf("second run: %v calls %d", err, calls)
	}
	wantCode(t, p.Err(), glovo.CodeNotReady)
	var ok Proof
	if err := ok.Run(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := ok.Err(); err != nil {
		t.Fatalf("a passed proof is not ready: %v", err)
	}
}
