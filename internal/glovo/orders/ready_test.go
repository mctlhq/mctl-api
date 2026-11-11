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

package orders

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// root is a superuser connection to the scratch database, used only to set up
// the ownership mutations the migration role cannot make.
func (e *env) root() *pgx.Conn {
	e.t.Helper()
	mu, err := url.Parse(e.migURL)
	if err != nil {
		e.t.Fatal(err)
	}
	su, err := url.Parse(adminURL(e.t))
	if err != nil {
		e.t.Fatal(err)
	}
	su.Path = mu.Path
	c, err := pgx.Connect(context.Background(), su.String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func (e *env) notReady(what string) {
	e.t.Helper()
	err := e.store.Ready(context.Background())
	if err == nil {
		e.t.Errorf("%s: Ready reported ready", what)
		return
	}
	if !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		e.t.Errorf("%s: Ready = %v, want not_ready", what, err)
	}
}

func (e *env) ready(what string) {
	e.t.Helper()
	if err := e.store.Ready(context.Background()); err != nil {
		e.t.Errorf("%s: Ready = %v", what, err)
	}
}

func TestReadyTriggerInventory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.ready("baseline")
	restore := func() {
		for _, tr := range triggerInventory {
			if _, err := e.admin.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON glovo.%s`, tr.Name, tr.Table)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.admin.Exec(ctx, `DROP TRIGGER IF EXISTS extra ON glovo.orders`); err != nil {
			t.Fatal(err)
		}
		if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
			t.Fatal(err)
		}
		e.ready("after restore")
	}
	for _, tr := range triggerInventory {
		if _, err := e.admin.Exec(ctx, fmt.Sprintf(`ALTER TABLE glovo.%s DISABLE TRIGGER %s`, tr.Table, tr.Name)); err != nil {
			t.Fatal(err)
		}
		e.notReady("disabled " + tr.Name)
		restore()

		if _, err := e.admin.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON glovo.%s`, tr.Name, tr.Table)); err != nil {
			t.Fatal(err)
		}
		e.notReady("dropped " + tr.Name)
		restore()

		other := "orders_immutable_rows"
		if tr.Function == other {
			other = "orders_guard"
		}
		if _, err := e.admin.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON glovo.%s`, tr.Name, tr.Table)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.admin.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON glovo.%s FOR EACH ROW EXECUTE FUNCTION glovo.%s()`,
			tr.Name, tr.Event, tr.Table, other)); err != nil {
			t.Fatal(err)
		}
		e.notReady("re-pointed " + tr.Name)
		restore()
	}
	if _, err := e.admin.Exec(ctx, `CREATE TRIGGER extra AFTER INSERT ON glovo.orders FOR EACH ROW EXECUTE FUNCTION glovo.orders_immutable_rows()`); err != nil {
		t.Fatal(err)
	}
	e.notReady("an unlisted trigger")
	restore()
}

func TestReadyOwnershipAndGrants(t *testing.T) {
	ctx := context.Background()
	type mutation struct {
		name string
		do   func(e *env)
	}
	for _, m := range []mutation{
		{"table owned by the runtime role", func(e *env) {
			mustExec(t, e.root(), `ALTER TABLE glovo.join_refs OWNER TO `+e.rt)
		}},
		{"table owned by an unrelated role", func(e *env) {
			r := e.root()
			e.extraRoles = append(e.extraRoles, "oth_"+e.rt)
			mustExec(t, r, fmt.Sprintf(`CREATE ROLE oth_%s NOLOGIN`, e.rt))
			mustExec(t, r, fmt.Sprintf(`ALTER TABLE glovo.order_effects OWNER TO oth_%s`, e.rt))
		}},
		{"table owned by a role the runtime role inherits", func(e *env) {
			r := e.root()
			e.extraRoles = append(e.extraRoles, "inh_"+e.rt)
			mustExec(t, r, fmt.Sprintf(`CREATE ROLE inh_%s NOLOGIN`, e.rt))
			mustExec(t, r, fmt.Sprintf(`GRANT inh_%s TO %s`, e.rt, e.rt))
			mustExec(t, r, fmt.Sprintf(`ALTER TABLE glovo.order_events OWNER TO inh_%s`, e.rt))
		}},
		{"trigger function owned by the runtime role", func(e *env) {
			mustExec(t, e.root(), `ALTER FUNCTION glovo.orders_guard() OWNER TO `+e.rt)
		}},
		{"schema owned by the runtime role", func(e *env) {
			mustExec(t, e.root(), `ALTER SCHEMA glovo OWNER TO `+e.rt)
		}},
		{"an extra grant", func(e *env) {
			mustExec(t, e.admin, `GRANT DELETE ON glovo.orders TO `+e.rt)
		}},
		{"an extra column grant", func(e *env) {
			mustExec(t, e.admin, `GRANT UPDATE (tenant) ON glovo.orders TO `+e.rt)
		}},
		{"a missing grant", func(e *env) {
			mustExec(t, e.admin, `REVOKE INSERT ON glovo.order_events FROM `+e.rt)
		}},
		{"a missing sequence grant", func(e *env) {
			mustExec(t, e.admin, `REVOKE USAGE ON SEQUENCE glovo.order_events_id_seq FROM `+e.rt)
		}},
		{"the work-item grant removed", func(e *env) {
			mustExec(t, e.admin, `REVOKE SELECT ON public.work_items FROM `+e.rt)
		}},
		{"schema CREATE for the runtime role", func(e *env) {
			mustExec(t, e.admin, `GRANT CREATE ON SCHEMA glovo TO `+e.rt)
		}},
		{"a version mismatch", func(e *env) {
			mustExec(t, e.admin, `UPDATE glovo.orders_schema_version SET version = 2`)
		}},
		{"a table missing", func(e *env) {
			mustExec(t, e.admin, `DROP TABLE glovo.order_effects CASCADE`)
		}},
	} {
		t.Run(m.name, func(t *testing.T) {
			e := newEnv(t)
			e.ready("baseline")
			m.do(e)
			e.notReady(m.name)
		})
	}
	_ = ctx
}

func TestReadyWrongMigrationRole(t *testing.T) {
	e := newEnv(t)
	// a valid, different role name: the schema is owned by a non-superuser role
	// and the runtime role is not its member, but it is not the named one
	s, err := NewStore(context.Background(), e.pool, e.rt, "someone_else", e.conns, fakeExecs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(context.Background()); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		t.Fatalf("Ready with a wrong migration role = %v", err)
	}
	if err := e.store.Ready(context.Background()); err != nil {
		t.Fatalf("Ready with the right one = %v", err)
	}
	// the runtime role named as migration role
	s2, _ := NewStore(context.Background(), e.pool, e.rt, e.rt, e.conns, fakeExecs{})
	if err := s2.Ready(context.Background()); err == nil {
		t.Fatal("Ready with runtime == migration role")
	}
}

func TestReadyNilCollaboratorWithDatabase(t *testing.T) {
	e := newEnv(t)
	for name, s := range map[string]func() (*Store, error){
		"nil connections": func() (*Store, error) {
			return NewStore(context.Background(), e.pool, e.rt, e.mig, nil, fakeExecs{})
		},
		"nil executions": func() (*Store, error) {
			return NewStore(context.Background(), e.pool, e.rt, e.mig, e.conns, nil)
		},
	} {
		st, err := s()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Ready(context.Background()); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
			t.Errorf("%s: Ready = %v", name, err)
		}
	}
}

func TestInjectedDatabaseErrorIsUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.mustCreate(scA, "k1", 500)
	// a closed pool is a database error, never not_ready
	pool, err := pgxpool.New(ctx, e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(ctx, pool, e.rt, e.mig, e.conns, fakeExecs{})
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	_, err = s.Get(ctx, pool, scA, o.OrderRef)
	wantCode(t, err, glovo.CodeUnavailable)
}

func TestLockTimeoutIsTenantBusy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.mustCreate(scA, "k1", 500)
	holder, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := e.store.LockOrder(ctx, holder, scA, o.OrderRef); err != nil {
		t.Fatal(err)
	}
	err = e.inTx(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
			return err
		}
		_, err := e.store.LockOrder(ctx, tx, scA, o.OrderRef)
		return err
	})
	wantCode(t, err, glovo.CodeTenantBusy)
	err = e.inTx(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
			return err
		}
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		_ = lo
		return err
	})
	wantCode(t, err, glovo.CodeTenantBusy)
}

func mustExec(t *testing.T, c *pgx.Conn, sql string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
