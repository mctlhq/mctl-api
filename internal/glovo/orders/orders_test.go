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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
)

var (
	scA  = Scope{Tenant: tenantA, PrincipalID: ownerA}
	scA2 = Scope{Tenant: tenantA, PrincipalID: ownerA2}
	scB  = Scope{Tenant: tenantB, PrincipalID: ownerB}
)

// ---- no database ----

func TestNewOrderRef(t *testing.T) {
	re := regexp.MustCompile(`^ordr_[A-Za-z0-9]{26}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		r := NewOrderRef()
		if !re.MatchString(r) || !orderRefRE.MatchString(r) || seen[r] {
			t.Fatalf("bad or repeated ref %q", r)
		}
		seen[r] = true
	}
}

func TestTriggerInventoryShape(t *testing.T) {
	if len(triggerInventory) != 8 {
		t.Fatalf("%d triggers, want 8", len(triggerInventory))
	}
	funcs, names := map[string]bool{}, map[string]bool{}
	for _, tr := range triggerInventory {
		funcs[tr.Function] = true
		if names[tr.Name] {
			t.Fatalf("duplicate trigger name %s", tr.Name)
		}
		names[tr.Name] = true
	}
	if len(funcs) != 5 {
		t.Fatalf("%d trigger functions, want 5", len(funcs))
	}
	for f := range funcs {
		if !regexp.MustCompile(`CREATE OR REPLACE FUNCTION glovo\.` + f + `\(`).MatchString(ordersFunctions) {
			t.Errorf("function %s is not created by CREATE OR REPLACE", f)
		}
	}
}

func TestRefusalMap(t *testing.T) {
	pg := func(code, constraint string) error {
		return &pgconn.PgError{Code: code, ConstraintName: constraint}
	}
	for name, c := range map[string]struct {
		err  error
		want glovo.Code
	}{
		"lock_timeout":      {pg("55P03", ""), glovo.CodeTenantBusy},
		"orders_execution":  {pg("23505", "orders_execution"), glovo.CodeInvalidTransition},
		"orders_approval":   {pg("23505", "orders_approval"), glovo.CodeInvalidTransition},
		"orders_command":    {pg("23505", "orders_command"), glovo.CodeInvalidTransition},
		"order_ref":         {pg("23505", "orders_order_ref_key"), glovo.CodeInvalidRequest},
		"trigger":           {pg("23000", ""), glovo.CodeInvalidTransition},
		"check":             {pg("23514", ""), glovo.CodeInvalidTransition},
		"other unique":      {pg("23505", "something"), glovo.CodeUnavailable},
		"other db error":    {errors.New("boom"), glovo.CodeUnavailable},
		"passthrough":       {glovo.Refuse(glovo.CodeConnectionRevoked), glovo.CodeConnectionRevoked},
		"context cancelled": {context.Canceled, glovo.CodeUnavailable},
	} {
		wantCode(t, mapErr(c.err), c.want)
		_ = name
	}
	// every code this slice returns is in the closed enum
	for _, c := range []glovo.Code{glovo.CodeNotFound, glovo.CodeNoConnection, glovo.CodeConnectionRevoked, glovo.CodeConnectionExpired,
		glovo.CodeStaleInstall, glovo.CodeInvalidRequest, glovo.CodeFingerprintChanged, glovo.CodeIdempotencyReused,
		glovo.CodeInvalidTransition, glovo.CodeTenantBusy, glovo.CodeUnavailable, glovo.CodeNotReady} {
		if !glovo.Registered(c) {
			t.Errorf("%s is not registered", c)
		}
	}
	for c, status := range map[glovo.Code]int{glovo.CodeNotFound: 404, glovo.CodeNoConnection: 404, glovo.CodeConnectionRevoked: 409,
		glovo.CodeConnectionExpired: 409, glovo.CodeStaleInstall: 403, glovo.CodeInvalidRequest: 400, glovo.CodeFingerprintChanged: 409,
		glovo.CodeIdempotencyReused: 409, glovo.CodeInvalidTransition: 409, glovo.CodeTenantBusy: 409, glovo.CodeUnavailable: 503, glovo.CodeNotReady: 503} {
		if glovo.Status(c) != status {
			t.Errorf("%s: status %d, want %d", c, glovo.Status(c), status)
		}
	}
}

func TestNilCollaboratorIsNotReady(t *testing.T) {
	for name, s := range map[string]*Store{"nil store": nil, "nil collaborators": {}} {
		_, err := s.Get(context.Background(), nil, scA, "ordr_x")
		wantCode(t, err, glovo.CodeNotReady)
		_, _, err = s.Create(context.Background(), nil, CreateInput{})
		wantCode(t, err, glovo.CodeNotReady)
		_, err = s.PeekOrderScope(context.Background(), nil, "ordr_x", nil)
		wantCode(t, err, glovo.CodeNotReady)
		_, err = s.MintJoinRefTx(context.Background(), nil, JoinTenant, "t", "", "t")
		wantCode(t, err, glovo.CodeNotReady)
		if err := s.Ready(context.Background()); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
			t.Errorf("%s: Ready = %v", name, err)
		}
	}
}

// ---- database ----

func TestApplySchemaTwiceAndReady(t *testing.T) {
	e := newEnv(t)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err != nil {
		t.Fatalf("second ApplySchema: %v", err)
	}
	if err := e.store.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
}

func TestApplySchemaRefusesForeignOwner(t *testing.T) {
	e := newEnvNoSchema(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `CREATE SCHEMA glovo`); err != nil {
		t.Fatal(err)
	}
	// a pre-created table owned by the runtime role, made by a superuser
	mu, err := url.Parse(e.migURL)
	if err != nil {
		t.Fatal(err)
	}
	su, err := url.Parse(adminURL(t))
	if err != nil {
		t.Fatal(err)
	}
	su.Path = mu.Path
	root, err := pgx.Connect(ctx, su.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close(ctx) }()
	if _, err := root.Exec(ctx, `CREATE TABLE glovo.orders (x int)`); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, `ALTER TABLE glovo.orders OWNER TO `+e.rt); err != nil {
		t.Fatal(err)
	}
	if err := ApplySchema(ctx, e.migURL, e.rt); err == nil || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("ApplySchema with a foreign-owned table = %v", err)
	}
}

func TestApplySchemaRefusesDowngrade(t *testing.T) {
	e := newEnv(t)
	if _, err := e.admin.Exec(context.Background(), `UPDATE glovo.orders_schema_version SET version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err == nil {
		t.Fatal("ApplySchema accepted a newer recorded version")
	}
	if err := e.store.Ready(context.Background()); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		t.Fatalf("Ready with a version mismatch = %v", err)
	}
}

func TestOwnerIsolationAndSameNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.mustCreate(scA, "k1", 500)
	for name, sc := range map[string]Scope{"other tenant": scB, "same tenant other member": scA2} {
		_, err := e.store.Get(ctx, e.pool, sc, o.OrderRef)
		wantCode(t, err, glovo.CodeNotFound)
		_, err = e.store.Snapshot(ctx, e.pool, sc, o.OrderRef, 1)
		wantCode(t, err, glovo.CodeNotFound)
		err = e.inTx(func(tx pgx.Tx) error { _, err := e.store.LockOrder(ctx, tx, sc, o.OrderRef); return err })
		wantCode(t, err, glovo.CodeNotFound)
		err = e.inTx(func(tx pgx.Tx) error {
			return e.store.BindApproval(ctx, tx, sc, Actor{Kind: ActorOwner, ID: sc.PrincipalID}, o.OrderRef, newAAR())
		})
		wantCode(t, err, glovo.CodeNotFound)
		_ = name
	}
	// missing, foreign and malformed refs are one error value
	var errs []error
	for _, ref := range []string{NewOrderRef(), o.OrderRef, "not-a-ref", "' OR 1=1 --"} {
		_, err := e.store.Get(ctx, e.pool, scB, ref)
		errs = append(errs, err)
	}
	for _, err := range errs {
		if err.Error() != errs[0].Error() {
			t.Fatalf("distinguishable not_found: %v vs %v", err, errs[0])
		}
	}
	if got, err := e.store.Get(ctx, e.pool, scA, o.OrderRef); err != nil || got.OrderRef != o.OrderRef || got.State != StateOpen || got.Version != 1 {
		t.Fatalf("owner Get = %+v, %v", got, err)
	}
}

func TestCreateIdempotency(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	in := e.input(scA, "k1", 500)
	first, replayed, err := e.create(in)
	if err != nil || replayed {
		t.Fatalf("first Create: %v %v", replayed, err)
	}
	again := in
	again.OrderRef, again.ExecutionID = NewOrderRef(), e.execution(scA.Tenant, scA.PrincipalID)
	got, replayed, err := e.create(again)
	if err != nil || !replayed || got.OrderRef != first.OrderRef || got.ExecutionID != first.ExecutionID {
		t.Fatalf("replay: %+v %v %v", got, replayed, err)
	}
	other := again
	other.RequestHash = "different"
	_, _, err = e.create(other)
	wantCode(t, err, glovo.CodeIdempotencyReused)

	if _, err := e.store.LookupByIdempotencyKey(ctx, e.pool, scA, "nope"); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("lookup miss = %v", err)
	}
	if o, err := e.store.LookupByIdempotencyKey(ctx, e.pool, scA, "k1"); err != nil || o.OrderRef != first.OrderRef {
		t.Fatalf("lookup hit = %+v %v", o, err)
	}
	var n int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM glovo.orders`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d orders, want 1 (%v)", n, err)
	}
	bad := e.input(scA, "k2", 500)
	bad.OrderRef = "ordr_short"
	_, _, err = e.create(bad)
	wantCode(t, err, glovo.CodeInvalidRequest)
}

func TestConcurrentCreateOneRow(t *testing.T) {
	e := newEnv(t)
	in := e.input(scA, "same-key", 500)
	var wg sync.WaitGroup
	results := make([]string, 20)
	errs := make([]error, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := in
			c.OrderRef = NewOrderRef()
			o, _, err := e.create(c)
			errs[i] = err
			if o != nil {
				results[i] = o.OrderRef
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if results[i] != results[0] {
			t.Fatalf("two order refs: %s %s", results[i], results[0])
		}
	}
	var n int
	if err := e.admin.QueryRow(context.Background(), `SELECT count(*) FROM glovo.orders`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d orders (%v)", n, err)
	}
}

func TestCreateRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	in := e.input(scA, "k1", 500)
	in.ExpectedFingerprint = fingerprintOf(t, basketJSON(501))
	_, _, err := e.create(in)
	wantCode(t, err, glovo.CodeFingerprintChanged)

	for name, c := range map[string]struct {
		mutate func(*CreateInput)
		want   glovo.Code
	}{
		"foreign tenant execution": {func(in *CreateInput) { in.ExecutionID = e.execution(tenantB, ownerB) }, glovo.CodeNotFound},
		"foreign owner execution":  {func(in *CreateInput) { in.ExecutionID = e.execution(tenantA, ownerA2) }, glovo.CodeNotFound},
		"missing execution":        {func(in *CreateInput) { in.ExecutionID = "we_0123456789abcdef0123" }, glovo.CodeNotFound},
		"uuid execution":           {func(in *CreateInput) { in.ExecutionID = "we_123e4567-e89b-12d3-a456-426614174000" }, glovo.CodeNotFound},
		"empty basket":             {func(in *CreateInput) { in.ApprovalBasket = []byte(`{}`) }, glovo.CodeInvalidRequest},
		"moved revision":           {func(in *CreateInput) { in.ExpectedInstallRevision = 4 }, glovo.CodeStaleInstall},
		"other connection":         {func(in *CreateInput) { in.ConnectionID = "gcn_ffffffffffffffffffff" }, glovo.CodeConnectionRevoked},
	} {
		c2 := e.input(scA, "r-"+name, 500)
		c.mutate(&c2)
		_, _, err := e.create(c2)
		if err == nil || !glovoIs(err, c.want) {
			t.Errorf("%s: got %v, want %s", name, err, c.want)
		}
	}

	// the same execution cannot bind a second order
	a := e.input(scA, "x1", 500)
	if _, _, err := e.create(a); err != nil {
		t.Fatal(err)
	}
	b := e.input(scA, "x2", 500)
	b.ExecutionID = a.ExecutionID
	_, _, err = e.create(b)
	wantCode(t, err, glovo.CodeInvalidTransition)

	// REPEATABLE READ is refused
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, _, err = e.store.Create(ctx, tx, e.input(scA, "rr", 500))
	wantCode(t, err, glovo.CodeUnavailable)
}

func TestConnectionRechecks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.mustCreate(scA, "k1", 500)
	snap, _ := e.store.Snapshot(ctx, e.pool, scA, o.OrderRef, 1)
	actor := Actor{Kind: ActorOwner, ID: ownerA}

	for name, c := range map[string]struct {
		err  error
		want glovo.Code
	}{
		"absent":  {glovo.Refuse(glovo.CodeNoConnection), glovo.CodeNoConnection},
		"revoked": {glovo.Refuse(glovo.CodeConnectionRevoked), glovo.CodeConnectionRevoked},
		"expired": {glovo.Refuse(glovo.CodeConnectionExpired), glovo.CodeConnectionExpired},
	} {
		e.conns.set(nil, c.err)
		_, _, err := e.create(e.input(scA, "c-"+name, 500))
		wantCode(t, err, c.want)
	}
	// revoked: reads work; Finalize and BindApproval do not; AppendSnapshot does not
	e.conns.set(nil, glovo.Refuse(glovo.CodeConnectionRevoked))
	if _, err := e.store.Get(ctx, e.pool, scA, o.OrderRef); err != nil {
		t.Fatalf("read after revoke: %v", err)
	}
	b, _, _ := basket.Parse(basketJSON(500))
	err := e.inTx(func(tx pgx.Tx) error {
		_, err := e.store.AppendSnapshot(ctx, tx, scA, actor, o.OrderRef, o.Version, b, snap.Fingerprint)
		return err
	})
	wantCode(t, err, glovo.CodeConnectionRevoked)
	err = e.inTx(func(tx pgx.Tx) error {
		_, err := e.store.Finalize(ctx, tx, scA, actor, o.OrderRef, o.Version, snap.Fingerprint)
		return err
	})
	wantCode(t, err, glovo.CodeConnectionRevoked)

	// the control-path terminal marks never read the connection
	before := e.conns.count()
	locked := false
	if err := e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		locked = true
		return e.store.MarkCancelled(ctx, tx, lo, Actor{Kind: ActorControlWorker, ID: "worker"})
	}); err != nil || !locked {
		t.Fatalf("MarkCancelled after revoke: %v", err)
	}
	if e.conns.count() != before {
		t.Fatal("MarkCancelled re-read the connection")
	}
}

func TestLifecycleSharedTransaction(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	actor := Actor{Kind: ActorOwner, ID: ownerA}
	worker := Actor{Kind: ActorControlWorker, ID: "worker"}
	in := e.input(scA, "k1", 500)
	o, _, err := e.create(in)
	if err != nil {
		t.Fatal(err)
	}
	// append a second snapshot with a new price, then finalize it
	b2raw := basketJSON(600)
	b2, _, err := basket.Parse(b2raw)
	if err != nil {
		t.Fatal(err)
	}
	fp2 := fingerprintOf(t, b2raw)
	var sn *Snapshot
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		sn, err = e.store.AppendSnapshot(ctx, tx, scA, actor, o.OrderRef, o.Version, b2, fp2)
		return err
	}); err != nil || sn.Seq != 2 || sn.Fingerprint != fp2 {
		t.Fatalf("AppendSnapshot: %+v %v", sn, err)
	}
	// stale version is a CAS miss
	err = e.inTx(func(tx pgx.Tx) error {
		_, err := e.store.Finalize(ctx, tx, scA, actor, o.OrderRef, o.Version, fp2)
		return err
	})
	wantCode(t, err, glovo.CodeInvalidTransition)
	cur, _ := e.store.Get(ctx, e.pool, scA, o.OrderRef)
	// a wrong fingerprint writes nothing
	err = e.inTx(func(tx pgx.Tx) error {
		_, err := e.store.Finalize(ctx, tx, scA, actor, o.OrderRef, cur.Version, in.ExpectedFingerprint)
		return err
	})
	wantCode(t, err, glovo.CodeFingerprintChanged)
	var fin *Order
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		fin, err = e.store.Finalize(ctx, tx, scA, actor, o.OrderRef, cur.Version, fp2)
		return err
	}); err != nil || fin.State != StateFinalized || fin.FinalBasketFingerprint != fp2 || fin.FinalSnapshotSeq != 2 {
		t.Fatalf("Finalize: %+v %v", fin, err)
	}
	// finalized: no more snapshots
	err = e.inTx(func(tx pgx.Tx) error {
		_, err := e.store.AppendSnapshot(ctx, tx, scA, actor, o.OrderRef, fin.Version, b2, fp2)
		return err
	})
	wantCode(t, err, glovo.CodeInvalidTransition)

	// dispatch without an approval is refused
	err = e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		return e.store.MarkDispatched(ctx, tx, lo, newCMD(), worker)
	})
	wantCode(t, err, glovo.CodeInvalidTransition)

	aar := newAAR()
	if err := e.inTx(func(tx pgx.Tx) error { return e.store.BindApproval(ctx, tx, scA, actor, o.OrderRef, aar) }); err != nil {
		t.Fatalf("BindApproval: %v", err)
	}
	err = e.inTx(func(tx pgx.Tx) error { return e.store.BindApproval(ctx, tx, scA, actor, o.OrderRef, newAAR()) })
	wantCode(t, err, glovo.CodeInvalidTransition)

	// control path: scope from the row, outside tenants is not_found
	if _, err := e.store.PeekOrderScope(ctx, e.pool, o.OrderRef, []string{tenantB}); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("peek outside tenants = %v", err)
	}
	sc, err := e.store.PeekOrderScope(ctx, e.pool, o.OrderRef, []string{tenantA, tenantB})
	if err != nil || sc != scA {
		t.Fatalf("peek = %+v %v", sc, err)
	}
	cmd := newCMD()
	if err := e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		if lo.OwnerPrincipalID != ownerA || lo.ApprovalRef != aar {
			t.Errorf("control order = %+v", lo)
		}
		before := e.conns.count()
		if err := e.store.MarkDispatched(ctx, tx, lo, cmd, worker); err != nil {
			return err
		}
		if e.conns.count() != before {
			t.Error("MarkDispatched re-read the connection")
		}
		return nil
	}); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	var effects int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM glovo.order_effects WHERE execution_id = $1`, in.ExecutionID).Scan(&effects); err != nil || effects != 1 {
		t.Fatalf("%d effect rows (%v)", effects, err)
	}
	// dispatched -> unknown -> (no Go edge to closed from unknown); dispatched -> closed
	if err := e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		if err := e.store.MarkUnknown(ctx, tx, lo, worker); err != nil {
			return err
		}
		return e.store.MarkClosed(ctx, tx, lo, worker)
	}); err == nil {
		t.Fatal("MarkClosed from unknown succeeded")
	}
	if err := e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		return e.store.MarkClosed(ctx, tx, lo, worker)
	}); err != nil {
		t.Fatalf("MarkClosed: %v", err)
	}
	err = e.inTx(func(tx pgx.Tx) error {
		lo, err := e.store.LockOrderForControl(ctx, tx, o.OrderRef, []string{tenantA})
		if err != nil {
			return err
		}
		return e.store.MarkCancelled(ctx, tx, lo, worker)
	})
	wantCode(t, err, glovo.CodeInvalidTransition)

	// events carry the actor kind and no basket or fingerprint
	rows, err := e.admin.Query(ctx, `SELECT actor_kind, event, to_state FROM glovo.order_events WHERE order_ref = $1 ORDER BY id`, o.OrderRef)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	kinds := map[string]int{}
	for rows.Next() {
		var k, ev, to string
		if err := rows.Scan(&k, &ev, &to); err != nil {
			t.Fatal(err)
		}
		kinds[k]++
	}
	if kinds["owner"] == 0 || kinds["control_worker"] == 0 {
		t.Fatalf("event actor kinds = %v", kinds)
	}
}

func TestSharedTransactionRollsBack(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	in := e.input(scA, "k1", 500)
	err := e.inTx(func(tx pgx.Tx) error {
		if _, _, err := e.store.Create(ctx, tx, in); err != nil {
			return err
		}
		return errors.New("failure after the last statement")
	})
	if err == nil {
		t.Fatal("expected the injected failure")
	}
	var n int
	if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM glovo.orders) + (SELECT count(*) FROM glovo.order_snapshots) + (SELECT count(*) FROM glovo.order_events)`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d rows left (%v)", n, err)
	}
}

func TestJoinRefs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var tnr, prr, irv string
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		if tnr, err = e.store.MintJoinRefTx(ctx, tx, JoinTenant, tenantA, "", tenantA); err != nil {
			return err
		}
		if prr, err = e.store.MintJoinRefTx(ctx, tx, JoinPrincipal, tenantA, ownerA, ownerA); err != nil {
			return err
		}
		irv, err = e.store.MintJoinRefTx(ctx, tx, JoinInstallRevision, tenantA, "", "gin_install:3")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for ref, prefix := range map[string]string{tnr: "tnr_", prr: "prr_", irv: "irv_"} {
		if !regexp.MustCompile(`^` + prefix + `[A-Za-z0-9]{26}$`).MatchString(ref) {
			t.Errorf("bad ref %q", ref)
		}
	}
	var again string
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		again, err = e.store.MintJoinRefTx(ctx, tx, JoinTenant, tenantA, "", tenantA)
		return err
	}); err != nil || again != tnr {
		t.Fatalf("insert-or-read: %q %v", again, err)
	}
	if _, err := e.store.LookupJoinRefTx(ctx, e.pool, JoinTenant, tenantB, "", tenantB); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("lookup of a never-minted ref = %v", err)
	}
	if sc, err := e.store.ScopeFromRefs(ctx, e.pool, tnr, prr); err != nil || sc != scA {
		t.Fatalf("ScopeFromRefs = %+v %v", sc, err)
	}
	var tnrB, prrB string
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		if tnrB, err = e.store.MintJoinRefTx(ctx, tx, JoinTenant, tenantB, "", tenantB); err != nil {
			return err
		}
		prrB, err = e.store.MintJoinRefTx(ctx, tx, JoinPrincipal, tenantB, ownerB, ownerB)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.ScopeFromRefs(ctx, e.pool, tnr, prrB); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("refs of two tenants = %v", err)
	}
	_ = tnrB
	if _, err := e.store.MintJoinRefTx(ctx, nil, JoinKind("order"), tenantA, "", "x"); !errors.Is(err, glovo.Refuse(glovo.CodeInvalidRequest)) {
		t.Fatalf("ordr_ kind = %v", err)
	}
}

func TestRegisteredGrantRows(t *testing.T) {
	want := map[string]string{
		"join_refs": "INSERT,SELECT", "order_snapshots": "INSERT,SELECT", "order_effects": "INSERT,SELECT",
		"order_events": "INSERT,SELECT", "orders": "INSERT,SELECT", "orders_schema_version": "SELECT",
	}
	for _, table := range orderTables {
		row, ok := glovo.GrantFor(table)
		if !ok {
			t.Fatalf("%s has no grant row", table)
		}
		if got := strings.Join(row.Privileges, ","); got != want[table] {
			t.Errorf("%s: %s, want %s", table, got, want[table])
		}
		if table == "orders" && strings.Join(row.UpdateColumns, ",") != "approval_ref,command_id,final_basket_fingerprint,final_snapshot_seq,state,updated_at,version" {
			t.Errorf("orders update columns: %v", row.UpdateColumns)
		}
	}
}
