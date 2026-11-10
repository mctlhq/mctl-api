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
	"fmt"
	"strings"
	"testing"
)

// rawExec runs one statement as the runtime role, outside the Go API.
func (e *env) rawExec(sql string, args ...any) error {
	_, err := e.pool.Exec(context.Background(), sql, args...)
	return err
}

func mustRefuse(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s was accepted", what)
	}
}

func TestRuntimeRoleCannotAlterOrDelete(t *testing.T) {
	e := newEnv(t)
	o := e.mustCreate(scA, "k1", 500)
	for _, sql := range []string{
		`DELETE FROM glovo.orders`,
		`TRUNCATE glovo.orders CASCADE`,
		`TRUNCATE glovo.order_events`,
		`ALTER TABLE glovo.orders DISABLE TRIGGER orders_guard`,
		`ALTER TABLE glovo.orders DISABLE TRIGGER ALL`,
		`DROP TRIGGER orders_guard ON glovo.orders`,
		`DROP TABLE glovo.order_snapshots CASCADE`,
		`DROP SCHEMA glovo CASCADE`,
		`ALTER TABLE glovo.orders ADD COLUMN x int`,
		`CREATE TABLE glovo.evil (x int)`,
		`UPDATE glovo.orders SET tenant = 'team-b'`,
		`UPDATE glovo.orders SET order_ref = 'ordr_0123456789abcdef0123'`,
		`UPDATE glovo.orders SET execution_id = 'we_0123456789abcdef0123'`,
		`DELETE FROM glovo.order_events`,
		`UPDATE glovo.order_events SET event = 'x'`,
		`UPDATE glovo.order_snapshots SET line_count = 9`,
		`DELETE FROM glovo.order_snapshots`,
		`UPDATE glovo.join_refs SET tenant = 'x'`,
		`DELETE FROM glovo.order_effects`,
	} {
		mustRefuse(t, sql, e.rawExec(sql))
	}
	_ = o
}

func TestLifecycleMatrixInSQL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	states := []string{StateOpen, StateFinalized, StateDispatched, StateCancelled, StateUnknown, StateClosed}
	allowed := map[string]bool{
		"open>finalized": true, "open>cancelled": true, "finalized>dispatched": true, "finalized>cancelled": true,
		"dispatched>cancelled": true, "dispatched>unknown": true, "dispatched>closed": true, "unknown>closed": true,
	}
	// An order in every state is made by the legitimate path plus the
	// migration role (which owns the tables and bypasses the column grants but
	// not the triggers).
	mk := func(state string) *Order {
		o := e.mustCreate(scA, "m-"+state+"-"+randHex(4), 500)
		if state == StateOpen {
			return o
		}
		if state == StateCancelled {
			if _, err := e.admin.Exec(ctx, `UPDATE glovo.orders SET state='cancelled' WHERE order_ref=$1`, o.OrderRef); err != nil {
				t.Fatal(err)
			}
			return o
		}
		o = e.finalize(scA, o)
		if state == StateFinalized {
			return o
		}
		if _, err := e.admin.Exec(ctx, `UPDATE glovo.orders SET approval_ref=$2 WHERE order_ref=$1`, o.OrderRef, newAAR()); err != nil {
			t.Fatal(err)
		}
		if _, err := e.admin.Exec(ctx, `UPDATE glovo.orders SET state='dispatched', command_id=$2 WHERE order_ref=$1`, o.OrderRef, newCMD()); err != nil {
			t.Fatal(err)
		}
		if state != StateDispatched {
			if _, err := e.admin.Exec(ctx, `UPDATE glovo.orders SET state=$2 WHERE order_ref=$1`, o.OrderRef, state); err != nil {
				t.Fatal(err)
			}
		}
		return o
	}
	for _, from := range states {
		for _, to := range states {
			if from == to {
				continue
			}
			o := mk(from)
			_, err := e.pool.Exec(ctx, `UPDATE glovo.orders SET state=$2 WHERE order_ref=$1`, o.OrderRef, to)
			if allowed[from+">"+to] {
				// the allowed pairs may still fail a CHECK of the target state
				// (a fingerprint or command id); they must not fail the matrix
				if err != nil && strings.Contains(err.Error(), "transition not allowed") {
					t.Errorf("%s -> %s refused by the matrix: %v", from, to, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("%s -> %s was accepted in SQL", from, to)
			}
		}
	}
}

func TestOrderWriteOnceColumns(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.finalize(scA, e.mustCreate(scA, "k1", 500))
	aar := newAAR()
	if err := e.rawExec(`UPDATE glovo.orders SET approval_ref=$2 WHERE order_ref=$1`, o.OrderRef, aar); err != nil {
		t.Fatalf("first approval_ref: %v", err)
	}
	mustRefuse(t, "approval_ref change", e.rawExec(`UPDATE glovo.orders SET approval_ref=$2 WHERE order_ref=$1`, o.OrderRef, newAAR()))
	mustRefuse(t, "approval_ref clear", e.rawExec(`UPDATE glovo.orders SET approval_ref='' WHERE order_ref=$1`, o.OrderRef))
	mustRefuse(t, "fingerprint change", e.rawExec(`UPDATE glovo.orders SET final_basket_fingerprint='sha256:'||repeat('0',64) WHERE order_ref=$1`, o.OrderRef))
	mustRefuse(t, "snapshot seq change", e.rawExec(`UPDATE glovo.orders SET final_snapshot_seq=7 WHERE order_ref=$1`, o.OrderRef))
	// command_id on dispatch only, and only with an approval
	mustRefuse(t, "command_id without a dispatch", e.rawExec(`UPDATE glovo.orders SET command_id=$2 WHERE order_ref=$1`, o.OrderRef, newCMD()))
	cmd := newCMD()
	if err := e.rawExec(`UPDATE glovo.orders SET state='dispatched', command_id=$2 WHERE order_ref=$1`, o.OrderRef, cmd); err == nil {
		// no effect row yet is allowed in SQL (the effect guard is on the effect insert)
		mustRefuse(t, "command_id change", e.rawExec(`UPDATE glovo.orders SET command_id=$2 WHERE order_ref=$1`, o.OrderRef, newCMD()))
	} else {
		t.Fatalf("dispatch: %v", err)
	}
	// the same aar_ or cmd_ or we_ cannot bind a second order
	o2 := e.finalize(scA, e.mustCreate(scA, "k2", 500))
	mustRefuse(t, "second order with the same aar_", e.rawExec(`UPDATE glovo.orders SET approval_ref=$2 WHERE order_ref=$1`, o2.OrderRef, aar))
	if err := e.rawExec(`UPDATE glovo.orders SET approval_ref=$2 WHERE order_ref=$1`, o2.OrderRef, newAAR()); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "second order with the same cmd_", e.rawExec(`UPDATE glovo.orders SET state='dispatched', command_id=$2 WHERE order_ref=$1`, o2.OrderRef, cmd))
	// command_id without an approval is refused
	o3 := e.finalize(scA, e.mustCreate(scA, "k3", 500))
	mustRefuse(t, "dispatch without an approval", e.rawExec(`UPDATE glovo.orders SET state='dispatched', command_id=$2 WHERE order_ref=$1`, o3.OrderRef, newCMD()))
	_ = ctx
}

func TestRawInsertGuards(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	exec := e.execution(tenantA, ownerA)
	other := e.execution(tenantB, ownerB)
	base := `INSERT INTO glovo.orders (order_id, order_ref, tenant, owner_principal_id, connection_id, install_id, install_revision,
 execution_id, idempotency_key, request_hash, created_at, updated_at%s) VALUES ($1, $2, $3, $4, 'gcn_x', 'gin_x', 1, $5, $6, 'h', now(), now()%s)`
	run := func(cols, vals, tenant, owner, execID string) error {
		return e.rawExec(fmt.Sprintf(base, cols, vals), "pord_"+randHex(8), NewOrderRef(), tenant, owner, execID, randHex(6))
	}
	if err := run("", "", tenantA, ownerA, exec); err != nil {
		t.Fatalf("a legitimate raw insert: %v", err)
	}
	mustRefuse(t, "insert as dispatched", run(", state, command_id", ", 'dispatched', 'cmd_"+strings.Repeat("A", 26)+"'", tenantA, ownerA, e.execution(tenantA, ownerA)))
	mustRefuse(t, "insert with a fingerprint", run(", final_basket_fingerprint, final_snapshot_seq", ", 'sha256:"+strings.Repeat("0", 64)+"', 1", tenantA, ownerA, e.execution(tenantA, ownerA)))
	mustRefuse(t, "insert with an aar_", run(", approval_ref", ", 'aar_"+strings.Repeat("a", 20)+"'", tenantA, ownerA, e.execution(tenantA, ownerA)))
	mustRefuse(t, "insert with a foreign tenant execution", run("", "", tenantA, ownerA, other))
	mustRefuse(t, "insert with a foreign owner execution", run("", "", tenantA, ownerA2, e.execution(tenantA, ownerA)))
	mustRefuse(t, "second order for the same we_", run("", "", tenantA, ownerA, exec))
	mustRefuse(t, "insert without an execution", run("", "", tenantA, ownerA, ""))
	mustRefuse(t, "insert with a uuid we_", run("", "", tenantA, ownerA, "we_123e4567-e89b-12d3-a456-426614174000"))
	mustRefuse(t, "insert with version 2", run(", version", ", 2", tenantA, ownerA, e.execution(tenantA, ownerA)))
	_ = ctx
}

func TestRawSnapshotAndEffectGuards(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.mustCreate(scA, "k1", 500)
	var orderID string
	if err := e.admin.QueryRow(ctx, `SELECT order_id FROM glovo.orders WHERE order_ref=$1`, o.OrderRef).Scan(&orderID); err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"x":1}`)
	good := `INSERT INTO glovo.order_snapshots (order_id, seq, basket_fingerprint, basket_canonical, line_count, created_at)
 VALUES ($1, $2, 'sha256:' || encode(sha256($3::bytea), 'hex'), $3, 1, now())`
	mustRefuse(t, "a snapshot whose fingerprint does not hash its bytes", e.rawExec(`INSERT INTO glovo.order_snapshots
 (order_id, seq, basket_fingerprint, basket_canonical, line_count, created_at) VALUES ($1, 5, 'sha256:`+strings.Repeat("0", 64)+`', $2, 1, now())`, orderID, canonical))
	if err := e.rawExec(good, orderID, 2, canonical); err != nil {
		t.Fatalf("a snapshot of an open order: %v", err)
	}
	if _, err := e.admin.Exec(ctx, `DELETE FROM glovo.order_snapshots WHERE order_id = $1 AND seq = 2`, orderID); err == nil {
		t.Fatal("the migration role deleted a snapshot: the append-only trigger is missing")
	}
	o = e.mustCreate(scA, "k1b", 500)
	if err := e.admin.QueryRow(ctx, `SELECT order_id FROM glovo.orders WHERE order_ref=$1`, o.OrderRef).Scan(&orderID); err != nil {
		t.Fatal(err)
	}
	// effect for an order that is not finalized
	effect := `INSERT INTO glovo.order_effects (effect_id, order_id, tenant, owner_principal_id, effect_kind, execution_id, basket_fingerprint, idempotency_key, request_hash, created_at)
 VALUES ($1, $2, $3, $4, 'place_order_fake', $5, $6, $7, 'h', now())`
	var execID, fp string
	fin := e.finalize(scA, o)
	execID, fp = fin.ExecutionID, fin.FinalBasketFingerprint
	// a snapshot for a finalized order
	mustRefuse(t, "a snapshot for a finalized order", e.rawExec(good, orderID, 3, canonical))
	for name, args := range map[string][]any{
		"another execution":   {"peff_1", orderID, tenantA, ownerA, "we_0123456789abcdef0123", fp, "ik1"},
		"another tenant":      {"peff_2", orderID, tenantB, ownerA, execID, fp, "ik2"},
		"another owner":       {"peff_3", orderID, tenantA, ownerA2, execID, fp, "ik3"},
		"another fingerprint": {"peff_4", orderID, tenantA, ownerA, execID, "sha256:" + strings.Repeat("1", 64), "ik4"},
		"unknown order":       {"peff_5", "pord_missing", tenantA, ownerA, execID, fp, "ik5"},
	} {
		mustRefuse(t, "an effect with "+name, e.rawExec(effect, args...))
	}
	if err := e.rawExec(effect, "peff_ok", orderID, tenantA, ownerA, execID, fp, "ik-ok"); err != nil {
		t.Fatalf("a legitimate effect: %v", err)
	}
	mustRefuse(t, "a second effect for the execution", e.rawExec(effect, "peff_ok2", orderID, tenantA, ownerA, execID, fp, "ik-ok2"))

	// an effect for an open order
	o2 := e.mustCreate(scA, "k2", 500)
	var id2 string
	if err := e.admin.QueryRow(ctx, `SELECT order_id FROM glovo.orders WHERE order_ref=$1`, o2.OrderRef).Scan(&id2); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "an effect for an open order", e.rawExec(effect, "peff_open", id2, tenantA, ownerA, o2.ExecutionID, fp, "ik-open"))
}
