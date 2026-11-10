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
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func (e *env) cancel(f fixture) (*Result, error) {
	return e.d.Cancel(context.Background(), e.tenants, f.orderRef)
}

func (e *env) dispatched(f fixture) string {
	e.t.Helper()
	res, err := e.dispatch(f)
	if err != nil {
		e.t.Fatalf("dispatch: %v", err)
	}
	e.idx.marks = nil
	return res.CommandID
}

func (e *env) commandRow(id string) (status, effect string) {
	e.t.Helper()
	if err := e.mp.QueryRow(context.Background(), `SELECT status, effect_state FROM bridge_commands WHERE command_id=$1`, id).Scan(&status, &effect); err != nil {
		e.t.Fatal(err)
	}
	return status, effect
}

func (e *env) setCommand(id, set string) {
	e.t.Helper()
	e.mustMig(`UPDATE bridge_commands SET `+set+` WHERE command_id=$1`, id)
}

func TestCancelOnOpenAndFinalizedOrders(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.mustMig(`UPDATE ctl_fake_orders SET state='open' WHERE order_ref=$1`, f.orderRef)
		res, err := e.cancel(f)
		if err != nil {
			t.Fatal(err)
		}
		if res.OrderState != orders.StateCancelled || res.EffectState != bridge.EffectNone || res.CommandID != "" {
			t.Fatalf("result %+v", res)
		}
		if got := e.orderState(f); got != orders.StateCancelled {
			t.Fatalf("order %s", got)
		}
		if got := e.aarState(f); got != "approved" {
			t.Fatalf("an open order has no receipt of its own; it was %s", got)
		}
		if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 0 {
			t.Fatalf("%d commands", n)
		}
	})
	t.Run("finalized revokes the receipt", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		res, err := e.cancel(f)
		if err != nil {
			t.Fatal(err)
		}
		if res.OrderState != orders.StateCancelled {
			t.Fatalf("result %+v", res)
		}
		if got := e.aarState(f); got != "denied" {
			t.Fatalf("receipt %s, want denied (revoked)", got)
		}
		if got := e.orderState(f); got != orders.StateCancelled {
			t.Fatalf("order %s", got)
		}
		if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 0 {
			t.Fatalf("%d commands", n)
		}
		// The cancelled order can no longer be dispatched.
		_, err = e.dispatch(f)
		wantCode(t, err, glovo.CodeInvalidTransition)
	})
	t.Run("a refused revoke keeps the order", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.idx.markErr = nil
		e.setOrder(f, func(o *orders.Order) { o.ApprovalRef = tok("aar_", 26) })
		_, err := e.cancel(f)
		if err == nil {
			t.Fatal("a ghost receipt must refuse the cancel")
		}
		if got := e.orderState(f); got != orders.StateFinalized {
			t.Fatalf("order %s after a refused cancel", got)
		}
	})
}

func TestCancelDispatched(t *testing.T) {
	t.Run("pending command is cancelled, order cancelled, receipt unknown", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		res, err := e.cancel(f)
		if err != nil {
			t.Fatal(err)
		}
		if res.OrderState != orders.StateCancelled || res.EffectState != bridge.EffectNone || res.CommandID != cmd {
			t.Fatalf("result %+v", res)
		}
		if s, ef := e.commandRow(cmd); s != bridge.StatusCancelled || ef != bridge.EffectNone {
			t.Fatalf("command %s/%s", s, ef)
		}
		if got := e.orderState(f); got != orders.StateCancelled {
			t.Fatalf("order %s", got)
		}
		if got := e.aarState(f); got != "unknown" {
			t.Fatalf("receipt %s, want unknown", got)
		}
		// A second cancel is a no-write answer on a terminal order.
		e.idx.marks = nil
		again, err := e.cancel(f)
		if err != nil || again.OrderState != orders.StateCancelled {
			t.Fatalf("second cancel: %+v %v", again, err)
		}
		if len(e.idx.marks) != 0 {
			t.Fatalf("a cancel of a cancelled order wrote %v", e.idx.marks)
		}
	})
	t.Run("a permit already issued makes the order unknown", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='leased', effect_state='permitted'`)
		res, err := e.cancel(f)
		if err != nil {
			t.Fatal(err)
		}
		if res.OrderState != orders.StateUnknown {
			t.Fatalf("result %+v: a permitted command must never read as cancelled", res)
		}
		if got := e.orderState(f); got != orders.StateUnknown {
			t.Fatalf("order %s", got)
		}
		if got := e.aarState(f); got != "reserved" {
			t.Fatalf("receipt %s: only the none/not_performed rows move it", got)
		}
	})
	t.Run("a command that already completed closes the order", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='completed', effect_state='succeeded', result_digest='sha256:aa',
			result='{"outcome":"succeeded","provider_effect":"applied","error_code":"none"}'::jsonb`)
		res, err := e.cancel(f)
		if err != nil {
			t.Fatal(err)
		}
		if res.OrderState != orders.StateClosed || res.EffectState != bridge.EffectSucceeded {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("unobservable effect is unavailable and rolls back", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		// A command row the table does not know: status expired with a completed-only effect is in
		// the table, so use a deleted command to make the pair unreadable.
		e.mustMig(`ALTER TABLE bridge_commands DISABLE TRIGGER USER`)
		e.mustMig(`DELETE FROM bridge_commands WHERE command_id=$1`, cmd)
		_, err := e.cancel(f)
		wantCode(t, err, glovo.CodeUnavailable)
		if got := e.orderState(f); got != orders.StateDispatched {
			t.Fatalf("order %s after an unobservable cancel", got)
		}
	})
	t.Run("terminal orders are not written", func(t *testing.T) {
		for _, st := range []string{orders.StateClosed, orders.StateCancelled, orders.StateUnknown} {
			e := newEnv(t)
			f := e.finalized(fixOpt{})
			cmd := e.dispatched(f)
			e.mustMig(`UPDATE ctl_fake_orders SET state=$2 WHERE order_ref=$1`, f.orderRef, st)
			res, err := e.cancel(f)
			if err != nil {
				t.Fatalf("%s: %v", st, err)
			}
			if res.OrderState != st || res.CommandID != cmd || len(e.idx.marks) != 0 {
				t.Fatalf("%s: %+v marks %v", st, res, e.idx.marks)
			}
			if s, _ := e.commandRow(cmd); s != bridge.StatusPending {
				t.Fatalf("%s: a terminal order's command was touched: %s", st, s)
			}
		}
	})
	t.Run("scope and readiness", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.tenants = []string{"other"}
		_, err := e.cancel(f)
		wantCode(t, err, glovo.CodeNotFound)
		e.tenants = []string{tenant}
		e.ready = errBoom
		_, err = e.cancel(f)
		wantCode(t, err, glovo.CodeNotReady)
		if got := e.orderState(f); got != orders.StateFinalized {
			t.Fatalf("order %s", got)
		}
	})
}

// The revoker (#959) cancels the open commands of a connection; the control
// worker then reads the outcome back and the order follows.
func TestRevocationThenRead(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	cmd := e.dispatched(f)
	e.tx(func(tx pgx.Tx) {
		if err := bridge.CancelOpenForConnections(context.Background(), tx, []string{f.connRef}, "service:revoker"); err != nil {
			t.Fatal(err)
		}
	})
	if s, ef := e.commandRow(cmd); s != bridge.StatusCancelled || ef != bridge.EffectNone {
		t.Fatalf("command %s/%s", s, ef)
	}
	v, err := e.d.ReadCommand(context.Background(), e.tenants, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != bridge.StatusCancelled || v.Outcome != "cancelled" || v.ProviderEffect != "none" || v.ErrorCode != "none" {
		t.Fatalf("view %+v", v)
	}
	if got := e.orderState(f); got != orders.StateCancelled {
		t.Fatalf("order %s: the read must catch the order up", got)
	}
	// And the dispatch refuses a connection that is gone.
	g := e.finalized(fixOpt{})
	e.conns.conn.State = glovo.Revoked
	_, err = e.dispatch(g)
	wantCode(t, err, glovo.CodeNoConnection)
}

func TestReadCommand(t *testing.T) {
	read := func(e *env, id string) (*CommandView, error) {
		return e.d.ReadCommand(context.Background(), e.tenants, id)
	}
	t.Run("pending leaves the order alone", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		v, err := read(e, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != bridge.StatusPending || v.Outcome != "" || v.CommandID != cmd || v.OrderRef != f.orderRef {
			t.Fatalf("view %+v", v)
		}
		if got := e.orderState(f); got != orders.StateDispatched || len(e.idx.marks) != 0 {
			t.Fatalf("order %s marks %v", got, e.idx.marks)
		}
	})
	t.Run("completed closes the order", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='completed', effect_state='succeeded', result_digest='sha256:aa',
			result='{"outcome":"succeeded","provider_effect":"applied","error_code":"none"}'::jsonb`)
		v, err := read(e, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if v.Outcome != "succeeded" || v.ProviderEffect != "applied" || v.ErrorCode != "none" || v.ResultDigest != "sha256:aa" {
			t.Fatalf("view %+v", v)
		}
		if got := e.orderState(f); got != orders.StateClosed {
			t.Fatalf("order %s", got)
		}
		// A repeat read of a closed order writes nothing.
		e.idx.marks = nil
		if _, err := read(e, cmd); err != nil || len(e.idx.marks) != 0 {
			t.Fatalf("repeat: %v marks %v", err, e.idx.marks)
		}
	})
	t.Run("completed with no permit row spends the receipt as unknown", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='completed', effect_state='not_performed', result_digest='sha256:aa',
			result='{"outcome":"failed_terminal","provider_effect":"none","error_code":"expired"}'::jsonb`)
		if _, err := read(e, cmd); err != nil {
			t.Fatal(err)
		}
		if got := e.orderState(f); got != orders.StateClosed {
			t.Fatalf("order %s", got)
		}
		if got := e.aarState(f); got != "unknown" {
			t.Fatalf("receipt %s", got)
		}
	})
	t.Run("expired without effect cancels the order", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='expired', effect_state='none'`)
		v, err := read(e, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if v.Outcome != "failed_terminal" || v.ProviderEffect != "none" || v.ErrorCode != "expired" {
			t.Fatalf("view %+v", v)
		}
		if got := e.orderState(f); got != orders.StateCancelled {
			t.Fatalf("order %s", got)
		}
	})
	t.Run("a possible effect makes the order unknown", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='expired', effect_state='permitted'`)
		v, err := read(e, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if v.ProviderEffect != "unknown" {
			t.Fatalf("view %+v", v)
		}
		if got := e.orderState(f); got != orders.StateUnknown {
			t.Fatalf("order %s", got)
		}
	})
	t.Run("completed without a readable result is unavailable", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.setCommand(cmd, `status='completed', effect_state='succeeded', result=NULL`)
		_, err := read(e, cmd)
		wantCode(t, err, glovo.CodeUnavailable)
		if got := e.orderState(f); got != orders.StateDispatched {
			t.Fatalf("order %s: an unreadable result must not move the order", got)
		}
	})
	t.Run("absent, foreign, malformed and other kinds are not_found", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		for name, id := range map[string]string{"absent": tok("cmd_", 26), "malformed": "cmd_short", "empty": ""} {
			if _, err := read(e, id); !errors.Is(err, glovo.ErrNotFound) {
				t.Errorf("%s: %v", name, err)
			}
		}
		e.tenants = []string{"other"}
		if _, err := read(e, cmd); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("foreign tenant: %v", err)
		}
		e.tenants = nil
		if _, err := read(e, cmd); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("empty bound: %v", err)
		}
	})
	t.Run("a command that is not the order's is unavailable", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		cmd := e.dispatched(f)
		e.mustMig(`UPDATE ctl_fake_orders SET command_id=$2 WHERE order_ref=$1`, f.orderRef, tok("cmd_", 26))
		_, err := read(e, cmd)
		wantCode(t, err, glovo.CodeUnavailable)
	})
}

func TestReadApprovalAndTenantFor(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	cmd := e.dispatched(f)
	st, err := e.d.ReadApproval(context.Background(), e.tenants, f.aar)
	if err != nil {
		t.Fatal(err)
	}
	if st.ApprovalRef != f.aar || st.State != "reserved" || st.OrderRef != f.orderRef || st.CommandID != cmd {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.d.ReadApproval(context.Background(), []string{"other"}, f.aar); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("foreign tenant: %v", err)
	}
	if _, err := e.d.ReadApproval(context.Background(), e.tenants, tok("aar_", 26)); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("absent: %v", err)
	}
	if _, err := e.d.ReadApproval(context.Background(), nil, f.aar); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("empty bound: %v", err)
	}
	for ref, want := range map[string]string{f.orderRef: tenant, cmd: tenant, f.aar: tenant, tok("ordr_", 26): "", "junk": ""} {
		if got := e.d.TenantFor(context.Background(), e.tenants, ref); got != want {
			t.Errorf("TenantFor(%s) = %q, want %q", ref, got, want)
		}
	}
	if got := e.d.TenantFor(context.Background(), []string{"other"}, f.orderRef); got != "" {
		t.Errorf("a foreign tenant resolved to %q", got)
	}
}

func TestReady(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.d.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	var nilD *Dispatcher
	wantCode(t, nilD.Ready(ctx), glovo.CodeNotReady)
	for name, mod := range map[string]func(d *Dispatcher){
		"bridge":  func(d *Dispatcher) { d.Bridge = nil },
		"orders":  func(d *Dispatcher) { d.Orders = nil },
		"start":   func(d *Dispatcher) { d.ControlStart = nil },
		"check":   func(d *Dispatcher) { d.ReadyCheck = nil },
		"members": func(d *Dispatcher) { d.Members = nil },
	} {
		d := e.fresh()
		mod(d)
		if err := d.Ready(ctx); Refusal(err).Code != glovo.CodeNotReady {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	// A positive answer is cached for ReadyTTL; a negative one never is.
	calls := 0
	d := e.fresh()
	d.ReadyTTL = 1 << 40
	d.ReadyCheck = func(context.Context) error {
		calls++
		if calls == 1 {
			return errBoom
		}
		return nil
	}
	wantCode(t, d.Ready(ctx), glovo.CodeNotReady)
	if err := d.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Ready(ctx); err != nil || calls != 2 {
		t.Fatalf("calls %d err %v: a positive answer must be cached and a negative one must not", calls, err)
	}
}

// A typed nil inside an interface is not == nil; Ready must still see a missing
// collaborator, for every one of them.
func TestReadyRefusesTypedNilCollaborators(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, mod := range map[string]func(d *Dispatcher){
		"db":       func(d *Dispatcher) { d.DB = (*pgxpool.Pool)(nil) },
		"bridge":   func(d *Dispatcher) { d.Bridge = (*bridge.Store)(nil) },
		"orders":   func(d *Dispatcher) { d.Orders = (*orders.Store)(nil) },
		"receipts": func(d *Dispatcher) { d.Receipts = (*workitems.Store)(nil) },
		"conns":    func(d *Dispatcher) { d.Conns = (*glovo.Store)(nil) },
		"members":  func(d *Dispatcher) { d.Members = (*fakeMembers)(nil) },
		"joins":    func(d *Dispatcher) { d.Joins = (*orders.Store)(nil) },
		"execs":    func(d *Dispatcher) { d.Execs = (*workitems.Store)(nil) },
	} {
		d := e.fresh()
		mod(d)
		if err := d.Ready(ctx); err == nil || Refusal(err).Code != glovo.CodeNotReady {
			t.Errorf("a typed-nil %s passed Ready: %v", name, err)
		}
	}
}
