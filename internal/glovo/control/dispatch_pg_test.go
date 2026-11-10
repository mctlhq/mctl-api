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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

func TestDispatchHappyPath(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{freshFor: 20 * time.Minute})
	res, err := e.dispatch(f)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.Replayed || res.OrderState != orders.StateDispatched || res.EffectState != bridge.EffectNone || !bridge.IsCommandID(res.CommandID) {
		t.Fatalf("result: %+v", res)
	}
	if got := e.orderState(f); got != orders.StateDispatched {
		t.Fatalf("order is %s", got)
	}
	if got := e.aarState(f); got != "reserved" {
		t.Fatalf("receipt is %s", got)
	}
	if got := e.str(`SELECT command_id FROM glovo.approval_bindings WHERE approval_id = $1`, f.aar); got != res.CommandID {
		t.Fatalf("binding command %s, want %s", got, res.CommandID)
	}
	var kind, wire, opKey, ref, digestOK string
	var seq, ttl int
	if err := e.mp.QueryRow(context.Background(), `SELECT operation_kind, wire_version, operation_key, approval_ref, sequence, ttl_seconds,
		(payload = $2::jsonb)::text FROM bridge_commands WHERE command_id = $1`, res.CommandID, string(e.canon)).
		Scan(&kind, &wire, &opKey, &ref, &seq, &ttl, &digestOK); err != nil {
		t.Fatal(err)
	}
	if kind != bridge.KindPlaceOrderFake || wire != bridge.WireV1alpha2 || opKey != "glovo-dispatch:"+f.orderRef || ref != f.aar || seq != 1 {
		t.Fatalf("command: %s %s %s %s %d", kind, wire, opKey, ref, seq)
	}
	if digestOK != "true" {
		t.Fatal("the payload is not the order snapshot's canonical basket")
	}
	if want := int(DispatchCommandTTL / time.Second); ttl != want {
		t.Fatalf("ttl %d, want %d", ttl, want)
	}
	if len(e.idx.marks) != 1 || e.idx.marks[0] != orders.StateDispatched {
		t.Fatalf("order marks: %v", e.idx.marks)
	}
}

func TestDispatchReplay(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	first, err := e.dispatch(f)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.dispatch(f)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !again.Replayed || again.CommandID != first.CommandID || again.OrderState != orders.StateDispatched {
		t.Fatalf("replay result: %+v", again)
	}
	if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 1 {
		t.Fatalf("%d commands after a replay", n)
	}
	// A replay still has to present the order's approval and fingerprint.
	_, err = e.d.Dispatch(context.Background(), e.tenants, f.orderRef, tok("aar_", 26), e.fingerprint)
	wantCode(t, err, glovo.CodeApprovalReplayed)
	_, err = e.d.Dispatch(context.Background(), e.tenants, f.orderRef, f.aar, "sha256:"+rnd(32))
	wantCode(t, err, glovo.CodeBasketChanged)
	if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 1 {
		t.Fatalf("%d commands after refused replays", n)
	}
}

func TestDispatchConcurrentIsOneCommand(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	const n = 8
	var wg sync.WaitGroup
	results := make([]*Result, n)
	errs := make([]error, n)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.dispatch(f)
		}()
	}
	wg.Wait()
	fresh, ids := 0, map[string]bool{}
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		ids[results[i].CommandID] = true
		if !results[i].Replayed {
			fresh++
		}
	}
	if fresh != 1 || len(ids) != 1 {
		t.Fatalf("%d fresh dispatches and %d command ids, want 1 and 1", fresh, len(ids))
	}
	if c := e.count(`SELECT count(*) FROM bridge_commands`); c != 1 {
		t.Fatalf("%d commands", c)
	}
}

// Every refusal leaves nothing behind: no command, the order still
// finalized, the receipt still approved.
func TestDispatchRefusals(t *testing.T) {
	type tc struct {
		name  string
		setup func(e *env, f fixture)
		call  func(e *env, f fixture) error
		code  glovo.Code
	}
	std := func(e *env, f fixture) error { _, err := e.dispatch(f); return err }
	cases := []tc{
		{"order open", func(e *env, f fixture) {
			e.mustMig(`UPDATE ctl_fake_orders SET state='open' WHERE order_ref=$1`, f.orderRef)
		}, std, glovo.CodeInvalidTransition},
		{"body fingerprint differs", nil, func(e *env, f fixture) error {
			_, err := e.d.Dispatch(context.Background(), e.tenants, f.orderRef, f.aar, "sha256:"+rnd(32))
			return err
		}, glovo.CodeBasketChanged},
		{"body approval is another", nil, func(e *env, f fixture) error {
			_, err := e.d.Dispatch(context.Background(), e.tenants, f.orderRef, tok("aar_", 26), e.fingerprint)
			return err
		}, glovo.CodeIntentMismatch},
		{"order has no approval", func(e *env, f fixture) { e.setOrder(f, func(o *orders.Order) { o.ApprovalRef = "" }) }, func(e *env, f fixture) error {
			_, err := e.d.Dispatch(context.Background(), e.tenants, f.orderRef, f.aar, e.fingerprint)
			return err
		}, glovo.CodeApprovalInvalid},
		{"approval is not a Glovo receipt", func(e *env, f fixture) {
			ghost := tok("aar_", 26)
			e.setOrder(f, func(o *orders.Order) { o.ApprovalRef = ghost })
		}, func(e *env, f fixture) error {
			_, err := e.d.Dispatch(context.Background(), e.tenants, f.orderRef, e.idx.tmpl[f.orderRef].ApprovalRef, e.fingerprint)
			return err
		}, glovo.CodeApprovalInvalid},
		{"binding names another connection", func(e *env, f fixture) {
			e.setOrder(f, func(o *orders.Order) { o.ConnectionID = tok("gcn_", 26) })
		}, std, glovo.CodeIntentMismatch},
		{"binding names another install", func(e *env, f fixture) {
			e.setOrder(f, func(o *orders.Order) { o.InstallID = "install-2" })
		}, std, glovo.CodeIntentMismatch},
		{"binding names another revision", func(e *env, f fixture) {
			e.setOrder(f, func(o *orders.Order) { o.InstallRevision = 4 })
		}, std, glovo.CodeIntentMismatch},
		{"receipt fingerprint differs from the order", func(e *env, f fixture) {
			// A consistent order and snapshot of another basket, so that only
			// the receipt's own binding can refuse.
			_, canon, err := basket.Parse([]byte(otherBasket))
			if err != nil {
				e.t.Fatal(err)
			}
			other := basket.Fingerprint(canon)
			e.setOrder(f, func(o *orders.Order) { o.FinalBasketFingerprint = other })
			e.idx.mu.Lock()
			e.idx.snaps[f.orderRef] = orders.Snapshot{OrderRef: f.orderRef, Seq: 1, Fingerprint: other, Canonical: canon}
			e.idx.mu.Unlock()
		}, func(e *env, f fixture) error {
			_, err := e.d.Dispatch(context.Background(), e.tenants, f.orderRef, f.aar, e.idx.tmpl[f.orderRef].FinalBasketFingerprint)
			return err
		}, glovo.CodeBasketChanged},
		{"receipt intent hash is not its binding's", func(e *env, f fixture) {
			e.forceApproval(f, `intent_hash = 'sha256:`+strings.Repeat("a", 64)+`'`)
		}, std, glovo.CodeIntentMismatch},
		{"order owner moved between peek and lock", func(e *env, f fixture) {
			e.idx.mu.Lock()
			e.idx.peekOwner = "prn_someoneelse"
			e.idx.mu.Unlock()
		}, std, glovo.CodeUnavailable},
		{"connection not active", func(e *env, f fixture) { e.conns.conn.State = glovo.Revoked }, std, glovo.CodeNoConnection},
		{"live connection is another", func(e *env, f fixture) { e.conns.conn.ConnectionID = tok("gcn_", 26) }, std, glovo.CodeConnectionRevoked},
		{"install revision moved", func(e *env, f fixture) { e.conns.conn.InstallRevision = 4 }, std, glovo.CodeStaleInstall},
		{"live connection read refused", func(e *env, f fixture) { e.conns.err = glovo.Refuse(glovo.CodeNoConnection) }, std, glovo.CodeNoConnection},
		{"live connection read failed", func(e *env, f fixture) { e.conns.err = errBoom }, std, glovo.CodeUnavailable},
		{"owner left the tenant", func(e *env, f fixture) { e.members.member = false }, std, glovo.CodeNoTenant},
		{"membership unreadable", func(e *env, f fixture) { e.members.err = errBoom }, std, glovo.CodeUnavailable},
		{"snapshot does not hash to the fingerprint", func(e *env, f fixture) {
			s := e.idx.snaps[f.orderRef]
			s.Canonical = []byte(`{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-2","quantity":1,"unit_price_minor":500}],"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`)
			e.idx.snaps[f.orderRef] = s
		}, std, glovo.CodeBasketChanged},
		{"snapshot row names another fingerprint than its basket", func(e *env, f fixture) {
			s := e.idx.snaps[f.orderRef]
			s.Fingerprint = "sha256:" + rnd(32)
			e.idx.snaps[f.orderRef] = s
		}, std, glovo.CodeBasketChanged},
		{"snapshot unreadable", func(e *env, f fixture) { delete(e.idx.snaps, f.orderRef) }, std, glovo.CodeUnavailable},
		{"tenant ref unreadable", func(e *env, f fixture) { e.joins.err = errBoom }, std, glovo.CodeUnavailable},
		{"execution binding unreadable", func(e *env, f fixture) { e.execs.err = errBoom }, std, glovo.CodeUnavailable},
		{"execution belongs to another tenant", func(e *env, f fixture) { e.execs.tenant = "other" }, std, glovo.CodeIntentMismatch},
		{"execution belongs to another work item", func(e *env, f fixture) { e.execs.wi = "wi_OTHER000000000000000000" }, std, glovo.CodeIntentMismatch},
		{"control start unreadable", func(e *env, f fixture) { e.startErr = errBoom }, std, glovo.CodeUnavailable},
		{"control start names another workflow", func(e *env, f fixture) { e.startWF = "wf-other" }, std, glovo.CodeIntentMismatch},
		{"not ready", func(e *env, f fixture) { e.ready = errBoom }, std, glovo.CodeNotReady},
		{"order outside the worker's tenants", func(e *env, f fixture) { e.tenants = []string{"other"} }, std, glovo.CodeNotFound},
		{"no tenants bound", func(e *env, f fixture) { e.tenants = nil }, std, glovo.CodeNotFound},
		{"order store refuses the mark", func(e *env, f fixture) { e.idx.markErr = glovo.Refuse(glovo.CodeInvalidTransition) }, std, glovo.CodeInvalidTransition},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			f := e.finalized(fixOpt{})
			if c.setup != nil {
				c.setup(e, f)
			}
			err := c.call(e, f)
			wantCode(t, err, c.code)
			state := orders.StateFinalized
			if c.name == "order open" {
				state = orders.StateOpen
			}
			if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 0 {
				t.Errorf("bridge_commands has %d rows after a refusal", n)
			}
			if got := e.orderState(f); got != state {
				t.Errorf("order is %s after a refusal", got)
			}
			if got := e.aarState(f); got != "approved" {
				t.Errorf("receipt is %s after a refusal", got)
			}
		})
	}
}

func TestDispatchReceiptStates(t *testing.T) {
	t.Run("pending is approval_invalid", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{noDecide: true})
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalInvalid)
		e.untouched(f, "pending")
	})
	t.Run("reserved for another command is approval_replayed", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		if _, err := e.dispatch(f); err != nil {
			t.Fatal(err)
		}
		// The order is put back to finalized with no command: only the receipt remembers.
		e.mustMig(`UPDATE ctl_fake_orders SET state='finalized', command_id='' WHERE order_ref=$1`, f.orderRef)
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalReplayed)
		if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 1 {
			t.Fatalf("%d commands", n)
		}
	})
	t.Run("revoked (denied) is approval_invalid", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.tx(func(tx pgx.Tx) {
			if err := e.st.RevokeGlovoApprovalTx(context.Background(), tx, f.aar, ActorID); err != nil {
				t.Fatal(err)
			}
		})
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalInvalid)
		e.untouched(f, "denied")
	})
}

// An approved receipt with no freshness bound, or one past expires_at, is
// refused with its own code: a NULL bound must not read as "no limit" and
// must not read as "expired" either.
func TestDispatchNullAndPastBounds(t *testing.T) {
	t.Run("NULL fresh_until is approval_invalid", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.forceApproval(f, `fresh_until = NULL`)
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalInvalid)
		e.untouched(f, "approved")
	})
	t.Run("past expires_at is approval_expired", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.forceApproval(f, `expires_at = now() - interval '1 minute'`)
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalExpired)
		e.untouched(f, "approved")
	})
	t.Run("past fresh_until is approval_expired", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.forceApproval(f, `fresh_until = now() - interval '1 minute'`)
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalExpired)
		e.untouched(f, "approved")
	})
}

// A receipt too close to its freshness bound is expired, and one with room
// has its command TTL capped by what is left of the bound.
func TestDispatchFreshnessWindow(t *testing.T) {
	t.Run("expired freshness bound", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{freshFor: 1500 * time.Millisecond})
		time.Sleep(900 * time.Millisecond)
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalExpired)
		e.untouched(f, "approved")
	})
	// fresh_until within ReservePermitMargin (120s) is refused before any
	// command row exists; just outside it dispatches.
	t.Run("boundary at the reserve margin", func(t *testing.T) {
		e := newEnv(t)
		spy := &enqueueSpy{Bridge: e.d.Bridge}
		e.d.Bridge = spy
		f := e.finalized(fixOpt{freshFor: 119 * time.Second})
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeApprovalExpired)
		// The refusal is dispatch's own: it must come before Enqueue, not from
		// ReserveGlovoApprovalTx refusing the same window further down.
		if spy.calls != 0 {
			t.Fatalf("Enqueue ran %d times for a receipt inside the reserve margin", spy.calls)
		}
		e.untouched(f, "approved")
		if n := e.count(`SELECT count(*) FROM bridge_commands WHERE approval_ref = $1`, f.aar); n != 0 {
			t.Fatalf("%d command rows exist after the refusal", n)
		}
		e2 := newEnv(t)
		spy2 := &enqueueSpy{Bridge: e2.d.Bridge}
		e2.d.Bridge = spy2
		f2 := e2.finalized(fixOpt{freshFor: 121 * time.Second})
		res, err := e2.dispatch(f2)
		if err != nil {
			t.Fatalf("121s: %v", err)
		}
		if spy2.calls != 1 {
			t.Fatalf("Enqueue ran %d times at 121s, want 1", spy2.calls)
		}
		var ttl int
		if err := e2.mp.QueryRow(context.Background(), `SELECT ttl_seconds FROM bridge_commands WHERE command_id=$1`, res.CommandID).Scan(&ttl); err != nil {
			t.Fatal(err)
		}
		if ttl < 119 || ttl > 121 {
			t.Fatalf("ttl %d, want 119..121", ttl)
		}
	})
	t.Run("ttl is capped at fresh_until", func(t *testing.T) {
		e := newEnv(t)
		// The receipt must stay fresh past the reserve margin (120s), so the
		// cap is observable between that margin and the 900s default.
		f := e.finalized(fixOpt{freshFor: 300 * time.Second})
		res, err := e.dispatch(f)
		if err != nil {
			t.Fatal(err)
		}
		var ttl int
		if err := e.mp.QueryRow(context.Background(), `SELECT ttl_seconds FROM bridge_commands WHERE command_id=$1`, res.CommandID).Scan(&ttl); err != nil {
			t.Fatal(err)
		}
		// floor, never ceil: the receipt has already aged a little, so a
		// ttl of 300 would outlive its 300s freshness bound.
		if ttl < 290 || ttl >= 300 {
			t.Fatalf("ttl %d, want 290..299 (the receipt is fresh for under 300s)", ttl)
		}
	})
}

// The sequence is the next of the execution; a command that appears between
// the read and the insert collides on the unique index and the whole call is
// refused and retryable, never a duplicate sequence.
func TestDispatchSequence(t *testing.T) {
	t.Run("continues the execution's sequence", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.rawCommand(f, 5, "op-seed")
		res, err := e.dispatch(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.count(`SELECT sequence FROM bridge_commands WHERE command_id=$1`, res.CommandID); got != 6 {
			t.Fatalf("sequence %d, want 6", got)
		}
	})
	t.Run("a concurrent insert is unavailable", func(t *testing.T) {
		e := newEnv(t)
		f := e.finalized(fixOpt{})
		e.startHook = func(ctx context.Context, _ dbq.Querier) error {
			e.startHook = nil
			e.rawCommand(f, 1, "op-racer")
			return nil
		}
		_, err := e.dispatch(f)
		wantCode(t, err, glovo.CodeUnavailable)
		if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 1 {
			t.Fatalf("%d commands, want only the racer's", n)
		}
		e.untouchedExceptCommands(f)
		// The retry sees the racer's sequence and goes on.
		if _, err := e.dispatch(f); err != nil {
			t.Fatalf("retry: %v", err)
		}
	})
}

// One transaction: a failure after the command was written and the receipt
// reserved rolls both back.
func TestDispatchIsOneTransaction(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	e.idx.markErr = errBoom
	_, err := e.dispatch(f)
	wantCode(t, err, glovo.CodeUnavailable)
	e.untouched(f, "approved")
	if n := e.count(`SELECT count(*) FROM bridge_command_transitions`); n != 0 {
		t.Fatalf("%d transitions survived the rollback", n)
	}
	if got := e.str(`SELECT coalesce(command_id,'') FROM glovo.approval_bindings WHERE approval_id=$1`, f.aar); got != "" {
		t.Fatalf("binding kept command %s", got)
	}
	e.idx.markErr = nil
	if _, err := e.dispatch(f); err != nil {
		t.Fatalf("a retry after the rollback: %v", err)
	}
}

// A hung membership provider holds L3 and L4 for at most the membership bound,
// then the dispatch is unavailable and both rows are free again. The provider
// here ignores its context, so the bound cannot rely on it.
func TestDispatchHungMembershipDoesNotHoldLocks(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{freshFor: 20 * time.Minute})
	e.members.hang = make(chan struct{})
	t.Cleanup(func() { close(e.members.hang) })
	type out struct {
		err error
		dur time.Duration
	}
	done := make(chan out, 1)
	go func() {
		start := time.Now()
		_, err := e.dispatch(f)
		done <- out{err, time.Since(start)}
	}()
	// While the read hangs, the approval row (L4) is locked.
	locked := false
	for i := 0; i < 40 && !locked; i++ {
		time.Sleep(50 * time.Millisecond)
		locked = e.rowLocked(`SELECT 1 FROM public.action_approval_requests WHERE id = $1 FOR UPDATE NOWAIT`, f.aar)
	}
	if !locked {
		t.Fatal("the approval row was not locked during the membership read: the test does not observe the hold")
	}
	var r out
	select {
	case r = <-done:
	case <-time.After(glovo.MembershipTimeout + 4*time.Second):
		t.Fatalf("the dispatch is still waiting on the hung provider after %s", glovo.MembershipTimeout+4*time.Second)
	}
	wantCode(t, r.err, glovo.CodeUnavailable)
	if r.dur > glovo.MembershipTimeout+2*time.Second {
		t.Fatalf("the dispatch took %s with a hung provider, bound is %s", r.dur, glovo.MembershipTimeout)
	}
	if e.rowLocked(`SELECT 1 FROM public.action_approval_requests WHERE id = $1 FOR UPDATE NOWAIT`, f.aar) {
		t.Fatal("the approval row is still locked after the timeout")
	}
	if e.rowLocked(`SELECT 1 FROM ctl_fake_orders WHERE order_ref = $1 FOR UPDATE NOWAIT`, f.orderRef) {
		t.Fatal("the order row is still locked after the timeout")
	}
	e.untouched(f, "approved")
}

// otherBasket is a valid basket that is not basePayload.
const otherBasket = `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-2","quantity":1,"unit_price_minor":500}],"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`

// A command effect that cannot be read is unavailable: it is never read as
// effect "none", which would let the order be cancelled while a permit may
// already have been issued.
func TestCancelUnreadableEffectIsUnavailable(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	ghost := tok("cmd_", 26)
	e.mustMig(`UPDATE ctl_fake_orders SET state='dispatched', command_id=$2 WHERE order_ref=$1`, f.orderRef, ghost)
	_, err := e.d.Cancel(context.Background(), e.tenants, f.orderRef)
	wantCode(t, err, glovo.CodeUnavailable)
	if got := e.orderState(f); got != orders.StateDispatched {
		t.Fatalf("order is %s after an unreadable effect, want dispatched", got)
	}
}

// A finalized order must not find a command already holding its operation key:
// the enqueue is not "created", the call is unavailable and nothing moves.
func TestDispatchExistingOperationKeyIsUnavailable(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	e.rawCommand(f, 1, "glovo-dispatch:"+f.orderRef)
	_, err := e.dispatch(f)
	if err == nil {
		t.Fatal("dispatch succeeded over an existing command for the order")
	}
	wantCode(t, err, glovo.CodeUnavailable)
	if got := e.orderState(f); got != orders.StateFinalized {
		t.Fatalf("order is %s, want finalized", got)
	}
	if got := e.aarState(f); got != "approved" {
		t.Fatalf("receipt is %s, want approved", got)
	}
	if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 1 {
		t.Fatalf("%d command rows, want the 1 seeded", n)
	}
}

// A row lock (L3, and L4 behind it) held past the 5 s lock_timeout is refused
// as tenant_busy, not as a generic failure; nothing is left behind.
func TestDispatchOrderLockTimeoutIsTenantBusy(t *testing.T) {
	e := newEnv(t)
	f := e.finalized(fixOpt{})
	ctx := context.Background()
	hold, err := e.mp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	var one int
	if err := hold.QueryRow(ctx, `SELECT 1 FROM ctl_fake_orders WHERE order_ref = $1 FOR UPDATE`, f.orderRef).Scan(&one); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, derr := e.dispatch(f)
	wantCode(t, derr, glovo.CodeTenantBusy)
	if d := time.Since(start); d < 4*time.Second || d > 9*time.Second {
		t.Fatalf("refused after %s, want about the 5s lock_timeout", d)
	}
	_ = hold.Rollback(ctx)
	e.untouched(f, "approved")
}

// enqueueSpy counts Enqueue calls on the bridge collaborator.
type enqueueSpy struct {
	Bridge
	calls int
}

func (s *enqueueSpy) Enqueue(ctx context.Context, tx pgx.Tx, in bridge.EnqueueInput) (string, bool, error) {
	s.calls++
	return s.Bridge.Enqueue(ctx, tx, in)
}
