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
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/receipt"
)

// realFixture is a finalized order whose connection is a real one.
func (e *env) realFixture() (fixture, *realConn) {
	e.t.Helper()
	rc := e.activateNew("key-" + rnd(6))
	return e.finalized(fixOpt{freshFor: 20 * time.Minute, real: rc}), rc
}

func (e *env) commandStatus(cmd string) (status string, cancel bool) {
	e.t.Helper()
	if err := e.mp.QueryRow(context.Background(), `SELECT status, cancel_requested FROM bridge_commands WHERE command_id = $1`, cmd).Scan(&status, &cancel); err != nil {
		e.t.Fatal(err)
	}
	return
}

func within(t *testing.T, what string, d time.Duration, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("%s did not finish in %s", what, d)
		return nil
	}
}

func stillBlocked(t *testing.T, what string, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		t.Fatalf("%s finished (%v) while the other side held its lock", what, err)
	case <-time.After(700 * time.Millisecond):
	}
}

// With the real store the happy path dispatches against a live connection.
func TestRealDispatchAgainstLiveConnection(t *testing.T) {
	e := newRealEnv(t)
	f, _ := e.realFixture()
	res, err := e.dispatch(f)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if st, cancel := e.commandStatus(res.CommandID); st != bridge.StatusPending || cancel {
		t.Fatalf("command %s cancel=%v", st, cancel)
	}
}

// T12, revocation race A: the revoker holds L2 exclusive uncommitted (a
// Reconnect paused after its locks), the dispatch blocks on L2, the revoker
// commits, and the dispatch is then refused. A dispatch against the superseded
// connection afterwards is connection_revoked.
func TestRevocationRaceRevokerFirst(t *testing.T) {
	e := newRealEnv(t)
	f, rc := e.realFixture()
	_, rev := e.installTenant()
	paused, release := make(chan struct{}), make(chan struct{})
	revoker := make(chan error, 1)
	var newConn *glovo.Connection
	go func() {
		r, err := e.gs.Reconnect(context.Background(), glovo.ConnectInput{Owner: ownerOf, ExpectedInstallRevision: rev,
			IdempotencyKey: "re-" + rnd(6), Actor: ownerActor,
			AfterLocks: func(context.Context, pgx.Tx) error { close(paused); <-release; return nil }}, rc.ref)
		if err == nil {
			newConn = r.Connection
		}
		revoker <- err
	}()
	<-paused
	dispatch := make(chan error, 1)
	go func() { _, err := e.dispatch(f); dispatch <- err }()
	stillBlocked(t, "the dispatch", dispatch)
	close(release)
	if err := within(t, "the revoker", 5*time.Second, revoker); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	err := within(t, "the dispatch", 5*time.Second, dispatch)
	if err == nil {
		t.Fatal("the dispatch succeeded against a revoked connection")
	}
	wantCode(t, err, glovo.CodeNoConnection)
	e.untouched(f, "approved")
	// Once the new connection is active the order's connection is another one.
	e.activate(newConn, rc.installID, rev)
	_, err = e.dispatch(f)
	wantCode(t, err, glovo.CodeConnectionRevoked)
	e.untouched(f, "approved")
}

// T13, revocation race B: the dispatch holds L2 shared uncommitted, the
// revoker blocks, the dispatch commits, then the revoker proceeds and cancels
// the command through the real hook.
func TestRevocationRaceDispatchFirst(t *testing.T) {
	e := newRealEnv(t)
	f, rc := e.realFixture()
	inDispatch, release := make(chan struct{}), make(chan struct{})
	e.startHook = func(context.Context, dbq.Querier) error { close(inDispatch); <-release; return nil }
	type dres struct {
		res *Result
		err error
	}
	dispatch := make(chan dres, 1)
	go func() { r, err := e.dispatch(f); dispatch <- dres{r, err} }()
	<-inDispatch
	revoker := make(chan error, 1)
	go func() {
		_, err := e.gs.Revoke(context.Background(), ownerOf, ownerActor, rc.ref, "user_revoked")
		revoker <- err
	}()
	stillBlocked(t, "the revoker", revoker)
	close(release)
	d := <-dispatch
	if d.err != nil {
		t.Fatalf("Dispatch: %v", d.err)
	}
	if err := within(t, "the revoker", 5*time.Second, revoker); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if st, cancel := e.commandStatus(d.res.CommandID); st != bridge.StatusCancelled || !cancel {
		t.Fatalf("the command is %s cancel_requested=%v after the revocation", st, cancel)
	}
}

// permitAttempt is what the bridge does to issue a write permit: PreLock and
// Check in one transaction with the real fence over the real stores. It
// returns the fence's answer; the transaction is committed only on success.
func (e *env) permitAttempt(cmd string) (string, error) {
	e.t.Helper()
	ctx := context.Background()
	fence := receipt.NewFence(e.st, e.idx, e.gs, e.members)
	var b bridge.FenceBinding
	if err := e.mp.QueryRow(ctx, `SELECT execution_id, work_item_id, tenant, owner_principal_id, connection_ref, install_revision, intent_hash,
		approval_ref, operation_key FROM bridge_commands WHERE command_id = $1`, cmd).
		Scan(&b.ExecutionID, &b.WorkItemID, &b.Tenant, &b.OwnerPrincipalID, &b.ConnectionRef, &b.InstallRevision, &b.IntentHash, &b.ApprovalRef, &b.OperationKey); err != nil {
		e.t.Fatal(err)
	}
	b.CommandID, b.LeaseEpoch = cmd, 1
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	caller := bridge.Caller{ProviderRef: provider, Actor: "test", Tenants: []string{tenant}}
	if err := fence.PreLock(ctx, tx, caller, cmd); err != nil {
		return "", err
	}
	ref, err := fence.Check(ctx, tx, b)
	if err != nil {
		fence.Release(tx)
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatalf("commit: %v", err)
	}
	return ref, nil
}

// T24: with the real #959 store, the real revocation hook and #989's fence, a
// command that is reserved but not permitted gets no permit after a revoke, a
// reconnect (superseded) or a connection that lapsed with no transition. The
// converged case gets one, so the check is not a refuse-everything stub.
func TestFenceEndToEndRevocation(t *testing.T) {
	cases := map[string]struct {
		do         func(e *env, rc *realConn, rev int64)
		wantCancel bool
	}{
		"converged": {do: func(*env, *realConn, int64) {}},
		"revoke": {wantCancel: true, do: func(e *env, rc *realConn, _ int64) {
			if _, err := e.gs.Revoke(context.Background(), ownerOf, ownerActor, rc.ref, "user_revoked"); err != nil {
				e.t.Fatal(err)
			}
		}},
		"reconnect supersedes": {wantCancel: true, do: func(e *env, rc *realConn, rev int64) {
			if _, err := e.gs.Reconnect(context.Background(), glovo.ConnectInput{Owner: ownerOf, ExpectedInstallRevision: rev,
				IdempotencyKey: "re-" + rnd(6), Actor: ownerActor}, rc.ref); err != nil {
				e.t.Fatal(err)
			}
		}},
		"connection lapsed with no transition": {do: func(e *env, _ *realConn, _ int64) { time.Sleep(4500 * time.Millisecond) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRealEnv(t)
			if name == "connection lapsed with no transition" {
				e.connTTL = 4 * time.Second
			}
			f, rc := e.realFixture()
			_, rev := e.installTenant()
			res, err := e.dispatch(f)
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			c.do(e, rc, rev)
			_, perr := e.permitAttempt(res.CommandID)
			permits := e.count(`SELECT count(*) FROM bridge_write_permits WHERE command_id = $1`, res.CommandID)
			if name == "converged" {
				if perr != nil {
					t.Fatalf("the converged case was refused: %v", perr)
				}
				if got := e.aarState(f); got != "consumed" {
					t.Fatalf("receipt %s, want consumed", got)
				}
				return
			}
			if perr == nil {
				t.Fatal("a permit was issued after the connection ended")
			}
			if permits != 0 {
				t.Fatalf("%d permit rows exist", permits)
			}
			if got := e.aarState(f); got == "consumed" {
				t.Fatal("the receipt was consumed")
			}
			st, cancel := e.commandStatus(res.CommandID)
			if c.wantCancel && (st != bridge.StatusCancelled || !cancel) {
				t.Fatalf("the revocation hook did not cancel the command: %s cancel_requested=%v", st, cancel)
			}
		})
	}
	t.Run("a foreign or absent command is not found before any lock", func(t *testing.T) {
		e := newRealEnv(t)
		fence := receipt.NewFence(e.st, e.idx, e.gs, e.members)
		ctx := context.Background()
		tx, err := e.rtp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		caller := bridge.Caller{ProviderRef: provider, Actor: "test", Tenants: []string{tenant}}
		if err := fence.PreLock(ctx, tx, caller, "cmd_ABCDEFGHIJKLMNOPQRSTUVWXYZ"); !errors.Is(err, bridge.ErrCommandNotFound) {
			t.Fatalf("PreLock of an absent command: %v", err)
		}
		var locks int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'`).Scan(&locks); err != nil || locks != 0 {
			t.Fatalf("an absent command took %d advisory locks (%v)", locks, err)
		}
	})
}

// T2, T19 and T21 together: random interleavings of two dispatches, a cancel,
// a revoke, a read and a permit attempt on one order, over the real
// connection store and fence. Invariants after every run: no deadlock (40P01)
// anywhere, at most one place_order_fake row and at most one permit row per
// approval, every successful dispatch names the same command, no receipt with a
// command is back to approved, and the order and the command agree.
func TestInterleavingsKeepTheInvariants(t *testing.T) {
	const rounds = 8
	for round := 0; round < rounds; round++ {
		round := round
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(985000 + round)))
			e := newRealEnv(t)
			f, rc := e.realFixture()
			ctx := context.Background()
			var mu sync.Mutex
			var errs []error
			var cmds []string
			note := func(err error) {
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				}
			}
			ops := []func(){
				func() {
					r, err := e.dispatch(f)
					note(err)
					if err == nil {
						mu.Lock()
						cmds = append(cmds, r.CommandID)
						mu.Unlock()
					}
				},
				func() {
					r, err := e.dispatch(f)
					note(err)
					if err == nil {
						mu.Lock()
						cmds = append(cmds, r.CommandID)
						mu.Unlock()
					}
				},
				func() { _, err := e.d.Cancel(ctx, e.tenants, f.orderRef); note(err) },
				func() { _, err := e.gs.Revoke(ctx, ownerOf, ownerActor, rc.ref, "user_revoked"); note(err) },
				func() {
					var cmd string
					_ = e.mp.QueryRow(ctx, `SELECT command_id FROM bridge_commands WHERE approval_ref = $1`, f.aar).Scan(&cmd)
					if cmd != "" {
						_, err := e.permitAttempt(cmd)
						_ = err // refusals are expected; deadlocks are checked below
						note(deadlockOf(err))
					}
				},
			}
			rng.Shuffle(len(ops), func(i, j int) { ops[i], ops[j] = ops[j], ops[i] })
			var wg sync.WaitGroup
			for _, op := range ops {
				delay := time.Duration(rng.Intn(4)) * time.Millisecond
				wg.Add(1)
				go func() {
					defer wg.Done()
					time.Sleep(delay)
					op()
				}()
			}
			wg.Wait()
			for _, err := range errs {
				if strings.Contains(err.Error(), "40P01") || strings.Contains(err.Error(), "deadlock") {
					t.Fatalf("a deadlock: %v", err)
				}
			}
			if n := e.count(`SELECT count(*) FROM bridge_commands WHERE approval_ref = $1 AND operation_kind = 'place_order_fake'`, f.aar); n > 1 {
				t.Fatalf("%d place_order_fake rows for one approval", n)
			}
			if n := e.count(`SELECT count(*) FROM bridge_write_permits p JOIN bridge_commands c USING (command_id) WHERE c.approval_ref = $1`, f.aar); n > 1 {
				t.Fatalf("%d permit rows for one approval", n)
			}
			for _, c := range cmds[min(1, len(cmds)):] {
				if c != cmds[0] {
					t.Fatalf("successful dispatches named different commands: %v", cmds)
				}
			}
			var cmd string
			_ = e.mp.QueryRow(ctx, `SELECT command_id FROM bridge_commands WHERE approval_ref = $1`, f.aar).Scan(&cmd)
			if cmd != "" && e.aarState(f) == "approved" {
				t.Fatal("a receipt with a command is back to approved")
			}
			if len(cmds) > 0 && cmds[0] != cmd {
				t.Fatalf("a dispatch returned %s but the stored command is %q", cmds[0], cmd)
			}
			if got := e.orderState(f); got == "dispatched" && e.str(`SELECT command_id FROM ctl_fake_orders WHERE order_ref = $1`, f.orderRef) != cmd {
				t.Fatalf("the dispatched order names another command than %s", cmd)
			}
		})
	}
}

// deadlockOf keeps only a deadlock out of a permit refusal.
func deadlockOf(err error) error {
	if err != nil && (strings.Contains(err.Error(), "40P01") || strings.Contains(err.Error(), "deadlock")) {
		return err
	}
	return nil
}

// A dispatch that cannot get L2 within the 5 s lock_timeout is refused as
// tenant_busy (409, retryable) and leaves nothing behind; it neither waits
// forever nor reports a generic failure.
func TestDispatchLockTimeoutIsTenantBusy(t *testing.T) {
	e := newRealEnv(t)
	f, rc := e.realFixture()
	_, rev := e.installTenant()
	paused, release := make(chan struct{}), make(chan struct{})
	revoker := make(chan error, 1)
	go func() {
		_, err := e.gs.Reconnect(context.Background(), glovo.ConnectInput{Owner: ownerOf, ExpectedInstallRevision: rev,
			IdempotencyKey: "re-" + rnd(6), Actor: ownerActor,
			AfterLocks: func(context.Context, pgx.Tx) error { close(paused); <-release; return nil }}, rc.ref)
		revoker <- err
	}()
	<-paused
	dispatch := make(chan error, 1)
	go func() { _, err := e.dispatch(f); dispatch <- err }()
	err := within(t, "the dispatch", 15*time.Second, dispatch)
	close(release)
	if rerr := within(t, "the revoker", 5*time.Second, revoker); rerr != nil {
		t.Fatalf("Reconnect: %v", rerr)
	}
	wantCode(t, err, glovo.CodeTenantBusy)
	e.untouched(f, "approved")
}
