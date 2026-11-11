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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/receipt"
)

// pausingFence is the real receipt fence with a barrier inside PreLock, so a
// test decides exactly which locks the permit holds while another session
// moves. takeL2First makes it acquire L2 shared itself before the barrier, which
// is the state the real PreLock passes through between its L2 and L3 steps.
type pausingFence struct {
	inner       *receipt.Fence
	gs          *glovo.Store
	owner       glovo.Owner
	takeL2First bool
	once        sync.Once
	entered     chan struct{}
	proceed     chan struct{}
}

func (f *pausingFence) PreLock(ctx context.Context, tx pgx.Tx, c bridge.Caller, cmd string) error {
	if f.takeL2First {
		if err := f.gs.LockOwnerShared(ctx, tx, f.owner.TenantID, f.owner.PrincipalID); err != nil {
			return err
		}
	}
	f.once.Do(func() { close(f.entered) })
	select {
	case <-f.proceed:
	case <-ctx.Done():
		return ctx.Err()
	}
	return f.inner.PreLock(ctx, tx, c, cmd)
}

func (f *pausingFence) Check(ctx context.Context, tx pgx.Tx, b bridge.FenceBinding) (string, error) {
	return f.inner.Check(ctx, tx, b)
}

func (f *pausingFence) Release(tx pgx.Tx) { f.inner.Release(tx) }

// leasedCommand dispatches the fixture, leases its command through the real
// Claim and returns the command id and its lease token.
func (e *env) leasedCommand(f fixture) (cmd, token string) {
	e.t.Helper()
	cmd = e.dispatched(f)
	got, err := e.bs.Claim(context.Background(), e.leaseCaller(), 1, time.Minute)
	if err != nil || len(got) != 1 || got[0].CommandID != cmd {
		e.t.Fatalf("claim: %v %v", got, err)
	}
	token = e.str(`SELECT lease_token FROM bridge_commands WHERE command_id = $1`, cmd)
	if token == "" {
		e.t.Fatal("no lease token")
	}
	return cmd, token
}

// leaseCaller is the bridge provider that may lease the v1alpha2 dispatch commands.
func (e *env) leaseCaller() bridge.Caller {
	return bridge.Caller{ProviderRef: provider, Actor: "test", Tenants: []string{tenant}, Versions: []string{bridge.WireV1alpha1, bridge.WireV1alpha2}}
}

func (e *env) pausingFence(takeL2First bool) *pausingFence {
	pf := &pausingFence{inner: receipt.NewFence(e.st, e.idx, e.gs, e.members), gs: e.gs, owner: ownerOf, takeL2First: takeL2First,
		entered: make(chan struct{}), proceed: make(chan struct{})}
	e.bs.SetFence(pf)
	return pf
}

// reached waits for the permit to arrive at the barrier; a permit that ends
// first (an unexpected refusal) fails the test at once instead of hanging it.
func reached(t *testing.T, pf *pausingFence, permit <-chan error) {
	t.Helper()
	select {
	case <-pf.entered:
	case err := <-permit:
		t.Fatalf("the permit ended before PreLock: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the permit never reached PreLock")
	}
}

// errStopActivate ends ActivateTx right after the paused AfterLocks.
var errStopActivate = errors.New("stop after the locks")

// holdL2Exclusive is a revoker held exactly between "L1 shared and L2 exclusive
// taken" and "open commands cancelled". It is the real ActivateTx lock
// sequence paused in AfterLocks, then the real hook
// bridge.CancelOpenForConnections for conn, then commit. closed reports the
// outcome of the whole transaction.
func (e *env) holdL2Exclusive(conn string) (paused <-chan struct{}, release func(), closed <-chan error) {
	e.t.Helper()
	pausedC, releaseC, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	rel := func() { once.Do(func() { close(releaseC) }) }
	e.t.Cleanup(rel)
	go func() {
		ctx := context.Background()
		tx, err := e.rtp.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = e.gs.ActivateTx(ctx, tx, glovo.ActivateInput{Owner: ownerOf, ConnectionID: conn, ExpiresIn: time.Minute, Actor: ownerActor,
			AfterLocks: func(ctx context.Context, tx pgx.Tx) error {
				close(pausedC)
				<-releaseC
				if err := bridge.CancelOpenForConnections(ctx, tx, []string{conn}, "svc:revoker"); err != nil {
					return err
				}
				return errStopActivate
			}})
		if !errors.Is(err, errStopActivate) {
			done <- err
			return
		}
		done <- tx.Commit(ctx)
	}()
	return pausedC, rel, done
}

// waitAdvisoryWaiters blocks until n advisory lock requests are waiting.
func (e *env) waitAdvisoryWaiters(n int) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.count(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`) >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("%d advisory waiters never appeared", n)
}

func noDeadlock(t *testing.T, who string, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), "40P01") || strings.Contains(err.Error(), "deadlock")) {
		t.Fatalf("%s deadlocked: %v", who, err)
	}
}

// T21, permit against a revoker holding L2 exclusive, as a forced interleaving.
//
// The permit is held at the entry of PreLock, which in the correct order is
// before it holds any lock. The revoker (a Reconnect paused after its locks)
// takes L2 exclusive. The permit is let go and must wait for L2 holding nothing;
// the revoker is released, cancels the leased command and commits, and only then
// does the permit see a cancelled command. If the permit locked the command row
// before PreLock it would hold L5 while waiting for L2, and the revoker would
// wait for L5 while holding L2: a deadlock Postgres breaks with 40P01.
func TestPermitWaitsForARevokerHoldingL2(t *testing.T) {
	e := newRealEnv(t)
	f, rc := e.realFixture()
	cmd, token := e.leasedCommand(f)
	pf := e.pausingFence(false)
	caller := e.leaseCaller()

	permit := make(chan error, 1)
	go func() { _, err := e.bs.IssueWritePermit(context.Background(), caller, cmd, token); permit <- err }()
	reached(t, pf, permit)

	paused, release, revoker := e.holdL2Exclusive(rc.ref)
	<-paused

	close(pf.proceed)
	stillBlocked(t, "the permit", permit)
	// The deterministic check of the order: a permit queued for L2 holds nothing,
	// least of all the command row the revoker needs next.
	if e.rowLocked(`SELECT 1 FROM bridge_commands WHERE command_id = $1 FOR UPDATE NOWAIT`, cmd) {
		t.Fatal("the permit holds the command row while it waits for L2")
	}
	release()
	rerr := within(t, "the revoker", 10*time.Second, revoker)
	perr := within(t, "the permit", 10*time.Second, permit)
	noDeadlock(t, "the revoker", rerr)
	noDeadlock(t, "the permit", perr)
	if rerr != nil {
		t.Fatalf("the revoker: %v", rerr)
	}
	if perr == nil || !errors.Is(perr, bridge.ErrCommandCancelled) {
		t.Fatalf("the permit after the revocation: %v, want ErrCommandCancelled", perr)
	}
	if n := e.count(`SELECT count(*) FROM bridge_write_permits WHERE command_id = $1`, cmd); n != 0 {
		t.Fatalf("%d permit rows after the revocation", n)
	}
	if st, cancel := e.commandStatus(cmd); st != bridge.StatusCancelled || !cancel {
		t.Fatalf("a leased command is %s cancel_requested=%v after the revocation", st, cancel)
	}
}

// T12, the three-party interleaving that makes the lock order matter. The
// permit holds L2 shared and has not yet taken L3; the revoker queues for L2
// exclusive behind it; a dispatch (a replay on the same order) then arrives.
// With L2 before L3 the dispatch queues behind the revoker holding nothing, the
// permit takes L3 and L4 and commits, and the revoker and dispatch follow. With
// L3 before L2 the dispatch holds the order row while queued behind the revoker,
// the permit waits for that row, the revoker waits for the permit's L2: a cycle.
func TestPermitRevokerDispatchLockOrder(t *testing.T) {
	e := newRealEnv(t)
	f, rc := e.realFixture()
	cmd, token := e.leasedCommand(f)
	pf := e.pausingFence(true)
	caller := e.leaseCaller()

	permit := make(chan error, 1)
	go func() { _, err := e.bs.IssueWritePermit(context.Background(), caller, cmd, token); permit <- err }()
	reached(t, pf, permit)

	revoker := make(chan error, 1)
	go func() {
		_, err := e.gs.Revoke(context.Background(), ownerOf, ownerActor, rc.ref, "user_revoked")
		revoker <- err
	}()
	e.waitAdvisoryWaiters(1)

	dispatch := make(chan error, 1)
	go func() { _, err := e.dispatch(f); dispatch <- err }()
	// Give the dispatch time to reach whichever lock it takes first.
	stillBlocked(t, "the dispatch", dispatch)
	stillBlocked(t, "the revoker", revoker)

	close(pf.proceed)
	perr := within(t, "the permit", 10*time.Second, permit)
	rerr := within(t, "the revoker", 10*time.Second, revoker)
	derr := within(t, "the dispatch", 10*time.Second, dispatch)
	noDeadlock(t, "the permit", perr)
	noDeadlock(t, "the revoker", rerr)
	noDeadlock(t, "the dispatch", derr)
	if perr != nil {
		t.Fatalf("the permit that held L2 first was refused: %v", perr)
	}
	if rerr != nil {
		t.Fatalf("Revoke: %v", rerr)
	}
	// The permit committed before the revocation, so the command is cancelled
	// with its effect unknown, never "none" and never succeeded.
	st, cancel := e.commandStatus(cmd)
	if st != bridge.StatusCancelled || !cancel {
		t.Fatalf("the leased command is %s cancel_requested=%v after the revocation", st, cancel)
	}
	if eff := e.str(`SELECT effect_state FROM bridge_commands WHERE command_id = $1`, cmd); eff != bridge.EffectUnknown {
		t.Fatalf("effect_state %q, want unknown for a permit that preceded the revocation", eff)
	}
	if n := e.count(`SELECT count(*) FROM bridge_write_permits WHERE command_id = $1`, cmd); n != 1 {
		t.Fatalf("%d permit rows, want 1", n)
	}
	if derr == nil {
		t.Log("the dispatch replay answered with the existing command")
	}
}

// T12, the order of the first two lock levels, observed directly. While a
// revoker holds L2 exclusive, a dispatch (and a cancel) waiting for L2 must hold
// no lock of a later level: not the order row (L3). Taking L3 first would hold
// the order against every other writer while queued behind a revoker. A
// deadlock cannot show this order wrong here: the cycle it would form runs
// through a queued shared request, which Postgres resolves by reordering the
// queue, so the test looks at what is held instead.
func TestWaitingForL2HoldsNoLaterLock(t *testing.T) {
	for name, op := range map[string]func(e *env, f fixture) error{
		"dispatch": func(e *env, f fixture) error { _, err := e.dispatch(f); return err },
		"cancel":   func(e *env, f fixture) error { _, err := e.cancel(f); return err },
	} {
		t.Run(name, func(t *testing.T) {
			e := newRealEnv(t)
			f, rc := e.realFixture()
			paused, release, revoker := e.holdL2Exclusive(rc.ref)
			<-paused
			done := make(chan error, 1)
			go func() { done <- op(e, f) }()
			e.waitAdvisoryWaiters(1)
			stillBlocked(t, name, done)
			if e.rowLocked(`SELECT 1 FROM ctl_fake_orders WHERE order_ref = $1 FOR UPDATE NOWAIT`, f.orderRef) {
				t.Fatalf("the %s holds the order row while it waits for L2", name)
			}
			release()
			if err := within(t, "the revoker", 10*time.Second, revoker); err != nil {
				t.Fatalf("the revoker: %v", err)
			}
			_ = within(t, name, 10*time.Second, done)
		})
	}
}
