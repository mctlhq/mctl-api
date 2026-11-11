package receipt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func wantCode(t *testing.T, err error, want glovo.Code) {
	t.Helper()
	got, ok := CodeOf(err)
	if !ok || got != want {
		t.Fatalf("code = %q (%v), want %q", got, err, want)
	}
	if !errors.Is(err, bridge.ErrWriteFenceRefused) {
		t.Fatalf("%v does not wrap ErrWriteFenceRefused", err)
	}
}

// T1/T14: the happy path spends the approval in the same transaction, in the
// lock order L1-L2, L3, L4.
func TestFenceHappyPathConsumesAndKeepsLockOrder(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ref, err := e.run(f, f.binding(e))
	if err != nil {
		t.Fatalf("fence: %v", err)
	}
	if !strings.HasPrefix(ref, "afr_") {
		t.Fatalf("fence ref %q", ref)
	}
	if got := e.state(f.aar); got != workitems.ApprovalConsumed {
		t.Fatalf("state = %s, want consumed", got)
	}
	if strings.Join(e.log[:2], ",") != "L1L2,L3" {
		t.Fatalf("lock order %v: L1-L2 then L3 first", e.log)
	}
}

// T21: PreLock takes L4 itself, so the approval row is locked before the
// caller's own statements run, never first reached from the consume.
func TestFencePreLockHoldsTheApprovalRow(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		t.Fatal(err)
	}
	probe, err := e.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Rollback(ctx) }()
	var one int
	err = probe.QueryRow(ctx, `SELECT 1 FROM public.action_approval_requests WHERE id=$1 FOR UPDATE NOWAIT`, f.aar).Scan(&one)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("the approval row is not locked after PreLock: %v", err)
	}
}

// T14: a refusal after the consume would leave nothing; a rolled-back tx keeps
// the approval reserved.
func TestFenceRollbackLeavesApprovalReserved(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, _ := e.rtp.Begin(ctx)
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := e.fence.Check(ctx, tx, f.binding(e)); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
	if got := e.state(f.aar); got != workitems.ApprovalReserved {
		t.Fatalf("state after rollback = %s, want reserved", got)
	}
	if _, err := e.run(f, f.binding(e)); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

// T10: the written payload decides, not the caller.
func TestFenceRecomputesFromWrittenContent(t *testing.T) {
	cases := map[string]string{
		"price changed":    strings.Replace(basePayload, `"unit_price_minor":500`, `"unit_price_minor":501`, 1),
		"item code":        strings.Replace(basePayload, `FAKE-1`, `FAKE-2`, 1),
		"extra field":      strings.Replace(basePayload, `"total_minor":749`, `"total_minor":749,"note":"x"`, 1),
		"wrapper":          `{"basket":` + basePayload + `}`,
		"missing lines":    strings.Replace(basePayload, `"lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],`, ``, 1),
		"not an object":    `[]`,
		"currency changed": strings.Replace(basePayload, `EUR`, `USD`, 1),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			f := e.reserved(p)
			_, err := e.run(f, f.binding(e))
			wantCode(t, err, glovo.CodeBasketChanged)
			if got := e.state(f.aar); got != workitems.ApprovalReserved {
				t.Fatalf("state = %s after refusal, want reserved", got)
			}
		})
	}
	t.Run("matching payload with other key order and spacing", func(t *testing.T) {
		e := newEnv(t)
		f := e.reserved(`{ "total_minor":749, "v":"mctl-approval-basket/v1", "store_ref":"pst_0123456789abcdef0123", "currency":"EUR",
		"lines":[{"unit_price_minor":500,"quantity":1,"item_code":"FAKE-1"}], "subtotal_minor":500,"delivery_fee_minor":199,
		"service_fee_minor":50,"discount_minor":0 }`)
		if _, err := e.run(f, f.binding(e)); err != nil {
			t.Fatalf("a matching payload must pass: %v", err)
		}
	})
}

// T10: a presented intent hash the written command does not carry.
func TestFenceRefusesIntentHashMismatch(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	b := f.binding(e)
	b.IntentHash = "sha256:" + strings.Repeat("0", 64)
	_, err := e.run(f, b)
	wantCode(t, err, glovo.CodeIntentMismatch)
}

// T6/T7: a spent approval does not pass twice, and a second command that
// names an approval reserved for another command is a replay.
func TestFenceReplayAndForeignCommand(t *testing.T) {
	t.Run("consumed approval, same command", func(t *testing.T) {
		e := newEnv(t)
		f := e.reserved("")
		if _, err := e.run(f, f.binding(e)); err != nil {
			t.Fatal(err)
		}
		_, err := e.run(f, f.binding(e))
		wantCode(t, err, glovo.CodeApprovalInvalid)
	})
	t.Run("second command names the reserved approval", func(t *testing.T) {
		e := newEnv(t)
		f := e.reserved("")
		g := e.siblingCommand(f)
		_, err := e.run(g, g.binding(e))
		wantCode(t, err, glovo.CodeApprovalReplayed)
		if got := e.state(f.aar); got != workitems.ApprovalReserved {
			t.Fatalf("state = %s, want reserved", got)
		}
	})
}

func TestFenceRefusals(t *testing.T) {
	type tc struct {
		name string
		do   func(e *env, f fixture)
		want glovo.Code
	}
	for _, c := range []tc{
		{"membership gone", func(e *env, _ fixture) { e.members.member = false }, glovo.CodeNoTenant},
		{"membership unreadable", func(e *env, _ fixture) { e.members.err = errors.New("gitops down") }, glovo.CodeUnavailable},
		{"connection replaced", func(e *env, _ fixture) { e.conns.conn.ConnectionID = tok("gcn_", 26) }, glovo.CodeConnectionRevoked},
		{"connection not active", func(e *env, _ fixture) { e.conns.conn.State = glovo.Revoked }, glovo.CodeNoConnection},
		{"install moved", func(e *env, _ fixture) { e.conns.conn.InstallRevision = 4 }, glovo.CodeStaleInstall},
		{"order not dispatched", func(e *env, _ fixture) { e.ord.order.State = "finalized" }, glovo.CodeInvalidTransition},
		{"order has another command", func(e *env, _ fixture) { e.ord.order.CommandID = tok("cmd_", 26) }, glovo.CodeInvalidTransition},
		{"order fingerprint differs", func(e *env, _ fixture) { e.ord.order.FinalBasketFingerprint = "sha256:" + strings.Repeat("1", 64) }, glovo.CodeBasketChanged},
		{"approval expired", func(e *env, f fixture) {
			// The guard (rightly) forbids moving fresh_until, so the owner role
			// suspends the user triggers for this one test statement.
			for _, q := range []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER USER`,
				`UPDATE public.action_approval_requests SET fresh_until=clock_timestamp()-interval '1 second' WHERE id='` + f.aar + `'`,
				`ALTER TABLE public.action_approval_requests ENABLE TRIGGER USER`} {
				if _, err := e.mp.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
			}
		}, glovo.CodeApprovalExpired},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			f := e.reserved("")
			c.do(e, f)
			_, err := e.run(f, f.binding(e))
			wantCode(t, err, c.want)
			if got := e.state(f.aar); got != workitems.ApprovalReserved {
				t.Fatalf("state = %s after refusal, want reserved", got)
			}
		})
	}
}

// T7b/T15c: a command outside the caller's scope is not found and takes no
// lock; a non-Glovo operation takes none either.
func TestPreLockScopeTakesNoLock(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	for name, c := range map[string]bridge.Caller{
		"other tenant":   {ProviderRef: provider, Actor: "x", Tenants: []string{"other"}},
		"other provider": {ProviderRef: "someone", Actor: "x", Tenants: []string{tenant}},
		"no tenants":     {ProviderRef: provider, Actor: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			e.log = nil
			e.tx(func(tx pgx.Tx) {
				if err := e.fence.PreLock(ctx, tx, c, f.cmd); !errors.Is(err, bridge.ErrCommandNotFound) {
					t.Fatalf("err = %v, want ErrCommandNotFound", err)
				}
			})
			if len(e.log) != 0 {
				t.Fatalf("locks taken for a foreign scope: %v", e.log)
			}
		})
	}
	t.Run("absent command", func(t *testing.T) {
		e.tx(func(tx pgx.Tx) {
			if err := e.fence.PreLock(ctx, tx, e.caller, tok("cmd_", 26)); !errors.Is(err, bridge.ErrCommandNotFound) {
				t.Fatalf("err = %v", err)
			}
		})
	})
}

// A Check with no PreLock for the transaction refuses instead of locking out
// of order.
func TestCheckWithoutPreLockRefuses(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, _ := e.rtp.Begin(ctx)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err := e.fence.Check(ctx, tx, f.binding(e))
	wantCode(t, err, glovo.CodeUnavailable)
}

// An incomplete fence refuses everything with not_ready.
func TestIncompleteFenceIsNotReady(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	var nilStore *workitems.Store
	for name, fn := range map[string]*Fence{
		"nil approvals (typed)": NewFence(nilStore, e.ord, e.conns, e.members),
		"nil orders":            NewFence(e.store, nil, e.conns, e.members),
		"nil conns":             NewFence(e.store, e.ord, nil, e.members),
		"nil members":           NewFence(e.store, e.ord, e.conns, nil),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tx, _ := e.rtp.Begin(ctx)
			defer func() { _ = tx.Rollback(ctx) }()
			wantCode(t, fn.PreLock(ctx, tx, e.caller, f.cmd), glovo.CodeNotReady)
			_, err := fn.Check(ctx, tx, f.binding(e))
			wantCode(t, err, glovo.CodeNotReady)
		})
	}
}

// A hung membership provider cannot hold L3, L4 and L5 past the bound: the
// permit is refused as unavailable, the approval stays reserved, and the rows
// are free again.
func TestFenceHungMembershipIsBoundedAndUnavailable(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	e.members.hang = make(chan struct{})
	t.Cleanup(func() { close(e.members.hang) })
	start := time.Now()
	errc := make(chan error, 1)
	go func() { _, err := e.run(f, f.binding(e)); errc <- err }()
	var err error
	select {
	case err = <-errc:
	case <-time.After(glovo.MembershipTimeout + 4*time.Second):
		t.Fatalf("the fence is still waiting on the hung provider after %s", glovo.MembershipTimeout+4*time.Second)
	}
	if dur := time.Since(start); dur > glovo.MembershipTimeout+2*time.Second {
		t.Fatalf("the fence took %s, bound is %s", dur, glovo.MembershipTimeout)
	}
	wantCode(t, err, glovo.CodeUnavailable)
	if got := e.state(f.aar); got != workitems.ApprovalReserved {
		t.Fatalf("state %s, want reserved", got)
	}
	e.tx(func(tx pgx.Tx) {
		var one int
		if err := tx.QueryRow(context.Background(), `SELECT 1 FROM public.action_approval_requests WHERE id=$1 FOR UPDATE NOWAIT`, f.aar).Scan(&one); err != nil {
			t.Fatalf("the approval row is still locked: %v", err)
		}
	})
}
