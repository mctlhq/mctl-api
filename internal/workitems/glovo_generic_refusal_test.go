package workitems

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// T9 (generic half): every generic approval path refuses a Glovo row in every
// stored state, and the generic creator refuses every glovo.* kind.
func TestGenericPathsRefuseGlovoKinds(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	check := func(t *testing.T, id, state string) {
		t.Helper()
		// Present the row's own identifying fields, so the only reason a generic
		// compare-and-set can refuse is the Glovo kind predicate itself.
		var target, artifact, requester, intent string
		if err := g.rtp.QueryRow(ctx, `SELECT target, artifact_hash, requested_by, intent_hash
			FROM public.action_approval_requests WHERE id=$1`, id).Scan(&target, &artifact, &requester, &intent); err != nil {
			t.Fatal(err)
		}
		calls := map[string]error{}
		_, calls["decide"] = g.store.DecideActionApproval(ctx, ActionDecisionInput{ID: id, DecidedBy: "oidc:other", Decision: DecisionApprove})
		_, calls["consume"] = g.store.ConsumeActionApproval(ctx, id, intent)
		_, calls["mark"] = g.store.MarkActionApprovalExecuted(ctx, id, target, artifact, requester)
		_, calls["reserve"] = g.store.ReserveActionApproval(ctx, id, target, artifact, requester, time.Hour)
		_, calls["settle"] = g.store.SettleActionApproval(ctx, id, requester, true)
		_, calls["settle-fail"] = g.store.SettleActionApproval(ctx, id, requester, false)
		for name, err := range calls {
			if !errors.Is(err, ErrApprovalKindNotSpendable) {
				t.Errorf("%s on a %s Glovo row: %v, want ErrApprovalKindNotSpendable", name, state, err)
			}
		}
		if st, _ := g.stored(t, id); st != state {
			t.Errorf("a generic path moved the row to %s, want %s", st, state)
		}
	}

	f := g.prepare(t)
	check(t, f.aar, ApprovalPending)
	g.decide(t, f, DecisionApprove)
	check(t, f.aar, ApprovalApproved)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
	})
	check(t, f.aar, ApprovalReserved)
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatal(err)
		}
	})
	check(t, f.aar, ApprovalUnknown)

	f2 := g.prepare(t)
	g.decide(t, f2, DecisionApprove)
	cmd2 := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f2.aar, f2.reserveCmd(cmd2)); err != nil {
			t.Fatal(err)
		}
		if err := g.store.ConsumeGlovoApprovalTx(ctx, tx, f2.aar, cmd2); err != nil {
			t.Fatal(err)
		}
	})
	check(t, f2.aar, ApprovalConsumed)

	f3 := g.prepare(t)
	g.decide(t, f3, DecisionDeny)
	check(t, f3.aar, ApprovalDenied)

	for _, kind := range []string{ActionKindGlovoPlaceOrderFake, "glovo.other", "glovo."} {
		_, _, err := g.store.CreateActionApproval(ctx, ActionApprovalInput{
			ActionIntent: ActionIntent{ActionKind: kind, Target: "x", ArtifactHash: "h"}, RequestedBy: "oidc:a",
			IdempotencyKey: "k", ExpiresAt: time.Now().Add(time.Hour)})
		if !errors.Is(err, ErrApprovalKindNotCreatable) {
			t.Errorf("generic create of %q: %v, want ErrApprovalKindNotCreatable", kind, err)
		}
	}
}
