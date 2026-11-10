package workitems

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// T2: expiry is judged by statement time. A permit transaction that began
// before fresh_until and consumes after it is refused; now() would let it pass.
func TestConsumeUsesStatementTimeNotTransactionStart(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	f := g.prepare(t)
	g.decide(t, f, DecisionApprove)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
	})
	// The guard rightly forbids moving fresh_until; the owner role suspends the
	// user triggers for this one statement to stage a window of two seconds.
	mp := g.pool(g.migURL)
	for _, q := range []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER USER`,
		`UPDATE public.action_approval_requests SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id='` + f.aar + `'`,
		`ALTER TABLE public.action_approval_requests ENABLE TRIGGER USER`} {
		if _, err := mp.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := g.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_sleep(2.5)`); err != nil {
		t.Fatal(err)
	}
	err = g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, cmd)
	var ge *glovo.Error
	if !errors.As(err, &ge) || ge.Code != glovo.CodeApprovalExpired {
		t.Fatalf("consume after fresh_until: %v, want approval_expired", err)
	}
	_ = tx.Rollback(ctx)
	if st, _ := g.stored(t, f.aar); st != ApprovalReserved {
		t.Fatalf("state = %s, want reserved", st)
	}
}
