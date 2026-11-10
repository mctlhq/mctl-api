package workitems

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// GlovoDecisions is what the HTTP decision route needs of the Glovo approval
// ledger (mctl-api#989 design section 5): the binding read on the Glovo pool,
// the decision as DecideGlovoApprovalTx on a transaction of the bridge pool
// (one database), and the readiness answer. Every dependency is required; a
// missing one is glovo.CodeNotReady, never a silent success.
type GlovoDecisions struct {
	Store *Store
	// Reader is the Glovo pool (glovo_runtime): the owner and tenant live in
	// glovo.approval_bindings, which the work-items role cannot read.
	Reader dbq.Querier
	// Begin opens a transaction of the bridge pool.
	Begin func(ctx context.Context) (pgx.Tx, error)
	// ReadyFn is receipt.Ready.
	ReadyFn func(ctx context.Context) error
}

func (d *GlovoDecisions) complete() bool {
	return d != nil && !glovo.IsNil(d.Store) && !glovo.IsNil(d.Reader) && d.Begin != nil && d.ReadyFn != nil
}

// Ready is nil only when every dependency is wired and ReadyFn passes.
func (d *GlovoDecisions) Ready(ctx context.Context) error {
	if !d.complete() {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	return d.ReadyFn(ctx)
}

// ForDecision is Store.GlovoApprovalForDecision on the Glovo pool.
func (d *GlovoDecisions) ForDecision(ctx context.Context, id string) (*ActionApprovalRequest, *GlovoBinding, error) {
	if !d.complete() {
		return nil, nil, glovo.Refuse(glovo.CodeNotReady)
	}
	return d.Store.GlovoApprovalForDecision(ctx, d.Reader, id)
}

// Decide runs DecideGlovoApprovalTx in its own transaction.
func (d *GlovoDecisions) Decide(ctx context.Context, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if !d.complete() {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return nil, mapGlovoPgErr("begin glovo decision", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := d.Store.DecideGlovoApprovalTx(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapGlovoPgErr("commit glovo decision", err)
	}
	return a, nil
}
