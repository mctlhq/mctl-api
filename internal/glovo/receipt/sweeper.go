package receipt

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// sweepLimit bounds one tick (design section 7).
const sweepLimit = 100

// Unknowner is the ledger write the sweeper uses (workitems.Store).
type Unknowner interface {
	MarkGlovoApprovalUnknownTx(ctx context.Context, tx pgx.Tx, id, commandID string) error
}

// Sweeper moves a reserved approval whose bound command ended without a
// permit to unknown. It takes L4 only (the aar_ row, SKIP LOCKED) and reads
// the command without a lock: a terminal command never changes again, so the
// plain read is safe. The terminal and no-permit filters are in the query, so
// a backlog of live reserved rows cannot fill the limit ahead of a due one. It starts nothing by itself: #985 task 9 owns the
// goroutine (OPEN-989-8 in the pull request).
type Sweeper struct {
	Begin     func(ctx context.Context) (pgx.Tx, error) // a transaction that reads the bridge tables and writes the ledger
	Approvals Unknowner
}

// Sweep runs one tick and returns how many approvals it moved to unknown. A
// failed read or write rolls the whole tick back and is an error.
func (s *Sweeper) Sweep(ctx context.Context) (int, error) {
	if s == nil || s.Begin == nil || isNil(s.Approvals) {
		return 0, glovo.Refuse(glovo.CodeNotReady)
	}
	tx, err := s.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("receipt: sweeper begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	type pair struct{ id, command string }
	rows, err := tx.Query(ctx, `SELECT a.id, b.command_id
		FROM public.action_approval_requests a JOIN glovo.approval_bindings b ON b.approval_id = a.id
		JOIN bridge_commands c ON c.command_id = b.command_id
		WHERE a.state = 'reserved' AND `+workitems.GlovoKindPredicate+` AND b.command_id <> ''
		  AND c.status IN ('completed','expired','cancelled')
		  AND NOT EXISTS (SELECT 1 FROM bridge_write_permits w WHERE w.command_id = c.command_id)
		ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT `+fmt.Sprint(sweepLimit))
	if err != nil {
		return 0, fmt.Errorf("receipt: sweeper read: %w", err)
	}
	var due []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.command); err != nil {
			rows.Close()
			return 0, fmt.Errorf("receipt: sweeper scan: %w", err)
		}
		due = append(due, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("receipt: sweeper read: %w", err)
	}
	moved := 0
	for _, p := range due {
		if err := s.Approvals.MarkGlovoApprovalUnknownTx(ctx, tx, p.id, p.command); err != nil {
			return 0, fmt.Errorf("receipt: sweeper mark unknown: %w", err)
		}
		moved++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("receipt: sweeper commit: %w", err)
	}
	return moved, nil
}

// Run sweeps every interval until ctx ends; a failed tick goes to onErr.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
