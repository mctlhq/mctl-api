package workitems

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventExecutionOrphanClosed records an execution closed because its owning
// engine run had already ended without reporting.
const EventExecutionOrphanClosed = "execution_orphan_closed"

// OpenExecutionsWithQueuedRequests lists open executions of one engine that
// have an open (pending or claimed) request and started at or before
// olderThan, oldest first, at most limit.
func (s *Store) OpenExecutionsWithQueuedRequests(ctx context.Context, engine string, olderThan time.Time, limit int) ([]Execution, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+executionColumns+` FROM work_item_executions
		WHERE engine=$1 AND phase IN `+openPhasesSQL+` AND started_at <= $2
		  AND EXISTS (SELECT 1 FROM work_item_execution_requests r
			WHERE r.work_item_id = work_item_executions.work_item_id AND r.state IN ('pending','claimed'))
		ORDER BY started_at, id LIMIT $3`, engine, olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("workitems: open executions with queued requests: %w", err)
	}
	defer rows.Close()
	out := []Execution{}
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: open executions with queued requests: %w", err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("workitems: open executions with queued requests: %w", err)
	}
	return out, nil
}

// OrphanCloseInput names an execution to close and the phase it was seen in.
type OrphanCloseInput struct {
	Mutation
	ExecutionID   string
	ExpectedPhase string
	// EngineStatus is the engine's own status for the run, recorded on the
	// event.
	EngineStatus string
}

// CloseOrphanedExecution moves an open execution to Error, guarded by a
// compare-and-set on its phase. closed=false means another writer moved the
// execution first (or it is terminal); nothing is changed then.
func (s *Store) CloseOrphanedExecution(ctx context.Context, in OrphanCloseInput) (*Execution, bool, error) {
	if err := in.Mutation.validate(); err != nil {
		return nil, false, err
	}
	if in.ExecutionID == "" || in.ExpectedPhase == "" || IsTerminalPhase(in.ExpectedPhase) {
		return nil, false, invalid("execution_id and a non-terminal expected_phase are required")
	}
	cur, err := s.ExecutionByID(ctx, in.ExecutionID)
	if err != nil {
		return nil, false, err
	}
	var out *Execution
	err = s.withTx(ctx, "workitem:"+cur.WorkItemID, func(tx pgx.Tx) error {
		now := s.now()
		e, err := scanExecution(tx.QueryRow(ctx, `UPDATE work_item_executions
			SET phase='`+PhaseError+`', ended_at=$3
			WHERE id=$1 AND phase=$2
			RETURNING `+executionColumns, in.ExecutionID, in.ExpectedPhase, now))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("workitems: close orphaned execution: %w", err)
		}
		if err := appendEvent(ctx, tx, e.WorkItemID, EventExecutionOrphanClosed, "", "", in.Mutation,
			map[string]any{"execution_id": e.ID, "engine_ref": e.EngineRef, "engine_status": in.EngineStatus}, now); err != nil {
			return err
		}
		out = e
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, out != nil, nil
}
