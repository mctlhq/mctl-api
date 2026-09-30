package workitems

// Delegation grant projections (mctl-api#376 slice B).
//
// Each of these is a narrow, purpose-built SELECT returning only
// delegation.Record's four fields -- deliberately distinct from
// executionRequestColumns / actionApprovalColumns / itemColumns, which stay
// unwidened (D1's job, not this slice's): those back the public read
// payloads of ExecutionRequest, ActionApproval and Get, and widening them
// would change what those endpoints return.
//
// A not-found row here is delegation.ErrNotBound, never
// ErrExecutionRequestNotFound / ErrApprovalNotFound / ErrNotFound:
// internal/delegation cannot import this package (that would cycle back
// into the package that implements its interfaces), so it is this
// package's job to speak delegation's own sentinel.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/delegation"
)

// ExecutionRequestGrant implements delegation.WorkItemSource for an xr_ ref:
// the requester, the requester's principal id, and the request's own work
// item and execution ids (the binding scope). itemID narrows the row the
// same way getExecutionRequest's AND work_item_id=$2 does, when non-empty.
func (s *Store) ExecutionRequestGrant(ctx context.Context, itemID, id string) (delegation.Record, error) {
	query := `SELECT work_item_id, requested_by, requested_by_principal_id, execution_id
		FROM work_item_execution_requests WHERE id=$1`
	args := []any{id}
	if itemID != "" {
		query += ` AND work_item_id=$2`
		args = append(args, itemID)
	}
	var rec delegation.Record
	err := s.pool.QueryRow(ctx, query, args...).Scan(&rec.WorkItemID, &rec.Subject, &rec.SubjectPrincipalID, &rec.ExecutionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return delegation.Record{}, delegation.ErrNotBound
	}
	if err != nil {
		return delegation.Record{}, fmt.Errorf("workitems: execution request grant: %w", err)
	}
	return rec, nil
}

// ActionApprovalGrant implements delegation.WorkItemSource for an aar_ ref:
// who decided it, their principal id, and the approval's own execution and
// work item ids.
func (s *Store) ActionApprovalGrant(ctx context.Context, id string) (delegation.Record, error) {
	var rec delegation.Record
	err := s.pool.QueryRow(ctx, `SELECT execution_id, work_item_id, decided_by, decided_by_principal_id
		FROM action_approval_requests WHERE id=$1`, id).Scan(&rec.ExecutionID, &rec.WorkItemID, &rec.Subject, &rec.SubjectPrincipalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return delegation.Record{}, delegation.ErrNotBound
	}
	if err != nil {
		return delegation.Record{}, fmt.Errorf("workitems: action approval grant: %w", err)
	}
	return rec, nil
}

// WorkItemGrant implements delegation.WorkItemSource for a wi_ ref: the
// item's owner and the owner's principal id. A work item has no execution id
// of its own, so Record.ExecutionID is always "".
func (s *Store) WorkItemGrant(ctx context.Context, id string) (delegation.Record, error) {
	var rec delegation.Record
	err := s.pool.QueryRow(ctx, `SELECT owner_principal, owner_principal_id
		FROM work_items WHERE id=$1`, id).Scan(&rec.Subject, &rec.SubjectPrincipalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return delegation.Record{}, delegation.ErrNotBound
	}
	if err != nil {
		return delegation.Record{}, fmt.Errorf("workitems: work item grant: %w", err)
	}
	rec.WorkItemID = id
	return rec, nil
}

// SurfaceRefBound implements delegation.WorkItemSource for a sil_ grant's
// binding: whether itemID carries a work_item_surface_refs row for
// (surface, actorExternalID). A surface link names neither an execution nor
// a work item of its own, so this correlation is its only binding scope.
func (s *Store) SurfaceRefBound(ctx context.Context, itemID, surface, actorExternalID string) (bool, error) {
	var bound bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM work_item_surface_refs
		WHERE work_item_id=$1 AND surface=$2 AND actor_external_id=$3)`, itemID, surface, actorExternalID).Scan(&bound)
	if err != nil {
		return false, fmt.Errorf("workitems: surface ref bound: %w", err)
	}
	return bound, nil
}
