package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Owner actions on a DevLoop (mctl-api#900): request changes, defer and
// request cancel. They are records of what an owner asked for, never
// aar_ decisions; the table holds ids, digests, codes and states only, no
// free text.

// OwnerActionIDPrefix starts every owner action id.
const OwnerActionIDPrefix = "oa_"

// OwnerActionSchemaVersion is stamped on every row.
const OwnerActionSchemaVersion = "owneraction/v1"

// Owner action kinds.
const (
	OwnerActionRequestChanges = "request_changes"
	OwnerActionDefer          = "defer"
	OwnerActionRequestCancel  = "request_cancel"
)

// Owner action states.
const (
	OwnerActionRequested = "requested"
	OwnerActionRecorded  = "recorded"
	OwnerActionSignalled = "signalled"
	OwnerActionFinished  = "finished"
)

var (
	// ErrOwnerActionIdempotencyConflict: the same principal reused an
	// idempotency key with different content.
	ErrOwnerActionIdempotencyConflict = errors.New("owner action idempotency key reused with different content")
	// ErrOwnerActionNotFound: no such owner action.
	ErrOwnerActionNotFound = errors.New("owner action not found")
	// ErrOwnerActionStateChanged: the compare-and-set on state did not match.
	ErrOwnerActionStateChanged = errors.New("owner action state changed")
)

const ownerActionSchema = `
CREATE TABLE IF NOT EXISTS dev_loop_owner_actions (
    id              TEXT PRIMARY KEY,
    workflow_id     TEXT NOT NULL,
    run_id          TEXT NOT NULL DEFAULT '',
    execution_id    TEXT NOT NULL DEFAULT '',
    approval_ref    TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL CHECK (action IN ('request_changes', 'defer', 'request_cancel')),
    reason_code     TEXT NOT NULL DEFAULT '',
    requested_by    TEXT NOT NULL,
    principal_id    TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    content_digest  TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('requested', 'recorded', 'signalled', 'finished')),
    outcome         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    schema_version  TEXT NOT NULL,
    UNIQUE (requested_by, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS dev_loop_owner_actions_one_cancel_per_run
    ON dev_loop_owner_actions (workflow_id, run_id) WHERE action = 'request_cancel';
CREATE UNIQUE INDEX IF NOT EXISTS dev_loop_owner_actions_one_per_grant
    ON dev_loop_owner_actions (approval_ref, action)
    WHERE action IN ('request_changes', 'defer');
CREATE INDEX IF NOT EXISTS dev_loop_owner_actions_workflow
    ON dev_loop_owner_actions (workflow_id, created_at);
`

// OwnerAction is one recorded owner action.
type OwnerAction struct {
	ID             string    `json:"id"`
	WorkflowID     string    `json:"workflow_id"`
	RunID          string    `json:"run_id,omitempty"`
	ExecutionID    string    `json:"execution_id,omitempty"`
	ApprovalRef    string    `json:"approval_ref,omitempty"`
	Action         string    `json:"action"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	RequestedBy    string    `json:"requested_by"`
	PrincipalID    string    `json:"principal_id,omitempty"`
	IdempotencyKey string    `json:"-"`
	ContentDigest  string    `json:"-"`
	State          string    `json:"state"`
	Outcome        string    `json:"outcome,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	SchemaVersion  string    `json:"schema_version"`
}

// OwnerActionInput is what CreateOwnerAction records.
type OwnerActionInput struct {
	WorkflowID     string
	RunID          string
	ExecutionID    string
	ApprovalRef    string
	Action         string
	ReasonCode     string
	RequestedBy    string
	PrincipalID    string
	IdempotencyKey string
	ContentDigest  string
	// State and Outcome are the initial ones: recorded/<outcome> for
	// request_changes and defer, requested/"" for request_cancel.
	State   string
	Outcome string
}

func (in OwnerActionInput) validate() error {
	switch in.Action {
	case OwnerActionRequestChanges, OwnerActionDefer, OwnerActionRequestCancel:
	default:
		return fmt.Errorf("workitems: unknown owner action %q", in.Action)
	}
	switch in.State {
	case OwnerActionRequested, OwnerActionRecorded:
	default:
		return fmt.Errorf("workitems: owner action initial state %q is not requested or recorded", in.State)
	}
	if in.WorkflowID == "" || in.RequestedBy == "" || in.IdempotencyKey == "" || in.ContentDigest == "" {
		return errors.New("workitems: owner action needs workflow id, requester, idempotency key and content digest")
	}
	if in.Action == OwnerActionRequestCancel && in.RunID == "" {
		return errors.New("workitems: a cancel is bound to a run id")
	}
	if in.Action != OwnerActionRequestCancel && in.ApprovalRef == "" {
		return errors.New("workitems: request_changes and defer name the grant they observed")
	}
	return nil
}

const ownerActionColumns = `id, workflow_id, run_id, execution_id, approval_ref, action, reason_code,
	requested_by, principal_id, idempotency_key, content_digest, state, outcome, created_at, updated_at, schema_version`

func scanOwnerAction(row pgx.Row) (*OwnerAction, error) {
	var o OwnerAction
	if err := row.Scan(&o.ID, &o.WorkflowID, &o.RunID, &o.ExecutionID, &o.ApprovalRef, &o.Action, &o.ReasonCode,
		&o.RequestedBy, &o.PrincipalID, &o.IdempotencyKey, &o.ContentDigest, &o.State, &o.Outcome,
		&o.CreatedAt, &o.UpdatedAt, &o.SchemaVersion); err != nil {
		return nil, err
	}
	return &o, nil
}

// CreateOwnerAction records an owner action, or returns the existing one
// (replayed=true): the row this principal's idempotency key names with the
// same content, the recorded cancel of the same run, or the action of the
// same kind already open on the same grant. The same key with different
// content is ErrOwnerActionIdempotencyConflict.
func (s *Store) CreateOwnerAction(ctx context.Context, in OwnerActionInput) (*OwnerAction, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *OwnerAction
	replayed := false
	err := s.withTx(ctx, "owner-action:"+in.WorkflowID, func(tx pgx.Tx) error {
		existing, err := scanOwnerAction(tx.QueryRow(ctx, `SELECT `+ownerActionColumns+
			` FROM dev_loop_owner_actions WHERE requested_by=$1 AND idempotency_key=$2`, in.RequestedBy, in.IdempotencyKey))
		switch {
		case err == nil:
			if existing.ContentDigest != in.ContentDigest {
				return ErrOwnerActionIdempotencyConflict
			}
			out, replayed = existing, true
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("workitems: read owner action by key: %w", err)
		}
		var q string
		var args []any
		if in.Action == OwnerActionRequestCancel {
			q = `SELECT ` + ownerActionColumns + ` FROM dev_loop_owner_actions
				WHERE workflow_id=$1 AND run_id=$2 AND action='request_cancel'`
			args = []any{in.WorkflowID, in.RunID}
		} else {
			q = `SELECT ` + ownerActionColumns + ` FROM dev_loop_owner_actions
				WHERE approval_ref=$1 AND action=$2`
			args = []any{in.ApprovalRef, in.Action}
		}
		existing, err = scanOwnerAction(tx.QueryRow(ctx, q, args...))
		switch {
		case err == nil:
			out, replayed = existing, true
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("workitems: read owner action: %w", err)
		}
		now := s.now()
		out, err = scanOwnerAction(tx.QueryRow(ctx, `INSERT INTO dev_loop_owner_actions (
				id, workflow_id, run_id, execution_id, approval_ref, action, reason_code, requested_by, principal_id,
				idempotency_key, content_digest, state, outcome, created_at, updated_at, schema_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,$15)
			RETURNING `+ownerActionColumns,
			OwnerActionIDPrefix+strings.ReplaceAll(uuid.NewString(), "-", ""), in.WorkflowID, in.RunID, in.ExecutionID,
			in.ApprovalRef, in.Action, in.ReasonCode, in.RequestedBy, in.PrincipalID, in.IdempotencyKey,
			in.ContentDigest, in.State, in.Outcome, now, OwnerActionSchemaVersion))
		if err != nil {
			return fmt.Errorf("workitems: insert owner action: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, replayed, nil
}

// MarkOwnerActionOutcome moves an owner action from one state to another and
// sets its outcome, compare-and-set on the state. A row no longer in
// fromState is ErrOwnerActionStateChanged.
func (s *Store) MarkOwnerActionOutcome(ctx context.Context, id, fromState, toState, outcome string) (*OwnerAction, error) {
	o, err := scanOwnerAction(s.pool.QueryRow(ctx, `UPDATE dev_loop_owner_actions
		SET state=$3, outcome=$4, updated_at=$5 WHERE id=$1 AND state=$2
		RETURNING `+ownerActionColumns, id, fromState, toState, outcome, s.now()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOwnerActionStateChanged
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: mark owner action: %w", err)
	}
	return o, nil
}

// GetOwnerAction returns one owner action.
func (s *Store) GetOwnerAction(ctx context.Context, id string) (*OwnerAction, error) {
	o, err := scanOwnerAction(s.pool.QueryRow(ctx, `SELECT `+ownerActionColumns+
		` FROM dev_loop_owner_actions WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOwnerActionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: read owner action: %w", err)
	}
	return o, nil
}

// ListOwnerActions returns a workflow's owner actions, oldest first.
func (s *Store) ListOwnerActions(ctx context.Context, workflowID string) ([]OwnerAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ownerActionColumns+
		` FROM dev_loop_owner_actions WHERE workflow_id=$1 ORDER BY created_at, id`, workflowID)
	if err != nil {
		return nil, fmt.Errorf("workitems: list owner actions: %w", err)
	}
	defer rows.Close()
	out := []OwnerAction{}
	for rows.Next() {
		o, err := scanOwnerAction(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: scan owner action: %w", err)
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}
