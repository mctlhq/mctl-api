package workitems

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sealed ContextSnapshots (mctl-agents#431, owner decisions A–B).
//
// One immutable snapshot per execution, INSERT-only:
//
//   - the id is derived from the content hash, and the stored hash is
//     recomputed from the stored canonical bytes on every write;
//   - the retry identity is the execution id: the same execution with the
//     same bytes is the same snapshot (a replay), the same execution with
//     different bytes is ErrSnapshotDivergence — never a second snapshot;
//   - a new execution (a new attempt the work-item layer created) may seal
//     its own snapshot, naming the prior execution/snapshot it continues;
//   - no route or method updates or deletes a snapshot, and a trigger
//     refuses an UPDATE of the table outright.

// SnapshotIDPrefix labels snapshot ids (contract "ID scheme").
const SnapshotIDPrefix = "cs_"

// MaxSnapshotBytes bounds one snapshot's canonical bytes.
const MaxSnapshotBytes = 1 << 20

var (
	// ErrSnapshotDivergence: this execution already sealed different bytes.
	ErrSnapshotDivergence = errors.New("execution already sealed a different context snapshot")
	// ErrPriorSnapshot: a named prior execution or snapshot does not exist
	// on this work item, or does not precede this execution.
	ErrPriorSnapshot = errors.New("prior execution or snapshot reference is missing or stale")
	// ErrExecutionNotFound: no such execution on this work item.
	ErrExecutionNotFound = errors.New("execution not found")
	// ErrSnapshotNotFound: no such snapshot on this work item.
	ErrSnapshotNotFound = errors.New("context snapshot not found")
)

const snapshotSchema = `
CREATE TABLE IF NOT EXISTS work_item_context_snapshots (
    id                 TEXT PRIMARY KEY,
    work_item_id       TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    execution_id       TEXT NOT NULL UNIQUE REFERENCES work_item_executions (id) ON DELETE CASCADE,
    execution_sequence INTEGER NOT NULL,
    content_hash       TEXT NOT NULL,
    canonical          BYTEA NOT NULL,
    strategy           TEXT NOT NULL,
    strategy_version   TEXT NOT NULL,
    prior_execution_id TEXT NOT NULL DEFAULT '',
    prior_snapshot_id  TEXT NOT NULL DEFAULT '',
    produced_by        TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    schema_version     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS work_item_context_snapshots_item
    ON work_item_context_snapshots (work_item_id, execution_sequence);
CREATE OR REPLACE FUNCTION work_item_context_snapshots_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'work_item_context_snapshots rows are immutable';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'work_item_context_snapshots_no_update') THEN
        CREATE TRIGGER work_item_context_snapshots_no_update
            BEFORE UPDATE ON work_item_context_snapshots
            FOR EACH ROW EXECUTE FUNCTION work_item_context_snapshots_immutable();
    END IF;
END;
$$;
`

const snapshotColumns = `id, work_item_id, execution_id, execution_sequence, content_hash, canonical,
	strategy, strategy_version, prior_execution_id, prior_snapshot_id, produced_by, created_at, schema_version`

// ContextSnapshot is one sealed, immutable snapshot. Canonical is served
// verbatim: its sha256 is ContentHash.
type ContextSnapshot struct {
	ID                string `json:"id"`
	WorkItemID        string `json:"work_item_id"`
	ExecutionID       string `json:"execution_id"`
	ExecutionSequence int    `json:"execution_sequence"`
	ContentHash       string `json:"content_hash"`
	// Canonical is served as base64 so its exact bytes (and so its hash)
	// survive any JSON re-encoding on the way.
	Canonical        []byte    `json:"canonical_b64"`
	Strategy         string    `json:"strategy"`
	StrategyVersion  string    `json:"strategy_version"`
	PriorExecutionID string    `json:"prior_execution_id,omitempty"`
	PriorSnapshotID  string    `json:"prior_snapshot_id,omitempty"`
	ProducedBy       string    `json:"produced_by"`
	CreatedAt        time.Time `json:"created_at"`
	SchemaVersion    string    `json:"schema_version"`
}

// SnapshotInput seals one execution's snapshot.
type SnapshotInput struct {
	Mutation
	WorkItemID  string
	ExecutionID string
	// ExecutionSequence is validation only: it must be the execution's
	// attempt. The identity is ExecutionID.
	ExecutionSequence int
	Canonical         []byte
	ContentHash       string
	Strategy          string
	StrategyVersion   string
	PriorExecutionID  string
	PriorSnapshotID   string
}

// HashCanonical is the content hash of canonical snapshot bytes.
func HashCanonical(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SnapshotIDFor derives a snapshot's id from its content hash.
func SnapshotIDFor(contentHash string) string {
	return SnapshotIDPrefix + strings.TrimPrefix(contentHash, "sha256:")[:32]
}

func (in SnapshotInput) validate() error {
	if err := checkIdentity("actor", in.Actor); err != nil {
		return err
	}
	if in.WorkItemID == "" || !strings.HasPrefix(in.ExecutionID, ExecutionIDPrefix) {
		return invalid("work item and execution ids are required")
	}
	if in.ExecutionSequence < 1 {
		return invalid("execution_sequence must be >= 1")
	}
	if len(in.Canonical) == 0 || len(in.Canonical) > MaxSnapshotBytes {
		return invalid("snapshot must be 1..%d bytes", MaxSnapshotBytes)
	}
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(in.Canonical))
	if err := dec.Decode(&obj); err != nil || dec.More() {
		return invalid("snapshot must be one JSON object")
	}
	if got := HashCanonical(in.Canonical); in.ContentHash != got {
		return invalid("content_hash %q is not the sha256 of the snapshot bytes (%s)", in.ContentHash, got)
	}
	if err := checkText("strategy", in.Strategy, MaxKeyBytes, true); err != nil {
		return err
	}
	if err := checkText("strategy_version", in.StrategyVersion, MaxKeyBytes, true); err != nil {
		return err
	}
	if in.PriorSnapshotID != "" && !strings.HasPrefix(in.PriorSnapshotID, SnapshotIDPrefix) {
		return invalid("prior_snapshot_id must be a %s id", SnapshotIDPrefix)
	}
	if in.PriorExecutionID != "" && !strings.HasPrefix(in.PriorExecutionID, ExecutionIDPrefix) {
		return invalid("prior_execution_id must be a %s id", ExecutionIDPrefix)
	}
	return nil
}

func scanSnapshot(row pgx.Row) (*ContextSnapshot, error) {
	var c ContextSnapshot
	var canonical []byte
	if err := row.Scan(&c.ID, &c.WorkItemID, &c.ExecutionID, &c.ExecutionSequence, &c.ContentHash, &canonical,
		&c.Strategy, &c.StrategyVersion, &c.PriorExecutionID, &c.PriorSnapshotID, &c.ProducedBy,
		&c.CreatedAt, &c.SchemaVersion); err != nil {
		return nil, err
	}
	// Verified on every read too: bytes that no longer hash to the stored
	// hash are never served as that snapshot.
	if got := HashCanonical(canonical); got != c.ContentHash {
		return nil, fmt.Errorf("workitems: snapshot %s: stored bytes hash to %s, not %s", c.ID, got, c.ContentHash)
	}
	c.Canonical = canonical
	c.CreatedAt = c.CreatedAt.UTC()
	return &c, nil
}

func getSnapshot(ctx context.Context, q querier, itemID, id string) (*ContextSnapshot, error) {
	c, err := scanSnapshot(q.QueryRow(ctx, `SELECT `+snapshotColumns+` FROM work_item_context_snapshots
		WHERE work_item_id=$1 AND id=$2`, itemID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: snapshot %s of %s: %w", id, itemID, ErrSnapshotNotFound)
	}
	return c, err
}

// SealSnapshot stores an execution's snapshot, or returns the one it
// already sealed with the same bytes (created=false). Different bytes for
// the same execution are ErrSnapshotDivergence.
func (s *Store) SealSnapshot(ctx context.Context, in SnapshotInput) (*ContextSnapshot, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *ContextSnapshot
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := getItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		exec, err := getExecution(ctx, tx, cur.ID, in.ExecutionID)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("workitems: execution %s of %s: %w", in.ExecutionID, cur.ID, ErrExecutionNotFound)
		}
		if err != nil {
			return err
		}
		if exec.Attempt != in.ExecutionSequence {
			return invalid("execution_sequence %d is not execution %s's attempt %d",
				in.ExecutionSequence, exec.ID, exec.Attempt)
		}
		existing, err := scanSnapshot(tx.QueryRow(ctx, `SELECT `+snapshotColumns+` FROM work_item_context_snapshots
			WHERE execution_id=$1`, exec.ID))
		switch {
		case err == nil:
			if existing.ContentHash != in.ContentHash {
				return &ConflictError{Err: fmt.Errorf("%w: execution %s sealed %s, not %s",
					ErrSnapshotDivergence, exec.ID, existing.ContentHash, in.ContentHash), Current: cur}
			}
			out = existing
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("workitems: find snapshot: %w", err)
		}
		if err := checkPrior(ctx, tx, cur, exec, in); err != nil {
			return err
		}
		now := s.now()
		out, err = scanSnapshot(tx.QueryRow(ctx, `INSERT INTO work_item_context_snapshots (`+snapshotColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+snapshotColumns,
			SnapshotIDFor(in.ContentHash), cur.ID, exec.ID, exec.Attempt, in.ContentHash, in.Canonical,
			in.Strategy, in.StrategyVersion, in.PriorExecutionID, in.PriorSnapshotID, in.Actor, now, SchemaVersion))
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// The same bytes already sealed for another execution: the
			// content-bound id cannot name two executions.
			return &ConflictError{Err: fmt.Errorf("%w: these bytes are already another execution's snapshot",
				ErrSnapshotDivergence), Current: cur}
		}
		if err != nil {
			return fmt.Errorf("workitems: insert snapshot: %w", err)
		}
		detail := map[string]string{"snapshot_id": out.ID, "execution_id": exec.ID, "content_hash": out.ContentHash}
		if err := appendEvent(ctx, tx, cur.ID, EventSnapshotSealed, "", "", in.Mutation, detail, now); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// checkPrior fails explicitly on a missing or stale continuity reference:
// it must exist on this work item and precede this execution.
func checkPrior(ctx context.Context, tx pgx.Tx, cur *WorkItem, exec *Execution, in SnapshotInput) error {
	priorExec := in.PriorExecutionID
	if in.PriorSnapshotID != "" {
		prior, err := getSnapshot(ctx, tx, cur.ID, in.PriorSnapshotID)
		if errors.Is(err, ErrSnapshotNotFound) {
			return &ConflictError{Err: fmt.Errorf("%w: no snapshot %s on %s", ErrPriorSnapshot, in.PriorSnapshotID, cur.ID), Current: cur}
		}
		if err != nil {
			return err
		}
		if priorExec != "" && priorExec != prior.ExecutionID {
			return &ConflictError{Err: fmt.Errorf("%w: snapshot %s belongs to %s, not %s",
				ErrPriorSnapshot, prior.ID, prior.ExecutionID, priorExec), Current: cur}
		}
		priorExec = prior.ExecutionID
	}
	if priorExec == "" {
		return nil
	}
	pe, err := getExecution(ctx, tx, cur.ID, priorExec)
	if errors.Is(err, ErrNotFound) {
		return &ConflictError{Err: fmt.Errorf("%w: no execution %s on %s", ErrPriorSnapshot, priorExec, cur.ID), Current: cur}
	}
	if err != nil {
		return err
	}
	if pe.Attempt >= exec.Attempt {
		return &ConflictError{Err: fmt.Errorf("%w: execution %s (attempt %d) does not precede %s (attempt %d)",
			ErrPriorSnapshot, pe.ID, pe.Attempt, exec.ID, exec.Attempt), Current: cur}
	}
	return nil
}

// Snapshot returns one snapshot of a work item, verified against its hash.
func (s *Store) Snapshot(ctx context.Context, itemID, id string) (*ContextSnapshot, error) {
	return getSnapshot(ctx, s.pool, itemID, id)
}

// ExecutionSnapshot returns the snapshot an execution sealed.
func (s *Store) ExecutionSnapshot(ctx context.Context, itemID, executionID string) (*ContextSnapshot, error) {
	c, err := scanSnapshot(s.pool.QueryRow(ctx, `SELECT `+snapshotColumns+` FROM work_item_context_snapshots
		WHERE work_item_id=$1 AND execution_id=$2`, itemID, executionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: snapshot of execution %s: %w", executionID, ErrSnapshotNotFound)
	}
	return c, err
}

// SnapshotRef points at a sealed snapshot without carrying its bytes.
type SnapshotRef struct {
	ID          string `json:"id"`
	ExecutionID string `json:"execution_id"`
	ContentHash string `json:"content_hash"`
}

// LatestSnapshot points at the snapshot of the latest execution that sealed
// one, or nil when none has.
func (s *Store) LatestSnapshot(ctx context.Context, itemID string) (*SnapshotRef, error) {
	var ref SnapshotRef
	err := s.pool.QueryRow(ctx, `SELECT id, execution_id, content_hash FROM work_item_context_snapshots
		WHERE work_item_id=$1 ORDER BY execution_sequence DESC LIMIT 1`, itemID).Scan(&ref.ID, &ref.ExecutionID, &ref.ContentHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: latest snapshot: %w", err)
	}
	return &ref, nil
}

// Snapshots lists a work item's snapshots, oldest execution first.
func (s *Store) Snapshots(ctx context.Context, itemID string) ([]ContextSnapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+snapshotColumns+` FROM work_item_context_snapshots
		WHERE work_item_id=$1 ORDER BY execution_sequence`, itemID)
	if err != nil {
		return nil, fmt.Errorf("workitems: list snapshots: %w", err)
	}
	defer rows.Close()
	out := []ContextSnapshot{}
	for rows.Next() {
		c, err := scanSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: list snapshots: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}
