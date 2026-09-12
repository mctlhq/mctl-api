// Copyright 2025 MCTL Authors
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

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lifecycleSchema follows the repo convention: CREATE ... IF NOT EXISTS
// executed at startup rather than a migration file (see internal/alerts and
// internal/agentregistry).
//
// The UNIQUE constraint on (entity_kind, entity_id, phase) is the whole
// invariant "at most one owner per entity phase", enforced by the database
// rather than by the code that writes to it. ADR-009 sketched a PARTIAL unique
// index over the active states; one row per key that transitions in place is
// strictly stronger, keeps the handoff lineage on the row it describes, and
// makes a read unambiguous without an ORDER BY. Recorded here rather than left
// as a silent divergence from the ADR.
const lifecycleSchema = `
CREATE TABLE IF NOT EXISTS lifecycle_ownership (
    id                   BIGSERIAL PRIMARY KEY,
    entity_kind          TEXT NOT NULL,
    entity_id            TEXT NOT NULL,
    phase                TEXT NOT NULL,
    entity_version       TEXT NOT NULL DEFAULT '',
    owner_type           TEXT NOT NULL,
    owner_id             TEXT NOT NULL,
    epoch                INTEGER NOT NULL DEFAULT 1,
    state                TEXT NOT NULL,
    acquired_at          TIMESTAMPTZ NOT NULL,
    last_progress_at     TIMESTAMPTZ NOT NULL,
    progress_evidence    TEXT NOT NULL DEFAULT '',
    proposal_ref         TEXT NOT NULL DEFAULT '',
    policy_ref           TEXT NOT NULL DEFAULT '',
    handoff_to_type      TEXT NOT NULL DEFAULT '',
    handoff_to_id        TEXT NOT NULL DEFAULT '',
    handoff_from_type    TEXT NOT NULL DEFAULT '',
    handoff_from_id      TEXT NOT NULL DEFAULT '',
    handoff_started_at   TIMESTAMPTZ,
    released_at          TIMESTAMPTZ,
    released_reason      TEXT NOT NULL DEFAULT '',
    temporal_workflow_id TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS lifecycle_ownership_entity_phase
  ON lifecycle_ownership (entity_kind, entity_id, phase);
CREATE INDEX IF NOT EXISTS lifecycle_ownership_state
  ON lifecycle_ownership (state);
CREATE INDEX IF NOT EXISTS lifecycle_ownership_progress
  ON lifecycle_ownership (last_progress_at);

CREATE TABLE IF NOT EXISTS lifecycle_events (
    id             BIGSERIAL PRIMARY KEY,
    entity_kind    TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    phase          TEXT NOT NULL,
    event          TEXT NOT NULL,
    owner_epoch    INTEGER NOT NULL DEFAULT 0,
    entity_version TEXT NOT NULL DEFAULT '',
    actor_type     TEXT NOT NULL DEFAULT '',
    actor_id       TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS lifecycle_events_entity
  ON lifecycle_events (entity_kind, entity_id, phase, id DESC);
`

const ownershipColumns = `entity_kind, entity_id, phase, entity_version,
	owner_type, owner_id, epoch, state, acquired_at, last_progress_at,
	progress_evidence, proposal_ref, policy_ref,
	handoff_to_type, handoff_to_id, handoff_from_type, handoff_from_id,
	handoff_started_at, released_at, released_reason, temporal_workflow_id,
	created_at, updated_at`

// acquireUpsertSQL is the statement that makes exclusivity a property of the
// database. It is a package-level constant, not an inline literal, so the test
// that proves the guard executes THIS statement rather than a copy of it —
// delete the WHERE clause and the test fails, which is the only reason the
// test is worth having.
const acquireUpsertSQL = `INSERT INTO lifecycle_ownership (` + ownershipColumns + `)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'','','','',NULL,NULL,'',$14,$15,$16)
			 ON CONFLICT (entity_kind, entity_id, phase) DO UPDATE SET
			   entity_version = EXCLUDED.entity_version,
			   owner_type = EXCLUDED.owner_type,
			   owner_id = EXCLUDED.owner_id,
			   epoch = EXCLUDED.epoch,
			   state = EXCLUDED.state,
			   acquired_at = EXCLUDED.acquired_at,
			   last_progress_at = EXCLUDED.last_progress_at,
			   progress_evidence = EXCLUDED.progress_evidence,
			   proposal_ref = EXCLUDED.proposal_ref,
			   policy_ref = EXCLUDED.policy_ref,
			   handoff_to_type = '', handoff_to_id = '',
			   handoff_from_type = '', handoff_from_id = '',
			   handoff_started_at = NULL,
			   released_at = NULL, released_reason = '',
			   temporal_workflow_id = EXCLUDED.temporal_workflow_id,
			   updated_at = EXCLUDED.updated_at
			 WHERE lifecycle_ownership.state IN ('released', 'terminal')
			 RETURNING ` + ownershipColumns

// Store is a PostgreSQL-backed lifecycle ownership store.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore connects and auto-creates the schema.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("lifecycle store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, lifecycleSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("lifecycle store: create schema: %w", err)
	}
	slog.Info("lifecycle ownership store initialized")
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// AcquireRequest is one actor asking to own (Entity, Phase).
type AcquireRequest struct {
	Entity             EntityRef
	Phase              string
	Owner              Owner
	ProposalRef        string
	PolicyRef          string
	TemporalWorkflowID string
}

// Acquire takes durable ownership of (entity, phase).
//
// Three outcomes, and the distinction between them is the point of this
// package:
//
//   - no record, or the last one is released/terminal — the caller becomes
//     owner. A fresh record starts at epoch 1; taking over a
//     released/terminal one increments the epoch, so an executor still
//     holding the previous epoch is fenced out.
//   - a record is active/handing-off and names THIS caller — idempotent. The
//     existing row is returned unchanged and the epoch does NOT move, so a
//     Temporal activity retry or an Argo pod restart re-acquiring is a no-op
//     rather than a self-inflicted fence.
//   - a record is active/handing-off and names SOMEBODY ELSE —
//     ErrOwnedByOther, with that owner returned so the loser learns who won.
//
// What actually guarantees exclusivity is the CONDITIONAL upsert below:
// ON CONFLICT ... DO UPDATE ... WHERE the existing row is released/terminal.
// An acquire that interleaves with a competing one matches no row, returns no
// row, and is reported as a loss. Correctness therefore belongs to the
// database, and survives this function being called from anywhere.
//
// pg_advisory_xact_lock on the entity/phase key (following
// agentregistry.promote) is serialization, not the guarantee: it keeps the
// common path to a single uncontended round trip and stops two callers
// burning work they will have to discard. Removing it would be a performance
// regression, not a correctness one — which is why the test that proves
// exclusivity exercises the upsert's SQL directly rather than hoping a
// goroutine storm lands inside the window.
func (s *Store) Acquire(ctx context.Context, req AcquireRequest) (*Ownership, error) {
	if !LegalPhase(req.Entity.Kind, req.Phase) {
		return nil, fmt.Errorf("%w: %s/%s", ErrUnknownPhase, req.Entity.Kind, req.Phase)
	}
	if req.Owner.Type == "" || req.Owner.ID == "" {
		return nil, fmt.Errorf("lifecycle: acquire: owner type and id are required")
	}

	var out *Ownership
	err := s.inTx(ctx, req.Entity, req.Phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		existing, err := scanOne(tx.QueryRow(ctx,
			`SELECT `+ownershipColumns+` FROM lifecycle_ownership
			 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
			req.Entity.Kind, req.Entity.ID, req.Phase))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}

		if existing != nil && (existing.State == StateActive || existing.State == StateHandingOff) {
			if existing.Owner == req.Owner {
				// Idempotent re-acquire. Refresh only the observed entity
				// version; epoch and progress are deliberately untouched —
				// re-acquiring is not progress.
				if req.Entity.Version != "" && req.Entity.Version != existing.Entity.Version {
					if _, err := tx.Exec(ctx,
						`UPDATE lifecycle_ownership SET entity_version = $1, updated_at = $2
						 WHERE entity_kind = $3 AND entity_id = $4 AND phase = $5`,
						req.Entity.Version, now, req.Entity.Kind, req.Entity.ID, req.Phase); err != nil {
						return fmt.Errorf("lifecycle: acquire: refresh version: %w", err)
					}
					existing.Entity.Version = req.Entity.Version
					existing.UpdatedAt = now
				}
				out = existing
				return nil
			}
			if err := insertEvent(ctx, tx, req.Entity, req.Phase, EventOwnerDenied,
				existing.Epoch, req.Owner, "already owned by "+existing.Owner.Type+"/"+existing.Owner.ID, now); err != nil {
				return err
			}
			out = existing
			return ErrOwnedByOther
		}

		epoch := 1
		if existing != nil {
			epoch = existing.Epoch + 1
		}

		row := tx.QueryRow(ctx, acquireUpsertSQL,
			req.Entity.Kind, req.Entity.ID, req.Phase, req.Entity.Version,
			req.Owner.Type, req.Owner.ID, epoch, StateActive, now, now,
			"acquired", req.ProposalRef, req.PolicyRef,
			req.TemporalWorkflowID, now, now)
		acquired, err := scanOne(row)
		if errors.Is(err, ErrNotFound) {
			// The upsert's WHERE matched nothing, so somebody committed an
			// active record between our read and our write. This is the path
			// that makes correctness a property of the DATABASE rather than of
			// the advisory lock above: even with the lock removed, an
			// interleaved acquire loses here instead of overwriting the winner.
			current, rerr := scanOne(tx.QueryRow(ctx,
				`SELECT `+ownershipColumns+` FROM lifecycle_ownership
				 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
				req.Entity.Kind, req.Entity.ID, req.Phase))
			if rerr != nil {
				return fmt.Errorf("lifecycle: acquire: re-read after conflict: %w", rerr)
			}
			if current.Owner == req.Owner {
				out = current
				return nil
			}
			if eerr := insertEvent(ctx, tx, req.Entity, req.Phase, EventOwnerDenied,
				current.Epoch, req.Owner, "lost acquire race to "+current.Owner.Type+"/"+current.Owner.ID, now); eerr != nil {
				return eerr
			}
			out = current
			return ErrOwnedByOther
		}
		if err != nil {
			return fmt.Errorf("lifecycle: acquire: %w", err)
		}
		if err := insertEvent(ctx, tx, req.Entity, req.Phase, EventOwnerAcquired,
			acquired.Epoch, req.Owner, req.PolicyRef, now); err != nil {
			return err
		}
		out = acquired
		return nil
	})
	if err != nil && !errors.Is(err, ErrOwnedByOther) {
		return nil, err
	}
	return out, err
}

// RecordProgress advances last_progress_at, and only the current owner at the
// current epoch may call it.
//
// evidence says WHAT was effected. Progress means a state change actually
// happened: a tick that polled and found nothing must not call this, because a
// heartbeat that refreshed the timer would let an owner prove liveness forever
// while achieving nothing.
func (s *Store) RecordProgress(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, evidence string) (*Ownership, error) {
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := s.currentFor(ctx, tx, entity, phase, owner, epoch)
		if err != nil {
			return err
		}
		version := current.Entity.Version
		if entity.Version != "" {
			version = entity.Version
		}
		updated, err := scanOne(tx.QueryRow(ctx,
			`UPDATE lifecycle_ownership
			   SET last_progress_at = $1, progress_evidence = $2,
			       entity_version = $3, updated_at = $1
			 WHERE entity_kind = $4 AND entity_id = $5 AND phase = $6 AND epoch = $7
			 RETURNING `+ownershipColumns,
			now, evidence, version, entity.Kind, entity.ID, phase, epoch))
		if err != nil {
			return fmt.Errorf("lifecycle: progress: %w", err)
		}
		if err := insertEvent(ctx, tx, entity, phase, EventProgress, epoch, owner, evidence, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	return out, err
}

// HandoffStart marks an explicit, durable intent to pass ownership on.
//
// The record stays owned while handing off — it does NOT become free. That is
// what makes the direct-implementer path (mctlhq/mctl-agents#239) a
// deterministic state a reconciler can adopt rather than a silent zero-owner
// gap: something always owns the row, and an incomplete handoff is visible as
// itself instead of as absence.
func (s *Store) HandoffStart(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, to Owner, reason string) (*Ownership, error) {
	if to.Type == "" || to.ID == "" {
		return nil, fmt.Errorf("lifecycle: handoff: target owner type and id are required")
	}
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		if _, err := s.currentFor(ctx, tx, entity, phase, owner, epoch); err != nil {
			return err
		}
		updated, err := scanOne(tx.QueryRow(ctx,
			`UPDATE lifecycle_ownership
			   SET state = $1, handoff_to_type = $2, handoff_to_id = $3,
			       handoff_started_at = $4, updated_at = $4
			 WHERE entity_kind = $5 AND entity_id = $6 AND phase = $7 AND epoch = $8
			 RETURNING `+ownershipColumns,
			StateHandingOff, to.Type, to.ID, now, entity.Kind, entity.ID, phase, epoch))
		if err != nil {
			return fmt.Errorf("lifecycle: handoff start: %w", err)
		}
		if err := insertEvent(ctx, tx, entity, phase, EventHandoffStarted, epoch, owner,
			"to "+to.Type+"/"+to.ID+": "+reason, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	return out, err
}

// HandoffComplete is called by the INCOMING owner. It bumps the epoch, which
// is what fences the outgoing owner's executors: anything still holding the
// previous epoch is rejected without consulting a clock.
//
// Only the actor the handoff names may complete it; a third party arriving
// mid-handoff gets ErrNotOwner rather than quietly stealing the row.
func (s *Store) HandoffComplete(ctx context.Context, entity EntityRef, phase string, incoming Owner) (*Ownership, error) {
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := scanOne(tx.QueryRow(ctx,
			`SELECT `+ownershipColumns+` FROM lifecycle_ownership
			 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
			entity.Kind, entity.ID, phase))
		if err != nil {
			return err
		}
		if current.State != StateHandingOff || current.HandoffTo == nil {
			return ErrNoHandoff
		}
		if *current.HandoffTo != incoming {
			return fmt.Errorf("%w: handoff names %s/%s", ErrNotOwner,
				current.HandoffTo.Type, current.HandoffTo.ID)
		}
		updated, err := scanOne(tx.QueryRow(ctx,
			`UPDATE lifecycle_ownership
			   SET owner_type = $1, owner_id = $2, epoch = epoch + 1, state = $3,
			       acquired_at = $4, last_progress_at = $4,
			       progress_evidence = 'handoff completed',
			       handoff_from_type = owner_type, handoff_from_id = owner_id,
			       handoff_to_type = '', handoff_to_id = '',
			       handoff_started_at = NULL, updated_at = $4
			 WHERE entity_kind = $5 AND entity_id = $6 AND phase = $7 AND epoch = $8
			 RETURNING `+ownershipColumns,
			incoming.Type, incoming.ID, StateActive, now,
			entity.Kind, entity.ID, phase, current.Epoch))
		if err != nil {
			return fmt.Errorf("lifecycle: handoff complete: %w", err)
		}
		if err := insertEvent(ctx, tx, entity, phase, EventHandoffCompleted,
			updated.Epoch, incoming, "from "+current.Owner.Type+"/"+current.Owner.ID, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	return out, err
}

// Release gives up ownership without the entity being finished — the work
// remains, and a reconciler or another actor may take it.
func (s *Store) Release(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, reason string) (*Ownership, error) {
	return s.finish(ctx, entity, phase, owner, epoch, StateReleased, EventOwnerReleased, reason)
}

// Terminal records that this phase is finished — the PR merged or closed, the
// proposal reached merged/rejected/review-stuck. Nothing should pick it up.
func (s *Store) Terminal(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, reason string) (*Ownership, error) {
	return s.finish(ctx, entity, phase, owner, epoch, StateTerminal, EventOwnerTerminal, reason)
}

func (s *Store) finish(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, state, event, reason string) (*Ownership, error) {
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		if _, err := s.currentFor(ctx, tx, entity, phase, owner, epoch); err != nil {
			return err
		}
		updated, err := scanOne(tx.QueryRow(ctx,
			`UPDATE lifecycle_ownership
			   SET state = $1, released_at = $2, released_reason = $3,
			       handoff_to_type = '', handoff_to_id = '', handoff_started_at = NULL,
			       updated_at = $2
			 WHERE entity_kind = $4 AND entity_id = $5 AND phase = $6 AND epoch = $7
			 RETURNING `+ownershipColumns,
			state, now, reason, entity.Kind, entity.ID, phase, epoch))
		if err != nil {
			return fmt.Errorf("lifecycle: %s: %w", state, err)
		}
		if err := insertEvent(ctx, tx, entity, phase, event, epoch, owner, reason, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	return out, err
}

// Get returns the ownership record for one (entity, phase).
func (s *Store) Get(ctx context.Context, entity EntityRef, phase string) (*Ownership, error) {
	return scanOne(s.pool.QueryRow(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
		entity.Kind, entity.ID, phase))
}

// GetMany returns ownership for several entity ids of one kind and phase.
//
// This is the shape the shepherd sweep needs: it asks about every candidate in
// one round trip. The per-proposal fan-out it replaces needed a thread pool and
// a wall-clock budget, and anything the budget did not answer in time was swept
// anyway — a single batched read needs neither.
func (s *Store) GetMany(ctx context.Context, kind, phase string, ids []string) (map[string]*Ownership, error) {
	out := make(map[string]*Ownership, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE entity_kind = $1 AND phase = $2 AND entity_id = ANY($3)`,
		kind, phase, ids)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: get many: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		o, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("lifecycle: get many: scan: %w", err)
		}
		out[o.Entity.ID] = o
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lifecycle: get many: %w", err)
	}
	return out, nil
}

// ListFilter selects records for the inspection surface.
type ListFilter struct {
	Kind  string
	Phase string
	State string
	Owner string
	Limit int
}

// List returns ownership records matching filter, newest update first.
func (s *Store) List(ctx context.Context, f ListFilter) ([]*Ownership, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE ($1 = '' OR entity_kind = $1)
		   AND ($2 = '' OR phase = $2)
		   AND ($3 = '' OR state = $3)
		   AND ($4 = '' OR owner_type = $4)
		 ORDER BY updated_at DESC
		 LIMIT $5`,
		f.Kind, f.Phase, f.State, f.Owner, limit)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: list: %w", err)
	}
	defer rows.Close()
	var out []*Ownership
	for rows.Next() {
		o, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("lifecycle: list: scan: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Events returns the transition history for one (entity, phase), newest first.
func (s *Store) Events(ctx context.Context, entity EntityRef, phase string, limit int) ([]*Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, entity_kind, entity_id, phase, event, owner_epoch, entity_version,
		        actor_type, actor_id, reason, created_at
		   FROM lifecycle_events
		  WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3
		  ORDER BY id DESC LIMIT $4`,
		entity.Kind, entity.ID, phase, limit)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: events: %w", err)
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		e := &Event{}
		if err := rows.Scan(&e.ID, &e.Entity.Kind, &e.Entity.ID, &e.Phase, &e.Event,
			&e.OwnerEpoch, &e.Entity.Version, &e.Actor.Type, &e.Actor.ID,
			&e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("lifecycle: events: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- internals ---------------------------------------------------------

// inTx runs fn inside a transaction holding the advisory lock for this
// entity/phase, so a read-then-write cannot interleave with a competing one.
//
// The lock key is hashed from the entity/phase triple rather than taken per
// table, so two different pull requests never serialize against each other.
func (s *Store) inTx(ctx context.Context, entity EntityRef, phase string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit succeeded

	// U+001F unit separator, not NUL: Postgres rejects 0x00 in a text value
	// outright ("invalid byte sequence for encoding UTF8"), so a NUL-joined
	// key fails every lock acquisition rather than colliding subtly. 0x1F is
	// valid UTF-8 and cannot occur in a kind, a phase or a GitHub identifier.
	key := entity.Kind + "\x1f" + entity.ID + "\x1f" + phase
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
		return fmt.Errorf("lifecycle: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("lifecycle: commit: %w", err)
	}
	return nil
}

// currentFor loads the record and checks the caller is entitled to drive it.
//
// The owner check and the epoch check are separate errors on purpose: "somebody
// else owns this" and "you owned this but ownership has since moved" are
// different situations for the caller, and collapsing them into one status
// would hide a handoff behind what looks like a permissions problem.
func (s *Store) currentFor(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string, owner Owner, epoch int) (*Ownership, error) {
	current, err := scanOne(tx.QueryRow(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
		entity.Kind, entity.ID, phase))
	if err != nil {
		return nil, err
	}
	if current.Owner != owner {
		return nil, fmt.Errorf("%w: current owner is %s/%s", ErrNotOwner,
			current.Owner.Type, current.Owner.ID)
	}
	if current.Epoch != epoch {
		return nil, fmt.Errorf("%w: current epoch is %d, caller has %d",
			ErrEpochMismatch, current.Epoch, epoch)
	}
	return current, nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, entity EntityRef, phase, event string, epoch int, actor Owner, reason string, now time.Time) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO lifecycle_events
		   (entity_kind, entity_id, phase, event, owner_epoch, entity_version,
		    actor_type, actor_id, reason, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		entity.Kind, entity.ID, phase, event, epoch, entity.Version,
		actor.Type, actor.ID, reason, now); err != nil {
		return fmt.Errorf("lifecycle: record event %s: %w", event, err)
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanOne(row scannable) (*Ownership, error) {
	o, err := scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return o, err
}

func scanRow(row scannable) (*Ownership, error) {
	o := &Ownership{}
	var handoffToType, handoffToID, handoffFromType, handoffFromID string
	if err := row.Scan(
		&o.Entity.Kind, &o.Entity.ID, &o.Phase, &o.Entity.Version,
		&o.Owner.Type, &o.Owner.ID, &o.Epoch, &o.State,
		&o.AcquiredAt, &o.LastProgressAt, &o.ProgressEvidence,
		&o.ProposalRef, &o.PolicyRef,
		&handoffToType, &handoffToID, &handoffFromType, &handoffFromID,
		&o.HandoffStartedAt, &o.ReleasedAt, &o.ReleasedReason,
		&o.TemporalWorkflowID, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if handoffToType != "" || handoffToID != "" {
		o.HandoffTo = &Owner{Type: handoffToType, ID: handoffToID}
	}
	if handoffFromType != "" || handoffFromID != "" {
		o.HandoffFrom = &Owner{Type: handoffFromType, ID: handoffFromID}
	}
	return o, nil
}
