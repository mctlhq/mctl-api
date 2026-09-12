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
// rather than by the code that writes to it. ADR-010 sketched a PARTIAL unique
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
    last_seen_at         TIMESTAMPTZ NOT NULL,
    last_progress_at     TIMESTAMPTZ NOT NULL,
    progress_evidence    TEXT NOT NULL DEFAULT '',
    proposal_ref         TEXT NOT NULL DEFAULT '',
    policy_ref           TEXT NOT NULL DEFAULT '',
    handoff_to_type      TEXT NOT NULL DEFAULT '',
    handoff_to_id        TEXT NOT NULL DEFAULT '',
    handoff_from_type    TEXT NOT NULL DEFAULT '',
    handoff_from_id      TEXT NOT NULL DEFAULT '',
    handoff_started_at   TIMESTAMPTZ,
    -- released_at/released_reason record when and why this ownership ENDED,
    -- for BOTH released and terminal. state is the discriminator between them:
    -- released means the work remains and somebody else may take it, terminal
    -- means the phase is finished. Reading released_at alone cannot tell them
    -- apart, and nothing should try.
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
CREATE INDEX IF NOT EXISTS lifecycle_ownership_seen
  ON lifecycle_ownership (last_seen_at);

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
	owner_type, owner_id, epoch, state, acquired_at, last_seen_at, last_progress_at,
	progress_evidence, proposal_ref, policy_ref,
	handoff_to_type, handoff_to_id, handoff_from_type, handoff_from_id,
	handoff_started_at, released_at, released_reason, temporal_workflow_id,
	created_at, updated_at`

// reacquireRefreshSQL is the idempotent re-acquire's write.
//
// A package-level constant for the same reason acquireUpsertSQL and
// recoverUpdateSQL are: its epoch/owner predicate cannot be exercised through
// Acquire, because inTx holds the advisory lock across the read and the write
// so nothing can interleave in-process, and the branch is only reached when the
// row already names the caller. Testing the statement directly is the only way
// to show the predicate is load-bearing rather than decorative — and this was
// the one write in the package that had no such predicate at all.
// The two carried-forward columns fall back IN THE STATEMENT, the way the
// epoch already does with `epoch = lifecycle_ownership.epoch + 1`. Reading
// them in Go and writing the value back promoted a READ into a WRITE, and
// nothing pinned either column — so the other statement of this pair got
// underneath: progressUpdateSQL writes entity_version while moving none of
// epoch, owner or state.
//
//  1. wf-1 owns at epoch 4, active, entity_version = sha-a. It ticks, calls
//     Acquire with no version, reads sha-a, and stalls.
//  2. wf-1's other step records progress carrying sha-b. The row takes sha-b
//     and a progress event naming sha-b is appended.
//  3. The stalled refresh matches epoch, owner and state, and writes sha-a
//     back.
//
// The row then says sha-a while its own latest event says sha-b — exactly the
// disagreement TestEventsCarryTheStoredVersion exists to prevent, produced by
// the write that argument was made to protect. And it runs BACKWARDS, so it
// does not heal: the next progress that omits a version reads sha-a and writes
// it again. Two overlapping re-acquires do the same to temporal_workflow_id,
// where the one carrying no id clears a correlation the other just recorded —
// on the path whose whole purpose is the pod restart, which is when that id
// changes.
//
// COALESCE/NULLIF makes the carry-forward the DATABASE's, so the stored value
// is never read into the caller and can never be written back stale. That is
// strictly better than pinning the columns: a predicate would refuse the write
// outright, where this simply leaves the newer value alone.
const reacquireRefreshSQL = `UPDATE lifecycle_ownership
					   SET last_seen_at = $1,
					       entity_version = COALESCE(NULLIF($2, ''), lifecycle_ownership.entity_version),
					       temporal_workflow_id = COALESCE(NULLIF($3, ''), lifecycle_ownership.temporal_workflow_id),
					       updated_at = $4
					 WHERE entity_kind = $5 AND entity_id = $6 AND phase = $7
					   AND epoch = $8 AND owner_type = $9 AND owner_id = $10
					   AND state = $11
					 RETURNING ` + ownershipColumns

// acquireUpsertSQL is the statement that makes exclusivity a property of the
// database. It is a package-level constant, not an inline literal, so the test
// that proves the guard executes THIS statement rather than a copy of it —
// delete the WHERE clause and the test fails, which is the only reason the
// test is worth having.
const acquireUpsertSQL = `INSERT INTO lifecycle_ownership (` + ownershipColumns + `)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'','','','',NULL,NULL,'',$15,$16,$17)
			 ON CONFLICT (entity_kind, entity_id, phase) DO UPDATE SET
			   entity_version = EXCLUDED.entity_version,
			   owner_type = EXCLUDED.owner_type,
			   owner_id = EXCLUDED.owner_id,
			   -- The DATABASE computes the next epoch, not the caller.
			   -- EXCLUDED.epoch would be a value derived from a read that may
			   -- already be stale: a caller stalled across
			   -- released@3 -> active@4 -> released@4 still matches the WHERE
			   -- above and would re-write epoch 4, un-fencing the previous
			   -- owner's executors. Serializing writers hides that, which is
			   -- exactly why it must not be left to them — the comment on
			   -- Acquire claims correctness survives the lock being removed,
			   -- and this is what makes that claim true rather than lucky.
			   epoch = lifecycle_ownership.epoch + 1,
			   state = EXCLUDED.state,
			   acquired_at = EXCLUDED.acquired_at,
			   last_seen_at = EXCLUDED.last_seen_at,
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

// validate rejects an unknown (kind, phase) pair and an empty id at EVERY
// entry point, not only at Acquire.
//
// Rows can in practice only be created through Acquire, so a typo elsewhere
// would have surfaced as ErrNotFound — which tells the caller "nobody owns
// this", the single most dangerous wrong answer this package can give, when
// the truth is "you asked about something that cannot exist".
func validate(entity EntityRef, phase string) error {
	if entity.ID == "" {
		return fmt.Errorf("%w: entity id is required", ErrUnknownPhase)
	}
	if !LegalPhase(entity.Kind, phase) {
		return fmt.Errorf("%w: %s/%s", ErrUnknownPhase, entity.Kind, phase)
	}
	return nil
}

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
// Four outcomes, and the distinction between them is the point of this
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
//     That holds at ANY age: a dead owner's row is not acquirable, it is
//     RECOVERABLE, and Recover is the only operation that takes ownership
//     from a live record. The actor a handoff NAMES gets the same refusal and
//     should call HandoffComplete, which is the path written for it.
//   - the re-acquire's own write matched nothing because the record changed
//     between the read and the write — ErrStaleRead, from
//     reacquireMissSentinel. It is the one outcome here whose correct response
//     is an immediate RETRY rather than standing down: the caller has not lost
//     the entity, it lost a read.
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
	// An empty id would otherwise make every forgetful caller contend over one
	// shared row keyed on (kind, "", phase) — an ownership record for nothing
	// in particular, indistinguishable from a real one.
	if err := validate(req.Entity, req.Phase); err != nil {
		return nil, err
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
				// Idempotent re-acquire. It IS a tick, so it refreshes
				// last_seen_at — the owner has demonstrably not died. It is
				// NOT progress and does not touch last_progress_at, and it
				// does not move the epoch: a Temporal activity retry or an
				// Argo pod restart must not fence its own in-flight work.
				//
				// Except while HANDING OFF. An owner in that state has said it
				// is leaving; if the incoming owner never completes, the only
				// thing that can notice is the handoff going stale, and an
				// outgoing owner that keeps polling would refresh last_seen_at
				// forever and hide it. So liveness is frozen at the moment the
				// handoff started, and HandoffStartedAt is what the reconciler
				// reads (mctlhq/mctl-agents#353).
				seen := now
				if existing.State == StateHandingOff {
					seen = existing.LastSeenAt
				}
				// entity_version and temporal_workflow_id are passed
				// through AS GIVEN — empty means "leave what is stored", and
				// the statement itself does that with COALESCE/NULLIF. The Go
				// fallback that used to sit here read the stored value and
				// wrote it back, which is how a stalled refresh could revert a
				// newer version recorded by progressUpdateSQL; see the header
				// above reacquireRefreshSQL. temporal_workflow_id IS refreshed
				// when one is supplied: this path exists for the pod restart
				// and workflow retry, which is precisely when it changes.
				// Pinned to the row this branch decided about — the only
				// write in the package that was not.
				//
				// OWNER and EPOCH, because HandoffComplete moves both without
				// touching the key, so it gets underneath: wf-1 reads its own
				// handing-off row at epoch 4 with last_seen_at frozen at T0,
				// stalls, the steward completes the handoff, and wf-1's UPDATE
				// then lands on the STEWARD's row writing wf-1's correlation
				// and, because the freeze makes `seen` a past timestamp,
				// actively AGEING a live owner until it satisfies IsDead.
				//
				// STATE, for the same reason progressUpdateSQL pins it: `seen`
				// a dozen lines above is DERIVED from the state this branch
				// read, so a different state would have produced a different
				// value. A HandoffStart landing between the read and the write
				// otherwise lets seen = now unfreeze a handing-off row — the
				// identical sequence progressUpdateSQL cites. And a Terminal at
				// the same epoch and owner moves neither of the other two, so
				// without this a stray re-acquire writes to a record currentFor
				// refuses every other write to.
				refreshed, err := scanOne(tx.QueryRow(ctx,
					reacquireRefreshSQL,

					seen, req.Entity.Version, req.TemporalWorkflowID, now,
					req.Entity.Kind, req.Entity.ID, req.Phase,
					existing.Epoch, existing.Owner.Type, existing.Owner.ID,
					existing.State))
				if errors.Is(err, ErrNotFound) {
					// Re-read, so the caller is told who holds it now rather
					// than that the row vanished — and so the SENTINEL matches
					// what actually happened.
					//
					// ErrOwnedByOther was exhaustive here until state joined
					// the WHERE: only the owner or the epoch could make this
					// statement miss, and both mean somebody else has it. The
					// state predicate adds two writers that miss it WITHOUT
					// moving either — HandoffStart (active -> handing-off) and
					// finish (-> released/terminal), both at the same owner and
					// epoch. A caller whose own Release commits between its
					// read and its write would otherwise be told "a DIFFERENT
					// healthy actor holds this... the caller must not mutate",
					// which is what types.go promises that sentinel means, and
					// handed back a row naming ITSELF — standing down on a free
					// record a plain retry of Acquire would take.
					//
					// ErrStaleRead says the one thing this caller needs to
					// hear: ownership has not moved, so retry — and a retry of
					// Acquire genuinely succeeds, because a released or
					// terminal row is takeable through acquireUpsertSQL and a
					// handing-off one is this same branch again with the state
					// it now has.
					//
					// NOT raceLostOn, deliberately, even though this is the
					// shape it was written for. Its absorbing-state case
					// answers ErrNotOwner, which is right for RecordProgress,
					// HandoffStart and finish — none of them may drive a
					// finished record — and wrong here, because Acquire is
					// exactly the operation that MAY take one.
					current, rerr := scanOne(tx.QueryRow(ctx,
						`SELECT `+ownershipColumns+` FROM lifecycle_ownership
						 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
						req.Entity.Kind, req.Entity.ID, req.Phase))
					if rerr != nil {
						return rerr
					}
					out = current
					return reacquireMissSentinel(existing, current)
				}
				if err != nil {
					return fmt.Errorf("lifecycle: acquire: refresh: %w", err)
				}
				out = refreshed
				return nil
			}
			if err := insertEvent(ctx, tx, existing.Entity, req.Phase, EventOwnerDenied,
				existing.Epoch, req.Owner, "already owned by "+existing.Owner.Type+"/"+existing.Owner.ID, now); err != nil {
				return err
			}
			out = existing
			return ErrOwnedByOther
		}

		// Only used by the INSERT branch. The DO UPDATE branch derives the
		// next epoch from the stored row, so a stale read cannot set it.
		const freshEpoch = 1

		row := tx.QueryRow(ctx, acquireUpsertSQL,
			req.Entity.Kind, req.Entity.ID, req.Phase, req.Entity.Version,
			req.Owner.Type, req.Owner.ID, freshEpoch, StateActive, now, now, now,
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
			if eerr := insertEvent(ctx, tx, current.Entity, req.Phase, EventOwnerDenied,
				current.Epoch, req.Owner, "lost acquire race to "+current.Owner.Type+"/"+current.Owner.ID, now); eerr != nil {
				return eerr
			}
			out = current
			return ErrOwnedByOther
		}
		if err != nil {
			return fmt.Errorf("lifecycle: acquire: %w", err)
		}
		if err := insertEvent(ctx, tx, acquired.Entity, req.Phase, EventOwnerAcquired,
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

// Why these three statements pin state in the WHERE, and what each pins.
//
// recoverUpdateSQL learned this first: an UPDATE guarded only by the epoch is
// not a compare-and-set over the decision the operation actually made. finish
// changes state while touching neither epoch nor last_seen_at, so it is
// invisible to every other writer's guard — which means a Terminal committing
// between a read and a write slipped past all three of the statements below.
//
// The predicate differs by what the statement DERIVED from the state it read:
//
//   - RecordProgress and HandoffStart each compute a value from current.State
//     (the liveness freeze, and the handoff clock). They pin the EXACT state
//     they read, because a different state would have produced a different
//     value. Pinning the class would let HandoffStart land between
//     RecordProgress's read and its write and reintroduce the freeze hole.
//   - finish derives nothing from state; it only needs currentFor's assertion
//     that the record is not yet absorbing to still hold at write time. It
//     pins the CLASS, so a legitimate concurrent HandoffStart does not make a
//     Release fail spuriously.
//
// Package-level constants rather than inline literals for the same reason
// recoverUpdateSQL is one: inTx holds the advisory lock across the read and
// the write, so nothing can interleave in-process and the predicate is
// unobservable through the API. Testing the statement directly is the only
// way to show it is load-bearing rather than decorative — and the comments at
// :233-235 and :240-243 claim correctness survives the lock being removed,
// which is a claim every write has to honour, not four of seven.

// entity_version falls back in the statement for the same reason it does in
// reacquireRefreshSQL, and against the same writer: the re-acquire refreshes
// entity_version while moving none of epoch or state, so a stalled progress
// write that read the stored version would put an older one back over it.
const progressUpdateSQL = `UPDATE lifecycle_ownership
			   SET last_progress_at = $1, last_seen_at = $2, progress_evidence = $3,
			       entity_version = COALESCE(NULLIF($4, ''), lifecycle_ownership.entity_version),
			       updated_at = $1
			 WHERE entity_kind = $5 AND entity_id = $6 AND phase = $7 AND epoch = $8
			   AND state = $9
			 RETURNING ` + ownershipColumns

// RecordProgress advances last_progress_at, and only the current owner at the
// current epoch may call it.
//
// evidence says WHAT was effected. Progress means a state change actually
// happened: a tick that polled and found nothing must not call this, because a
// heartbeat that refreshed the timer would let an owner prove liveness forever
// while achieving nothing.
func (s *Store) RecordProgress(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, evidence string) (*Ownership, error) {
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := s.currentFor(ctx, tx, entity, phase, owner, epoch)
		if err != nil {
			return err
		}
		// Same freeze as the idempotent re-acquire, and for the same reason.
		// currentFor admits handing-off, so without this the outgoing owner
		// defeats the freeze by recording PROGRESS instead of re-acquiring:
		// it keeps pushing commits, last_seen_at keeps moving, IsDead stays
		// false forever, and an abandoned handoff is never recoverable.
		//
		// Progress itself is still recorded — the work did happen. Only the
		// liveness clock stops, because an owner that has declared it is
		// leaving must not be able to keep the handoff open indefinitely.
		seen := now
		if current.State == StateHandingOff {
			seen = current.LastSeenAt
		}
		updated, err := scanOne(tx.QueryRow(ctx, progressUpdateSQL,
			now, seen, evidence, entity.Version,
			entity.Kind, entity.ID, phase, epoch, current.State))
		if errors.Is(err, ErrNotFound) {
			return raceLostOn(ctx, tx, entity, phase, epoch, current.State, "progress")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: progress: %w", err)
		}
		// updated.Entity, not the request entity: RecordProgress falls back to
		// the stored version when the caller omits one, and an event row that
		// disagreed with the row it describes would make the audit trail worse
		// than absent.
		if err := insertEvent(ctx, tx, updated.Entity, phase, EventProgress, epoch, owner, evidence, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	if err != nil {
		// A commit failure means the row may not exist as described, so the
		// caller must not be handed one. Acquire already draws this line for
		// its denial path; the rest of the write methods now match it.
		return nil, err
	}
	return out, nil
}

// handoffStartUpdateSQL pins BOTH inputs its SET values were derived from.
//
// The state clause was the first. The second took a round longer to find,
// because the rule "pin what the statement derived from the row it read" was
// written as though state were the only such input. It is not: the caller
// derives `started` from current.HandoffTo and current.HandoffStartedAt, and a
// RETARGET by the same owner moves both while leaving the epoch and the state
// alone — handing-off stays handing-off. So a retarget is the one writer that
// gets underneath a predicate of epoch + state:
//
//  1. wf-1 owns at epoch 4, handing off to shepherd/cron since T0.
//  2. wf-1 re-announces the same target: reads handoff_to = shepherd/cron,
//     computes started = T0, and stalls.
//  3. wf-1 redirects to pr-steward/steward. The row takes T1, the call
//     returns success, and a handoff-started event naming steward is written.
//  4. The stalled re-announcement still matches epoch 4 AND handing-off, and
//     writes shepherd/cron with T0 back over it.
//
// The retarget is acknowledged, evented, and then silently reverted: steward —
// the actor the API and the event trail both named — gets ErrNotOwner from
// HandoffComplete, and the surviving handoff is judged against the clock of
// the one it replaced, which is exactly what the re-announce guard exists to
// prevent. The reverting write also suppresses its own event, because
// `reannounced` is computed from the same stale read, so the row ends up
// naming shepherd/cron with the last event saying steward.
//
// handoff_started_at needs no clause of its own: it moves in lockstep with
// handoff_to under every writer here, which is the same lockstep
// TestHandoffCompleteCannotLandOnAFinishedOrRetargetedRow identified and then
// deliberately broke with a raw write. last_seen_at needs none either, and for
// a different reason worth stating: nothing can move it forward on a
// handing-off row at the same epoch, because all three writers that could
// reach it freeze it.
//
// The binds are the values that were READ (the empty pair on an active row,
// which is what acquireUpsertSQL and finishUpdateSQL write), not the ones
// being written — this asks "is the row still the one I derived from", not "is
// it already what I want".
const handoffStartUpdateSQL = `UPDATE lifecycle_ownership
			   SET state = $1, handoff_to_type = $2, handoff_to_id = $3,
			       handoff_started_at = $4, last_seen_at = $5, updated_at = $6
			 WHERE entity_kind = $7 AND entity_id = $8 AND phase = $9 AND epoch = $10
			   AND state = $11
			   AND handoff_to_type = $12 AND handoff_to_id = $13
			 RETURNING ` + ownershipColumns

// HandoffStart marks an explicit, durable intent to pass ownership on.
//
// The record stays owned while handing off — it does NOT become free. That is
// what makes the direct-implementer path (mctlhq/mctl-agents#239) a
// deterministic state a reconciler can adopt rather than a silent zero-owner
// gap: something always owns the row, and an incomplete handoff is visible as
// itself instead of as absence.
func (s *Store) HandoffStart(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, to Owner, reason string) (*Ownership, error) {
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	if to.Type == "" || to.ID == "" {
		return nil, fmt.Errorf("lifecycle: handoff: target owner type and id are required")
	}
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := s.currentFor(ctx, tx, entity, phase, owner, epoch)
		if err != nil {
			return err
		}
		// The THIRD writer an outgoing owner can reach, and the only one that
		// would RESET the clocks rather than move them.
		//
		// currentFor admits handing-off and this call does not move the epoch,
		// so the same owner can announce the handoff again on every tick — the
		// idempotent-retry shape this package supports everywhere else, and the
		// natural form of a "declare handoff" step under a Temporal retry
		// policy. Writing handoff_started_at = now there would restart the very
		// clock the freezes in Acquire and RecordProgress left as the surviving
		// signal, so no column on the row would remember when the handoff began
		// and an abandoned one could never be recovered.
		//
		// A re-announcement to the SAME target is therefore a no-op on both
		// clocks. Re-announcing to a DIFFERENT target is a new handoff and
		// starts them, because that is a decision the owner actually made.
		started, seen := now, now
		if current.State == StateHandingOff {
			// Liveness stays frozen for ANY call made while handing off,
			// including a retarget: redirecting the handoff is a decision
			// about the target, not evidence that the outgoing owner is
			// healthy, and leaving it unfrozen would be the remaining way for
			// a handing-off owner to refresh its own clock forever.
			seen = current.LastSeenAt
			if current.HandoffTo != nil && *current.HandoffTo == to && current.HandoffStartedAt != nil {
				// Re-announcing the SAME target is a no-op on the handoff
				// clock too. A DIFFERENT target is a new decision and starts
				// its own, or a redirected handoff would be judged against the
				// clock of the one it replaced.
				started = *current.HandoffStartedAt
			}
		}
		// The handoff target AS READ, which is what `started` was derived
		// from. An active row carries empty strings, so this is a real
		// predicate on every path, not only on the handing-off one.
		wasTo := Owner{}
		if current.HandoffTo != nil {
			wasTo = *current.HandoffTo
		}
		updated, err := scanOne(tx.QueryRow(ctx, handoffStartUpdateSQL,
			StateHandingOff, to.Type, to.ID, started, seen, now,
			entity.Kind, entity.ID, phase, epoch, current.State,
			wasTo.Type, wasTo.ID))
		if errors.Is(err, ErrNotFound) {
			// raceLostOn cannot see handoff_to, and a retarget moves neither
			// the epoch nor the state — so it would fall through to the
			// catch-all and answer ErrStaleRead, which MEANS retry. A retry of
			// the stalled re-announcement reads the new target, takes the
			// `to != current.HandoffTo` branch, and performs the revert as a
			// fresh retarget: evented and with a new clock, so milder than the
			// silent one, but still the outcome the predicate was added to
			// prevent — now recommended by the sentinel.
			//
			// So name it here, the way handoffCompleteUpdateSQL's no-row path
			// names its own. ErrNotOwner, not ErrStaleRead: the caller's
			// decision was about a target that is no longer the row's, and
			// re-issuing the same call is exactly what it must not do.
			latest, rerr := scanOne(tx.QueryRow(ctx,
				`SELECT `+ownershipColumns+` FROM lifecycle_ownership
				 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
				entity.Kind, entity.ID, phase))
			if rerr != nil {
				return rerr
			}
			// The idempotency question FIRST, the way finishedBy and
			// handoffAlreadyCompleted ask it on their own no-row paths. The
			// retarget arm below compares against the target that was READ and
			// never against the one being ANNOUNCED, so without this a
			// duplicate of THIS very call — Temporal fires its retry on the
			// first attempt's timeout, so the duplicate runs concurrently
			// rather than after it — misses on the handoff_to predicate, sees
			// a target different from the one it read, and is told an actor
			// retargeted away from it while the row is exactly what it asked
			// for. That is verbatim the defect already fixed for finish and
			// for HandoffComplete, in the one write that had no no-row branch
			// until this round.
			//
			// The retry keeps the FIRST attempt's clock, like both siblings:
			// finishedBy keeps the first completion time, and
			// handoffAlreadyCompleted returns the row as first written.
			if latest.Epoch == epoch && latest.Owner == owner &&
				latest.State == StateHandingOff &&
				sameHandoffTarget(latest.HandoffTo, &to) {
				out = latest
				return nil
			}
			if latest.Epoch == epoch && latest.State == current.State &&
				!sameHandoffTarget(latest.HandoffTo, current.HandoffTo) {
				return fmt.Errorf("%w: the handoff was retargeted while this one "+
					"was in flight", ErrNotOwner)
			}
			return raceLostOn(ctx, tx, entity, phase, epoch, current.State, "handoff start")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: handoff start: %w", err)
		}
		// Only on a real transition. A polled handoff re-announcing the same
		// target every tick would otherwise write one identical row per tick
		// into an append-only table that has no retention.
		reannounced := current.State == StateHandingOff &&
			current.HandoffTo != nil && *current.HandoffTo == to
		if !reannounced {
			if err := insertEvent(ctx, tx, updated.Entity, phase, EventHandoffStarted, epoch, owner,
				"to "+to.Type+"/"+to.ID+": "+reason, now); err != nil {
				return err
			}
		}
		out = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// handoffCompleteUpdateSQL is the last of the seven writes to get a predicate
// over the decision it makes, and it makes two.
//
// The epoch alone guarded neither. Neither finish nor a HandoffStart retarget
// moves the epoch, so both got underneath it:
//
//   - a Terminal committing between the read and the write let the incoming
//     owner write state = active, owner = steward, epoch + 1 over a MERGED
//     entity — and the old SET did not clear released_at, so the row also kept
//     a release timestamp it had no business carrying;
//   - a retarget let an actor the handoff no longer names complete it, which
//     contradicts the check at the read directly.
//
// handoff_to is pinned against $1/$2 rather than new binds because those ARE
// the incoming owner: the row must still name as its target the actor that is
// about to become its owner.
const handoffCompleteUpdateSQL = `UPDATE lifecycle_ownership
			   SET owner_type = $1, owner_id = $2, epoch = epoch + 1, state = $3,
			       acquired_at = $4, last_seen_at = $4, last_progress_at = $4,
			       progress_evidence = 'handoff completed',
			       -- The outgoing owner's Temporal workflow and policy grant
			       -- are not the incoming one's. Leaving either would make the
			       -- row explain the current owner with the previous owner's
			       -- reasons.
			       temporal_workflow_id = $9, policy_ref = $10,
			       handoff_from_type = owner_type, handoff_from_id = owner_id,
			       handoff_to_type = '', handoff_to_id = '',
			       handoff_started_at = NULL,
			       -- A completed handoff is a live record. Carrying a release
			       -- timestamp into it would make the row describe itself as
			       -- both owned and given up.
			       released_at = NULL, released_reason = '', updated_at = $4
			 WHERE entity_kind = $5 AND entity_id = $6 AND phase = $7 AND epoch = $8
			   AND state = $11
			   AND handoff_to_type = $1 AND handoff_to_id = $2
			 RETURNING ` + ownershipColumns

// HandoffComplete is called by the INCOMING owner. It bumps the epoch, which
// is what fences the outgoing owner's executors: anything still holding the
// previous epoch is rejected without consulting a clock.
//
// Only the actor the handoff names may complete it; a third party arriving
// mid-handoff gets ErrNotOwner rather than quietly stealing the row.
func (s *Store) HandoffComplete(ctx context.Context, entity EntityRef, phase string, incoming Owner, opts ...OwnerOption) (*Ownership, error) {
	// Same options as Recover, for the same reason: clearing the outgoing
	// owner's correlation without letting the incoming one supply its own
	// leaves the row explaining nobody.
	cfg := ownerConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	// The INCOMING owner too, as Acquire and Recover already do for theirs. It
	// is written into owner_type/owner_id, so an empty one would produce a
	// live record owned by nobody — a row that passes every later guard by
	// naming the empty owner.
	//
	// Stated plainly rather than claimed as a guard: NO test can turn this
	// red today, and it is not one of the seven CAS clauses. HandoffStart
	// already refuses an empty target, so no row can name the empty owner in
	// handoff_to, and handoffCompleteUpdateSQL pins handoff_to against the
	// incoming binds — an empty incoming therefore matches nothing and is
	// already refused, one layer further in and with a worse message. This is
	// a boundary check on an entry point, put here so the three writes that
	// take an owner answer the same way, and so that a future caller reaching
	// this one by a different route does not find it the only one missing.
	if incoming.Type == "" || incoming.ID == "" {
		return nil, fmt.Errorf("lifecycle: handoff complete: owner type and id are required")
	}
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
		if current.State == StateActive && current.Owner == incoming {
			// Already completed, and by this caller. A dropped HTTP response
			// makes a Temporal activity or an Argo pod retry the exact call,
			// and answering ErrNoHandoff there fails a step whose work had
			// already succeeded — the one shape retries are guaranteed to
			// produce. Idempotent, like the re-acquire above it.
			out = current
			return nil
		}
		if current.State != StateHandingOff || current.HandoffTo == nil {
			return ErrNoHandoff
		}
		if *current.HandoffTo != incoming {
			return fmt.Errorf("%w: handoff names %s/%s", ErrNotOwner,
				current.HandoffTo.Type, current.HandoffTo.ID)
		}
		updated, err := scanOne(tx.QueryRow(ctx, handoffCompleteUpdateSQL,
			incoming.Type, incoming.ID, StateActive, now,
			entity.Kind, entity.ID, phase, current.Epoch,
			cfg.temporalWorkflowID, cfg.policyRef, StateHandingOff))
		if errors.Is(err, ErrNotFound) {
			// Which of the three predicates failed decides what the caller is
			// told, so re-read rather than guess. A retarget and a finished
			// entity are different situations and only one of them is the
			// caller's own problem.
			latest, rerr := scanOne(tx.QueryRow(ctx,
				`SELECT `+ownershipColumns+` FROM lifecycle_ownership
				 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
				entity.Kind, entity.ID, phase))
			if rerr != nil {
				return rerr
			}
			if latest.State == StateHandingOff && latest.Epoch == current.Epoch &&
				(latest.HandoffTo == nil || *latest.HandoffTo != incoming) {
				return fmt.Errorf("%w: the handoff was retargeted while completion "+
					"was in flight", ErrNotOwner)
			}
			if handoffAlreadyCompleted(latest, incoming, current.Epoch) {
				out = latest
				return nil
			}
			return raceLostOn(ctx, tx, entity, phase, current.Epoch,
				StateHandingOff, "handoff completion")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: handoff complete: %w", err)
		}
		if err := insertEvent(ctx, tx, updated.Entity, phase, EventHandoffCompleted,
			updated.Epoch, incoming, "from "+current.Owner.Type+"/"+current.Owner.ID, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

const finishUpdateSQL = `UPDATE lifecycle_ownership
			   SET state = $1, released_at = $2, released_reason = $3,
			       handoff_to_type = '', handoff_to_id = '', handoff_started_at = NULL,
			       updated_at = $2
			 WHERE entity_kind = $4 AND entity_id = $5 AND phase = $6 AND epoch = $7
			   AND state IN ('active', 'handing-off')
			 RETURNING ` + ownershipColumns

// Release gives up ownership without the entity being finished — the work
// remains, and a reconciler or another actor may take it.
//
// Idempotent for the caller's own repeat: a second Release at the same owner
// and epoch returns the record already written, KEEPING the first call's
// reason and completion time rather than overwriting them, and appending no
// second event. It stays absorbing for everyone else — a Release after a
// Terminal, or either at a different owner or epoch, is still refused.
func (s *Store) Release(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, reason string) (*Ownership, error) {
	return s.finish(ctx, entity, phase, owner, epoch, StateReleased, EventOwnerReleased, reason)
}

// Terminal records that this phase is finished — the PR merged or closed, the
// proposal reached merged/rejected/review-stuck. Nothing should pick it up.
//
// Idempotent for the caller's own repeat on the same terms as Release above:
// the first call's reason and completion time survive, and no second event is
// appended.
func (s *Store) Terminal(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, reason string) (*Ownership, error) {
	return s.finish(ctx, entity, phase, owner, epoch, StateTerminal, EventOwnerTerminal, reason)
}

func (s *Store) finish(ctx context.Context, entity EntityRef, phase string, owner Owner, epoch int, state, event, reason string) (*Ownership, error) {
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	var out *Ownership
	err := s.inTx(ctx, entity, phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		// Already in the state this call would produce, at this caller's own
		// owner and epoch: answer success rather than ErrNotOwner.
		//
		// currentFor refuses an absorbing record, which is right for a stray
		// transition and wrong for the caller's own retry — and the retry is
		// the shape HandoffComplete's idempotent branch cites as its reason for
		// existing: a dropped HTTP response makes a Temporal activity or an
		// Argo pod repeat the identical call. Without this, Terminal commits,
		// the response is lost, the retry answers "the caller tried to ... a
		// record whose owner is somebody else" — about a record the caller
		// holds and has already finished — and an activity whose work
		// succeeded fails at the final step of the phase.
		//
		// This was the last asymmetry in the package. Acquire is idempotent for
		// the caller that already won, HandoffStart is a no-op on a
		// re-announcement, HandoffComplete returns the record it already wrote,
		// and a re-acquire that raced its own Release is told to retry rather
		// than to stand down.
		//
		// `state` is in the comparison, so it does NOT weaken the absorbing
		// rule: Terminal then RELEASE asks for a different state, falls through
		// to currentFor, and is refused exactly as TestTerminalIsAbsorbing
		// pins. Owner and epoch are in it for the same reason they are in every
		// other guard here — this answers for the caller's own completed write,
		// nobody else's.
		//
		// Asked TWICE, and the second time is the one that carries the
		// guarantee. This read happens BEFORE the write, so it answers only
		// for a retry that FOLLOWS the original; two identical calls that
		// OVERLAP — the common shape, since a Temporal retry fires on the
		// first attempt's timeout rather than on its failure — both read
		// active@4, both pass currentFor, and the loser's UPDATE matches
		// nothing. Only inTx's advisory lock orders the two reads, and
		// "the advisory lock makes it safe" is the reasoning this file
		// rejects for EXCLUDED.epoch, for Recover's liveness and for all
		// seven WHERE clauses: a claim every write has to honour, not four
		// of seven. So the question is asked again on the statement's own
		// no-row path below, where the CAS is, and this read is a fast path
		// rather than the guarantee.
		done, err := s.finishedBy(ctx, tx, entity, phase, owner, epoch, state)
		if err != nil {
			return err
		}
		if done != nil {
			out = done
			return nil
		}
		if _, err := s.currentFor(ctx, tx, entity, phase, owner, epoch); err != nil {
			return err
		}
		updated, err := scanOne(tx.QueryRow(ctx, finishUpdateSQL,
			state, now, reason, entity.Kind, entity.ID, phase, epoch))
		if errors.Is(err, ErrNotFound) {
			// The write matched nothing. Before deciding the caller lost a
			// race, ask whether it lost it to ITSELF: an overlapping duplicate
			// of this very call leaves the row in exactly the state this one
			// asked for, at this owner and this epoch.
			done, derr := s.finishedBy(ctx, tx, entity, phase, owner, epoch, state)
			if derr != nil {
				return derr
			}
			if done != nil {
				out = done
				return nil
			}
			return raceLostOn(ctx, tx, entity, phase, epoch, "", "the "+state+" write")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: %s: %w", state, err)
		}
		if err := insertEvent(ctx, tx, updated.Entity, phase, event, epoch, owner, reason, now); err != nil {
			return err
		}
		out = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// finishedBy answers whether the row is ALREADY in the state this call would
// produce, written by this caller at this epoch — in which case the caller's
// own write has landed and there is nothing left to do.
//
// A nil record with a nil error means "not finished by you"; it is not an
// error, and every caller must distinguish the two.
//
// The triple is exact rather than approximate. finish never moves the epoch,
// and currentFor forbids a second absorbing transition at the same one, so at
// most one absorbing state exists per epoch and this cannot match a different
// write. `state` being in it is what keeps Terminal absorbing: a Release after
// a Terminal asks for a different state, does not match, and is refused.
func (s *Store) finishedBy(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string, owner Owner, epoch int, state string) (*Ownership, error) {
	row, err := scanOne(tx.QueryRow(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
		entity.Kind, entity.ID, phase))
	if err != nil {
		return nil, err
	}
	if row.State == state && row.Owner == owner && row.Epoch == epoch {
		return row, nil
	}
	return nil, nil
}

// Get returns the ownership record for one (entity, phase).
func (s *Store) Get(ctx context.Context, entity EntityRef, phase string) (*Ownership, error) {
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
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
	if !LegalPhase(kind, phase) {
		return nil, fmt.Errorf("%w: %s/%s", ErrUnknownPhase, kind, phase)
	}
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
	// OwnerType filters on the owner's TYPE (shepherd, pr-steward, ...), not
	// on a specific owner id. Named for what it matches: the previous name
	// `Owner` read as though it would accept "dev-loop-mctlhq-mctl-web-7".
	OwnerType string
	Limit     int
}

// List returns ownership records matching filter, newest update first.
func (s *Store) List(ctx context.Context, f ListFilter) ([]*Ownership, error) {
	limit := f.Limit
	// Two different questions, deliberately not one branch. An unset or
	// nonsensical limit gets the DEFAULT page; an over-large one gets the CAP.
	// Collapsing them meant a caller asking for 501 received 100 — less than
	// what it asked for AND less than it is allowed, which is not what a cap
	// means and is the one clamp that can silently truncate a caller trying to
	// read more.
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE ($1 = '' OR entity_kind = $1)
		   AND ($2 = '' OR phase = $2)
		   AND ($3 = '' OR state = $3)
		   AND ($4 = '' OR owner_type = $4)
		 ORDER BY updated_at DESC
		 LIMIT $5`,
		f.Kind, f.Phase, f.State, f.OwnerType, limit)
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
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	// Two different questions, deliberately not one branch. An unset or
	// nonsensical limit gets the DEFAULT page; an over-large one gets the CAP.
	// Collapsing them meant a caller asking for 501 received 100 — less than
	// what it asked for AND less than it is allowed, which is not what a cap
	// means and is the one clamp that can silently truncate a caller trying to
	// read more.
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
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

// recoverUpdateSQL is the compare-and-set that takes ownership from a dead
// owner. A package-level constant, not an inline literal, so the test that
// proves the guard executes THIS statement rather than a copy of it — the
// last_seen_at predicate cannot be exercised through Recover itself, because
// inTx holds the advisory lock across the read and the write, so nothing can
// interleave between them in-process. Testing the statement directly is the
// only way to show the predicate is load-bearing rather than decorative.
const recoverUpdateSQL = `UPDATE lifecycle_ownership
			   SET owner_type = $1, owner_id = $2, epoch = epoch + 1, state = $3,
			       acquired_at = $4, last_seen_at = $4, last_progress_at = $4,
			       progress_evidence = $5, policy_ref = $6, temporal_workflow_id = $7,
			       handoff_from_type = owner_type, handoff_from_id = owner_id,
			       handoff_to_type = '', handoff_to_id = '', handoff_started_at = NULL,
			       released_at = NULL, released_reason = '', updated_at = $4
			 WHERE entity_kind = $8 AND entity_id = $9 AND phase = $10
			   AND epoch = $11 AND last_seen_at = $12
			   AND state IN ('active', 'handing-off')
			 RETURNING ` + ownershipColumns

// OwnerOption carries an incoming owner's own correlation fields.
//
// They are options rather than parameters because a reconciler recovering a
// dead workflow usually has neither, and defaulting them to empty is right:
// carrying the DEAD owner's temporal_workflow_id and policy_ref forward would
// leave the row naming a workflow that is gone as the reason the current owner
// holds it.
type OwnerOption func(*ownerConfig)

type ownerConfig struct {
	policyRef          string
	temporalWorkflowID string
}

// WithPolicyRef records which policy put this owner on this entity.
func WithPolicyRef(ref string) OwnerOption {
	return func(c *ownerConfig) { c.policyRef = ref }
}

// WithWorkflowID records the incoming owner's Temporal workflow.
func WithWorkflowID(id string) OwnerOption {
	return func(c *ownerConfig) { c.temporalWorkflowID = id }
}

// Recover takes ownership from an owner that is DEAD, and only from one.
//
// This is the operation that makes IsDead mean something. Without it the
// package computes careful positive evidence that an owner has crashed and
// then has no way to act on it: Acquire refuses any active row at any age, and
// every other exit from active requires the owner's own identity and epoch. A
// crashed worker would hold its entity forever — the inverse of the failure
// this package was built to fix, and just as bad.
//
// Three properties keep it from becoming a way to steal work:
//
//  1. Liveness is re-checked SERVER-SIDE, under the advisory lock, against the
//     phase's bound. A caller may not assert that an owner is dead; it may only
//     ask for the question to be re-asked. Letting the asker decide would put
//     the takeover in the hands of whoever wants to act.
//  2. Only liveness counts. An owner that is alive but has effected nothing is
//     stuck, not dead, and stays its own — handing a stuck entity to another
//     machine produces a second stuck machine.
//  3. expectedEpoch pins the decision to the record the caller actually read,
//     so a recovery based on a stale read fails rather than lands. It is
//     required: a caller that never read the row has no business declaring
//     its owner dead.
//
// The epoch increments, which fences the dead owner's executors if the process
// ever comes back.
func (s *Store) Recover(ctx context.Context, entity EntityRef, phase string, newOwner Owner, expectedEpoch int, evidence string, opts ...OwnerOption) (*Ownership, error) {
	cfg := ownerConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	policyRef, temporalWorkflowID := cfg.policyRef, cfg.temporalWorkflowID
	if err := validate(entity, phase); err != nil {
		return nil, err
	}
	if newOwner.Type == "" || newOwner.ID == "" {
		return nil, fmt.Errorf("lifecycle: recover: owner type and id are required")
	}
	if evidence == "" {
		// A takeover with no recorded reason is the one mutation here that is
		// hardest to reconstruct afterwards.
		return nil, fmt.Errorf("lifecycle: recover: evidence is required")
	}
	if expectedEpoch <= 0 {
		// Required, not optional. The doc above lists pinning the decision to
		// the record the caller actually read as one of three properties that
		// keep this from being a way to steal work, and accepting 0 silently
		// removed it — a caller that never read the row could recover it.
		return nil, fmt.Errorf("lifecycle: recover: expectedEpoch is required")
	}

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
		if current.Epoch != expectedEpoch {
			return fmt.Errorf("%w: current epoch is %d, caller has %d",
				ErrEpochMismatch, current.Epoch, expectedEpoch)
		}
		// A handing-off row IS recoverable, and the recoverer wins: the named
		// target never completed the handoff and the outgoing owner is dead,
		// so honouring the pending handoff would leave the row wedged on an
		// actor that may never arrive. The abandoned target is recorded in the
		// recovered event's reason.
		if current.State != StateActive && current.State != StateHandingOff {
			// Released and terminal need no recovery — Acquire already takes
			// them, and routing that through here would blur "this owner died"
			// with "this owner finished".
			return fmt.Errorf("%w: record is %s; use Acquire", ErrNotOwner, current.State)
		}
		if !current.IsDead(now) {
			return fmt.Errorf("%w: last seen %s", ErrOwnerAlive, current.LastSeenAt.Format(time.RFC3339))
		}

		// last_seen_at is in the WHERE, not just the epoch.
		//
		// The epoch guard alone is not a compare-and-set over the decision
		// this operation actually makes. IsDead was evaluated on the row read
		// above, and the one write that refreshes last_seen_at WITHOUT moving
		// the epoch is the idempotent re-acquire — which is exactly what a
		// crashed owner's pod does when it comes back:
		//
		//   1. wf-1 owns at epoch 4, unseen 11h. Dead.
		//   2. A reconciler reads the row, IsDead is true, and stalls.
		//   3. wf-1 restarts and re-acquires: last_seen_at = now, epoch stays 4.
		//   4. The reconciler's UPDATE still matches epoch = 4 and takes the
		//      row from an owner that just proved it is alive.
		//
		// inTx serializing writers hides that, which is precisely why it must
		// not be relied on — the same argument the epoch comment above makes.
		// Pinning last_seen_at makes the liveness evidence part of the CAS.
		recovered, err := scanOne(tx.QueryRow(ctx,
			recoverUpdateSQL,

			newOwner.Type, newOwner.ID, StateActive, now, "recovered: "+evidence,
			policyRef, temporalWorkflowID,
			entity.Kind, entity.ID, phase, current.Epoch, current.LastSeenAt))
		if errors.Is(err, ErrNotFound) {
			// The row moved between the read and the write. Which of the three
			// predicates failed decides what the caller is told, so re-read
			// rather than guess: a revived owner and a finished entity are
			// different situations, and only one of them is ErrOwnerAlive.
			latest, rerr := scanOne(tx.QueryRow(ctx,
				`SELECT `+ownershipColumns+` FROM lifecycle_ownership
				 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
				entity.Kind, entity.ID, phase))
			if rerr != nil {
				return rerr
			}
			// The idempotency question first, as finish, HandoffComplete and
			// HandoffStart all now ask it on their own no-row paths. Recover
			// is the last write that did not, and it misses for the same
			// reason they do: recoverUpdateSQL pins last_seen_at AND the
			// epoch, and a duplicate of this very call moves both. The
			// re-read then sees epoch + 1 and answers ErrEpochMismatch about a
			// takeover that landed exactly as asked.
			//
			// A duplicate is not exotic here either. Recover is called by the
			// reconciler, whose tick is an Argo pod that can be retried, and by
			// operators through the API — both of which produce the same
			// request twice.
			//
			// Pinned to epoch + 1, like handoffAlreadyCompleted, so a LATER
			// unrelated takeover that happened to land on the same owner
			// cannot read as ours.
			//
			// What this establishes is the POSTCONDITION, not authorship: three
			// statements can produce (epoch+1, newOwner, active) —
			// recoverUpdateSQL, handoffCompleteUpdateSQL when the incoming
			// owner IS newOwner, and acquireUpsertSQL when newOwner takes a row
			// its dying owner released at the same epoch. The second is
			// reachable on the very path this arm runs on: a stalled handoff
			// whose named target is the actor being recovered to. The caller
			// does hold the row at the returned epoch either way, which is what
			// it asked for — but no `recovered` event exists, the supplied
			// evidence is discarded, and WithPolicyRef/WithWorkflowID are not
			// applied. Narrowing it further (handoff_from naming the previous
			// owner, which only the two takeover statements set) is
			// mctl-api#302.
			//
			// StateActive is load-bearing and not decoration: a duplicate
			// recovery lands at epoch+1 and that owner may then Release at the
			// new epoch. Without it this arm returns a RELEASED row as a
			// successful recovery, and the caller's next RecordProgress is
			// refused by currentFor's absorbing check having just been told it
			// owns the entity. With it the switch answers honestly.
			if latest.Epoch == current.Epoch+1 && latest.Owner == newOwner &&
				latest.State == StateActive {
				out = latest
				return nil
			}
			switch {
			case latest.State != StateActive && latest.State != StateHandingOff:
				return fmt.Errorf("%w: it reached %s while recovery was in flight",
					ErrNotOwner, latest.State)
			case latest.Epoch != current.Epoch:
				return fmt.Errorf("%w: ownership moved to epoch %d while recovery was in flight",
					ErrEpochMismatch, latest.Epoch)
			default:
				return fmt.Errorf("%w: it was seen again while recovery was in flight", ErrOwnerAlive)
			}
		}
		if err != nil {
			return fmt.Errorf("lifecycle: recover: %w", err)
		}
		// Which condition made it recoverable, not merely that it was. After
		// the liveness freeze an abandoned handoff and a crashed owner both
		// reach IsDead at the same bound, so the event is the only place the
		// difference survives — and it is the difference an operator reading
		// back a takeover actually wants.
		cause := "dead"
		if current.HandoffStalled(now) {
			cause = "handoff to " + handoffTargetOf(current) + " abandoned"
		}
		if err := insertEvent(ctx, tx, recovered.Entity, phase, EventRecovered,
			recovered.Epoch, newOwner,
			fmt.Sprintf("from %s/%s (%s, last seen %s): %s",
				current.Owner.Type, current.Owner.ID, cause,
				current.LastSeenAt.Format(time.RFC3339), evidence), now); err != nil {
			return err
		}
		out = recovered
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- internals ---------------------------------------------------------

// inTx runs fn inside a transaction holding the advisory lock for this
// entity/phase, so a read-then-write cannot interleave with a competing one.
//
// The lock key is hashed from the entity/phase triple rather than taken per
// table, so unrelated entities rarely serialize against each other. Rarely,
// not never: hashtext is 32-bit, so distinct keys can collide and share a
// lock. That costs a little contention and nothing else — correctness is the
// conditional upsert's job, not this lock's.
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
		// ErrOwnedByOther is a RESULT, not a failure: the caller lost a
		// contended acquire, and the denial event fn just recorded is the
		// evidence of that. Rolling back here would discard exactly the row
		// an operator needs to explain why an actor stood down, so the
		// transaction is committed and the error returned alongside it.
		// Every other error is a genuine failure and still rolls back.
		if errors.Is(err, ErrOwnedByOther) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return fmt.Errorf("lifecycle: commit denial: %w", cerr)
			}
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("lifecycle: commit: %w", err)
	}
	return nil
}

// sameHandoffTarget compares two optional handoff targets, treating "no
// target" as a value rather than as an absence — an active row genuinely has
// none, and that is what a first handoff derives from.
func sameHandoffTarget(a, b *Owner) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// handoffAlreadyCompleted says whether the no-row path was lost to an
// OVERLAPPING duplicate of this same completion rather than to a competitor.
//
// A function for the same reason as reacquireMissSentinel below: inTx holds
// the advisory lock across the read and the write, so the second of two
// SEQUENTIAL completions reads active-and-mine and answers through the
// idempotent branch before ever reaching the statement. Only two completions
// in flight AT ONCE reach here, which the lock makes unreachable through the
// API — so calling this directly is the only way to show it distinguishes
// anything. It exists because the guarantee must not depend on the lock: that
// is the standard this file applies to all seven WHERE clauses.
//
// The epoch is pinned to exactly one past the one this caller read, because
// handoffCompleteUpdateSQL bumps it. Without that a LATER, unrelated handoff
// that happened to land on the same incoming owner would read as this
// caller's own write.
func handoffAlreadyCompleted(latest *Ownership, incoming Owner, fromEpoch int) bool {
	return latest.State == StateActive &&
		latest.Owner == incoming &&
		latest.Epoch == fromEpoch+1
}

// reacquireMissSentinel says what the re-acquire's no-row path means.
//
// A function, not three lines inside the closure, for the same reason the
// statements around it are package constants: inTx holds the advisory lock
// across the read and the write, so the interleaving that reaches this path
// cannot be produced through Acquire — and a released row is read as released
// and takes the acquireUpsertSQL takeover path instead, so an end-to-end test
// passes whatever this returns. Calling it directly is the only way to show it
// distinguishes anything.
func reacquireMissSentinel(existing, current *Ownership) error {
	// The ABSORBING class first, BEFORE the owner.
	//
	// The owner test cannot come first, because an owner change coincides with
	// the row having finished by a plain sequence: wf-1 reads its active row
	// and stalls; wf-1 Releases; shepherd Acquires through the takeover path;
	// shepherd Releases. The re-read returns {released, shepherd, epoch 2} —
	// a row NO actor holds, and one TestReleasedOwnershipCanBeRetakenAtANewEpoch
	// pins as takeable — and answering ErrOwnedByOther there tells a caller
	// obeying the contract to stand down on a free record.
	//
	// This is the same argument the rejection of raceLostOn a few lines above
	// makes: its absorbing-state arm answers ErrNotOwner because RecordProgress,
	// HandoffStart and finish may not drive a finished record. Acquire is the
	// one operation that MAY take one, so for Acquire the absorbing class is
	// not a loss at all — it is the retry succeeding.
	if current.State != StateActive && current.State != StateHandingOff {
		return fmt.Errorf("%w: it became %s while the re-acquire was in flight",
			ErrStaleRead, current.State)
	}
	// Still held, and by somebody else. The only genuine loss.
	//
	// The OWNER clause alone, not `owner != || epoch !=`. Collapsing the two
	// repeated this defect one disjunct over: same owner with a moved epoch is
	// an ordinary sequence — wf-1 stalls, its workflow Releases, a new run
	// Acquires through the takeover path, owner still wf-1 at epoch 5 — and the
	// caller was told a different actor held a row naming itself. Checking only
	// the owner is also more honest about the mechanism: every write that moves
	// the owner bumps the epoch with it, so the epoch clause could never add a
	// genuine loss, only false ones.
	if current.Owner != existing.Owner {
		return ErrOwnedByOther
	}
	// Everything below is ErrStaleRead, because for Acquire it means RETRY, not
	// stand down, and a retry genuinely succeeds by taking this same branch at
	// the values the row now has.
	if current.Epoch != existing.Epoch {
		return fmt.Errorf("%w: the epoch moved to %d while the re-acquire was in flight",
			ErrStaleRead, current.Epoch)
	}
	if current.State != existing.State {
		return fmt.Errorf("%w: it moved from %s to %s while the re-acquire was in flight",
			ErrStaleRead, existing.State, current.State)
	}
	// Every predicate reads as satisfied, so the row changed and changed back,
	// or something outside this package wrote it. Claiming a transition here
	// would be inventing one — the same thing raceLostOn's catch-all refuses to
	// do, and which that classifier's test forbids explicitly.
	return fmt.Errorf("%w: it changed while the re-acquire was in flight", ErrStaleRead)
}

// raceLostOn says which predicate a guarded UPDATE failed on, by re-reading.
//
// The three statements above all answer "no row" for several different
// reasons, and the caller needs to tell them apart: ownership moving on, the
// record finishing underneath, and an owner that never held it are three
// situations, not one. Guessing would collapse them, so re-read — the same
// shape Recover's no-row path uses, and for the same reason.
//
// pinnedState is the state the caller derived from and pinned exactly, or ""
// when the statement pinned only the non-absorbing class. op names the
// operation for the message.
func raceLostOn(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string, epoch int, pinnedState, op string) error {
	latest, err := scanOne(tx.QueryRow(ctx,
		`SELECT `+ownershipColumns+` FROM lifecycle_ownership
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
		entity.Kind, entity.ID, phase))
	if err != nil {
		// Including ErrNotFound: the row was deleted outright, which is not a
		// state this package produces but is still the honest answer.
		return err
	}
	switch {
	case latest.Epoch != epoch:
		return fmt.Errorf("%w: ownership moved to epoch %d while %s was in flight",
			ErrEpochMismatch, latest.Epoch, op)
	case latest.State != StateActive && latest.State != StateHandingOff:
		return fmt.Errorf("%w: record became %s while %s was in flight",
			ErrNotOwner, latest.State, op)
	case pinnedState != "" && latest.State != pinnedState:
		return fmt.Errorf("%w: record moved from %s to %s while %s was in flight",
			ErrStaleRead, pinnedState, latest.State, op)
	default:
		// Every predicate the statement carries now reads as satisfied, so the
		// row changed and changed back, or something outside this package
		// wrote it. Refuse rather than retry: the caller's decision was made
		// against a read that is no longer demonstrably the one it matched.
		return fmt.Errorf("%w: it changed while %s was in flight", ErrStaleRead, op)
	}
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
	// released and terminal are ABSORBING. Owner and epoch both survive a
	// Terminal() untouched, so without this an actor that terminated a record
	// could call Release() afterwards — a stray retry, a duplicate signal — and
	// flip a dead entity back to released, where a reconciler would pick it up
	// again. Leaving an absorbing state requires Acquire, which bumps the epoch.
	if current.State != StateActive && current.State != StateHandingOff {
		return nil, fmt.Errorf("%w: record is %s, which is terminal for its owner",
			ErrNotOwner, current.State)
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
		&o.AcquiredAt, &o.LastSeenAt, &o.LastProgressAt, &o.ProgressEvidence,
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

// handoffTargetOf names the actor an abandoned handoff was waiting for, for
// the recovery event's reason.
func handoffTargetOf(o *Ownership) string {
	if o == nil || o.HandoffTo == nil {
		return "an unnamed actor"
	}
	return o.HandoffTo.Type + "/" + o.HandoffTo.ID
}
