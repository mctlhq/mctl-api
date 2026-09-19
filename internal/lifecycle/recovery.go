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
	"time"

	"github.com/jackc/pgx/v5"
)

// Recovery transitions: a narrow, named set of operations a HUMAN operator
// drives when the ordinary actor-owned writes (store.go) cannot make
// progress — a stuck-but-alive owner, a stalled handoff, or a claim an
// operator wants fenced. Unlike Recover (store.go, called by an ACTOR
// re-establishing its own kind of ownership), every method here takes a
// Principal and records it as a `human-codeowner` event actor, and none of
// them can install an arbitrary owner on a live row: Fence installs nobody,
// RequestHandoff only ever names the actor a handoff would target anyway
// (its own HandoffComplete still has to be called by that actor), RetryHandoff
// changes no owner at all, and RequestReconcile changes no ownership column.
//
// There is deliberately no force_owner-shaped parameter and no way to disable
// a precondition check. See ADR-010 and mctl-agents#353 (the separate,
// out-of-scope sweep this is not).

// RecoveryPreconditions are the fail-closed CAS inputs every recovery
// transition carries. All four are compared on the READ inside the
// advisory-locked transaction AND pinned into the UPDATE's own WHERE clause
// (or, for RequestReconcile, checked against the read with no UPDATE at
// all) — so a row that changes between the two refuses the write rather than
// silently landing on a different row than the one the operator looked at.
//
// ExpectedVersion is a pointer, and nil is a caller error rather than "any
// version": entity version is not part of the ownership key and is not a
// precondition on any ordinary actor write (a new head on the same pull
// request is normal mid-work, not a handoff) — but a human operator's
// recovery DECISION was made by reading the entity, so if the head moved
// after that read, the decision may be void. That is also why version is a
// precondition HERE and nowhere else in this package.
type RecoveryPreconditions struct {
	ExpectedOwner   Owner
	ExpectedEpoch   int
	ExpectedVersion *string
	// ExpectedLastSeenAt is an optional extra pin on the liveness evidence the
	// operator read. When set, a last_seen_at that moved between the read and
	// the write (e.g. the owner's own tick landing mid-recovery) refuses the
	// write with ErrLastSeenAtMismatch, on top of whatever the transition's
	// own liveness/progress re-derivation already refuses.
	ExpectedLastSeenAt *time.Time
}

// RecoveryRequest names the entity/phase being recovered, the preconditions
// pinning the decision, the acting human principal, and why.
type RecoveryRequest struct {
	Entity    EntityRef
	Phase     string
	Pre       RecoveryPreconditions
	Principal string
	Reason    string
}

// Snapshot is the row's identity-relevant fields as read, BEFORE a recovery
// transition mutated (or, for RequestReconcile, did not mutate) it. Carried on
// RecoveryResult so a caller building an audit entry has the before/after pair
// without a second read.
type Snapshot struct {
	Owner      Owner
	Epoch      int
	State      string
	Version    string
	LastSeenAt time.Time
}

// RecoveryResult is the outcome of a successful recovery transition.
type RecoveryResult struct {
	Ownership *Ownership
	Before    Snapshot
	// Licensed names which condition permitted the transition: "dead",
	// "stuck", "handoff-stalled", or "none" (RequestReconcile, which requires
	// no licensing condition — it only appends an event).
	Licensed string
	Event    string
}

func snapshotOf(o *Ownership) Snapshot {
	return Snapshot{
		Owner: o.Owner, Epoch: o.Epoch, State: o.State,
		Version: o.Entity.Version, LastSeenAt: o.LastSeenAt,
	}
}

// validatePreconditions rejects a malformed CAS input with a typed error —
// a plain error here would become an unexplained 500 at the API layer, the
// same reasoning requireEpoch documents for the ordinary writes.
func validatePreconditions(pre RecoveryPreconditions) error {
	if pre.ExpectedOwner.Type == "" || pre.ExpectedOwner.ID == "" {
		return fmt.Errorf("%w: expected_owner_type and expected_owner_id are required", ErrInvalidPrecondition)
	}
	if pre.ExpectedEpoch <= 0 {
		return fmt.Errorf("%w: expected_epoch is required", ErrInvalidPrecondition)
	}
	if pre.ExpectedVersion == nil {
		return fmt.Errorf("%w: expected_version is required (an empty string matches an unset version)", ErrInvalidPrecondition)
	}
	return nil
}

// validateRecoveryRequest checks the fields validatePreconditions does not:
// the human principal an event is attributed to, and the reason recorded on
// it. Both are required for the same reason evidence is required on Recover
// (store.go) — a takeover with no recorded reason or no recorded actor is the
// hardest thing here to reconstruct afterwards.
func validateRecoveryRequest(req RecoveryRequest) error {
	if req.Principal == "" {
		return fmt.Errorf("%w: principal is required", ErrInvalidPrecondition)
	}
	if req.Reason == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidPrecondition)
	}
	return validatePreconditions(req.Pre)
}

// checkPreconditions compares a freshly read row against the pinned
// preconditions, in the order that lets an operator tell the three apart:
// epoch first (ownership moved to a different generation entirely), then
// owner (a different actor holds the same generation — should not happen
// alongside a matching epoch, but a caller's stale read could still claim
// it), then entity version (the row is exactly the one this owner still
// holds, but its content moved since the operator looked). The optional
// last_seen_at pin is checked last: it is evidence about liveness, not about
// identity, so it is the least specific of the four disagreements.
func checkPreconditions(current *Ownership, pre RecoveryPreconditions) error {
	if current.Epoch != pre.ExpectedEpoch {
		return fmt.Errorf("%w: current epoch is %d, caller expected %d",
			ErrEpochMismatch, current.Epoch, pre.ExpectedEpoch)
	}
	if current.Owner != pre.ExpectedOwner {
		return fmt.Errorf("%w: current owner is %s/%s, caller expected %s/%s",
			ErrOwnerMismatch, current.Owner.Type, current.Owner.ID,
			pre.ExpectedOwner.Type, pre.ExpectedOwner.ID)
	}
	if pre.ExpectedVersion != nil && current.Entity.Version != *pre.ExpectedVersion {
		return fmt.Errorf("%w: current entity version is %q, caller expected %q",
			ErrVersionMismatch, current.Entity.Version, *pre.ExpectedVersion)
	}
	if pre.ExpectedLastSeenAt != nil && !current.LastSeenAt.Equal(*pre.ExpectedLastSeenAt) {
		return fmt.Errorf("%w: last_seen_at is now %s, caller's read was pinned to %s",
			ErrLastSeenAtMismatch, current.LastSeenAt.Format(time.RFC3339), pre.ExpectedLastSeenAt.Format(time.RFC3339))
	}
	return nil
}

// ownershipByKeySQL is the plain re-read every method below uses, both for
// its first look at the row and to explain a CAS statement's own "0 rows"
// outcome. A package-level constant rather than a repeated literal — every
// other read in this package (store.go) inlines this same text, and it is
// duplicated here rather than exported from there to keep this file's own CAS
// statements next to the read they explain.
const ownershipByKeySQL = `SELECT ` + ownershipColumns + ` FROM lifecycle_ownership
	 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`

func readOwnership(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string) (*Ownership, error) {
	return scanOne(tx.QueryRow(ctx, ownershipByKeySQL, entity.Kind, entity.ID, phase))
}

// fenceUpdateSQL takes a DEAD claim off the row without installing a new
// owner. Pinned in the WHERE: the entity triple, epoch, owner, entity
// version and last_seen_at (the same liveness-evidence pin recoverUpdateSQL
// uses, and load-bearing for the identical reason — see its comment in
// store.go: an owner that revives between the read and this write must not
// be fenced out from underneath itself), and the non-absorbing state class.
//
// epoch = epoch + 1 is computed BY THE STATEMENT, never bound from a
// caller-supplied value — the same reasoning acquireUpsertSQL's comment gives
// for its own epoch column: a value derived from a read that may already be
// stale must not become the row's new fencing generation.
//
// The handoff quartet is cleared (a fenced claim is not mid-handoff to
// anybody), but owner_type/owner_id are NOT cleared: the row still names who
// it was fenced FROM, for forensics. released_reason carries the rest: the
// old owner, the epoch transition, the licensing condition, and the
// operator's own reason text.
const fenceUpdateSQL = `UPDATE lifecycle_ownership
			   SET state = 'released', epoch = epoch + 1,
			       released_at = $1, released_reason = $2,
			       handoff_to_type = '', handoff_to_id = '', handoff_started_at = NULL,
			       updated_at = $1
			 WHERE entity_kind = $3 AND entity_id = $4 AND phase = $5
			   AND epoch = $6 AND owner_type = $7 AND owner_id = $8
			   AND entity_version = $9 AND last_seen_at = $10
			   AND state IN ('active', 'handing-off')
			 RETURNING ` + ownershipColumns

// FenceDeadClaim releases a row whose owner is DEAD, installing no successor.
//
// Liveness is re-derived server-side, under the advisory lock, against the
// phase's bound — the same rule Store.Recover enforces and for the same
// reason: an operator may not assert that an owner is dead, only ask for the
// question to be re-asked.
func (s *Store) FenceDeadClaim(ctx context.Context, req RecoveryRequest) (*RecoveryResult, error) {
	if err := validate(req.Entity, req.Phase); err != nil {
		return nil, err
	}
	if err := validateRecoveryRequest(req); err != nil {
		return nil, err
	}
	var out *RecoveryResult
	err := s.inTx(ctx, req.Entity, req.Phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := readOwnership(ctx, tx, req.Entity, req.Phase)
		if err != nil {
			return err
		}
		before := snapshotOf(current)
		if err := checkPreconditions(current, req.Pre); err != nil {
			return err
		}
		if current.State != StateActive && current.State != StateHandingOff {
			return fmt.Errorf("%w: record is %s; use Acquire", ErrNotOwner, current.State)
		}
		if !current.IsDead(now) {
			return fmt.Errorf("%w: last seen %s", ErrOwnerAlive, current.LastSeenAt.Format(time.RFC3339))
		}
		licensed := "dead"
		cause := "dead"
		if current.HandoffStalled(now) {
			licensed = "handoff-stalled"
			cause = "handoff to " + handoffTargetOf(current) + " abandoned"
		}
		reasonText := fmt.Sprintf("fenced: %s/%s at epoch %d->%d (%s): %s",
			current.Owner.Type, current.Owner.ID, current.Epoch, current.Epoch+1, cause, req.Reason)

		recovered, err := scanOne(tx.QueryRow(ctx, fenceUpdateSQL,
			now, reasonText,
			req.Entity.Kind, req.Entity.ID, req.Phase,
			req.Pre.ExpectedEpoch, req.Pre.ExpectedOwner.Type, req.Pre.ExpectedOwner.ID,
			*req.Pre.ExpectedVersion, current.LastSeenAt))
		if errors.Is(err, ErrNotFound) {
			return fenceRaceLost(ctx, tx, req.Entity, req.Phase, req.Pre)
		}
		if err != nil {
			return fmt.Errorf("lifecycle: fence: %w", err)
		}
		if eerr := insertEvent(ctx, tx, recovered.Entity, req.Phase, EventFenced, recovered.Epoch,
			Owner{Type: OwnerHumanCodeowner, ID: req.Principal}, reasonText, now); eerr != nil {
			return eerr
		}
		out = &RecoveryResult{Ownership: recovered, Before: before, Licensed: licensed, Event: EventFenced}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// fenceRaceLost explains fenceUpdateSQL's own "0 rows" outcome by re-reading
// under the same lock and returning whichever mismatch actually explains it:
// an ordinary precondition drift, the record having finished underneath, or —
// the one outcome specific to Fence — the owner having come back to life
// between the read and the write.
func fenceRaceLost(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string, pre RecoveryPreconditions) error {
	latest, err := readOwnership(ctx, tx, entity, phase)
	if err != nil {
		return err
	}
	if cerr := checkPreconditions(latest, pre); cerr != nil {
		return cerr
	}
	if latest.State != StateActive && latest.State != StateHandingOff {
		return fmt.Errorf("%w: record became %s while fence was in flight", ErrNotOwner, latest.State)
	}
	if !latest.IsDead(time.Now().UTC()) {
		return fmt.Errorf("%w: last seen %s", ErrOwnerAlive, latest.LastSeenAt.Format(time.RFC3339))
	}
	return fmt.Errorf("%w: it changed while fence was in flight", ErrStaleRead)
}

// handoffRequestUpdateSQL starts a handoff off a STUCK (never dead) owner,
// toward a named target — the same STATE the row ends up in as an ordinary
// HandoffStart, but triggered by an operator escalating a stuck claim rather
// than by the owner's own decision to leave.
//
// Pinned in the WHERE: state = 'active' with an EMPTY handoff_to (so this
// cannot silently retarget a handoff already in flight — RetryHandoff is the
// operation for that), plus epoch, owner and entity version. Epoch is left
// UNCHANGED by the SET: the outgoing owner keeps driving until the named
// target calls its own HandoffComplete, exactly as an ordinary HandoffStart
// does.
//
// last_seen_at is set to the same `now` as handoff_started_at, mirroring
// handoffStartUpdateSQL's own active -> handing-off transition (store.go):
// this call is only reachable from an active row (RequestHandoff refuses
// anything else before building the statement's args), so there is no
// existing handoff to freeze the clock against — the row is not yet
// handing off until this write lands.
const handoffRequestUpdateSQL = `UPDATE lifecycle_ownership
			   SET state = $1, handoff_to_type = $2, handoff_to_id = $3,
			       handoff_started_at = $4, last_seen_at = $5, updated_at = $6
			 WHERE entity_kind = $7 AND entity_id = $8 AND phase = $9
			   AND state = $10 AND handoff_to_type = '' AND handoff_to_id = ''
			   AND epoch = $11 AND owner_type = $12 AND owner_id = $13 AND entity_version = $14
			 RETURNING ` + ownershipColumns

// RequestHandoff escalates a STUCK owner by starting a handoff toward
// toOwner. It is refused on a healthy owner (not licensed), a dead one (fence
// it instead — recovering a stuck row would only produce a second stuck
// machine, while a dead one needs Fence or Recover, not an escalation), and
// one already handing off (retry that handoff instead of layering a second
// one on top of it).
//
// The outgoing owner is not removed: exactly like an ordinary HandoffStart,
// the row stays owned until toOwner calls HandoffComplete, so an incomplete
// handoff is a visible state rather than a zero-owner gap.
func (s *Store) RequestHandoff(ctx context.Context, req RecoveryRequest, toOwner Owner) (*RecoveryResult, error) {
	if err := validate(req.Entity, req.Phase); err != nil {
		return nil, err
	}
	if err := validateRecoveryRequest(req); err != nil {
		return nil, err
	}
	if toOwner.Type == "" || toOwner.ID == "" {
		return nil, fmt.Errorf("%w: to-owner type and id are required", ErrInvalidPrecondition)
	}
	var out *RecoveryResult
	err := s.inTx(ctx, req.Entity, req.Phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := readOwnership(ctx, tx, req.Entity, req.Phase)
		if err != nil {
			return err
		}
		before := snapshotOf(current)
		if err := checkPreconditions(current, req.Pre); err != nil {
			return err
		}
		switch {
		case current.State == StateHandingOff:
			return fmt.Errorf("%w: already handing off to %s; use retry-handoff instead",
				ErrOwnerNotStuck, handoffTargetOf(current))
		case current.State != StateActive:
			return fmt.Errorf("%w: record is %s; use Acquire", ErrNotOwner, current.State)
		case current.IsDead(now):
			return fmt.Errorf("%w: owner is dead; use fence instead of handoff", ErrOwnerNotStuck)
		case !current.IsStuck(now):
			return fmt.Errorf("%w: owner is healthy", ErrOwnerNotStuck)
		}

		updated, err := scanOne(tx.QueryRow(ctx, handoffRequestUpdateSQL,
			StateHandingOff, toOwner.Type, toOwner.ID, now, now, now,
			req.Entity.Kind, req.Entity.ID, req.Phase,
			StateActive, req.Pre.ExpectedEpoch, req.Pre.ExpectedOwner.Type, req.Pre.ExpectedOwner.ID,
			*req.Pre.ExpectedVersion))
		if errors.Is(err, ErrNotFound) {
			return recoveryRaceLost(ctx, tx, req.Entity, req.Phase, req.Pre, "handoff request")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: request handoff: %w", err)
		}
		reasonText := fmt.Sprintf("handoff requested to %s/%s (owner stuck since %s): %s",
			toOwner.Type, toOwner.ID, current.LastProgressAt.Format(time.RFC3339), req.Reason)
		if eerr := insertEvent(ctx, tx, updated.Entity, req.Phase, EventHandoffRequested, updated.Epoch,
			Owner{Type: OwnerHumanCodeowner, ID: req.Principal}, reasonText, now); eerr != nil {
			return eerr
		}
		out = &RecoveryResult{Ownership: updated, Before: before, Licensed: "stuck", Event: EventHandoffRequested}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// handoffRetryUpdateSQL re-arms a STALLED handoff's clock for the SAME
// target, changing nothing else. Pinned in the WHERE: handoff_to_type/id AND
// the observed handoff_started_at — the retarget hazard handoffStartUpdateSQL
// documents in store.go applies here just the same: without pinning the
// clock a retry that raced a legitimate retarget could re-arm a handoff for a
// target the row no longer names — plus epoch, owner and entity version.
const handoffRetryUpdateSQL = `UPDATE lifecycle_ownership
			   SET handoff_started_at = $1, updated_at = $1
			 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4
			   AND state = 'handing-off'
			   AND handoff_to_type = $5 AND handoff_to_id = $6 AND handoff_started_at = $7
			   AND epoch = $8 AND owner_type = $9 AND owner_id = $10 AND entity_version = $11
			 RETURNING ` + ownershipColumns

// RetryHandoff re-arms a handoff that has STALLED — started, and never
// completed within the phase's liveness bound. Refused on a row that is not
// handing off at all (ErrNoHandoff, the same sentinel HandoffComplete uses
// for the identical situation) and on one still inside its bound
// (ErrHandoffNotStalled).
//
// Only handoff_started_at and updated_at move. Owner, target, state and epoch
// are unchanged — this does not retarget the handoff or touch who holds it,
// only how long the incoming owner has left to complete it.
func (s *Store) RetryHandoff(ctx context.Context, req RecoveryRequest) (*RecoveryResult, error) {
	if err := validate(req.Entity, req.Phase); err != nil {
		return nil, err
	}
	if err := validateRecoveryRequest(req); err != nil {
		return nil, err
	}
	var out *RecoveryResult
	err := s.inTx(ctx, req.Entity, req.Phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := readOwnership(ctx, tx, req.Entity, req.Phase)
		if err != nil {
			return err
		}
		before := snapshotOf(current)
		if err := checkPreconditions(current, req.Pre); err != nil {
			return err
		}
		if current.State != StateHandingOff || current.HandoffTo == nil || current.HandoffStartedAt == nil {
			return ErrNoHandoff
		}
		if !current.HandoffStalled(now) {
			return fmt.Errorf("%w: started %s, still within bound",
				ErrHandoffNotStalled, current.HandoffStartedAt.Format(time.RFC3339))
		}

		updated, err := scanOne(tx.QueryRow(ctx, handoffRetryUpdateSQL,
			now,
			req.Entity.Kind, req.Entity.ID, req.Phase,
			current.HandoffTo.Type, current.HandoffTo.ID, *current.HandoffStartedAt,
			req.Pre.ExpectedEpoch, req.Pre.ExpectedOwner.Type, req.Pre.ExpectedOwner.ID,
			*req.Pre.ExpectedVersion))
		if errors.Is(err, ErrNotFound) {
			return recoveryRaceLost(ctx, tx, req.Entity, req.Phase, req.Pre, "handoff retry")
		}
		if err != nil {
			return fmt.Errorf("lifecycle: retry handoff: %w", err)
		}
		reasonText := fmt.Sprintf("handoff to %s/%s re-armed (stalled since %s): %s",
			current.HandoffTo.Type, current.HandoffTo.ID, current.HandoffStartedAt.Format(time.RFC3339), req.Reason)
		if eerr := insertEvent(ctx, tx, updated.Entity, req.Phase, EventHandoffRetried, updated.Epoch,
			Owner{Type: OwnerHumanCodeowner, ID: req.Principal}, reasonText, now); eerr != nil {
			return eerr
		}
		out = &RecoveryResult{Ownership: updated, Before: before, Licensed: "handoff-stalled", Event: EventHandoffRetried}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RequestReconcile appends a reconcile-requested event and modifies NO
// ownership column — it is a request for attention, not a claim on the row.
// Preconditions are still checked against a fresh read inside the
// advisory-locked transaction, and the same 412 sentinels apply on mismatch:
// an operator's request to look again is itself a decision made from a read,
// and a stale one should be refused rather than silently attributed to a row
// it no longer describes.
func (s *Store) RequestReconcile(ctx context.Context, req RecoveryRequest) (*RecoveryResult, error) {
	if err := validate(req.Entity, req.Phase); err != nil {
		return nil, err
	}
	if err := validateRecoveryRequest(req); err != nil {
		return nil, err
	}
	var out *RecoveryResult
	err := s.inTx(ctx, req.Entity, req.Phase, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		current, err := readOwnership(ctx, tx, req.Entity, req.Phase)
		if err != nil {
			return err
		}
		before := snapshotOf(current)
		if err := checkPreconditions(current, req.Pre); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, current.Entity, req.Phase, EventReconcileRequested, current.Epoch,
			Owner{Type: OwnerHumanCodeowner, ID: req.Principal}, req.Reason, now); err != nil {
			return err
		}
		out = &RecoveryResult{Ownership: current, Before: before, Licensed: "none", Event: EventReconcileRequested}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// recoveryRaceLost explains a "0 rows" outcome from RequestHandoff or
// RetryHandoff's own CAS statements. Re-reads under the same lock: if any of
// the ordinary preconditions now disagree, that mismatch is the honest
// explanation; if the record finished outright, ErrNotOwner; otherwise
// something specific to the transition's own extra predicate (the empty
// handoff_to gate, or the retarget guard) moved, and the caller's correct
// response is the same one raceLostOn's own catch-all in store.go gives —
// retry, because the record has not moved to a different owner or epoch.
func recoveryRaceLost(ctx context.Context, tx pgx.Tx, entity EntityRef, phase string, pre RecoveryPreconditions, op string) error {
	latest, err := readOwnership(ctx, tx, entity, phase)
	if err != nil {
		return err
	}
	if cerr := checkPreconditions(latest, pre); cerr != nil {
		return cerr
	}
	if latest.State != StateActive && latest.State != StateHandingOff {
		return fmt.Errorf("%w: record became %s while %s was in flight", ErrNotOwner, latest.State, op)
	}
	return fmt.Errorf("%w: it changed while %s was in flight", ErrStaleRead, op)
}
