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
	"reflect"
	"testing"
	"time"
)

// ageLastSeen backdates last_seen_at directly in the table -- the only way to
// simulate a crash without waiting out the phase's liveness bound (matches
// the pattern in store_test.go's own Recover tests).
func ageLastSeen(t *testing.T, s *Store, entity EntityRef, phase string, d time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(d), entity.Kind, entity.ID, phase,
	); err != nil {
		t.Fatalf("age last_seen_at: %v", err)
	}
}

func ageLastProgress(t *testing.T, s *Store, entity EntityRef, phase string, d time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE lifecycle_ownership SET last_progress_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(d), entity.Kind, entity.ID, phase,
	); err != nil {
		t.Fatalf("age last_progress_at: %v", err)
	}
}

// ageHandoff backdates BOTH handoff clocks together, because that is the only
// shape a real handing-off row can have: every writer keeps
// last_seen_at <= handoff_started_at (store.go:640-660 freezes seen while
// moving started; handoffRequestUpdateSQL writes them equal). Moving
// handoff_started_at alone would produce seen > started, which no writer in
// this package can reach, and a stalled-but-alive row is exactly the case
// production never has — so a test built on it cannot see whether a retry
// actually extends anything.
func ageHandoff(t *testing.T, s *Store, entity EntityRef, phase string, d time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE lifecycle_ownership SET handoff_started_at = $1, last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(d), entity.Kind, entity.ID, phase,
	); err != nil {
		t.Fatalf("age handoff clocks: %v", err)
	}
}

func strPtr(s string) *string { return &s }

func fenceReq(entity EntityRef, phase string, owner Owner, epoch int, version string, principal, reason string) RecoveryRequest {
	return RecoveryRequest{
		Entity: entity, Phase: phase,
		Pre: RecoveryPreconditions{
			ExpectedOwner: owner, ExpectedEpoch: epoch, ExpectedVersion: strPtr(version),
		},
		Principal: principal, Reason: reason,
	}
}

// TestFenceDeadClaim_RefusesStaleEpoch pins that the epoch precondition is
// checked before anything else, and that a mismatch leaves the row untouched.
func TestFenceDeadClaim_RefusesStaleEpoch(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "fence-stale-epoch")
	owner := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastSeen(t, s, entity, PhaseReviewRemediation, -11*time.Hour)

	_, err = s.FenceDeadClaim(ctx, fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch+7, got.Entity.Version, "op1", "x"))
	if !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("want ErrEpochMismatch, got %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.State != StateActive || after.Epoch != got.Epoch {
		t.Fatalf("row changed on a refused fence: %+v", after)
	}
}

// TestFenceDeadClaim_RefusesMovedVersion pins that entity_version is a
// precondition here even though it is not part of the ownership key.
func TestFenceDeadClaim_RefusesMovedVersion(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "fence-moved-version")
	owner := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastSeen(t, s, entity, PhaseReviewRemediation, -11*time.Hour)

	_, err = s.FenceDeadClaim(ctx, fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch, "sha-does-not-match", "op1", "x"))
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("want ErrVersionMismatch, got %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.State != StateActive {
		t.Fatalf("row changed on a refused fence: %+v", after)
	}
}

// TestFenceDeadClaim_RefusesMismatchedOwner pins the owner precondition
// separately from epoch, matching checkPreconditions's own ordering.
func TestFenceDeadClaim_RefusesMismatchedOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "fence-mismatched-owner")
	owner := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastSeen(t, s, entity, PhaseReviewRemediation, -11*time.Hour)

	_, err = s.FenceDeadClaim(ctx, fenceReq(entity, PhaseReviewRemediation, shepherd, got.Epoch, got.Entity.Version, "op1", "x"))
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("want ErrOwnerMismatch, got %v", err)
	}
}

// TestFenceDeadClaim_RefusesLiveOwnerAndFinishedRow_SucceedsOnDead is the
// core licensing test: a live owner is refused, a released row is refused,
// and a dead one is fenced -- released, epoch bumped, owner still named for
// forensics, one fenced event recorded.
func TestFenceDeadClaim_RefusesLiveOwnerAndFinishedRow_SucceedsOnDead(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "fence-licensing")
	owner := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Still alive: refused.
	if _, err := s.FenceDeadClaim(ctx, fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "x")); !errors.Is(err, ErrOwnerAlive) {
		t.Fatalf("fence of a live owner: want ErrOwnerAlive, got %v", err)
	}

	// Released: refused with ErrNotOwner, not ErrOwnerAlive -- a finished row
	// needs Acquire, not a fence.
	released, err := s.Release(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "done for now")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := s.FenceDeadClaim(ctx, fenceReq(entity, PhaseReviewRemediation, owner, released.Epoch, released.Entity.Version, "op1", "x")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("fence of a released row: want ErrNotOwner, got %v", err)
	}

	// Re-acquire, then age past the liveness bound and fence it.
	entity2 := pr(prefix, "fence-licensing-dead")
	got2, err := s.Acquire(ctx, AcquireRequest{Entity: entity2, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	ageLastSeen(t, s, entity2, PhaseReviewRemediation, -11*time.Hour)

	result, err := s.FenceDeadClaim(ctx, fenceReq(entity2, PhaseReviewRemediation, owner, got2.Epoch, got2.Entity.Version, "op1", "unseen for 11h"))
	if err != nil {
		t.Fatalf("fence a dead owner: %v", err)
	}
	if result.Ownership.State != StateReleased {
		t.Fatalf("fence did not release: %+v", result.Ownership)
	}
	if result.Ownership.Epoch != got2.Epoch+1 {
		t.Fatalf("fence did not bump the epoch: %d -> %d", got2.Epoch, result.Ownership.Epoch)
	}
	if result.Ownership.Owner != owner {
		t.Fatalf("fence must keep the fenced owner named for forensics: %+v", result.Ownership.Owner)
	}
	if result.Licensed != "dead" {
		t.Fatalf("licensed = %q, want dead", result.Licensed)
	}

	events, err := s.Events(ctx, entity2, PhaseReviewRemediation, 20)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Event == EventFenced {
			found = true
			if e.Actor != (Owner{Type: OwnerHumanCodeowner, ID: "op1"}) {
				t.Fatalf("fenced event actor = %+v, want human-codeowner/op1", e.Actor)
			}
		}
	}
	if !found {
		t.Fatal("no fenced event written")
	}
}

// TestFenceDeadClaim_LosesRaceOnRefreshedLastSeenAt proves last_seen_at is
// pinned in the CAS: a revival between the read and the write must not be
// fenced out from underneath itself.
func TestFenceDeadClaim_LosesRaceOnRefreshedLastSeenAt(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "fence-race")
	owner := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastSeen(t, s, entity, PhaseReviewRemediation, -11*time.Hour)

	// The operator "read" the row while it was dead...
	req := fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "unseen for 11h")

	// ...but the owner revives (re-acquires) before the fence call lands.
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner}); err != nil {
		t.Fatalf("revive: %v", err)
	}

	if _, err := s.FenceDeadClaim(ctx, req); !errors.Is(err, ErrOwnerAlive) {
		t.Fatalf("fence must lose the race to a revived owner: want ErrOwnerAlive, got %v", err)
	}
}

// TestRequestHandoff_OnlySucceedsOnStuckOwner exercises the full licensing
// matrix: refused on a healthy owner, refused on a dead one (fence instead),
// refused on one already handing off (retry instead), and succeeds on a
// stuck one without moving the epoch -- and the named target's ordinary
// HandoffComplete still works afterward.
func TestRequestHandoff_OnlySucceedsOnStuckOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	target := Owner{Type: OwnerPRSteward, ID: "steward"}

	// Healthy: refused.
	healthy := pr(prefix, "handoff-healthy")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: healthy, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.RequestHandoff(ctx, fenceReq(healthy, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "escalating"), target); !errors.Is(err, ErrOwnerNotStuck) {
		t.Fatalf("healthy owner: want ErrOwnerNotStuck, got %v", err)
	}

	// Dead: refused (fence is the right tool).
	dead := pr(prefix, "handoff-dead")
	got, err = s.Acquire(ctx, AcquireRequest{Entity: dead, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastSeen(t, s, dead, PhaseReviewRemediation, -11*time.Hour)
	if _, err := s.RequestHandoff(ctx, fenceReq(dead, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "escalating"), target); !errors.Is(err, ErrOwnerNotStuck) {
		t.Fatalf("dead owner: want ErrOwnerNotStuck, got %v", err)
	}

	// Stuck: succeeds, epoch unchanged.
	stuck := pr(prefix, "handoff-stuck")
	got, err = s.Acquire(ctx, AcquireRequest{Entity: stuck, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ageLastProgress(t, s, stuck, PhaseReviewRemediation, -72*time.Hour)

	result, err := s.RequestHandoff(ctx, fenceReq(stuck, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "escalating a stuck PR"), target)
	if err != nil {
		t.Fatalf("stuck owner: %v", err)
	}
	if result.Ownership.State != StateHandingOff {
		t.Fatalf("state = %q, want handing-off", result.Ownership.State)
	}
	if result.Ownership.Epoch != got.Epoch {
		t.Fatalf("epoch moved: %d -> %d", got.Epoch, result.Ownership.Epoch)
	}
	if result.Ownership.HandoffTo == nil || *result.Ownership.HandoffTo != target {
		t.Fatalf("handoff target not recorded: %+v", result.Ownership.HandoffTo)
	}
	if result.Licensed != "stuck" {
		t.Fatalf("licensed = %q, want stuck", result.Licensed)
	}

	// Already handing off: refused.
	if _, err := s.RequestHandoff(ctx, fenceReq(stuck, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "again"), target); !errors.Is(err, ErrOwnerNotStuck) {
		t.Fatalf("already handing off: want ErrOwnerNotStuck, got %v", err)
	}

	// The named target's ordinary path still works.
	completed, err := s.HandoffComplete(ctx, stuck, PhaseReviewRemediation, target)
	if err != nil {
		t.Fatalf("handoff complete after operator-requested handoff: %v", err)
	}
	if completed.Owner != target || completed.State != StateActive {
		t.Fatalf("handoff did not complete: %+v", completed)
	}
}

// TestRetryHandoff_OnlySucceedsOnStalledHandoff pins that a handoff still
// inside its bound is refused, a non-handing-off row is refused, and a
// stalled one is re-armed with owner/target/state/epoch unchanged.
func TestRetryHandoff_OnlySucceedsOnStalledHandoff(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	target := Owner{Type: OwnerPRSteward, ID: "steward"}

	// Not handing off at all.
	notHandingOff := pr(prefix, "retry-not-handing-off")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: notHandingOff, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.RetryHandoff(ctx, fenceReq(notHandingOff, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "retry")); !errors.Is(err, ErrNoHandoff) {
		t.Fatalf("not handing off: want ErrNoHandoff, got %v", err)
	}

	// Handing off, but still within bound.
	fresh := pr(prefix, "retry-fresh")
	got, err = s.Acquire(ctx, AcquireRequest{Entity: fresh, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	handedOff, err := s.HandoffStart(ctx, fresh, PhaseReviewRemediation, owner, got.Epoch, target, "handing off")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	if _, err := s.RetryHandoff(ctx, fenceReq(fresh, PhaseReviewRemediation, owner, handedOff.Epoch, handedOff.Entity.Version, "op1", "retry")); !errors.Is(err, ErrHandoffNotStalled) {
		t.Fatalf("fresh handoff: want ErrHandoffNotStalled, got %v", err)
	}

	// Handing off and stalled.
	stalled := pr(prefix, "retry-stalled")
	got, err = s.Acquire(ctx, AcquireRequest{Entity: stalled, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	handedOff, err = s.HandoffStart(ctx, stalled, PhaseReviewRemediation, owner, got.Epoch, target, "handing off")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	ageHandoff(t, s, stalled, PhaseReviewRemediation, -11*time.Hour)

	before, err := s.Get(ctx, stalled, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	result, err := s.RetryHandoff(ctx, fenceReq(stalled, PhaseReviewRemediation, owner, handedOff.Epoch, handedOff.Entity.Version, "op1", "re-arming"))
	if err != nil {
		t.Fatalf("retry a stalled handoff: %v", err)
	}
	if result.Ownership.Owner != before.Owner || result.Ownership.Epoch != before.Epoch || result.Ownership.State != before.State {
		t.Fatalf("owner/epoch/state moved on retry: before %+v, after %+v", before, result.Ownership)
	}
	if result.Ownership.HandoffTo == nil || *result.Ownership.HandoffTo != target {
		t.Fatalf("target moved on retry: %+v", result.Ownership.HandoffTo)
	}
	if result.Ownership.HandoffStartedAt == nil || !result.Ownership.HandoffStartedAt.After(*before.HandoffStartedAt) {
		t.Fatalf("handoff_started_at did not move forward: before %v, after %v", before.HandoffStartedAt, result.Ownership.HandoffStartedAt)
	}
	if result.Licensed != "handoff-stalled" {
		t.Fatalf("licensed = %q, want handoff-stalled", result.Licensed)
	}

	// The point of the operation. Both clocks are measured against the same
	// LivenessBound, so a stalled row is always also dead; if the retry moved
	// only handoff_started_at the row would stay dead and Store.Recover could
	// still bump the epoch out from under the target the retry just protected.
	now := time.Now().UTC()
	if !before.HandoffStalled(now) || !before.IsDead(now) {
		t.Fatalf("premise: a stalled handoff must also be dead before the retry: stalled=%v dead=%v",
			before.HandoffStalled(now), before.IsDead(now))
	}
	if !result.Ownership.LastSeenAt.After(before.LastSeenAt) {
		t.Fatalf("last_seen_at did not move forward: before %v, after %v",
			before.LastSeenAt, result.Ownership.LastSeenAt)
	}
	if result.Ownership.IsDead(now) || result.Ownership.HandoffStalled(now) {
		t.Fatalf("retry left the row takeable: dead=%v stalled=%v",
			result.Ownership.IsDead(now), result.Ownership.HandoffStalled(now))
	}
}

// TestRequestReconcile_LeavesRowUnchanged pins that reconcile touches no
// ownership column and appends exactly one event.
func TestRequestReconcile_LeavesRowUnchanged(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "reconcile")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	before, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	result, err := s.RequestReconcile(ctx, fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "please look at this"))
	if err != nil {
		t.Fatalf("request reconcile: %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("reconcile changed the row: before %+v, after %+v", before, after)
	}
	if result.Licensed != "none" {
		t.Fatalf("licensed = %q, want none", result.Licensed)
	}

	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 20)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	count := 0
	for _, e := range events {
		if e.Event == EventReconcileRequested {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("reconcile-requested events = %d, want 1", count)
	}

	// Preconditions still fail closed even though nothing else is at stake.
	if _, err := s.RequestReconcile(ctx, fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch+1, got.Entity.Version, "op1", "x")); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("stale epoch on reconcile: want ErrEpochMismatch, got %v", err)
	}
}

// TestRequestReconcile_ExpectedLastSeenAt exercises the optional
// last_seen_at pin: a request pinned to the row's actual last_seen_at
// succeeds, and one pinned to a reading the row has since moved past is
// refused with ErrLastSeenAtMismatch -- not ErrStaleRead, which the 409 arm
// of writeLifecycleError (internal/api/handlers_lifecycle.go) would answer
// with the wrong instruction (retry blindly) for what is actually a stale
// operator read. ErrLastSeenAtMismatch maps to 412 there, the same as
// ErrOwnerMismatch and ErrVersionMismatch, both exercised above.
func TestRequestReconcile_ExpectedLastSeenAt(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "reconcile-last-seen-at")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	current, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Pinned to the row's actual reading: succeeds like any other matching
	// precondition.
	req := fenceReq(entity, PhaseReviewRemediation, owner, got.Epoch, got.Entity.Version, "op1", "reading last_seen_at")
	seenAt := current.LastSeenAt
	req.Pre.ExpectedLastSeenAt = &seenAt
	if _, err := s.RequestReconcile(ctx, req); err != nil {
		t.Fatalf("matching last_seen_at: want success, got %v", err)
	}

	// Pinned to a reading the row has moved past: refused, and with the
	// sentinel that maps to 412 -- not ErrStaleRead, which means "retry" and
	// maps to 409.
	stale := current.LastSeenAt.Add(-1 * time.Hour)
	req.Pre.ExpectedLastSeenAt = &stale
	_, err = s.RequestReconcile(ctx, req)
	if !errors.Is(err, ErrLastSeenAtMismatch) {
		t.Fatalf("stale last_seen_at: want ErrLastSeenAtMismatch, got %v", err)
	}
	if errors.Is(err, ErrStaleRead) {
		t.Fatalf("stale last_seen_at must not also answer ErrStaleRead (409): got %v", err)
	}
}

// TestValidatePreconditions_RejectsMalformedInput pins that a missing or
// invalid precondition is a typed error, not a plain one -- a plain error at
// this boundary becomes an unexplained 500 at the API layer.
func TestValidatePreconditions_RejectsMalformedInput(t *testing.T) {
	valid := RecoveryPreconditions{ExpectedOwner: Owner{Type: "shepherd", ID: "cron"}, ExpectedEpoch: 1, ExpectedVersion: strPtr("")}
	if err := validatePreconditions(valid); err != nil {
		t.Fatalf("a well-formed precondition set was rejected: %v", err)
	}

	cases := []RecoveryPreconditions{
		{ExpectedEpoch: 1, ExpectedVersion: strPtr("")},                                   // no owner
		{ExpectedOwner: Owner{Type: "shepherd", ID: "cron"}, ExpectedVersion: strPtr("")}, // no epoch
		{ExpectedOwner: Owner{Type: "shepherd", ID: "cron"}, ExpectedEpoch: 1},            // nil version
		{ExpectedOwner: Owner{Type: "shepherd", ID: "cron"}, ExpectedEpoch: 0, ExpectedVersion: strPtr("")},
	}
	for i, c := range cases {
		if err := validatePreconditions(c); !errors.Is(err, ErrInvalidPrecondition) {
			t.Errorf("case %d: want ErrInvalidPrecondition, got %v", i, err)
		}
	}
}
