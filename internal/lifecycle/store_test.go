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
	"os"
	"sync"
	"testing"
	"time"
)

// newTestStore connects to the Postgres that .github/workflows/validate.yml
// runs as a service for the `test` job (image postgres:16, TEST_DATABASE_URL
// exported). The skip below therefore fires on a developer laptop, NOT in CI —
// these tests run on every pull request.
//
// That distinction matters for this package specifically: a Go test with a
// mocked pool could only show that the code HANDLES a conflict, never that the
// database PRODUCES one, and the compare-and-set is the entire safety property
// here.
//
// Cleanup is scoped to the keys each test creates rather than an unscoped
// DELETE. The job runs `go test -p 1 ./...` precisely because packages sharing
// this database were wiping each other's rows; an unscoped delete here would
// re-create that problem from a new direction.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed lifecycle store test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// Unique per test, so parallel or repeated runs never collide.
	prefix := fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM lifecycle_events WHERE entity_id LIKE $1`, prefix+"%")
		_, _ = s.pool.Exec(ctx, `DELETE FROM lifecycle_ownership WHERE entity_id LIKE $1`, prefix+"%")
		s.Close()
	})
	return s, prefix
}

func pr(prefix, name string) EntityRef {
	return EntityRef{Kind: KindPullRequest, ID: prefix + "-" + name, Version: "sha-a"}
}

func devloop(id string) Owner { return Owner{Type: OwnerDevLoopWorkflow, ID: id} }

var shepherd = Owner{Type: OwnerShepherd, ID: "cron"}

func TestAcquireIsExclusive(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "exclusive")

	first, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: devloop("wf-1"),
	})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if first.Epoch != 1 || first.State != StateActive {
		t.Fatalf("want epoch 1 active, got epoch %d state %q", first.Epoch, first.State)
	}

	loser, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd,
	})
	if !errors.Is(err, ErrOwnedByOther) {
		t.Fatalf("want ErrOwnedByOther, got %v", err)
	}
	// The loser must learn WHO won, not merely that it lost — otherwise it
	// cannot tell a healthy owner from an unreachable store.
	if loser == nil || loser.Owner != devloop("wf-1") {
		t.Fatalf("loser was not told the winner: %+v", loser)
	}
}

// TestConcurrentAcquireHasExactlyOneWinner is the test this package exists
// for. N goroutines released simultaneously against one real Postgres row.
func TestConcurrentAcquireHasExactlyOneWinner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "race")

	const n = 12
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(n)

	var mu sync.Mutex
	winners := 0
	losers := 0
	var winnerNamed []Owner

	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			start.Wait() // release everyone at once
			got, err := s.Acquire(ctx, AcquireRequest{
				Entity: entity, Phase: PhaseReviewRemediation,
				Owner: devloop(fmt.Sprintf("wf-%d", i)),
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case errors.Is(err, ErrOwnedByOther):
				losers++
				if got != nil {
					winnerNamed = append(winnerNamed, got.Owner)
				}
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	start.Done()
	done.Wait()

	if winners != 1 {
		t.Fatalf("want exactly 1 winner, got %d (losers %d)", winners, losers)
	}
	if losers != n-1 {
		t.Fatalf("want %d losers, got %d", n-1, losers)
	}
	// Every loser must name the SAME winner. Disagreement would mean the
	// losers observed different owners, i.e. the row moved under them.
	for _, w := range winnerNamed {
		if w != winnerNamed[0] {
			t.Fatalf("losers disagree about the winner: %+v", winnerNamed)
		}
	}
}

func TestReacquireBySameOwnerIsIdempotent(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "retry")
	owner := devloop("wf-1")

	first, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// A Temporal activity retry or an Argo pod restart re-acquires. That must
	// not bump the epoch: doing so would fence the caller's own in-flight work.
	again, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if again.Epoch != first.Epoch {
		t.Fatalf("re-acquire moved the epoch %d -> %d", first.Epoch, again.Epoch)
	}
	if !again.LastProgressAt.Equal(first.LastProgressAt) {
		t.Fatalf("re-acquire counted as progress")
	}
}

func TestProgressRequiresCurrentOwnerAndEpoch(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "progress")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "nope"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("want ErrNotOwner for a non-owner, got %v", err)
	}
	if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, owner, got.Epoch+5, "nope"); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("want ErrEpochMismatch for a stale epoch, got %v", err)
	}

	adv, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "pushed fix abc123")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if !adv.LastProgressAt.After(got.LastProgressAt) {
		t.Fatalf("progress did not advance last_progress_at")
	}
	if adv.ProgressEvidence != "pushed fix abc123" {
		t.Fatalf("evidence not recorded: %q", adv.ProgressEvidence)
	}
}

// TestHandoffFencesThePreviousOwner covers the direct-implementer path
// (mctlhq/mctl-agents#239): the row is never unowned, and once the incoming
// owner completes, the outgoing one can no longer act.
func TestHandoffFencesThePreviousOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	mid, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "workflow exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	// Handing off is NOT unowned. A reconciler must see a deterministic state,
	// not an absence it has to guess about.
	if mid.State != StateHandingOff || mid.HandoffTo == nil || *mid.HandoffTo != shepherd {
		t.Fatalf("handoff state wrong: %+v", mid)
	}
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: devloop("wf-2")}); !errors.Is(err, ErrOwnedByOther) {
		t.Fatalf("a third party acquired mid-handoff: %v", err)
	}
	if _, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, devloop("wf-3")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("an unnamed actor completed the handoff: %v", err)
	}

	done, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd)
	if err != nil {
		t.Fatalf("handoff complete: %v", err)
	}
	if done.Epoch != got.Epoch+1 {
		t.Fatalf("handoff did not bump the epoch: %d -> %d", got.Epoch, done.Epoch)
	}
	if done.Owner != shepherd || done.State != StateActive {
		t.Fatalf("handoff did not transfer ownership: %+v", done)
	}
	if done.HandoffFrom == nil || *done.HandoffFrom != outgoing {
		t.Fatalf("handoff lineage lost: %+v", done.HandoffFrom)
	}
	// The fence: the previous owner's epoch is no longer current.
	if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, "stale"); !errors.Is(err, ErrNotOwner) && !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("pre-handoff owner could still act: %v", err)
	}
}

func TestReleasedOwnershipCanBeRetakenAtANewEpoch(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "release")
	first := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: first})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rel, err := s.Release(ctx, entity, PhaseReviewRemediation, first, got.Epoch, "workflow ended")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if rel.State != StateReleased || rel.ReleasedAt == nil {
		t.Fatalf("release state wrong: %+v", rel)
	}

	next, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd})
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	// Epoch must advance across the gap, otherwise an executor from the
	// released owner's era would still look current.
	if next.Epoch != got.Epoch+1 {
		t.Fatalf("epoch did not advance across release: %d -> %d", got.Epoch, next.Epoch)
	}
	if next.ReleasedAt != nil || next.ReleasedReason != "" {
		t.Fatalf("stale release metadata survived re-acquire: %+v", next)
	}
}

func TestTerminalIsReachedAndRecorded(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "terminal")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	fin, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged")
	if err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if fin.State != StateTerminal {
		t.Fatalf("want terminal, got %q", fin.State)
	}

	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 50)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Event] = true
	}
	for _, want := range []string{EventOwnerAcquired, EventOwnerTerminal} {
		if !seen[want] {
			t.Fatalf("event %q not recorded; got %v", want, seen)
		}
	}
}

func TestGetManyBatchesOneRoundTrip(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()

	owned := pr(prefix, "batch-owned")
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: owned, Phase: PhaseReviewRemediation, Owner: devloop("wf-1")}); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	unknown := pr(prefix, "batch-unknown")

	got, err := s.GetMany(ctx, KindPullRequest, PhaseReviewRemediation, []string{owned.ID, unknown.ID})
	if err != nil {
		t.Fatalf("get many: %v", err)
	}
	if _, ok := got[owned.ID]; !ok {
		t.Fatalf("owned entity missing from batch result")
	}
	// An entity with no record must be ABSENT, not a zero value. "I have no
	// record" and "nobody owns it" are the same answer here, but they must not
	// be confusable with "the store did not answer".
	if _, ok := got[unknown.ID]; ok {
		t.Fatalf("unknown entity should not appear in batch result")
	}
}

func TestUnknownPhaseIsRejected(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	_, err := s.Acquire(ctx, AcquireRequest{
		Entity: EntityRef{Kind: KindPullRequest, ID: prefix + "-bad"},
		Phase:  "investigate", // legal for a proposal one day, never for a PR
		Owner:  devloop("wf-1"),
	})
	if !errors.Is(err, ErrUnknownPhase) {
		t.Fatalf("want ErrUnknownPhase, got %v", err)
	}
}

// TestStalenessIsDerivedNotStored pins the rule that nothing sweeps rows to
// mark them stale — the caller computes it from last_progress_at on read.
func TestStalenessIsDerivedNotStored(t *testing.T) {
	now := time.Now().UTC()
	o := &Ownership{
		Entity:         EntityRef{Kind: KindPullRequest},
		Phase:          PhaseReviewRemediation,
		State:          StateActive,
		LastProgressAt: now.Add(-7 * time.Hour),
	}
	if !o.IsStale(now) {
		t.Fatalf("7h with no progress should be stale for a 6h bound")
	}
	if o.IsHealthy(now) {
		t.Fatalf("a stale owner is not healthy")
	}
	o.LastProgressAt = now.Add(-5 * time.Hour)
	if o.IsStale(now) {
		t.Fatalf("5h is inside the 6h bound and must not be stale")
	}
	// A single missed in-loop tick (~4h cadence) must never look stale.
	o.LastProgressAt = now.Add(-4*time.Hour - time.Minute)
	if o.IsStale(now) {
		t.Fatalf("one missed tick must not make a healthy owner look stale")
	}
	// Unknown pairs refuse to be called stale: "stale" is what licenses
	// another actor to take over, so the safe direction is false.
	u := &Ownership{Entity: EntityRef{Kind: "unknown"}, Phase: "nope", State: StateActive}
	if u.IsStale(now) {
		t.Fatalf("unknown (kind, phase) must not be reported stale")
	}
	// Released records are never stale — there is nobody to be stale.
	o.State = StateReleased
	o.LastProgressAt = now.Add(-100 * time.Hour)
	if o.IsStale(now) {
		t.Fatalf("a released record must not be reported stale")
	}
}

// TestConditionalUpsertRefusesToOverwriteAnActiveOwner exercises the SQL that
// actually guarantees exclusivity, directly.
//
// The goroutine-storm test above is a smoke test, not a proof: with the
// advisory lock in place the transactions serialize, so the contenders take
// the ordinary "already owned" path and never reach the read-then-write
// window. Removing the lock does not fail it either, because the first
// transaction usually commits before the others read.
//
// So the guard is tested where it lives. Seed an active owner, then run the
// exact ON CONFLICT ... DO UPDATE ... WHERE state IN ('released','terminal')
// that Acquire issues, as a competing owner would. It must return no row —
// which is how Acquire detects a lost race — and must leave the stored owner
// and epoch untouched.
func TestConditionalUpsertRefusesToOverwriteAnActiveOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "upsert-guard")
	winner := devloop("wf-winner")

	if _, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: winner,
	}); err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	now := time.Now().UTC()
	// The PRODUCTION statement, not a copy of it. Deleting the WHERE clause in
	// store.go must fail this test, and does. Scanned through the same helper
	// Acquire uses, so a column mismatch surfaces as a scan error rather than
	// letting the assertion below pass for the wrong reason.
	stolen, err := scanOne(s.pool.QueryRow(ctx, acquireUpsertSQL,
		entity.Kind, entity.ID, PhaseReviewRemediation, entity.Version,
		OwnerShepherd, "cron", 99, StateActive, now, now,
		"stolen", "", "", "", now, now,
	))
	if err == nil {
		t.Fatalf("the upsert overwrote an active owner, returning %+v", stolen.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound (no row matched the WHERE), got %v", err)
	}

	final, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Owner != winner {
		t.Fatalf("stored owner changed to %+v", final.Owner)
	}
	if final.Epoch != 1 {
		t.Fatalf("epoch moved to %d", final.Epoch)
	}
}

// TestConditionalUpsertAllowsTakeoverOfAReleasedRow is the other half: the
// same statement MUST succeed once the row is no longer active, or ownership
// could never be handed on at all. A guard that only ever refuses is as broken
// as one that only ever permits.
func TestConditionalUpsertAllowsTakeoverOfAReleasedRow(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "upsert-takeover")
	first := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: first})
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}
	if _, err := s.Release(ctx, entity, PhaseReviewRemediation, first, got.Epoch, "done"); err != nil {
		t.Fatalf("release: %v", err)
	}

	next, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd})
	if err != nil {
		t.Fatalf("takeover after release must succeed, got %v", err)
	}
	if next.Owner != shepherd || next.State != StateActive {
		t.Fatalf("takeover did not transfer ownership: %+v", next)
	}
}

// TestTerminalIsAbsorbing pins agy's P1 on mctl-api#295: Terminal leaves owner
// and epoch untouched, so without a state check the SAME actor could call
// Release afterwards — a stray retry or duplicate signal — and flip a dead
// entity back to released, where a reconciler would pick it up again.
func TestTerminalIsAbsorbing(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "absorbing")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}

	// Same owner, same epoch — the only thing standing between this and a
	// resurrected record is the state check.
	if _, err := s.Release(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "stray retry"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("release after terminal must be refused, got %v", err)
	}
	if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "stray"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("progress after terminal must be refused, got %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, shepherd, "stray"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("handoff after terminal must be refused, got %v", err)
	}

	final, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.State != StateTerminal {
		t.Fatalf("record left terminal: %q", final.State)
	}

	// Leaving an absorbing state is possible, but only through Acquire, which
	// bumps the epoch and so fences anything holding the old one.
	retaken, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd})
	if err != nil {
		t.Fatalf("acquire after terminal: %v", err)
	}
	if retaken.Epoch != got.Epoch+1 {
		t.Fatalf("epoch did not advance out of terminal: %d -> %d", got.Epoch, retaken.Epoch)
	}
}

// TestEventsCarryTheStoredVersion pins agy's P2: RecordProgress falls back to
// the stored entity version when the caller omits one, and the event row must
// describe the row it belongs to rather than the (empty) request.
func TestEventsCarryTheStoredVersion(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "event-version") // Version: "sha-a"
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Caller omits the version because nothing changed.
	versionless := EntityRef{Kind: entity.Kind, ID: entity.ID}
	if _, err := s.RecordProgress(ctx, versionless, PhaseReviewRemediation, owner, got.Epoch, "pushed fix"); err != nil {
		t.Fatalf("progress: %v", err)
	}

	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var progress *Event
	for _, e := range events {
		if e.Event == EventProgress {
			progress = e
			break
		}
	}
	if progress == nil {
		t.Fatalf("no progress event recorded")
	}
	if progress.Entity.Version != "sha-a" {
		t.Fatalf("event lost the version context: got %q, want %q", progress.Entity.Version, "sha-a")
	}
}
