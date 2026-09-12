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
	"strings"
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

// TestLivenessAndProgressAreSeparate pins the split that an earlier version of
// this package got wrong: one field, one bound, and therefore two failures.
func TestLivenessAndProgressAreSeparate(t *testing.T) {
	now := time.Now().UTC()
	fresh := func() *Ownership {
		return &Ownership{
			Entity:         EntityRef{Kind: KindPullRequest},
			Phase:          PhaseReviewRemediation,
			State:          StateActive,
			LastSeenAt:     now,
			LastProgressAt: now,
		}
	}

	// THE case the single-bound design broke: a PR waiting on human review.
	// The owner is ticking and healthy; it has simply had nothing to effect.
	// It must NOT be takeable, at any age, or the reconciler thrashes
	// ownership every bound-width and fences the real worker out when the
	// review finally lands.
	waiting := fresh()
	waiting.LastProgressAt = now.Add(-40 * time.Hour)
	if waiting.IsDead(now) {
		t.Fatalf("an owner that is ticking must never be dead, whatever progress it has made")
	}
	if !waiting.IsHealthy(now) {
		t.Fatalf("a live owner with no progress still holds the entity legitimately")
	}

	// Past the progress bound it is STUCK — escalate to a human, do not
	// hand it to another machine that will be just as stuck.
	stuck := fresh()
	stuck.LastProgressAt = now.Add(-49 * time.Hour)
	if !stuck.IsStuck(now) {
		t.Fatalf("49h with no progress should be stuck for a 48h bound")
	}
	if stuck.IsDead(now) {
		t.Fatalf("stuck is not dead — it must not license a takeover")
	}
	if !stuck.IsHealthy(now) {
		t.Fatalf("a stuck-but-alive owner still holds the entity; nobody else may take it")
	}

	// One entirely missed tick. Cadence is ~4h, so the next opportunity is at
	// 8h; the liveness bound must survive that, which is why it is 10h and not
	// 6h. This assertion is the one that fails if anyone "simplifies" the
	// bound back toward the cadence.
	missed := fresh()
	missed.LastSeenAt = now.Add(-8*time.Hour - 30*time.Minute)
	if missed.IsDead(now) {
		t.Fatalf("one fully missed tick must not make a healthy owner look dead")
	}

	// Genuinely gone.
	dead := fresh()
	dead.LastSeenAt = now.Add(-11 * time.Hour)
	if !dead.IsDead(now) {
		t.Fatalf("11h unseen should be dead for a 10h bound")
	}
	if dead.IsHealthy(now) {
		t.Fatalf("a dead owner is not healthy")
	}

	// Unknown pairs refuse to be declared dead: that is what licenses another
	// actor to act, so the safe direction is false.
	u := &Ownership{Entity: EntityRef{Kind: "unknown"}, Phase: "nope", State: StateActive, LastSeenAt: now.Add(-1000 * time.Hour)}
	if u.IsDead(now) || u.IsStuck(now) {
		t.Fatalf("unknown (kind, phase) must not be reported dead or stuck")
	}

	// Released records have nobody to be dead.
	rel := fresh()
	rel.State = StateReleased
	rel.LastSeenAt = now.Add(-1000 * time.Hour)
	if rel.IsDead(now) || rel.IsStuck(now) {
		t.Fatalf("a released record must not be reported dead or stuck")
	}
}

// TestReacquireRefreshesLivenessNotProgress pins that a tick which re-acquires
// proves the owner exists without claiming it achieved anything.
func TestReacquireRefreshesLivenessNotProgress(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "liveness")
	owner := devloop("wf-1")

	first, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	again, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if !again.LastSeenAt.After(first.LastSeenAt) {
		t.Fatalf("re-acquire did not refresh liveness")
	}
	if !again.LastProgressAt.Equal(first.LastProgressAt) {
		t.Fatalf("re-acquire counted as progress")
	}
	if again.Epoch != first.Epoch {
		t.Fatalf("re-acquire moved the epoch %d -> %d", first.Epoch, again.Epoch)
	}
}

// TestListFilters covers the one exported method that had no test, including
// the limit clamp.
func TestListFilters(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()

	a := pr(prefix, "list-a")
	b := pr(prefix, "list-b")
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: a, Phase: PhaseReviewRemediation, Owner: devloop("wf-1")}); err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	got, err := s.Acquire(ctx, AcquireRequest{Entity: b, Phase: PhaseReviewRemediation, Owner: shepherd})
	if err != nil {
		t.Fatalf("acquire b: %v", err)
	}
	if _, err := s.Release(ctx, b, PhaseReviewRemediation, shepherd, got.Epoch, "done"); err != nil {
		t.Fatalf("release b: %v", err)
	}

	countMine := func(f ListFilter) int {
		records, err := s.List(ctx, f)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		n := 0
		for _, o := range records {
			if strings.HasPrefix(o.Entity.ID, prefix) {
				n++
			}
		}
		return n
	}

	if n := countMine(ListFilter{Kind: KindPullRequest, Phase: PhaseReviewRemediation}); n != 2 {
		t.Fatalf("unfiltered: want 2 of mine, got %d", n)
	}
	if n := countMine(ListFilter{Kind: KindPullRequest, Phase: PhaseReviewRemediation, State: StateActive}); n != 1 {
		t.Fatalf("state filter: want 1, got %d", n)
	}
	if n := countMine(ListFilter{Kind: KindPullRequest, Phase: PhaseReviewRemediation, OwnerType: OwnerShepherd}); n != 1 {
		t.Fatalf("owner filter: want 1, got %d", n)
	}
	if n := countMine(ListFilter{Kind: KindDevLoopProposal, Phase: PhaseImplement}); n != 0 {
		t.Fatalf("kind filter should exclude everything here, got %d", n)
	}
	// Clamp: a nonsense limit must not become an unbounded scan or an error.
	if _, err := s.List(ctx, ListFilter{Limit: -5}); err != nil {
		t.Fatalf("negative limit: %v", err)
	}
	if _, err := s.List(ctx, ListFilter{Limit: 100000}); err != nil {
		t.Fatalf("oversized limit: %v", err)
	}

	// An over-cap limit must yield the CAP, not the default. The two were one
	// branch, so a caller asking for 501 received 100 — less than it asked for
	// and less than it is allowed, which is the one clamp that can silently
	// truncate a caller trying to read MORE. Needs more than the default page
	// to be visible at all, which is why the rows are made here.
	for i := range 150 {
		e := pr(prefix, fmt.Sprintf("list-clamp-%03d", i))
		if _, err := s.Acquire(ctx, AcquireRequest{Entity: e, Phase: PhaseReviewRemediation, Owner: devloop("wf-1")}); err != nil {
			t.Fatalf("acquire clamp row %d: %v", i, err)
		}
	}
	big, err := s.List(ctx, ListFilter{Limit: 100000})
	if err != nil {
		t.Fatalf("oversized limit: %v", err)
	}
	if len(big) <= 100 {
		t.Fatalf("an over-cap limit returned the default page, not the cap: %d rows", len(big))
	}
}

// TestUnknownPhaseIsRejectedEverywhere pins that a typo gets ErrUnknownPhase
// and not ErrNotFound. "Nobody owns this" is the most dangerous wrong answer
// this package can give, so it must never be the answer to a malformed
// question.
func TestUnknownPhaseIsRejectedEverywhere(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	bad := EntityRef{Kind: KindPullRequest, ID: prefix + "-typo"}
	owner := devloop("wf-1")

	checks := map[string]error{}
	_, checks["get"] = s.Get(ctx, bad, "investigate")
	_, checks["progress"] = s.RecordProgress(ctx, bad, "investigate", owner, 1, "x")
	_, checks["handoff-start"] = s.HandoffStart(ctx, bad, "investigate", owner, 1, shepherd, "x")
	_, checks["handoff-complete"] = s.HandoffComplete(ctx, bad, "investigate", owner)
	_, checks["release"] = s.Release(ctx, bad, "investigate", owner, 1, "x")
	_, checks["terminal"] = s.Terminal(ctx, bad, "investigate", owner, 1, "x")
	_, checks["events"] = s.Events(ctx, bad, "investigate", 10)
	_, checks["get-many"] = s.GetMany(ctx, KindPullRequest, "investigate", []string{bad.ID})

	for name, err := range checks {
		if !errors.Is(err, ErrUnknownPhase) {
			t.Fatalf("%s: want ErrUnknownPhase, got %v", name, err)
		}
	}

	// An empty entity id is the same class of mistake.
	if _, err := s.Get(ctx, EntityRef{Kind: KindPullRequest}, PhaseReviewRemediation); !errors.Is(err, ErrUnknownPhase) {
		t.Fatalf("empty id: want ErrUnknownPhase, got %v", err)
	}
}

// TestDenialEventSurvivesTheLostAcquire pins that losing a contended acquire
// still leaves evidence. The denial is written inside the transaction that
// returns ErrOwnedByOther, so a naive rollback-on-any-error would discard
// exactly the row an operator needs to explain why an actor stood down.
func TestDenialEventSurvivesTheLostAcquire(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "denial")

	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: devloop("wf-1")}); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd}); !errors.Is(err, ErrOwnedByOther) {
		t.Fatalf("want ErrOwnedByOther, got %v", err)
	}

	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 50)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, e := range events {
		if e.Event == EventOwnerDenied && e.Actor == shepherd {
			return
		}
	}
	t.Fatalf("the denial event was not persisted; events: %+v", events)
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
		OwnerShepherd, "cron", 99, StateActive, now, now, now,
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
	for _, e := range events {
		if e.Event != EventProgress {
			continue
		}
		if e.Entity.Version != "sha-a" {
			t.Fatalf("event lost the version context: got %q, want %q", e.Entity.Version, "sha-a")
		}
		return
	}
	t.Fatalf("no progress event recorded")
}

// TestRecoverOnlyTakesFromADeadOwner is what makes IsDead mean something.
// Without Recover the package computes careful positive evidence that an owner
// crashed and then cannot act on it, so a crashed worker holds its entity
// forever — the inverse of the failure this package exists to fix.
func TestRecoverOnlyTakesFromADeadOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover")
	crashed := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: crashed})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// A live owner is not recoverable, whatever the caller believes. The
	// client may not assert death; the server re-checks it.
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "I think it died"); !errors.Is(err, ErrOwnerAlive) {
		t.Fatalf("recover from a live owner must be refused, got %v", err)
	}

	// Age it past the liveness bound, directly in the table — the only way to
	// simulate a crash without waiting 10 hours.
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(-11*time.Hour), entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("age the row: %v", err)
	}

	// A stale expectedEpoch must fail rather than land.
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch+7, "x"); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("recover with a stale epoch must fail, got %v", err)
	}
	// A takeover with no recorded reason is the hardest mutation here to
	// reconstruct afterwards, so it is refused.
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, ""); err == nil {
		t.Fatalf("recover without evidence must be refused")
	}

	recovered, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "unseen for 11h")
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered.Owner != shepherd || recovered.State != StateActive {
		t.Fatalf("recover did not transfer ownership: %+v", recovered)
	}
	// The epoch must advance, or the dead owner's executors are un-fenced if
	// its process ever comes back.
	if recovered.Epoch != got.Epoch+1 {
		t.Fatalf("recover did not bump the epoch: %d -> %d", got.Epoch, recovered.Epoch)
	}
	if recovered.HandoffFrom == nil || *recovered.HandoffFrom != crashed {
		t.Fatalf("recover lost the lineage: %+v", recovered.HandoffFrom)
	}
	if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, crashed, got.Epoch, "back from the dead"); err == nil {
		t.Fatalf("the recovered-from owner could still act")
	}

	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 20)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, e := range events {
		if e.Event == EventRecovered {
			return
		}
	}
	t.Fatalf("no recovered event written; a takeover must leave evidence")
}

// TestRecoverRefusesAStuckButLivingOwner pins the distinction the whole
// liveness/progress split exists for. Stuck is not dead: handing a stuck entity
// to another machine produces a second stuck machine and an epoch bump.
func TestRecoverRefusesAStuckButLivingOwner(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "stuck-not-dead")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Ticking happily, achieving nothing for days — a PR waiting on review.
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_progress_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(-72*time.Hour), entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("age progress: %v", err)
	}

	current, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	now := time.Now().UTC()
	if !current.IsStuck(now) {
		t.Fatalf("72h without progress should read as stuck")
	}
	if current.IsDead(now) {
		t.Fatalf("a ticking owner must never read as dead")
	}
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "looks idle"); !errors.Is(err, ErrOwnerAlive) {
		t.Fatalf("a stuck owner must not be recoverable, got %v", err)
	}
}

// TestEpochIsComputedByTheDatabase pins that the next epoch comes from the
// stored row rather than from a value the caller derived from a read that may
// already be stale. Serializing writers hides the difference, which is exactly
// why it must not be left to them.
func TestEpochIsComputedByTheDatabase(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "epoch-monotonic")

	owner := devloop("wf-1")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Release(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "done"); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Drive the epoch up underneath, the way a competing writer would.
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET epoch = 41
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3`,
		entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("bump epoch: %v", err)
	}

	// A fresh acquire must continue from the STORED epoch, not from anything
	// the caller computed before that bump.
	next, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: shepherd})
	if err != nil {
		t.Fatalf("acquire after bump: %v", err)
	}
	if next.Epoch != 42 {
		t.Fatalf("epoch did not come from the database: want 42, got %d", next.Epoch)
	}
}

// TestRecoverPinsTheLivenessEvidenceInItsCAS is the race the epoch guard alone
// did not cover: the idempotent re-acquire refreshes last_seen_at WITHOUT
// moving the epoch, which is exactly what a crashed owner's pod does when it
// restarts.
//
//  1. wf-1 owns at epoch N, unseen 11h. Dead.
//  2. A reconciler reads the row and decides to recover.
//  3. wf-1 restarts and re-acquires: last_seen_at = now, epoch unchanged.
//  4. Without last_seen_at in the WHERE, the reconciler's UPDATE still matches
//     and takes the row from an owner that just proved it is alive.
func TestRecoverPinsTheLivenessEvidenceInItsCAS(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-cas")
	crashed := devloop("wf-crashed")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: crashed})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	stale := time.Now().UTC().Add(-11 * time.Hour)
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		stale, entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("age the row: %v", err)
	}

	// Step 3, standing in for the stall: the owner comes back and re-acquires.
	// Epoch is deliberately unchanged by that path.
	revived, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: crashed})
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if revived.Epoch != got.Epoch {
		t.Fatalf("re-acquire moved the epoch, which would mask this race: %d -> %d", got.Epoch, revived.Epoch)
	}

	// A recovery decided on the pre-restart liveness must now fail. Today it
	// fails at the IsDead re-check inside the transaction; the WHERE predicate
	// is what keeps it failing if that check ever moves outside.
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "unseen for 11h"); !errors.Is(err, ErrOwnerAlive) {
		t.Fatalf("recovery must lose to a revived owner, got %v", err)
	}
	final, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Owner != crashed {
		t.Fatalf("the revived owner lost its row to %+v", final.Owner)
	}
}

func TestRecoverOnAHandingOffRowLetsTheRecovererWin(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-handoff")
	dying := devloop("wf-dying")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: dying})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, dying, got.Epoch, Owner{Type: OwnerPRSteward, ID: "steward"}, "exiting"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(-11*time.Hour), entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("age the row: %v", err)
	}

	// The owner died mid-handoff and the named target never completed it.
	// Honouring the pending handoff would wedge the row on an actor that may
	// never arrive, so the recoverer wins and the handoff is abandoned.
	recovered, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "died mid-handoff")
	if err != nil {
		t.Fatalf("recover from handing-off: %v", err)
	}
	if recovered.Owner != shepherd || recovered.State != StateActive {
		t.Fatalf("recoverer did not win: %+v", recovered)
	}
	if recovered.HandoffTo != nil {
		t.Fatalf("the abandoned handoff target survived: %+v", recovered.HandoffTo)
	}
}

func TestRecoverRefusesAFinishedRow(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-finished")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	// Released and terminal need no recovery — Acquire already takes them, and
	// routing that through Recover would blur "this owner died" with "this
	// owner finished".
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "x"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("recover on a terminal row must be refused, got %v", err)
	}
}

func TestHandoffCompleteWithoutAHandoff(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "no-handoff")

	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: devloop("wf-1")}); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd); !errors.Is(err, ErrNoHandoff) {
		t.Fatalf("want ErrNoHandoff on an active row, got %v", err)
	}
}

// TestRecoverUpdateRefusesAStaleLivenessRead exercises the predicate directly,
// because Recover itself cannot.
//
// inTx holds the advisory lock across the read and the write, so nothing can
// interleave between them in-process — which means the test above passes with
// or without last_seen_at in the WHERE, and is therefore not evidence for it.
// The predicate is what keeps the IsDead decision inside the compare-and-set
// if that ordering ever changes, so it is tested where it lives: run the
// production statement with the liveness value the decision was made on, after
// the row has moved on, and require it to match nothing.
func TestRecoverUpdateRefusesAStaleLivenessRead(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	staleSeen := got.LastSeenAt

	// The owner ticks again: last_seen_at moves, the epoch deliberately does
	// not. This is the restarted-pod case.
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner}); err != nil {
		t.Fatalf("re-acquire: %v", err)
	}

	now := time.Now().UTC()
	stolen, err := scanOne(s.pool.QueryRow(ctx, recoverUpdateSQL,
		OwnerShepherd, "cron", StateActive, now, "recovered: stale read",
		"", "",
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch, staleSeen,
	))
	if err == nil {
		t.Fatalf("a recovery decided on stale liveness took the row: %+v", stolen.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound (no row matched the WHERE), got %v", err)
	}

	// And with the CURRENT liveness value it must succeed, or the predicate is
	// simply blocking recovery outright.
	current, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := scanOne(s.pool.QueryRow(ctx, recoverUpdateSQL,
		OwnerShepherd, "cron", StateActive, now, "recovered: fresh read",
		"", "",
		entity.Kind, entity.ID, PhaseReviewRemediation, current.Epoch, current.LastSeenAt,
	)); err != nil {
		t.Fatalf("recovery on a fresh liveness read must succeed, got %v", err)
	}
}

// TestRecoverUpdateRefusesAFinishedRow closes the gap the liveness predicate
// alone left open. finish() changes `state` while touching neither `epoch` nor
// `last_seen_at`, so those two predicates cannot see it:
//
//  1. wf-1 owns at epoch N, unseen 11h. Dead.
//  2. A reconciler reads the row — active, IsDead — and stalls.
//  3. wf-1's process comes back and calls Terminal("merged").
//  4. Without `state` in the WHERE, the reconciler's UPDATE still matches and
//     hands a FINISHED entity to a new owner as live work.
//
// That is the resurrection TestTerminalIsAbsorbing pins for currentFor, through
// the one operation that does not go via currentFor — and worse, because a
// merged PR would get driven again.
func TestRecoverUpdateRefusesAFinishedRow(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-finished-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Step 3, out of band: the row finishes without epoch or last_seen_at moving.
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	finished, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	now := time.Now().UTC()
	resurrected, err := scanOne(s.pool.QueryRow(ctx, recoverUpdateSQL,
		OwnerShepherd, "cron", StateActive, now, "recovered: stale state",
		"", "",
		entity.Kind, entity.ID, PhaseReviewRemediation, finished.Epoch, finished.LastSeenAt,
	))
	if err == nil {
		t.Fatalf("a finished entity was handed to %+v as live work", resurrected.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound (no row matched the WHERE), got %v", err)
	}

	// And through the API the caller is told WHICH predicate failed: a
	// finished record is not a revived owner.
	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, finished.Epoch, "x"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("want ErrNotOwner for a finished row, got %v", err)
	}
}

// TestHandingOffFreezesLiveness pins that an outgoing owner cannot hold an
// abandoned handoff open by continuing to poll.
func TestHandingOffFreezesLiveness(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-freeze")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	mid, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}

	// BOTH writers that an outgoing owner can reach must be frozen. Pinning
	// only one of them is why an earlier mutation of this guard passed: it
	// unfroze the re-acquire path while RecordProgress still moved the clock.
	time.Sleep(10 * time.Millisecond)
	again, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if !again.LastSeenAt.Equal(mid.LastSeenAt) {
		t.Fatalf("re-acquire refreshed liveness during a handoff: %v -> %v", mid.LastSeenAt, again.LastSeenAt)
	}

	time.Sleep(10 * time.Millisecond)
	progressed, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, "pushed abc123")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if !progressed.LastSeenAt.Equal(mid.LastSeenAt) {
		t.Fatalf("recording progress refreshed liveness during a handoff: %v -> %v",
			mid.LastSeenAt, progressed.LastSeenAt)
	}
	// The work still counts — only the liveness clock stops.
	if !progressed.LastProgressAt.After(mid.LastProgressAt) {
		t.Fatalf("progress during a handoff was not recorded")
	}
	again = progressed

	// And the handoff's own age is what a reconciler reads.
	if again.HandoffStartedAt == nil {
		t.Fatalf("handoff_started_at is not recorded")
	}
	if again.HandoffStalled(again.HandoffStartedAt.Add(time.Minute)) {
		t.Fatalf("a minute-old handoff must not be stalled")
	}
	if !again.HandoffStalled(again.HandoffStartedAt.Add(11 * time.Hour)) {
		t.Fatalf("an 11h handoff must be stalled for a 10h bound")
	}
}

// TestRecoveryEventNamesTheAbandonedHandoff gives HandoffStalled a consumer.
// After the liveness freeze an abandoned handoff and a crashed owner both reach
// IsDead at the same bound, so the event reason is the only place the
// difference survives — and it is the difference an operator reading back a
// takeover wants.
func TestRecoveryEventNamesTheAbandonedHandoff(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "recover-cause")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch,
		Owner{Type: OwnerPRSteward, ID: "steward"}, "exiting"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	stale := time.Now().UTC().Add(-11 * time.Hour)
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1, handoff_started_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		stale, entity.Kind, entity.ID, PhaseReviewRemediation,
	); err != nil {
		t.Fatalf("age the row: %v", err)
	}

	if _, err := s.Recover(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "nobody arrived"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 20)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, e := range events {
		if e.Event == EventRecovered {
			if !strings.Contains(e.Reason, "abandoned") || !strings.Contains(e.Reason, "steward") {
				t.Fatalf("the recovery does not say the handoff was abandoned: %q", e.Reason)
			}
			return
		}
	}
	t.Fatalf("no recovered event")
}

// TestReannouncingAHandoffDoesNotRestartTheClock closes the third writer.
//
// Acquire and RecordProgress freeze last_seen_at on a handing-off row, which
// leaves handoff_started_at as the surviving signal that the handoff is old.
// HandoffStart writes BOTH columns, and currentFor admits handing-off without
// moving the epoch — so an owner re-announcing the handoff every tick, which is
// the idempotent-retry shape this package supports everywhere else, would reset
// the one clock the other two freezes preserved. Nothing on the row would
// remember when the handoff began.
func TestReannouncingAHandoffDoesNotRestartTheClock(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-reannounce")
	outgoing := devloop("wf-1")
	target := Owner{Type: OwnerPRSteward, ID: "steward"}

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	first, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, target, "exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	if first.HandoffStartedAt == nil {
		t.Fatalf("handoff_started_at not recorded")
	}

	time.Sleep(10 * time.Millisecond)
	again, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, target, "still exiting")
	if err != nil {
		t.Fatalf("re-announce: %v", err)
	}
	if !again.HandoffStartedAt.Equal(*first.HandoffStartedAt) {
		t.Fatalf("re-announcing restarted the handoff clock: %v -> %v",
			*first.HandoffStartedAt, *again.HandoffStartedAt)
	}
	if !again.LastSeenAt.Equal(first.LastSeenAt) {
		t.Fatalf("re-announcing refreshed liveness: %v -> %v", first.LastSeenAt, again.LastSeenAt)
	}

	// A handoff to a DIFFERENT target is a new decision, so it does start the
	// clocks — otherwise the freeze would make a redirected handoff
	// permanently un-recoverable for the wrong reason.
	time.Sleep(10 * time.Millisecond)
	redirected, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch,
		Owner{Type: OwnerShepherd, ID: "cron"}, "redirecting")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	if !redirected.HandoffStartedAt.After(*first.HandoffStartedAt) {
		t.Fatalf("a handoff to a new target did not start its own clock")
	}
}

// TestHandoffCompleteRecordsTheIncomingOwnersCorrelation pins the capability
// added alongside the clearing, which nothing exercised.
func TestHandoffCompleteRecordsTheIncomingOwnersCorrelation(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-correlation")
	outgoing := devloop("wf-outgoing")

	got, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing,
		PolicyRef: "policy-outgoing", TemporalWorkflowID: "wf-outgoing",
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "exiting"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}

	done, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd,
		WithPolicyRef("policy-incoming"), WithWorkflowID("wf-incoming"))
	if err != nil {
		t.Fatalf("handoff complete: %v", err)
	}
	// The row must explain the CURRENT owner, not the previous one.
	if done.PolicyRef != "policy-incoming" {
		t.Fatalf("policy_ref still explains the outgoing owner: %q", done.PolicyRef)
	}
	if done.TemporalWorkflowID != "wf-incoming" {
		t.Fatalf("temporal_workflow_id still names the outgoing workflow: %q", done.TemporalWorkflowID)
	}

	// And with no options it clears rather than inheriting, which is the
	// behaviour the options replaced.
	entity2 := pr(prefix, "handoff-correlation-cleared")
	got2, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity2, Phase: PhaseReviewRemediation, Owner: outgoing,
		PolicyRef: "policy-outgoing", TemporalWorkflowID: "wf-outgoing",
	})
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity2, PhaseReviewRemediation, outgoing, got2.Epoch, shepherd, "x"); err != nil {
		t.Fatalf("handoff start 2: %v", err)
	}
	cleared, err := s.HandoffComplete(ctx, entity2, PhaseReviewRemediation, shepherd)
	if err != nil {
		t.Fatalf("handoff complete 2: %v", err)
	}
	if cleared.PolicyRef != "" || cleared.TemporalWorkflowID != "" {
		t.Fatalf("outgoing owner's correlation survived: %+v", cleared)
	}
}

// TestReacquireCannotLandOnSomebodyElsesRow closes the one write that carried
// no epoch predicate, which both reviewers found independently.
//
// HandoffComplete moves owner and epoch without touching the key, so it gets
// underneath the re-acquire: wf-1 reads its own handing-off row with
// last_seen_at frozen at T0, the steward completes the handoff, and wf-1's
// UPDATE then lands on the steward's row. Worse than a stale overwrite —
// because the freeze makes `seen` a PAST timestamp, it actively AGES a live
// owner until it satisfies IsDead and Recover fences its executors.
func TestReacquireCannotLandOnSomebodyElsesRow(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "reacquire-cas")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "exiting"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	handed, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd,
		WithWorkflowID("wf-steward"))
	if err != nil {
		t.Fatalf("handoff complete: %v", err)
	}

	// Through the API the previous owner already loses at the read: the row
	// names the steward now, so Acquire takes the owned-by-other branch and
	// never reaches the refresh. inTx also serialises, so nothing can
	// interleave in-process. The predicate therefore has to be tested where it
	// lives — with the PRODUCTION statement, run as the stalled owner would.
	lost, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing,
		TemporalWorkflowID: "wf-1",
	})
	if !errors.Is(err, ErrOwnedByOther) {
		t.Fatalf("the previous owner's re-acquire landed: %v", err)
	}
	if lost == nil || lost.Owner != shepherd {
		t.Fatalf("the loser was not told who won: %+v", lost)
	}

	stale := time.Now().UTC().Add(-3 * time.Hour)
	stolen, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		stale, "sha-from-wf-1", "wf-1", time.Now().UTC(),
		entity.Kind, entity.ID, PhaseReviewRemediation,
		got.Epoch, outgoing.Type, outgoing.ID, StateHandingOff,
	))
	if err == nil {
		t.Fatalf("a stalled owner's refresh landed on %+v", stolen.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound (no row matched the WHERE), got %v", err)
	}

	final, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Owner != shepherd || final.Epoch != handed.Epoch {
		t.Fatalf("the row moved under the new owner: %+v", final)
	}
	if final.TemporalWorkflowID != "wf-steward" {
		t.Fatalf("the row explains the current owner with the previous one's correlation: %q",
			final.TemporalWorkflowID)
	}
	// And the new owner was not aged backwards.
	if !final.LastSeenAt.Equal(handed.LastSeenAt) {
		t.Fatalf("a live owner was aged by somebody else's retry: %v -> %v",
			handed.LastSeenAt, final.LastSeenAt)
	}
}

// TestHandoffCompleteIsIdempotent covers the exact shape a retry produces: the
// work succeeded and the response was lost.
func TestHandoffCompleteIsIdempotent(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-idempotent")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "exiting"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	first, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd)
	if err != nil {
		t.Fatalf("handoff complete: %v", err)
	}

	// The response was dropped; the activity runs again.
	again, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, shepherd)
	if err != nil {
		t.Fatalf("a retried handoff must not fail: %v", err)
	}
	if again.Epoch != first.Epoch {
		t.Fatalf("the retry bumped the epoch again: %d -> %d", first.Epoch, again.Epoch)
	}
	// A DIFFERENT actor retrying is still refused — idempotency is for the
	// caller that already won, not for anyone who asks twice.
	if _, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, devloop("wf-2")); !errors.Is(err, ErrNoHandoff) {
		t.Fatalf("an unrelated actor completed a finished handoff: %v", err)
	}
}

// TestRetargetingAHandoffDoesNotRefreshLiveness is the remaining path by which
// a handing-off owner could have kept its own clock alive.
func TestRetargetingAHandoffDoesNotRefreshLiveness(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-retarget")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	first, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch,
		Owner{Type: OwnerPRSteward, ID: "steward"}, "exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	redirected, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch,
		shepherd, "redirecting")
	if err != nil {
		t.Fatalf("retarget: %v", err)
	}
	// The handoff clock restarts, because redirecting is a real decision.
	if !redirected.HandoffStartedAt.After(*first.HandoffStartedAt) {
		t.Fatalf("a handoff to a new target did not start its own clock")
	}
	// Liveness does NOT, because redirecting says nothing about whether the
	// outgoing owner is healthy.
	if !redirected.LastSeenAt.Equal(first.LastSeenAt) {
		t.Fatalf("retargeting refreshed the outgoing owner's liveness: %v -> %v",
			first.LastSeenAt, redirected.LastSeenAt)
	}
}

// TestReannouncingAHandoffWritesNoDuplicateEvent keeps a polled handoff from
// filling an append-only table with identical rows.
func TestReannouncingAHandoffWritesNoDuplicateEvent(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-events")
	outgoing := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	for range 4 {
		if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, shepherd, "exiting"); err != nil {
			t.Fatalf("handoff start: %v", err)
		}
	}
	events, err := s.Events(ctx, entity, PhaseReviewRemediation, 50)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	started := 0
	for _, e := range events {
		if e.Event == EventHandoffStarted {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("a polled handoff wrote %d handoff-started events", started)
	}
}

// TestProgressUpdateRefusesTheStateItDidNotRead pins the state predicate on
// progressUpdateSQL, in both directions.
//
// RecordProgress derives the liveness freeze from the state it read: an active
// row moves last_seen_at, a handing-off one must not. With only the epoch in
// the WHERE, a HandoffStart landing between the read and the write let the
// freeze be defeated by the write it was meant to stop — the row is now
// handing-off, but the UPDATE still carries the seen = now computed from the
// stale active read. Pinning the exact state read makes the derivation part of
// the compare-and-set.
//
// Driven through the statement rather than the API because inTx holds the
// advisory lock across the read and the write, so nothing can interleave
// in-process and the predicate is unobservable through RecordProgress.
func TestProgressUpdateRefusesTheStateItDidNotRead(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "progress-state-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Out of band, at the SAME epoch: the row starts handing off after a
	// caller has already read it as active.
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, owner, got.Epoch,
		shepherd, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	frozen, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Truncated to the microsecond on the way IN, so the assertion on the way
	// out can stay exact: timestamptz has microsecond resolution, and
	// time.Now() is microsecond-resolution on macOS but nanosecond on Linux.
	// Sizing a tolerance around the difference would admit a full second
	// against a sub-microsecond truncation; removing the difference does not.
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	// The write a caller that read `active` would issue: seen = now, which is
	// exactly the refresh the handing-off freeze exists to prevent.
	revived, err := scanOne(s.pool.QueryRow(ctx, progressUpdateSQL,
		now, now, "pushed a commit", "sha-b",
		entity.Kind, entity.ID, PhaseReviewRemediation, frozen.Epoch, StateActive))
	if err == nil {
		t.Fatalf("a stale active read refreshed a handing-off row to last_seen_at %s", revived.LastSeenAt)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound (no row matched the WHERE), got %v", err)
	}
	// The damage the predicate prevents, checked directly: liveness is still
	// frozen, so the abandoned handoff still reaches its bound.
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get after: %v", err)
	}
	if !after.LastSeenAt.Equal(frozen.LastSeenAt) {
		t.Fatalf("liveness moved from %s to %s despite the refused write",
			frozen.LastSeenAt, after.LastSeenAt)
	}

	// The other direction: the predicate is not merely always false. The same
	// statement with the state the row actually has matches and writes.
	ok, err := scanOne(s.pool.QueryRow(ctx, progressUpdateSQL,
		now, frozen.LastSeenAt, "pushed a commit", "sha-b",
		entity.Kind, entity.ID, PhaseReviewRemediation, frozen.Epoch, StateHandingOff))
	if err != nil {
		t.Fatalf("the statement refused the state the row really has: %v", err)
	}
	if !ok.LastProgressAt.Equal(now) {
		t.Fatalf("progress was recorded at %s, want %s", ok.LastProgressAt, now)
	}
}

// TestHandoffStartUpdateRefusesTheStateItDidNotRead pins the same predicate on
// handoffStartUpdateSQL.
//
// HandoffStart derives TWO values from the state it read — the liveness freeze
// and whether the handoff clock restarts. A caller that read `active` computes
// started = now and seen = now; if the row became handing-off underneath it,
// landing that write restarts the clock of a handoff already in progress and
// unfreezes the outgoing owner, which together make an abandoned handoff
// unrecoverable — the precise failure the freeze was added for.
func TestHandoffStartUpdateRefusesTheStateItDidNotRead(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-state-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, owner, got.Epoch,
		shepherd, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	begun, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if begun.HandoffStartedAt == nil {
		t.Fatalf("handoff clock was never started")
	}

	now := time.Now().UTC().Add(time.Hour)
	// The handoff_to binds are the ones a caller that read an ACTIVE row would
	// carry: acquireUpsertSQL writes empty strings. So only the state clause
	// can refuse this write, which is what this test is about.
	restarted, err := scanOne(s.pool.QueryRow(ctx, handoffStartUpdateSQL,
		StateHandingOff, shepherd.Type, shepherd.ID, now, now, now,
		entity.Kind, entity.ID, PhaseReviewRemediation, begun.Epoch, StateActive,
		"", ""))
	if err == nil {
		t.Fatalf("a stale active read restarted the handoff clock to %v", restarted.HandoffStartedAt)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get after: %v", err)
	}
	if !after.HandoffStartedAt.Equal(*begun.HandoffStartedAt) {
		t.Fatalf("handoff clock restarted from %s to %s despite the refused write",
			*begun.HandoffStartedAt, *after.HandoffStartedAt)
	}
	if !after.LastSeenAt.Equal(begun.LastSeenAt) {
		t.Fatalf("liveness moved from %s to %s despite the refused write",
			begun.LastSeenAt, after.LastSeenAt)
	}

	// Other direction: with the state the row really has, the same statement
	// lands — this is the legitimate retarget path.
	other := Owner{Type: OwnerPRSteward, ID: "steward-1"}
	ok, err := scanOne(s.pool.QueryRow(ctx, handoffStartUpdateSQL,
		StateHandingOff, other.Type, other.ID, now, begun.LastSeenAt, now,
		entity.Kind, entity.ID, PhaseReviewRemediation, begun.Epoch, StateHandingOff,
		shepherd.Type, shepherd.ID))
	if err != nil {
		t.Fatalf("the statement refused the state the row really has: %v", err)
	}
	if ok.HandoffTo == nil || *ok.HandoffTo != other {
		t.Fatalf("retarget did not land: %+v", ok.HandoffTo)
	}
}

// TestFinishUpdateRefusesAnAbsorbingRecord pins the class predicate on
// finishUpdateSQL.
//
// finish is the one write that changes state while touching neither the epoch
// nor last_seen_at, so it is invisible to every other writer's guard — and it
// was also the one with no state guard of its own. Terminal followed by a
// stray retried Release at the same epoch therefore downgraded a finished
// entity back to released, where a reconciler picks it up again.
//
// It pins the CLASS, not an exact state: a concurrent HandoffStart is a
// legitimate thing to release on top of, and pinning `active` would make that
// fail spuriously.
func TestFinishUpdateRefusesAnAbsorbingRecord(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "finish-state-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	done, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	now := time.Now().UTC()
	downgraded, err := scanOne(s.pool.QueryRow(ctx, finishUpdateSQL,
		StateReleased, now, "stray retry",
		entity.Kind, entity.ID, PhaseReviewRemediation, done.Epoch))
	if err == nil {
		t.Fatalf("a merged entity was downgraded to %s and is claimable again", downgraded.State)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.State != StateTerminal {
		t.Fatalf("record is %s, want it still terminal", after.State)
	}

	// Other direction, on both members of the class the predicate admits.
	for _, state := range []string{StateActive, StateHandingOff} {
		live := pr(prefix, "finish-ok-"+state)
		fresh, err := s.Acquire(ctx, AcquireRequest{Entity: live, Phase: PhaseReviewRemediation, Owner: owner})
		if err != nil {
			t.Fatalf("acquire %s: %v", state, err)
		}
		if state == StateHandingOff {
			if _, err := s.HandoffStart(ctx, live, PhaseReviewRemediation, owner, fresh.Epoch,
				shepherd, "leaving"); err != nil {
				t.Fatalf("handoff start: %v", err)
			}
		}
		ok, err := scanOne(s.pool.QueryRow(ctx, finishUpdateSQL,
			StateReleased, now, "done",
			live.Kind, live.ID, PhaseReviewRemediation, fresh.Epoch))
		if err != nil {
			t.Fatalf("the statement refused a %s record: %v", state, err)
		}
		if ok.State != StateReleased {
			t.Fatalf("release from %s did not land: %s", state, ok.State)
		}
	}
}

// TestReacquireRefreshCannotUnfreezeAStateItDidNotRead pins the state
// predicate on reacquireRefreshSQL.
//
// The branch that issues it derives `seen` from the state it read: an active
// row moves last_seen_at, a handing-off one stays frozen. With only epoch and
// owner in the WHERE, a HandoffStart landing between the read and the write
// let seen = now unfreeze a handing-off row — the identical sequence
// progressUpdateSQL pins, arriving at the record through Acquire instead.
func TestReacquireRefreshCannotUnfreezeAStateItDidNotRead(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "reacquire-state-sql")
	owner := devloop("wf-1")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, owner, got.Epoch,
		shepherd, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	frozen, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	now := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	// The refresh a caller that read `active` would issue.
	revived, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		now, "sha-b", "wf-1", now,
		entity.Kind, entity.ID, PhaseReviewRemediation,
		frozen.Epoch, owner.Type, owner.ID, StateActive))
	if err == nil {
		t.Fatalf("a stale active read unfroze a handing-off row to %s", revived.LastSeenAt)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	after, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get after: %v", err)
	}
	if !after.LastSeenAt.Equal(frozen.LastSeenAt) {
		t.Fatalf("liveness moved from %s to %s despite the refused write",
			frozen.LastSeenAt, after.LastSeenAt)
	}

	// A finished row is refused too: finish moves neither epoch nor owner, so
	// without the predicate a stray re-acquire writes to a record currentFor
	// refuses every other write to.
	done := pr(prefix, "reacquire-terminal-sql")
	fresh, err := s.Acquire(ctx, AcquireRequest{Entity: done, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, done, PhaseReviewRemediation, owner, fresh.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if _, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		now, "sha-b", "wf-1", now,
		done.Kind, done.ID, PhaseReviewRemediation,
		fresh.Epoch, owner.Type, owner.ID, StateActive)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a merged entity accepted a re-acquire refresh: %v", err)
	}

	// Other direction: with the state the row really has, it lands.
	ok, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		frozen.LastSeenAt, "sha-b", "wf-1", now,
		entity.Kind, entity.ID, PhaseReviewRemediation,
		frozen.Epoch, owner.Type, owner.ID, StateHandingOff))
	if err != nil {
		t.Fatalf("the statement refused the state the row really has: %v", err)
	}
	if ok.Entity.Version != "sha-b" {
		t.Fatalf("the refresh did not land: %+v", ok.Entity)
	}
}

// TestHandoffCompleteCannotLandOnAFinishedOrRetargetedRow pins the two
// predicates on handoffCompleteUpdateSQL.
//
// Neither finish nor a retarget moves the epoch, so the epoch alone guarded
// neither decision this statement makes.
func TestHandoffCompleteCannotLandOnAFinishedOrRetargetedRow(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	steward := Owner{Type: OwnerPRSteward, ID: "steward-1"}

	// 1. A merged entity must not be resurrected as live work.
	merged := pr(prefix, "handoff-complete-terminal")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: merged, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, merged, PhaseReviewRemediation, owner, got.Epoch,
		steward, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	begun, err := s.Get(ctx, merged, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Out of band, at the same epoch: the PR merges while the incoming owner
	// is between its read and its write.
	if _, err := s.Terminal(ctx, merged, PhaseReviewRemediation, owner, begun.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	resurrected, err := scanOne(s.pool.QueryRow(ctx, handoffCompleteUpdateSQL,
		steward.Type, steward.ID, StateActive, now,
		merged.Kind, merged.ID, PhaseReviewRemediation, begun.Epoch,
		"wf-steward", "", StateHandingOff))
	if err == nil {
		t.Fatalf("a merged entity was handed to %+v as live work", resurrected.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	after, err := s.Get(ctx, merged, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get after: %v", err)
	}
	if after.State != StateTerminal {
		t.Fatalf("record is %s, want it still terminal", after.State)
	}

	// 2. An actor the handoff no longer names must not complete it.
	moved := pr(prefix, "handoff-complete-retargeted")
	got2, err := s.Acquire(ctx, AcquireRequest{Entity: moved, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, moved, PhaseReviewRemediation, owner, got2.Epoch,
		steward, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	aimed, err := s.Get(ctx, moved, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Retargeted at the same epoch, which a retarget does not move.
	if _, err := s.HandoffStart(ctx, moved, PhaseReviewRemediation, owner, aimed.Epoch,
		shepherd, "redirected"); err != nil {
		t.Fatalf("retarget: %v", err)
	}
	stolen, err := scanOne(s.pool.QueryRow(ctx, handoffCompleteUpdateSQL,
		steward.Type, steward.ID, StateActive, now,
		moved.Kind, moved.ID, PhaseReviewRemediation, aimed.Epoch,
		"wf-steward", "", StateHandingOff))
	if err == nil {
		t.Fatalf("an actor the handoff no longer names completed it: %+v", stolen.Owner)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// Through the API the caller is told which predicate failed.
	if _, err := s.HandoffComplete(ctx, moved, PhaseReviewRemediation, steward); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("want ErrNotOwner for a retargeted handoff, got %v", err)
	}

	// 3. state is pinned SEPARATELY, and this is the only case that proves it.
	//
	// Every writer today keeps state = handing-off and a non-empty handoff_to
	// in lockstep — handoffStartUpdateSQL sets both, finish, Recover and this
	// statement clear both — so in case 1 above the handoff_to predicate alone
	// already refuses the merged row, and removing `AND state = $11` leaves
	// that test green. A predicate no test can turn red is not a guard.
	//
	// So the invariant is broken deliberately, with a raw write no code path
	// performs, and the statement is asked to refuse the combination anyway.
	// That is what the predicate is for: it does not defend against today's
	// writers, it defends against tomorrow's forgetting to clear handoff_to.
	desync := pr(prefix, "handoff-complete-desynced")
	got3, err := s.Acquire(ctx, AcquireRequest{Entity: desync, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, desync, PhaseReviewRemediation, owner, got3.Epoch,
		steward, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	held, err := s.Get(ctx, desync, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET state = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		StateTerminal, desync.Kind, desync.ID, PhaseReviewRemediation); err != nil {
		t.Fatalf("desync: %v", err)
	}
	if _, err := scanOne(s.pool.QueryRow(ctx, handoffCompleteUpdateSQL,
		steward.Type, steward.ID, StateActive, now,
		desync.Kind, desync.ID, PhaseReviewRemediation, held.Epoch,
		"wf-steward", "", StateHandingOff)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a terminal row still naming a handoff target was completed: %v", err)
	}

	// Other direction: the named target still completes, and the completed row
	// carries no release timestamp.
	ok, err := scanOne(s.pool.QueryRow(ctx, handoffCompleteUpdateSQL,
		shepherd.Type, shepherd.ID, StateActive, now,
		moved.Kind, moved.ID, PhaseReviewRemediation, aimed.Epoch,
		"wf-cron", "", StateHandingOff))
	if err != nil {
		t.Fatalf("the named target was refused: %v", err)
	}
	if ok.Owner != shepherd || ok.State != StateActive {
		t.Fatalf("handoff did not complete: %+v", ok)
	}
	if ok.ReleasedAt != nil {
		t.Fatalf("a completed handoff kept a release timestamp: %v", ok.ReleasedAt)
	}
}

// TestReacquireTellsAStaleReaderToRetryNotThatItLost pins the sentinel on the
// re-acquire's no-row path, which the state predicate made reachable by two
// new routes.
//
// ErrOwnedByOther was exhaustive there until state joined the WHERE: only the
// owner or the epoch could make the statement miss, and both mean somebody
// else has it. HandoffStart and finish now miss it WITHOUT moving either, so a
// caller whose own Release committed between its read and its write was told
// "a DIFFERENT healthy actor holds this... the caller must not mutate" — which
// is what types.go promises that sentinel means — and handed back a row naming
// ITSELF. A caller obeying the contract stands down on a record a plain retry
// of Acquire would take.
//
// The interleaving cannot be produced through Acquire, because inTx holds the
// advisory lock across the read and the write, so the classification is driven
// with the row in the state the interleaving would have left it in.
func TestReacquireTellsAStaleReaderToRetryNotThatItLost(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")

	// The state each out-of-band writer leaves behind, at the SAME owner and
	// epoch — which is what makes the old sentinel wrong.
	for _, tc := range []struct {
		name  string
		leave func(t *testing.T, e EntityRef, epoch int)
		want  string
	}{
		{"released by its own owner", func(t *testing.T, e EntityRef, epoch int) {
			if _, err := s.Release(ctx, e, PhaseReviewRemediation, owner, epoch, "done"); err != nil {
				t.Fatalf("release: %v", err)
			}
		}, StateReleased},
		{"terminal", func(t *testing.T, e EntityRef, epoch int) {
			if _, err := s.Terminal(ctx, e, PhaseReviewRemediation, owner, epoch, "merged"); err != nil {
				t.Fatalf("terminal: %v", err)
			}
		}, StateTerminal},
		{"handing off", func(t *testing.T, e EntityRef, epoch int) {
			if _, err := s.HandoffStart(ctx, e, PhaseReviewRemediation, owner, epoch,
				shepherd, "leaving"); err != nil {
				t.Fatalf("handoff start: %v", err)
			}
		}, StateHandingOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entity := pr(prefix, "reacquire-stale-"+tc.want)
			got, err := s.Acquire(ctx, AcquireRequest{
				Entity: entity, Phase: PhaseReviewRemediation, Owner: owner,
			})
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			tc.leave(t, entity, got.Epoch)

			// What the interleaving would have left behind, classified by the
			// production function. Not driven through Acquire: under the lock
			// the row is READ in its new state, so a released one takes the
			// acquireUpsertSQL takeover path and an end-to-end call succeeds
			// whatever this returns — which is exactly how a wrong sentinel
			// survived here.
			latest, err := s.Get(ctx, entity, PhaseReviewRemediation)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if latest.State != tc.want {
				t.Fatalf("setup left %s, want %s", latest.State, tc.want)
			}
			err = reacquireMissSentinel(got, latest)
			if errors.Is(err, ErrOwnedByOther) {
				t.Fatalf("a %s row naming this very owner was reported as held by another actor",
					tc.want)
			}
			if !errors.Is(err, ErrStaleRead) {
				t.Fatalf("want ErrStaleRead on a %s row, got %v", tc.want, err)
			}

			// The other direction, with state, owner and epoch varied ONE AT
			// A TIME. Changing several together cannot tell which clause
			// answered, which is twice now how a clause survived here carrying
			// the very defect this function exists to remove.

			// A HOLDING row that names somebody else: the only genuine loss.
			stolen := *latest
			stolen.State = StateActive
			stolen.Owner = shepherd
			stolen.Epoch = got.Epoch + 1
			if err := reacquireMissSentinel(got, &stolen); !errors.Is(err, ErrOwnedByOther) {
				t.Fatalf("want ErrOwnedByOther when a held row really moved, got %v", err)
			}
			// Same, at the SAME epoch — unreachable today, since every write
			// that moves the owner bumps the epoch, but the owner is the clause
			// that decides and it has to be the one that fires.
			usurped := *latest
			usurped.State = StateActive
			usurped.Owner = shepherd
			if err := reacquireMissSentinel(got, &usurped); !errors.Is(err, ErrOwnedByOther) {
				t.Fatalf("want ErrOwnedByOther when the owner changed, got %v", err)
			}

			// An ABSORBING row that names somebody else. Reachable by a plain
			// sequence — wf-1 Releases, shepherd Acquires, shepherd Releases —
			// and it is a row NO actor holds, which Acquire may take. This is
			// the case the owner-first ordering got wrong.
			finished := *latest
			finished.State = StateReleased
			finished.Owner = shepherd
			finished.Epoch = got.Epoch + 1
			err = reacquireMissSentinel(got, &finished)
			if errors.Is(err, ErrOwnedByOther) {
				t.Fatalf("a released row no actor holds was reported as held by another: %v", err)
			}
			if !errors.Is(err, ErrStaleRead) {
				t.Fatalf("want ErrStaleRead for a finished row, got %v", err)
			}

			// Same owner, moved epoch: wf-1 stalls, its workflow Releases, a
			// new run re-Acquires through the takeover path. Nobody else ever
			// held it, so this is a retry, not a loss.
			recycled := *latest
			recycled.State = StateActive
			recycled.Epoch = got.Epoch + 1
			err = reacquireMissSentinel(got, &recycled)
			if errors.Is(err, ErrOwnedByOther) {
				t.Fatalf("a row still naming this owner at a new epoch was reported as held "+
					"by another actor: %v", err)
			}
			if !errors.Is(err, ErrStaleRead) {
				t.Fatalf("want ErrStaleRead for a recycled epoch, got %v", err)
			}
			if !strings.Contains(err.Error(), "epoch moved to") {
				t.Fatalf("the error does not say the epoch moved: %v", err)
			}

			// Nothing changed at all. The row changed and changed back, or
			// something outside this package wrote it — and the answer must not
			// invent a transition, which is what the sibling classifier's own
			// test forbids.
			same := *latest
			same.State = StateActive
			same.Owner = got.Owner
			same.Epoch = got.Epoch
			err = reacquireMissSentinel(got, &same)
			if !errors.Is(err, ErrStaleRead) {
				t.Fatalf("want ErrStaleRead when nothing explains the miss, got %v", err)
			}
			if strings.Contains(err.Error(), "became") || strings.Contains(err.Error(), "moved") {
				t.Fatalf("the catch-all claimed a transition it cannot know: %v", err)
			}
		})
	}
}

// TestRaceLostOnNamesWhichPredicateFailed drives the classifier directly.
//
// It is unreachable through the API by construction — inTx holds the advisory
// lock across every read and its write, which is the whole reason the
// statements it serves are package constants — so a direct test is the only
// one there can be. Without it the four arms are indistinguishable from one
// arm that always returns the same thing.
func TestRaceLostOnNamesWhichPredicateFailed(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")

	call := func(t *testing.T, e EntityRef, epoch int, pinned string) error {
		t.Helper()
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		return raceLostOn(ctx, tx, e, PhaseReviewRemediation, epoch, pinned, "the write")
	}

	// 1. Epoch moved: the caller lost the record and must stop.
	moved := pr(prefix, "race-epoch")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: moved, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Release(ctx, moved, PhaseReviewRemediation, owner, got.Epoch, "done"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := s.Acquire(ctx, AcquireRequest{Entity: moved, Phase: PhaseReviewRemediation, Owner: shepherd}); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if err := call(t, moved, got.Epoch, StateActive); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("want ErrEpochMismatch, got %v", err)
	}

	// 2. The record reached an absorbing state at the same epoch.
	done := pr(prefix, "race-absorbing")
	got2, err := s.Acquire(ctx, AcquireRequest{Entity: done, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, done, PhaseReviewRemediation, owner, got2.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if err := call(t, done, got2.Epoch, StateActive); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("want ErrNotOwner for an absorbing record, got %v", err)
	}

	// 3. Still holding, but not in the state the caller derived from: retry.
	shifted := pr(prefix, "race-pinned")
	got3, err := s.Acquire(ctx, AcquireRequest{Entity: shifted, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.HandoffStart(ctx, shifted, PhaseReviewRemediation, owner, got3.Epoch,
		shepherd, "leaving"); err != nil {
		t.Fatalf("handoff start: %v", err)
	}
	err = call(t, shifted, got3.Epoch, StateActive)
	if !errors.Is(err, ErrStaleRead) {
		t.Fatalf("want ErrStaleRead for a state the caller did not read, got %v", err)
	}
	// The MESSAGE is what separates this arm from the catch-all below: both
	// answer ErrStaleRead, so asserting only the sentinel lets this arm be
	// deleted with the test green. Naming both states is the arm's entire
	// contribution — it is what an operator reading the failure needs.
	if !strings.Contains(err.Error(), StateActive) || !strings.Contains(err.Error(), StateHandingOff) {
		t.Fatalf("the error does not say which state it moved from and to: %v", err)
	}

	// 4. Every predicate reads as satisfied — the row changed and changed
	//    back, or something outside this package wrote it. Still refuse, and
	//    say so differently: there is no from/to to report.
	err = call(t, shifted, got3.Epoch, StateHandingOff)
	if !errors.Is(err, ErrStaleRead) {
		t.Fatalf("want ErrStaleRead when nothing explains the miss, got %v", err)
	}
	if strings.Contains(err.Error(), "moved from") {
		t.Fatalf("the catch-all claimed a transition it cannot know: %v", err)
	}

	// 5. A row that is gone entirely is reported as gone, not misclassified.
	if err := call(t, pr(prefix, "race-absent"), 1, StateActive); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound for a deleted row, got %v", err)
	}
}

// TestFinishIsIdempotentForTheCallerThatAlreadyFinished pins the last
// asymmetry in the package: a successful write reporting failure on retry.
//
// currentFor refuses an absorbing record, which is right for a stray
// transition and wrong for the caller's own repeat — and the repeat is the
// shape HandoffComplete's idempotent branch names as its reason for existing.
// A dropped HTTP response makes a Temporal activity or an Argo pod send the
// identical call again, and the answer was "the caller tried to progress, hand
// off or release a record whose owner is somebody else" about a record the
// caller holds and has already finished.
func TestFinishIsIdempotentForTheCallerThatAlreadyFinished(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")

	for _, tc := range []struct {
		name  string
		call  func(e EntityRef, epoch int) (*Ownership, error)
		state string
		event string
	}{
		{"terminal", func(e EntityRef, epoch int) (*Ownership, error) {
			return s.Terminal(ctx, e, PhaseReviewRemediation, owner, epoch, "merged")
		}, StateTerminal, EventOwnerTerminal},
		{"release", func(e EntityRef, epoch int) (*Ownership, error) {
			return s.Release(ctx, e, PhaseReviewRemediation, owner, epoch, "done")
		}, StateReleased, EventOwnerReleased},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entity := pr(prefix, "finish-idempotent-"+tc.name)
			got, err := s.Acquire(ctx, AcquireRequest{
				Entity: entity, Phase: PhaseReviewRemediation, Owner: owner,
			})
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			first, err := tc.call(entity, got.Epoch)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			// The retry: identical arguments, as Temporal would send them.
			again, err := tc.call(entity, got.Epoch)
			if err != nil {
				t.Fatalf("a retried %s failed on work that had already succeeded: %v", tc.name, err)
			}
			if again.State != tc.state || again.Owner != owner || again.Epoch != got.Epoch {
				t.Fatalf("the retry returned a different record: %+v", again)
			}
			if !again.ReleasedAt.Equal(*first.ReleasedAt) {
				t.Fatalf("the retry rewrote the completion time: %s -> %s",
					*first.ReleasedAt, *again.ReleasedAt)
			}

			// And it is a no-op on the audit trail — an append-only table with
			// no retention must not gain a row per retry.
			var events int
			if err := s.pool.QueryRow(ctx,
				`SELECT count(*) FROM lifecycle_events
				 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3 AND event = $4`,
				entity.Kind, entity.ID, PhaseReviewRemediation, tc.event).Scan(&events); err != nil {
				t.Fatalf("count events: %v", err)
			}
			if events != 1 {
				t.Fatalf("a retried %s wrote %d events, want 1", tc.name, events)
			}
		})
	}

	// The other direction, and the property this must not weaken: a DIFFERENT
	// absorbing transition is still refused, because `state` is in the guard.
	entity := pr(prefix, "finish-idempotent-cross")
	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged"); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if _, err := s.Release(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "stray"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a merged entity was downgraded to released: %v", err)
	}

	// And somebody else's retry is not the caller's: same state, wrong owner.
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, shepherd, got.Epoch, "merged"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("another actor was handed this caller's completed write: %v", err)
	}
	// Same state and owner, wrong epoch.
	if _, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch+1, "merged"); err == nil {
		t.Fatalf("a stale epoch was treated as this caller's completed write")
	}
}

// TestFinishIdempotencySurvivesTheAdvisoryLockBeingRemoved pins the half of
// the idempotency that the pre-write read cannot carry.
//
// Two identical Terminal calls that OVERLAP rather than follow one another —
// and overlap is the COMMON shape, because a Temporal retry fires on the first
// attempt's timeout rather than on its failure — both read active@4, both pass
// currentFor, and the loser's finishUpdateSQL matches nothing because the
// state predicate no longer holds. raceLostOn then re-reads, finds the epoch
// unchanged and the state absorbing, and answers
// "record became terminal while the terminal write was in flight" — verbatim
// the answer the idempotency exists to stop giving.
//
// inTx takes the advisory lock before the closure runs, which orders the two
// reads and hides it. That is exactly the reasoning this file rejects for
// EXCLUDED.epoch, for Recover's liveness and for all seven WHERE clauses: a
// claim every write has to honour, not four of seven. So the question is asked
// again on the statement's own no-row path, and finishedBy is a named function
// for the same reason reacquireMissSentinel is — the lock makes the
// interleaving unreachable through the API, so driving it directly is the only
// way to show it distinguishes anything.
func TestFinishIdempotencySurvivesTheAdvisoryLockBeingRemoved(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	entity := pr(prefix, "finish-norow")

	got, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: owner,
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// The winning half of the overlap, written through the very statement the
	// loser is about to miss on — so the row is in precisely the state the
	// loser's own write would have produced.
	if _, err := scanOne(s.pool.QueryRow(ctx, finishUpdateSQL,
		StateTerminal, time.Now().UTC(), "merged",
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch)); err != nil {
		t.Fatalf("out-of-band terminal: %v", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The loser's no-row re-read: its own completed write, so success.
	done, err := s.finishedBy(ctx, tx, entity, PhaseReviewRemediation, owner, got.Epoch, StateTerminal)
	if err != nil {
		t.Fatalf("finishedBy: %v", err)
	}
	if done == nil {
		t.Fatal("a Terminal that lost the race to its OWN duplicate was told it lost")
	}
	if done.State != StateTerminal || done.Owner != owner || done.Epoch != got.Epoch {
		t.Fatalf("finishedBy returned a different record: %+v", done)
	}

	// The other three directions, one field at a time. Varying more than one
	// at once cannot tell which conjunct answered, which is how a clause
	// survives a mutation with the suite green.
	for _, tc := range []struct {
		name  string
		owner Owner
		epoch int
		state string
	}{
		// A Release after a Terminal asks for a different state. This is the
		// conjunct that keeps Terminal absorbing.
		{"a different state", owner, got.Epoch, StateReleased},
		// Somebody else's completed write is not this caller's answer.
		{"a different owner", devloop("wf-2"), got.Epoch, StateTerminal},
		// A stale epoch names a generation this caller no longer holds.
		{"a different epoch", owner, got.Epoch + 1, StateTerminal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.finishedBy(ctx, tx, entity, PhaseReviewRemediation, tc.owner, tc.epoch, tc.state)
			if err != nil {
				t.Fatalf("finishedBy: %v", err)
			}
			if got != nil {
				t.Fatalf("finishedBy answered for %s: %+v", tc.name, got)
			}
		})
	}
}

// TestHandoffCompleteIdempotencySurvivesTheAdvisoryLockBeingRemoved is the
// same property on the other write that has it.
//
// HandoffComplete's idempotent branch is also a pre-write read, so it answers
// only for a completion that FOLLOWS the original. Two completions in flight
// at once both read handing-off, and the loser's UPDATE matches nothing
// because the state predicate no longer holds — and the statement bumps the
// epoch, so raceLostOn answers ErrEpochMismatch about a handoff that completed
// exactly as asked.
func TestHandoffCompleteIdempotencySurvivesTheAdvisoryLockBeingRemoved(t *testing.T) {
	incoming := Owner{Type: OwnerPRSteward, ID: "steward"}
	base := &Ownership{State: StateActive, Owner: incoming, Epoch: 5}

	if !handoffAlreadyCompleted(base, incoming, 4) {
		t.Fatal("a completion that lost the race to its OWN duplicate was told it lost")
	}

	for _, tc := range []struct {
		name string
		row  Ownership
	}{
		// Still handing off: nobody completed anything, so this is a real miss.
		{"still handing off", Ownership{State: StateHandingOff, Owner: incoming, Epoch: 5}},
		// Completed to somebody else — a retarget that landed, not our write.
		{"a different incoming owner", Ownership{State: StateActive, Owner: Owner{Type: OwnerPRSteward, ID: "other"}, Epoch: 5}},
		// The epoch this caller read plus one is the ONLY generation its own
		// write could have produced; anything further is a later handoff that
		// happened to land on the same owner.
		{"a later handoff to the same owner", Ownership{State: StateActive, Owner: incoming, Epoch: 7}},
		// A finished row is not a completed handoff.
		{"terminal", Ownership{State: StateTerminal, Owner: incoming, Epoch: 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := tc.row
			if handoffAlreadyCompleted(&row, incoming, 4) {
				t.Fatalf("answered for %s: %+v", tc.name, row)
			}
		})
	}
}

// TestAnOverlappingTerminalReachesTheNoRowPathAndSucceeds drives the
// interleaving itself rather than the predicate, so the CALL SITE is pinned
// and not only finishedBy.
//
// The advisory lock stops two Store calls from overlapping, but nothing stops
// a writer that does not take it — which is the whole point: the guarantee
// must not depend on the lock. Under READ COMMITTED an UPDATE that blocks on a
// concurrently locked row re-evaluates its WHERE against the committed
// version, so the winner's state change makes the loser's predicate fail and
// the loser sees zero rows. That is the real production shape, reproduced
// exactly:
//
//	tx2 (no lock)  UPDATE ... terminal        -- holds the row
//	Terminal()     read: active@1             -- fast path misses
//	Terminal()     UPDATE ...                 -- blocks on tx2's row lock
//	tx2            COMMIT
//	Terminal()     re-evaluates WHERE -> 0 rows, no-row path
//
// Without the idempotency on that path the answer is
// "record became terminal while the terminal write was in flight" for a
// terminal that landed exactly as asked.
func TestAnOverlappingTerminalReachesTheNoRowPathAndSucceeds(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	entity := pr(prefix, "finish-overlap")

	got, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: owner,
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// The winner: the identical write, from a connection that takes no
	// advisory lock, held open so the loser blocks on the ROW lock.
	winner, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin winner: %v", err)
	}
	defer func() { _ = winner.Rollback(ctx) }()
	if _, err := scanOne(winner.QueryRow(ctx, finishUpdateSQL,
		StateTerminal, time.Now().UTC(), "merged",
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch)); err != nil {
		t.Fatalf("winner terminal: %v", err)
	}

	type result struct {
		own *Ownership
		err error
	}
	done := make(chan result, 1)
	go func() {
		own, err := s.Terminal(ctx, entity, PhaseReviewRemediation, owner, got.Epoch, "merged")
		done <- result{own, err}
	}()

	// Let the loser get past its read and onto the blocked UPDATE. If it has
	// not blocked yet the test still passes through the fast path, which would
	// make this a weaker test rather than a flaky one — so assert it really
	// did block, by requiring that it has NOT finished before the commit.
	select {
	case r := <-done:
		t.Fatalf("the loser never blocked on the row lock: %+v %v", r.own, r.err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := winner.Commit(ctx); err != nil {
		t.Fatalf("commit winner: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("a Terminal that lost the race to an identical overlapping "+
				"Terminal was told it failed: %v", r.err)
		}
		if r.own.State != StateTerminal || r.own.Owner != owner || r.own.Epoch != got.Epoch {
			t.Fatalf("the loser returned a different record: %+v", r.own)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loser never returned after the winner committed")
	}

	// One event, not two: the loser wrote nothing.
	var events int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM lifecycle_events
		 WHERE entity_kind = $1 AND entity_id = $2 AND phase = $3 AND event = $4`,
		entity.Kind, entity.ID, PhaseReviewRemediation, EventOwnerTerminal).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 0 {
		t.Fatalf("the loser appended %d events for a write it did not make", events)
	}
}

// TestAStalledReannouncementCannotRevertARetarget closes the second input
// handoffStartUpdateSQL derives from and did not pin.
//
// The rule the package applies to all seven writes is "pin what the statement
// DERIVED from the row it read", and for HandoffStart the state is not the
// only such input: `started` comes from current.HandoffTo and
// current.HandoffStartedAt. A retarget by the SAME owner moves both while
// leaving the epoch and the state alone — handing-off stays handing-off — so
// it is the one writer that gets underneath a predicate of epoch + state.
//
// A re-announcement that read the OLD target and stalled would then write it
// back over an acknowledged, evented retarget, roll handoff_started_at back to
// the replaced handoff's clock, and suppress its own event because
// `reannounced` is computed from the same stale read — leaving the row naming
// one actor and the last event naming another.
//
// Driven through the statement directly, because inTx serialises the two
// writers through the API and the constant is shared for exactly this reason.
func TestAStalledReannouncementCannotRevertARetarget(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-retarget-revert")
	outgoing := devloop("wf-1")
	first := Owner{Type: OwnerPRSteward, ID: "cron"}
	second := Owner{Type: OwnerPRSteward, ID: "steward"}

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	started, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, first, "exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}

	// The retarget the stalled re-announcement is about to try to undo. Same
	// owner, same epoch, same state — nothing the old predicate could see.
	retargeted, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, second, "redirect")
	if err != nil {
		t.Fatalf("retarget: %v", err)
	}
	if retargeted.HandoffTo == nil || *retargeted.HandoffTo != second {
		t.Fatalf("retarget did not take: %+v", retargeted.HandoffTo)
	}

	// The stalled re-announcement, replayed with the values it read BEFORE the
	// retarget: the old target, the old clock, the old state.
	_, err = scanOne(s.pool.QueryRow(ctx, handoffStartUpdateSQL,
		StateHandingOff, first.Type, first.ID, *started.HandoffStartedAt, started.LastSeenAt, time.Now().UTC(),
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch, StateHandingOff,
		first.Type, first.ID))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a stalled re-announcement reverted an acknowledged retarget: %v", err)
	}

	// And the row still names the actor the API and the event trail named.
	now, err := s.Get(ctx, entity, PhaseReviewRemediation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if now.HandoffTo == nil || *now.HandoffTo != second {
		t.Fatalf("the handoff target moved back: %+v", now.HandoffTo)
	}
	if !now.HandoffStartedAt.Equal(*retargeted.HandoffStartedAt) {
		t.Fatalf("the handoff clock rolled back to the replaced handoff: %v -> %v",
			*retargeted.HandoffStartedAt, *now.HandoffStartedAt)
	}

	// And the API says WHICH thing happened, rather than falling through to
	// raceLostOn's catch-all. That matters beyond the message: ErrStaleRead
	// means retry, and a retry of the stalled re-announcement reads the new
	// target, takes the retarget branch, and performs the revert as a fresh
	// retarget — evented and with a new clock, but still the outcome the
	// predicate was added to prevent, recommended by the sentinel.
	// Driven through the real interleaving, because through the API the
	// re-announcement re-reads inside its own transaction and sees the new
	// target, so it is an ordinary retarget. Under READ COMMITTED a blocked
	// UPDATE re-evaluates its WHERE against the committed version, so a
	// connection that takes no advisory lock and holds the row reproduces the
	// stall exactly.
	blocker, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker: %v", err)
	}
	third := Owner{Type: OwnerPRSteward, ID: "third"}
	if _, err := scanOne(blocker.QueryRow(ctx, handoffStartUpdateSQL,
		StateHandingOff, third.Type, third.ID, time.Now().UTC(), now.LastSeenAt, time.Now().UTC(),
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch, StateHandingOff,
		second.Type, second.ID)); err != nil {
		_ = blocker.Rollback(ctx)
		t.Fatalf("blocker retarget: %v", err)
	}

	stalled := make(chan error, 1)
	go func() {
		_, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, second, "stalled")
		stalled <- err
	}()
	select {
	case err := <-stalled:
		_ = blocker.Rollback(ctx)
		t.Fatalf("the stalled re-announcement never blocked: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("commit blocker: %v", err)
	}
	select {
	case err := <-stalled:
		if err == nil {
			t.Fatal("a stalled re-announcement reverted a retarget through the API")
		}
		// ErrStaleRead MEANS retry, and a retry reads the new target and
		// performs the revert as a fresh retarget — evented and with a new
		// clock, but still the outcome the predicate was added to prevent.
		if errors.Is(err, ErrStaleRead) {
			t.Fatalf("a retarget was reported as a stale read, which means retry: %v", err)
		}
		if !errors.Is(err, ErrNotOwner) || !strings.Contains(err.Error(), "retargeted") {
			t.Fatalf("want a named retarget refusal, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled re-announcement never returned")
	}

	// The other direction: the predicate must not refuse a genuine
	// re-announcement, which is the write it sits on top of.
	if _, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, third, "still exiting"); err != nil {
		t.Fatalf("a genuine re-announcement was refused: %v", err)
	}
	// And so must the first handoff off an ACTIVE row, where the pinned
	// columns are the empty strings acquireUpsertSQL wrote.
	fresh := pr(prefix, "handoff-retarget-fresh")
	f, err := s.Acquire(ctx, AcquireRequest{Entity: fresh, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire fresh: %v", err)
	}
	if _, err := s.HandoffStart(ctx, fresh, PhaseReviewRemediation, outgoing, f.Epoch, first, "exiting"); err != nil {
		t.Fatalf("the first handoff off an active row was refused: %v", err)
	}
}

// TestAnOverlappingHandoffCompleteReachesTheNoRowPathAndSucceeds pins the
// CALL SITE of handoffAlreadyCompleted, not only the predicate.
//
// finish's equivalent got both a table over finishedBy and a real row-lock
// interleaving; HandoffComplete's got only the table, so deleting the two
// lines that wire the helper in left the suite green. Same harness: a
// connection that takes no advisory lock holds the row, the loser reads
// handing-off, blocks on the row lock, and after the commit its WHERE no
// longer matches — and because the statement bumps the epoch, raceLostOn
// answers ErrEpochMismatch about a handoff that completed exactly as asked.
func TestAnOverlappingHandoffCompleteReachesTheNoRowPathAndSucceeds(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	entity := pr(prefix, "handoff-complete-overlap")
	outgoing := devloop("wf-1")
	incoming := Owner{Type: OwnerPRSteward, ID: "steward"}

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: outgoing})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	begun, err := s.HandoffStart(ctx, entity, PhaseReviewRemediation, outgoing, got.Epoch, incoming, "exiting")
	if err != nil {
		t.Fatalf("handoff start: %v", err)
	}

	// The winner: the identical completion, through the same statement, from a
	// connection that takes no advisory lock and holds the row.
	winner, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin winner: %v", err)
	}
	defer func() { _ = winner.Rollback(ctx) }()
	if _, err := scanOne(winner.QueryRow(ctx, handoffCompleteUpdateSQL,
		incoming.Type, incoming.ID, StateActive, time.Now().UTC(),
		entity.Kind, entity.ID, PhaseReviewRemediation, begun.Epoch,
		"", "", StateHandingOff)); err != nil {
		t.Fatalf("winner completion: %v", err)
	}

	type result struct {
		own *Ownership
		err error
	}
	done := make(chan result, 1)
	go func() {
		own, err := s.HandoffComplete(ctx, entity, PhaseReviewRemediation, incoming)
		done <- result{own, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("the loser never blocked on the row lock: %+v %v", r.own, r.err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := winner.Commit(ctx); err != nil {
		t.Fatalf("commit winner: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("a completion that lost the race to an identical overlapping "+
				"completion was told it failed: %v", r.err)
		}
		if r.own.State != StateActive || r.own.Owner != incoming || r.own.Epoch != begun.Epoch+1 {
			t.Fatalf("the loser returned a different record: %+v", r.own)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loser never returned after the winner committed")
	}
}

// TestACarriedForwardVersionCannotRevertANewerOne pins the last two derived
// inputs: entity_version and temporal_workflow_id.
//
// Both were Go-side fallbacks ONTO the stored value — a read promoted into a
// write — and neither statement pinned the column. The writer that gets
// underneath is the other statement of the pair: progressUpdateSQL writes
// entity_version while moving none of epoch, owner or state, so a stalled
// re-acquire that had read sha-a puts it back over sha-b. The row then
// disagrees with its own latest event, which is exactly what
// TestEventsCarryTheStoredVersion exists to prevent — and it runs BACKWARDS,
// so it does not heal on the next tick.
//
// The fix is the one the epoch already had: the carry-forward is the
// DATABASE's (COALESCE/NULLIF), so the stored value is never read into the
// caller and cannot be written back stale.
func TestACarriedForwardVersionCannotRevertANewerOne(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	entity := pr(prefix, "version-carry")

	got, err := s.Acquire(ctx, AcquireRequest{
		Entity: entity, Phase: PhaseReviewRemediation, Owner: owner,
		TemporalWorkflowID: "wf-run-1",
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got.Entity.Version != "sha-a" {
		t.Fatalf("setup: want sha-a, got %q", got.Entity.Version)
	}

	// The newer version, written out of band through the production statement
	// — the other half of the pair, which moves neither epoch nor state.
	now := time.Now().UTC()
	if _, err := scanOne(s.pool.QueryRow(ctx, progressUpdateSQL,
		now, now, "pushed sha-b", "sha-b",
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch, StateActive)); err != nil {
		t.Fatalf("out-of-band progress: %v", err)
	}

	// The stalled re-acquire, replayed with what it read BEFORE: no version of
	// its own, so it used to carry sha-a forward.
	refreshed, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		now, "", "", now,
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch,
		owner.Type, owner.ID, StateActive))
	if err != nil {
		t.Fatalf("re-acquire refresh: %v", err)
	}
	if refreshed.Entity.Version != "sha-b" {
		t.Fatalf("a stalled re-acquire reverted the version to %q", refreshed.Entity.Version)
	}
	if refreshed.TemporalWorkflowID != "wf-run-1" {
		t.Fatalf("an empty correlation id cleared the stored one: %q", refreshed.TemporalWorkflowID)
	}

	// The other direction: a value that IS supplied must still be written, or
	// the carry-forward has become a freeze. This is the pod-restart case the
	// re-acquire exists for.
	replaced, err := scanOne(s.pool.QueryRow(ctx, reacquireRefreshSQL,
		now, "sha-c", "wf-run-2", now,
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch,
		owner.Type, owner.ID, StateActive))
	if err != nil {
		t.Fatalf("re-acquire refresh with values: %v", err)
	}
	if replaced.Entity.Version != "sha-c" || replaced.TemporalWorkflowID != "wf-run-2" {
		t.Fatalf("a supplied version or correlation id was ignored: %+v", replaced)
	}

	// And the same both ways through progressUpdateSQL, which carries the
	// version forward on the identical argument.
	kept, err := scanOne(s.pool.QueryRow(ctx, progressUpdateSQL,
		now, now, "still working", "",
		entity.Kind, entity.ID, PhaseReviewRemediation, got.Epoch, StateActive))
	if err != nil {
		t.Fatalf("progress with no version: %v", err)
	}
	if kept.Entity.Version != "sha-c" {
		t.Fatalf("a progress write with no version cleared the stored one: %q", kept.Entity.Version)
	}
}

// TestEventsClampAlsoCapsRatherThanDefaults covers the half of the clamp split
// that had no test. Two identical branches with one test between them is the
// shape that let the handoff_to predicate ship unpinned for a round.
func TestEventsClampAlsoCapsRatherThanDefaults(t *testing.T) {
	s, prefix := newTestStore(t)
	ctx := context.Background()
	owner := devloop("wf-1")
	entity := pr(prefix, "events-clamp")

	got, err := s.Acquire(ctx, AcquireRequest{Entity: entity, Phase: PhaseReviewRemediation, Owner: owner})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// One event per progress write, so more than the default page of 100.
	for i := range 120 {
		if _, err := s.RecordProgress(ctx, entity, PhaseReviewRemediation, owner, got.Epoch,
			fmt.Sprintf("tick %d", i)); err != nil {
			t.Fatalf("progress %d: %v", i, err)
		}
	}
	big, err := s.Events(ctx, entity, PhaseReviewRemediation, 100000)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(big) <= 100 {
		t.Fatalf("an over-cap limit returned the default page, not the cap: %d events", len(big))
	}
	small, err := s.Events(ctx, entity, PhaseReviewRemediation, 0)
	if err != nil {
		t.Fatalf("events default: %v", err)
	}
	if len(small) != 100 {
		t.Fatalf("an unset limit did not take the default page: %d events", len(small))
	}
}
