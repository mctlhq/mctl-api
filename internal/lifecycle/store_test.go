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
