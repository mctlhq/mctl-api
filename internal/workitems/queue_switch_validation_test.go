package workitems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Validation tests for the queue-while-active switch (issue-931 T1-T8, T10).
// Real PostgreSQL, like the rest of this package.

func runningExec(t *testing.T, s *Store, w *WorkItem, ref string) *Execution {
	t.Helper()
	e, _, err := s.AttachExecution(context.Background(), ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: ref, Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func endExec(t *testing.T, s *Store, w *WorkItem, ref, phase string) {
	t.Helper()
	if _, _, err := s.AttachExecution(context.Background(), ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: ref, Phase: phase}); err != nil {
		t.Fatal(err)
	}
}

func countRequests(t *testing.T, s *Store, itemID string) int {
	t.Helper()
	xs, err := s.ExecutionRequests(context.Background(), itemID)
	if err != nil {
		t.Fatal(err)
	}
	return len(xs)
}

func countKind(t *testing.T, s *Store, itemID, kind string) int {
	n := 0
	for _, k := range eventKinds(t, s, itemID) {
		if k == kind {
			n++
		}
	}
	return n
}

// T1: switch off - 409 execution_active, nothing stored, nothing remembered.
func TestQueueValidation_T1_OffStoresNothingAndRemembersNothing(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	runningExec(t, s, w, "wf#run_1")
	in := xrInput(w, ExecutionRequestResume, keyed("github:alice", "k-1", "h-1"))
	for i := 0; i < 2; i++ { // the same key again is still refused: not remembered
		_, _, err := s.CreateExecutionRequest(ctx, in)
		if !errors.Is(err, ErrExecutionActive) {
			t.Fatalf("attempt %d err = %v", i, err)
		}
	}
	if n := countRequests(t, s, w.ID); n != 0 {
		t.Fatalf("%d request rows", n)
	}
	if n := countKind(t, s, w.ID, EventExecutionRequested); n != 0 {
		t.Fatalf("%d execution_requested events", n)
	}
	var keys int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM work_item_idempotency WHERE work_item_id=$1`, w.ID).Scan(&keys); err == nil && keys != 0 {
		t.Fatalf("%d idempotency records", keys)
	}
	// Once the execution has closed the very same key creates normally
	// (proving the refused call left no record behind).
	endExec(t, s, w, "wf#run_1", PhaseSucceeded)
	x, created, err := s.CreateExecutionRequest(ctx, in)
	if err != nil || !created || x.QueuedBehindExecutionID != "" {
		t.Fatalf("after close = %+v %v %v", x, created, err)
	}
}

// T2: queued request keeps every stored field; the event names the blocker.
func TestQueueValidation_T2_QueuedFieldsAndEvent(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	intent := appendIntent(t, s, w, "resume please")
	e := runningExec(t, s, w, "wf#run_1")
	m := keyed("github:alice", "k-2", "h-2")
	m.Surface, m.ActingPrincipal = "telegram", "surface:telegram"
	m.ActorPrincipalID, m.ViaPrincipalID = "prn_alice", "prn_tg"
	in := xrInput(w, ExecutionRequestResume, m)
	in.IntentID = &intent.ID
	in.ResumedFromExecutionID = e.ID
	x := requestExecution(t, s, in)
	got, err := s.ExecutionRequest(ctx, w.ID, x.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != ExecutionRequestPending || got.RequestedBy != "github:alice" || got.Surface != "telegram" ||
		got.ActingPrincipal != "surface:telegram" || got.IntentID == nil || *got.IntentID != intent.ID ||
		got.ResumedFromExecutionID != e.ID || got.ExpectedStateVersion != in.ExpectedStateVersion || got.IdempotencyKey != "k-2" {
		t.Fatalf("stored %+v", got)
	}
	if x.QueuedBehindExecutionID != e.ID {
		t.Fatalf("response blocker = %q want %q", x.QueuedBehindExecutionID, e.ID)
	}
	if got.QueuedBehindExecutionID != "" {
		t.Fatalf("queued_behind is stored on the row: %q", got.QueuedBehindExecutionID)
	}
	events, _ := s.Events(ctx, w.ID)
	var detail map[string]any
	for _, ev := range events {
		if ev.Kind == EventExecutionRequested {
			_ = json.Unmarshal(ev.Detail, &detail)
		}
	}
	if detail["queued_behind_execution_id"] != e.ID {
		t.Fatalf("event detail %v", detail)
	}
	// A request made with no execution open carries no blocker.
	w2 := open(t, s, CreateInput{Title: "calm"})
	y := requestExecution(t, s, xrInput(w2, ExecutionRequestStart, Mutation{}))
	if y.QueuedBehindExecutionID != "" {
		t.Fatalf("unblocked request has blocker %q", y.QueuedBehindExecutionID)
	}
}

// T3: replay while open and after close; one row; other body is key reuse.
func TestQueueValidation_T3_ReplayOpenAndClosed(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	runningExec(t, s, w, "wf#run_1")
	in := xrInput(w, ExecutionRequestResume, keyed("github:alice", "k-3", "h-3"))
	first := requestExecution(t, s, in)
	for _, phase := range []string{"", PhaseSucceeded} {
		if phase != "" {
			endExec(t, s, w, "wf#run_1", phase)
		}
		again, created, err := s.CreateExecutionRequest(ctx, in)
		if err != nil || created || again.ID != first.ID {
			t.Fatalf("replay(%q) = %+v %v %v", phase, again, created, err)
		}
		if n := countRequests(t, s, w.ID); n != 1 {
			t.Fatalf("replay(%q): %d rows", phase, n)
		}
	}
	diff := in
	diff.Mutation = keyed("github:alice", "k-3", "h-OTHER")
	if _, _, err := s.CreateExecutionRequest(ctx, diff); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("other body = %v", err)
	}
	if n := countKind(t, s, w.ID, EventExecutionRequested); n != 1 {
		t.Fatalf("%d execution_requested events", n)
	}
}

// T4: every other refusal is unchanged while an execution is open and the
// switch is on, and none of them stores anything.
func TestQueueValidation_T4_OtherRefusalsUnchanged(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	other := open(t, s, CreateInput{Title: "other"})
	e := runningExec(t, s, w, "wf#run_1")
	foreignIntent := appendIntent(t, s, other, "x")
	redactable := appendIntent(t, s, w, "to redact")
	redact(t, s, redactable)

	stale := xrInput(w, ExecutionRequestResume, Mutation{})
	stale.ExpectedStateVersion = 99
	if _, _, err := s.CreateExecutionRequest(ctx, stale); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("stale version = %v", err)
	}
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, Mutation{})); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("start while open = %v", err)
	}
	unknown := xrInput(w, ExecutionRequestResume, Mutation{})
	unknown.ResumedFromExecutionID = "we_nope"
	if _, _, err := s.CreateExecutionRequest(ctx, unknown); !errors.Is(err, ErrExecutionNotFound) {
		t.Errorf("unknown resumed_from = %v", err)
	}
	foreign := xrInput(w, ExecutionRequestResume, Mutation{})
	foreign.IntentID = &foreignIntent.ID
	if _, _, err := s.CreateExecutionRequest(ctx, foreign); !errors.Is(err, ErrIntentNotFound) {
		t.Errorf("foreign intent = %v", err)
	}
	red := xrInput(w, ExecutionRequestResume, Mutation{})
	red.IntentID = &redactable.ID
	if _, _, err := s.CreateExecutionRequest(ctx, red); !errors.Is(err, ErrIntentUnavailable) {
		t.Errorf("redacted intent = %v", err)
	}
	if n := countRequests(t, s, w.ID); n != 0 {
		t.Fatalf("refusals stored %d rows", n)
	}
	// A second open request.
	ok := xrInput(w, ExecutionRequestResume, Mutation{})
	ok.ResumedFromExecutionID = e.ID
	requestExecution(t, s, ok)
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestResume, Mutation{})); !errors.Is(err, ErrExecutionRequestOpen) {
		t.Errorf("second open request = %v", err)
	}
	// A terminal item, with an execution still open (archive then ask).
	runningExec(t, s, other, "wf#run_9")
	arch, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: other.ID, Action: ActionArchive, ExpectedStateVersion: other.StateVersion})
	if err != nil {
		t.Fatal(err)
	}
	tin := xrInput(other, ExecutionRequestResume, Mutation{})
	tin.ExpectedStateVersion = arch.StateVersion
	if _, _, err := s.CreateExecutionRequest(ctx, tin); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("terminal item with open execution = %v", err)
	}
}

func setLapsed(t *testing.T, s *Store, reqID string) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `UPDATE work_item_execution_requests SET claim_expires_at = now() - interval '1 minute' WHERE id=$1`, reqID); err != nil {
		t.Fatal(err)
	}
}

// T5: claim guard for pending and for lapsed-claimed; blocked items never
// starve an unblocked one; no claim event is written for a blocked item.
func TestQueueValidation_T5_ClaimGuard(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	runningExec(t, s, w, "wf#run_1")
	x := requestExecution(t, s, xrInput(w, ExecutionRequestResume, Mutation{}))
	if got, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute}); got != nil || err != nil {
		t.Fatalf("pending behind running = %+v %v", got, err)
	}
	// Lapsed claim: claim it while the item is calm, then open an execution.
	endExec(t, s, w, "wf#run_1", PhaseSucceeded)
	claimed := claim(t, s)
	if claimed.ID != x.ID {
		t.Fatal("wrong request")
	}
	runningExec(t, s, w, "wf#run_2")
	setLapsed(t, s, x.ID)
	if got, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute}); got != nil || err != nil {
		t.Fatalf("lapsed-claimed behind running = %+v %v", got, err)
	}
	if n := countKind(t, s, w.ID, EventExecutionRequestClaimed); n != 1 {
		t.Fatalf("claim events = %d, want only the first", n)
	}

	// Starvation: 9 blocked items (older) then one unblocked item.
	s2 := queueStore(t)
	for i := 0; i < claimCandidates+1; i++ {
		b := open(t, s2, CreateInput{Title: fmt.Sprintf("blocked-%d", i)})
		runningExec(t, s2, b, "wf#run_b")
		requestExecution(t, s2, xrInput(b, ExecutionRequestResume, Mutation{}))
	}
	free := open(t, s2, CreateInput{Title: "free"})
	fx := requestExecution(t, s2, xrInput(free, ExecutionRequestStart, Mutation{}))
	if got := claim(t, s2); got.ID != fx.ID {
		t.Fatalf("claimed %s, want the unblocked %s", got.ID, fx.ID)
	}
}

// T6: all four outcomes (Cancel and Timeout reach mctl-api as Error).
func TestQueueValidation_T6_FourOutcomes(t *testing.T) {
	for name, phase := range map[string]string{"succeeded": PhaseSucceeded, "failed": PhaseFailed, "error-cancel": PhaseError, "error-timeout": PhaseError} {
		t.Run(name, func(t *testing.T) {
			s := queueStore(t)
			ctx := context.Background()
			w := open(t, s, CreateInput{})
			e := runningExec(t, s, w, "wf#run_1")
			m := keyed("github:alice", "k-6", "h-6")
			m.Surface = "telegram"
			in := xrInput(w, ExecutionRequestResume, m)
			x := requestExecution(t, s, in)
			if got, _, _ := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute}); got != nil {
				t.Fatal("claimable while running")
			}
			endExec(t, s, w, "wf#run_1", phase)
			got := claim(t, s)
			if got.ID != x.ID || got.RequestedBy != "github:alice" || got.Surface != "telegram" || got.IdempotencyKey != "k-6" ||
				got.ExpectedStateVersion != in.ExpectedStateVersion || got.Kind != ExecutionRequestResume {
				t.Fatalf("claimed %+v", got)
			}
			done, _, next, created, err := s.FulfilExecutionRequest(ctx, fulfil(got, got.ClaimToken, "wf#run_2"))
			if err != nil || !created {
				t.Fatalf("fulfil = %v %v", created, err)
			}
			if next.ResumedFromExecutionID != e.ID || done.ExecutionID != next.ID || done.State != ExecutionRequestFulfilled {
				t.Fatalf("exec %+v request %+v", next, done)
			}
			if execs, _ := s.Executions(ctx, w.ID); len(execs) != 2 {
				t.Fatalf("%d executions", len(execs))
			}
		})
	}
}

// T7: state_version advanced after queueing -> fulfil refuses, attaches
// nothing, and the holder can reject.
func TestQueueValidation_T7_StaleVersionAtFulfil(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	runningExec(t, s, w, "wf#run_1")
	requestExecution(t, s, xrInput(w, ExecutionRequestResume, Mutation{}))
	if _, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: w.StateVersion}); err != nil {
		t.Fatal(err)
	}
	endExec(t, s, w, "wf#run_1", PhaseSucceeded)
	x := claim(t, s)
	_, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "wf#run_2"))
	conflictCurrent(t, err, ErrVersionConflict)
	if execs, _ := s.Executions(ctx, w.ID); len(execs) != 1 {
		t.Fatalf("%d executions, want 1", len(execs))
	}
	r, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ClaimRef{Mutation: as(platform), RequestID: x.ID, ClaimToken: x.ClaimToken}, Reason: "stale"})
	if err != nil || r.State != ExecutionRequestRejected {
		t.Fatalf("reject = %+v %v", r, err)
	}
}

// Fulfil race: an execution opens after claim; fulfil is execution_active
// and the request stays claimed.
func TestQueueValidation_FulfilRaceStaysClaimed(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	runningExec(t, s, w, "wf#run_1")
	requestExecution(t, s, xrInput(w, ExecutionRequestResume, Mutation{}))
	endExec(t, s, w, "wf#run_1", PhaseSucceeded)
	x := claim(t, s)
	runningExec(t, s, w, "wf#run_direct")
	_, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "wf#run_2"))
	if !errors.Is(err, ErrExecutionActive) {
		t.Fatalf("fulfil = %v", err)
	}
	got, _ := s.ExecutionRequest(ctx, w.ID, x.ID)
	if got.State != ExecutionRequestClaimed {
		t.Fatalf("state %s", got.State)
	}
}

// T8: an execution opens between the candidate scan and the item lock.
func TestQueueValidation_T8_RaceBetweenScanAndLock(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
	holder, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "workitem:"+w.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var got *ExecutionRequest
	var cerr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, _, cerr = s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := holder.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claim never reached the item lock (scan found no candidate?)")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The claimant has scanned the request as a candidate and waits on the
	// lock; open an execution now, then release.
	if _, err := insertExecution(ctx, holder, as(platform), w.ID, EngineTemporal, "wf#run_late", PhaseRunning, "", 1, AttachPathAttach, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if cerr != nil || got != nil {
		t.Fatalf("claim = %+v %v, want nil", got, cerr)
	}
	if n := countKind(t, s, w.ID, EventExecutionRequestClaimed); n != 0 {
		t.Fatalf("claim events = %d", n)
	}
	r, _ := s.ExecutionRequests(ctx, w.ID)
	if len(r) != 1 || r[0].State != ExecutionRequestPending {
		t.Fatalf("request touched: %+v", r)
	}
}

// T10: the loop reports Succeeded first; the sweeper's close is a no-op.
func TestQueueValidation_T10_CloseOrphanedLosesToSucceeded(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e := runningExec(t, s, w, "wf#run_1")
	endExec(t, s, w, "wf#run_1", PhaseSucceeded)
	before := countKind(t, s, w.ID, EventExecutionOrphanClosed)
	c, closed, err := s.CloseOrphanedExecution(ctx, OrphanCloseInput{Mutation: as(platform), ExecutionID: e.ID, ExpectedPhase: PhaseRunning, EngineStatus: "Terminated"})
	if err != nil || closed || c != nil {
		t.Fatalf("close = %+v %v %v", c, closed, err)
	}
	got, _ := s.ExecutionByID(ctx, e.ID)
	if got.Phase != PhaseSucceeded {
		t.Fatalf("phase %s", got.Phase)
	}
	if countKind(t, s, w.ID, EventExecutionOrphanClosed) != before {
		t.Fatal("an orphan event was written")
	}
	if _, _, err := s.CloseOrphanedExecution(ctx, OrphanCloseInput{Mutation: as(platform), ExecutionID: e.ID, ExpectedPhase: PhaseSucceeded}); err == nil {
		t.Fatal("a terminal expected_phase must be refused")
	}
}

// Fulfil of a START request keeps the active-execution guard (checkStart
// passes allowActive=false): execution_active, request stays claimed.
func TestQueueValidation_StartFulfilStillRefusesActive(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
	x := claim(t, s)
	runningExec(t, s, w, "wf#run_direct")
	_, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "wf#run_2"))
	if !errors.Is(err, ErrExecutionActive) {
		t.Fatalf("fulfil start = %v", err)
	}
	if got, _ := s.ExecutionRequest(ctx, w.ID, x.ID); got.State != ExecutionRequestClaimed {
		t.Fatalf("state %s", got.State)
	}
}

// Switch off: the candidate query is the pre-change text, character for
// character (issue-931 task 4 DoD).
func TestQueueValidation_ClaimSQLOffIsByteIdentical(t *testing.T) {
	const original = `SELECT id, work_item_id FROM work_item_execution_requests
		WHERE state='pending' OR (state='claimed' AND claim_expires_at <= $1)
		ORDER BY created_at, id LIMIT $2`
	if got := claimCandidateSQL(false); got != original {
		t.Fatalf("switch-off SQL changed:\n%q\n%q", got, original)
	}
}
