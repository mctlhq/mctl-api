package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseQueueWhileActive(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "off": false, "on": true, "ON": true} {
		got, err := ParseQueueWhileActive(raw)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"true", "1", "onn"} {
		if _, err := ParseQueueWhileActive(raw); err == nil || !strings.Contains(err.Error(), QueueWhileActiveEnv) {
			t.Errorf("%q = %v, want an error naming the variable", raw, err)
		}
	}
}

func TestClaimCandidateSQL_OffIsTheOriginalQuery(t *testing.T) {
	off := claimCandidateSQL(false)
	if strings.Contains(off, "NOT EXISTS") || strings.Contains(off, "work_item_executions") {
		t.Fatalf("switch-off SQL must not look at executions: %s", off)
	}
	if !strings.Contains(claimCandidateSQL(true), "NOT EXISTS") {
		t.Fatal("switch-on SQL lacks the open-execution guard")
	}
}

func queueStore(t *testing.T) *Store {
	s := newStoreForTest(t)
	s.queueWhileActive = true
	return s
}

// Switch on: a resume behind a running execution is stored, not claimable
// until the execution ends, then claimable with its fields unchanged.
func TestQueueWhileActive_CreateAndClaimGuard(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "wf#run_1", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	in := xrInput(w, ExecutionRequestResume, keyed("github:alice", "k-1", "h-1"))
	x := requestExecution(t, s, in)
	if x.State != ExecutionRequestPending || x.QueuedBehindExecutionID != e.ID {
		t.Fatalf("queued %+v", x)
	}
	if again, created, err := s.CreateExecutionRequest(ctx, in); err != nil || created || again.ID != x.ID {
		t.Fatalf("replay = %+v %v %v", again, created, err)
	}
	if got, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute}); err != nil || got != nil {
		t.Fatalf("claim behind a running execution = %+v %v", got, err)
	}
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "wf#run_1", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	if got := claim(t, s); got.ID != x.ID || got.ExpectedStateVersion != in.ExpectedStateVersion {
		t.Fatalf("claim after end = %+v", got)
	}
}

// Switch off: the original refusal, nothing stored.
func TestQueueWhileActive_OffRefuses(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "wf#run_1", Phase: PhaseRunning}); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestResume, keyed("github:alice", "k-1", "h-1")))
	if !errors.Is(err, ErrExecutionActive) {
		t.Fatalf("err = %v", err)
	}
	if xs, _ := s.ExecutionRequests(ctx, w.ID); len(xs) != 0 {
		t.Fatalf("stored %+v", xs)
	}
}

// The orphan close is a compare-and-set and never touches a terminal phase.
func TestCloseOrphanedExecution(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "wf#run_1", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	requestExecution(t, s, xrInput(w, ExecutionRequestResume, as("github:alice")))
	got, err := s.OpenExecutionsWithQueuedRequests(ctx, EngineTemporal, time.Now().Add(time.Hour), 10, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("candidates = %+v %v", got, err)
	}
	in := OrphanCloseInput{Mutation: as(platform), ExecutionID: e.ID, ExpectedPhase: PhaseRunning, EngineStatus: "Terminated"}
	c, closed, err := s.CloseOrphanedExecution(ctx, in)
	if err != nil || !closed || c.Phase != PhaseError || c.EndedAt == nil {
		t.Fatalf("close = %+v %v %v", c, closed, err)
	}
	if _, closed, err := s.CloseOrphanedExecution(ctx, in); err != nil || closed {
		t.Fatalf("second close = %v %v", closed, err)
	}
	if kinds := eventKinds(t, s, w.ID); kinds[len(kinds)-1] != EventExecutionOrphanClosed {
		t.Fatalf("events %v", kinds)
	}
}

// Paging past non-closable candidates reaches the ones behind them.
func TestOpenExecutionsWithQueuedRequests_Cursor(t *testing.T) {
	s := queueStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		w := open(t, s, CreateInput{})
		if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "wf#run_1", Phase: PhaseRunning}); err != nil {
			t.Fatal(err)
		}
		requestExecution(t, s, xrInput(w, ExecutionRequestResume, as("github:alice")))
	}
	until := time.Now().Add(time.Hour)
	seen := map[string]bool{}
	var cursor *Execution
	for {
		got, err := s.OpenExecutionsWithQueuedRequests(ctx, EngineTemporal, until, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range got {
			if seen[e.ID] {
				t.Fatalf("execution %s returned twice", e.ID)
			}
			seen[e.ID] = true
		}
		if len(got) < 2 {
			break
		}
		cursor = &got[len(got)-1]
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d executions, want 5", len(seen))
	}
}
