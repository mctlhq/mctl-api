package workitems

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const platform = "service:mctl-agent"

func xrInput(item *WorkItem, kind string, m Mutation) ExecutionRequestInput {
	if m.Actor == "" {
		m = as("github:alice")
	}
	return ExecutionRequestInput{Mutation: m, WorkItemID: item.ID, Kind: kind, ExpectedStateVersion: item.StateVersion}
}

func requestExecution(t *testing.T, s *Store, in ExecutionRequestInput) *ExecutionRequest {
	t.Helper()
	x, created, err := s.CreateExecutionRequest(context.Background(), in)
	if err != nil || !created {
		t.Fatalf("CreateExecutionRequest: %v %v", created, err)
	}
	return x
}

func claim(t *testing.T, s *Store) *ExecutionRequest {
	t.Helper()
	x, _, err := s.ClaimExecutionRequest(context.Background(), ClaimInput{Mutation: as(platform), Lease: time.Minute})
	if err != nil || x == nil {
		t.Fatalf("claim = %+v %v", x, err)
	}
	return x
}

func fulfil(x *ExecutionRequest, token, ref string) FulfilInput {
	return FulfilInput{ClaimRef: ClaimRef{Mutation: as(platform), RequestID: x.ID, ClaimToken: token}, Engine: EngineTemporal, EngineRef: ref}
}

func eventKinds(t *testing.T, s *Store, id string) []string {
	t.Helper()
	events, err := s.Events(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for i := range events {
		kinds = append(kinds, events[i].Kind)
	}
	return kinds
}

func TestExecutionRequest_OneOpenPerItemAndIdempotent(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})

	first := requestExecution(t, s, xrInput(w, ExecutionRequestStart, keyed("github:alice", "k-1", "h-1")))
	if !strings.HasPrefix(first.ID, ExecutionRequestIDPrefix) || first.State != ExecutionRequestPending ||
		first.RequestedBy != "github:alice" || first.ExecutionID != "" || first.SchemaVersion != SchemaVersion {
		t.Fatalf("created %+v", first)
	}
	// The same key and body is the same request.
	again, created, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, keyed("github:alice", "k-1", "h-1")))
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("replay = %+v %v %v", again, created, err)
	}
	// The same key with another body, or from another actor, is a reuse.
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, keyed("github:alice", "k-1", "h-2"))); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("reused key = %v", err)
	}
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, keyed("github:bob", "k-1", "h-1"))); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("another actor's key = %v", err)
	}
	// Any other request while one is open names the open one.
	_, _, err = s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, as("github:bob")))
	var open *OpenRequestError
	if !errors.As(err, &open) || !errors.Is(err, ErrExecutionRequestOpen) || open.Open.ID != first.ID {
		t.Fatalf("second open request = %v", err)
	}
	// Still open once claimed.
	claim(t, s)
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, as("github:bob"))); !errors.As(err, &open) || open.Open.State != ExecutionRequestClaimed {
		t.Fatalf("request over a claimed one = %v", err)
	}
	list, err := s.ExecutionRequests(ctx, w.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d %v", len(list), err)
	}
}

func TestExecutionRequest_RefusesWhatCouldNeverBeFulfilled(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	other := open(t, s, CreateInput{Title: "another"})

	stale := xrInput(w, ExecutionRequestStart, Mutation{})
	stale.ExpectedStateVersion = 7
	if cur := conflictCurrent(t, func() error { _, _, err := s.CreateExecutionRequest(ctx, stale); return err }(), ErrVersionConflict); cur.StateVersion != 1 {
		t.Fatalf("current = %+v", cur)
	}
	// resume on an item that never ran: it starts instead.
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestResume, Mutation{})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resume with nothing to resume = %v", err)
	}
	// start names no execution to resume from.
	withFrom := xrInput(w, ExecutionRequestStart, Mutation{})
	withFrom.ResumedFromExecutionID = "we_x"
	if _, _, err := s.CreateExecutionRequest(ctx, withFrom); !errors.Is(err, ErrInvalid) {
		t.Fatalf("start with resumed_from = %v", err)
	}

	// Foreign references: another item's execution and intent.
	foreignExec, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: other.ID, Engine: EngineArgo, EngineRef: "o-1", Phase: PhaseSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	foreignIntent, _, err := s.AppendIntent(ctx, IntentInput{Mutation: as("github:alice"), WorkItemID: other.ID, Text: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineArgo, EngineRef: "w-1", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	resume := xrInput(w, ExecutionRequestResume, Mutation{})
	resume.ResumedFromExecutionID = foreignExec.ID
	if _, _, err := s.CreateExecutionRequest(ctx, resume); !errors.Is(err, ErrExecutionNotFound) {
		t.Fatalf("resume from another item's execution = %v", err)
	}
	resume.ResumedFromExecutionID = ""
	resume.IntentID = &foreignIntent.ID
	if _, _, err := s.CreateExecutionRequest(ctx, resume); !errors.Is(err, ErrIntentNotFound) {
		t.Fatalf("another item's intent = %v", err)
	}
	// start on an item that already ran: it resumes instead.
	if _, _, err := s.CreateExecutionRequest(ctx, xrInput(w, ExecutionRequestStart, Mutation{})); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("start after a run = %v", err)
	}

	// A terminal item.
	archived, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionArchive, ExpectedStateVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	resume.IntentID = nil
	resume.ExpectedStateVersion = archived.StateVersion
	if cur := conflictCurrent(t, func() error { _, _, err := s.CreateExecutionRequest(ctx, resume); return err }(), ErrInvalidTransition); cur.State != StateArchived {
		t.Fatalf("current = %+v", cur)
	}
	if list, _ := s.ExecutionRequests(ctx, w.ID); len(list) != 0 {
		t.Fatalf("refused requests were stored: %+v", list)
	}
}

// However many claimants race, one wins the request. The race is forced:
// the item's lock is held until every claimant has found the request
// pending and queued behind that lock, so each one reaches the claim
// UPDATE believing it can win, and only the compare-and-set decides.
func TestExecutionRequest_ClaimHasOneWinner(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))

	const claimants = 8
	// Enough connections for every claimant to hold one while it waits.
	connStr := os.Getenv("TEST_DATABASE_URL")
	sep := "?"
	if strings.Contains(connStr, "?") {
		sep = "&"
	}
	racers, err := NewStore(ctx, connStr+sep+"pool_max_conns=16")
	if err != nil {
		t.Fatal(err)
	}
	defer racers.Close()
	holder, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "workitem:"+w.ID); err != nil {
		t.Fatal(err)
	}
	s = racers
	var wg sync.WaitGroup
	var mu sync.Mutex
	var won []*ExecutionRequest
	errs := make(chan error, claimants)
	start := make(chan struct{})
	for i := 0; i < claimants; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			x, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute})
			if err != nil {
				errs <- err
				return
			}
			if x != nil {
				mu.Lock()
				won = append(won, x)
				mu.Unlock()
			}
		}()
	}
	close(start)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := holder.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == claimants {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d claimants queued on the item lock", waiting, claimants)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("claim: %v", err)
	}
	if len(won) != 1 {
		t.Fatalf("%d claimants won", len(won))
	}
	claimed := 0
	for _, k := range eventKinds(t, s, w.ID) {
		if k == EventExecutionRequestClaimed {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("claimed events = %d", claimed)
	}
	// Nothing else is claimable while the lease holds.
	if x, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: as(platform), Lease: time.Minute}); x != nil || err != nil {
		t.Fatalf("claim during the lease = %+v %v", x, err)
	}
}

// A lapsed claim is claimable again, and its holder can no longer act on
// it, even as the same principal.
func TestExecutionRequest_LapsedClaimIsFenced(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
	stale := claim(t, s)

	base := time.Now().UTC()
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	// The lapsed holder, before anyone re-claims.
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(stale, stale.ClaimToken, "run-stale")); !errors.Is(err, ErrExecutionRequestNotClaimed) {
		t.Fatalf("fulfil on a lapsed lease = %v", err)
	}
	fresh := claim(t, s)
	if fresh.ID != stale.ID || fresh.ClaimToken == stale.ClaimToken || fresh.ClaimedBy != platform {
		t.Fatalf("re-claim = %+v", fresh)
	}
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(stale, stale.ClaimToken, "run-stale")); !errors.Is(err, ErrExecutionRequestNotClaimed) {
		t.Fatalf("stale holder fulfil = %v", err)
	}
	if _, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ClaimRef{Mutation: as(platform), RequestID: stale.ID, ClaimToken: stale.ClaimToken}, Reason: "late"}); !errors.Is(err, ErrExecutionRequestNotClaimed) {
		t.Fatalf("stale holder reject = %v", err)
	}
	// Another principal with the right token is not the holder either.
	other := fulfil(fresh, fresh.ClaimToken, "run-1")
	other.Actor = "service:someone-else"
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, other); !errors.Is(err, ErrExecutionRequestNotClaimed) {
		t.Fatalf("another principal fulfil = %v", err)
	}
	if _, _, exec, _, err := s.FulfilExecutionRequest(ctx, fulfil(fresh, fresh.ClaimToken, "run-1")); err != nil || exec.EngineRef != "run-1" {
		t.Fatalf("holder fulfil = %+v %v", exec, err)
	}
	if execs, _ := s.Executions(ctx, w.ID); len(execs) != 1 {
		t.Fatalf("executions = %+v", execs)
	}
}

func TestExecutionRequest_FulfilStartThenResume(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	intent, _, err := s.AppendIntent(ctx, IntentInput{Mutation: as("github:alice"), WorkItemID: w.ID, Text: "run it"})
	if err != nil {
		t.Fatal(err)
	}
	in := xrInput(w, ExecutionRequestStart, Mutation{})
	in.IntentID = &intent.ID
	requestExecution(t, s, in)
	x := claim(t, s)
	if x.IntentID == nil || *x.IntentID != intent.ID {
		t.Fatalf("claimed %+v", x)
	}

	done, item, first, created, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1"))
	if err != nil || !created {
		t.Fatalf("fulfil start: %v %v", created, err)
	}
	if done.State != ExecutionRequestFulfilled || done.ExecutionID != first.ID || done.ClosedAt == nil ||
		first.Phase != PhaseRunning || first.Attempt != 1 || first.ResumedFromExecutionID != "" || item.State != StateActive {
		t.Fatalf("fulfilled %+v exec %+v item %+v", done, first, item)
	}
	// The holder repeating the same run gets the same execution; another
	// run is refused.
	again, _, same, created, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1"))
	if err != nil || created || same.ID != first.ID || again.ExecutionID != first.ID {
		t.Fatalf("re-fulfil = %+v %v %v", same, created, err)
	}
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-9")); !errors.Is(err, ErrExecutionRequestClosed) {
		t.Fatalf("fulfil with another run = %v", err)
	}
	if execs, _ := s.Executions(ctx, w.ID); len(execs) != 1 {
		t.Fatalf("executions after start = %+v", execs)
	}

	// Finish the run, park the item, and ask to resume it.
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	parked, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	resume := xrInput(parked, ExecutionRequestResume, Mutation{})
	resume.ResumedFromExecutionID = first.ID
	requestExecution(t, s, resume)
	y := claim(t, s)
	done, item, second, created, err := s.FulfilExecutionRequest(ctx, fulfil(y, y.ClaimToken, "run-2"))
	if err != nil || !created {
		t.Fatalf("fulfil resume: %v %v", created, err)
	}
	if second.Attempt != 2 || second.ResumedFromExecutionID != first.ID || done.ExecutionID != second.ID ||
		item.State != StateActive || item.StateVersion != parked.StateVersion+1 {
		t.Fatalf("resumed exec %+v item %+v", second, item)
	}
	want := []string{"created", "intent_appended", "execution_requested", "execution_request_claimed", "execution_attached",
		"execution_request_fulfilled", "state_changed", "execution_requested", "execution_request_claimed", "resumed",
		"execution_request_fulfilled"}
	if got := eventKinds(t, s, w.ID); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v", got)
	}
}

// Fulfil re-decides against the item as it is now: a request whose item
// moved on is refused, and stays claimed for the platform to reject.
func TestExecutionRequest_FulfilRechecksTheItem(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
	x := claim(t, s)
	if _, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionArchive, ExpectedStateVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("fulfil after the item moved = %v", err)
	}
	if execs, _ := s.Executions(ctx, w.ID); len(execs) != 0 {
		t.Fatalf("executions = %+v", execs)
	}
	got, _ := s.ExecutionRequest(ctx, w.ID, x.ID)
	if got.State != ExecutionRequestClaimed {
		t.Fatalf("request = %+v", got)
	}
}

func TestExecutionRequest_Reject(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
	x := claim(t, s)
	ref := ClaimRef{Mutation: as(platform), RequestID: x.ID, ClaimToken: x.ClaimToken}

	if _, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ref, Reason: "token ghp_" + strings.Repeat("a", 36)}); !errors.Is(err, ErrSecretInText) {
		t.Fatalf("secret reason = %v", err)
	}
	if _, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ref, Reason: strings.Repeat("r", MaxExecutionRequestReason+1)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long reason = %v", err)
	}
	if _, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ref}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no reason = %v", err)
	}
	got, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ref, Reason: "no capacity"})
	if err != nil || got.State != ExecutionRequestRejected || got.Reason != "no capacity" || got.ExecutionID != "" {
		t.Fatalf("reject = %+v %v", got, err)
	}
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1")); !errors.Is(err, ErrExecutionRequestClosed) {
		t.Fatalf("fulfil a rejected request = %v", err)
	}
	// A rejected request is closed: the item takes a new one.
	requestExecution(t, s, xrInput(w, ExecutionRequestStart, Mutation{}))
}
