package workitems

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed work-items store test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	wipe := func() {
		// Every other table cascades from work_items.
		if _, err := s.pool.Exec(ctx, "DELETE FROM work_items"); err != nil {
			t.Fatal(err)
		}
	}
	wipe()
	t.Cleanup(func() {
		wipe()
		s.Close()
	})
	return s
}

func as(actor string) Mutation { return Mutation{Actor: actor, Surface: "cli", RequestID: "req-1"} }

func keyed(actor, key, hash string) Mutation {
	m := as(actor)
	m.IdempotencyKey, m.RequestHash = key, hash
	return m
}

func open(t *testing.T, s *Store, in CreateInput) *WorkItem {
	t.Helper()
	if in.Actor == "" {
		in.Mutation = as("github:alice")
	}
	if in.Tenant == "" {
		in.Tenant = "acme"
	}
	if in.Visibility == "" {
		in.Visibility = VisibilityTenant
	}
	if in.OriginSurface == "" {
		in.OriginSurface = "cli"
	}
	if in.Title == "" {
		in.Title = "ship the thing"
	}
	w, created, err := s.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !created {
		t.Fatalf("Create returned an existing item %s", w.ID)
	}
	return w
}

func conflictCurrent(t *testing.T, err error, want error) *WorkItem {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Current == nil {
		t.Fatalf("err %v does not carry the current item", err)
	}
	return ce.Current
}

func TestTransitionTable(t *testing.T) {
	for _, terminal := range []string{StateCompleted, StateSuperseded, StateArchived} {
		if !IsTerminal(terminal) {
			t.Errorf("%s is not terminal", terminal)
		}
		for _, action := range []string{ActionWait, ActionResume, ActionComplete, ActionSupersede, ActionArchive} {
			if _, err := Next(terminal, action); !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("%s from %s allowed", action, terminal)
			}
		}
	}
	if _, err := Next(StateActive, ActionResume); !errors.Is(err, ErrInvalidTransition) {
		t.Error("resume from active is not in the table")
	}
	if to, err := Next(StateWaiting, ActionResume); err != nil || to != StateActive {
		t.Errorf("resume from waiting = %q, %v", to, err)
	}
}

func TestCreateAndGet(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	if !strings.HasPrefix(w.ID, WorkItemIDPrefix) || w.State != StateActive || w.StateVersion != 1 ||
		w.SchemaVersion != SchemaVersion || w.OwnerPrincipal != "github:alice" || w.CreatedBy != "github:alice" {
		t.Fatalf("created %+v", w)
	}
	got, err := s.Get(ctx, w.ID)
	if err != nil || *got != *w {
		t.Fatalf("Get = %+v, %v; want %+v", got, err, w)
	}
	if _, err := s.Get(ctx, "wi_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) err = %v", err)
	}
	events, err := s.Events(ctx, w.ID)
	if err != nil || len(events) != 1 || events[0].Kind != EventCreated || events[0].ToState != StateActive ||
		events[0].ActorPrincipal != "github:alice" || events[0].RequestID != "req-1" {
		t.Fatalf("events = %+v, %v", events, err)
	}
}

func TestCreateRequiresAnActor(t *testing.T) {
	s := newStoreForTest(t)
	_, _, err := s.Create(context.Background(), CreateInput{Tenant: "acme", Visibility: VisibilityTenant, OriginSurface: "cli", Title: "x"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestCreateIsIdempotentPerTenantKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	in := CreateInput{Mutation: keyed("github:alice", "k1", "h1"), Tenant: "acme", Visibility: VisibilityTenant, OriginSurface: "telegram", Title: "a"}
	first, created, err := s.Create(ctx, in)
	if err != nil || !created {
		t.Fatalf("first create: %v %v", created, err)
	}
	again, created, err := s.Create(ctx, in)
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("replay = %v %v %v; want %s", again, created, err, first.ID)
	}
	in.RequestHash = "h2"
	if _, _, err := s.Create(ctx, in); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("reused key with another request: err = %v", err)
	}
	// The key is per tenant.
	in.Tenant, in.RequestHash = "other", "h1"
	if other, created, err := s.Create(ctx, in); err != nil || !created || other.ID == first.ID {
		t.Fatalf("other tenant = %v %v %v", other, created, err)
	}
}

func TestExternalKeyDedupesOnlyOpenWork(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{ExternalKey: "https://github.com/mctlhq/mctl-api/issues/349"})
	dup, created, err := s.Create(ctx, CreateInput{Mutation: as("github:bob"), Tenant: "acme", Visibility: VisibilityTenant,
		OriginSurface: "telegram", Title: "same issue", ExternalKey: w.ExternalKey})
	if err != nil || created || dup.ID != w.ID {
		t.Fatalf("dedupe = %v %v %v", dup, created, err)
	}
	if _, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionComplete, ExpectedStateVersion: 1}); err != nil {
		t.Fatal(err)
	}
	fresh := open(t, s, CreateInput{ExternalKey: w.ExternalKey})
	if fresh.ID == w.ID {
		t.Fatal("a completed item still claimed its external key")
	}
}

func TestTransitionsAndVersionConflicts(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})

	waiting, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID,
		Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: 1})
	if err != nil || waiting.State != StateWaiting || waiting.WaitingReason != WaitingInput || waiting.StateVersion != 2 {
		t.Fatalf("wait = %+v, %v", waiting, err)
	}

	// A stale version is a 409 carrying the current state; nothing changes.
	_, err = s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionComplete, ExpectedStateVersion: 1})
	if cur := conflictCurrent(t, err, ErrVersionConflict); cur.StateVersion != 2 || cur.State != StateWaiting {
		t.Fatalf("conflict current = %+v", cur)
	}

	done, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionComplete, ExpectedStateVersion: 2})
	if err != nil || done.State != StateCompleted || done.WaitingReason != "" || done.CompletedAt == nil || done.StateVersion != 3 {
		t.Fatalf("complete = %+v, %v", done, err)
	}
	_, err = s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionArchive, ExpectedStateVersion: 3})
	if cur := conflictCurrent(t, err, ErrInvalidTransition); cur.State != StateCompleted || cur.StateVersion != 3 {
		t.Fatalf("out of terminal: current = %+v", cur)
	}
	if _, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: "wi_missing", Action: ActionArchive, ExpectedStateVersion: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: err = %v", err)
	}
	for _, bad := range []TransitionInput{
		{WorkItemID: w.ID, Action: ActionWait, ExpectedStateVersion: 3},                                 // no reason
		{WorkItemID: w.ID, Action: ActionArchive, WaitingReason: WaitingInput, ExpectedStateVersion: 3}, // stray reason
		{WorkItemID: w.ID, Action: ActionSupersede, ExpectedStateVersion: 3},                            // no successor
		{WorkItemID: w.ID, Action: ActionArchive},                                                       // no version
		{WorkItemID: w.ID, Action: ActionResume, ExpectedStateVersion: 3},                               // own route
	} {
		bad.Mutation = as("github:alice")
		if _, err := s.Transition(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestSupersedeNeedsASuccessorInTheSameTenant(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	elsewhere := open(t, s, CreateInput{Tenant: "other"})
	in := TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Action: ActionSupersede, SupersededBy: elsewhere.ID, ExpectedStateVersion: 1}
	if _, err := s.Transition(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-tenant successor: err = %v", err)
	}
	next := open(t, s, CreateInput{})
	in.SupersededBy = next.ID
	got, err := s.Transition(ctx, in)
	if err != nil || got.State != StateSuperseded || got.SupersededBy != next.ID {
		t.Fatalf("supersede = %+v, %v", got, err)
	}
}

func TestTransitionReplayAppliesOnce(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	in := TransitionInput{Mutation: keyed("github:alice", "t1", "h"), WorkItemID: w.ID, Action: ActionWait, WaitingReason: WaitingApproval, ExpectedStateVersion: 1}
	first, err := s.Transition(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// The retry still names version 1; it is a replay, not a conflict.
	again, err := s.Transition(ctx, in)
	if err != nil || again.StateVersion != first.StateVersion {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	in.RequestHash = "different"
	if _, err := s.Transition(ctx, in); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("reused key: err = %v", err)
	}
	events, _ := s.Events(ctx, w.ID)
	if len(events) != 2 {
		t.Fatalf("events = %+v; the replay must not append", events)
	}
}

func TestConcurrentTransitionsResolveToExactlyOne(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	const racers, rounds = 16, 5
	for range rounds {
		w := open(t, s, CreateInput{})
		var ready, done sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, racers)
		for i := range racers {
			ready.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				ready.Done()
				<-start
				_, errs[i] = s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w.ID,
					Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: 1})
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrVersionConflict):
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d transitions won, want exactly 1", won)
		}
		got, _ := s.Get(ctx, w.ID)
		events, _ := s.Events(ctx, w.ID)
		if got.StateVersion != 2 || len(events) != 2 {
			t.Fatalf("state_version = %d with %d events, want 2 and 2", got.StateVersion, len(events))
		}
	}
}

func TestExecutionsAttachCorrelateAndStayUnique(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	agent := as("service:mctl-agent")

	run, created, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "dev-loop-1", Phase: PhaseRunning})
	if err != nil || !created || run.Attempt != 1 || !strings.HasPrefix(run.ID, ExecutionIDPrefix) || run.EndedAt != nil {
		t.Fatalf("attach = %+v %v %v", run, created, err)
	}
	// A second live execution is refused.
	_, _, err = s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineArgo, EngineRef: "wf-2", Phase: PhasePending})
	conflictCurrent(t, err, ErrExecutionActive)

	// The same (engine, ref) correlates a later phase instead of duplicating.
	ended, created, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "dev-loop-1", Phase: PhaseSucceeded})
	if err != nil || created || ended.ID != run.ID || ended.Phase != PhaseSucceeded || ended.EndedAt == nil {
		t.Fatalf("correlate = %+v %v %v", ended, created, err)
	}
	_, _, err = s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "dev-loop-1", Phase: PhaseRunning})
	conflictCurrent(t, err, ErrInvalidTransition)

	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: "k8s", EngineRef: "x", Phase: PhaseRunning}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown engine: err = %v", err)
	}
	execs, err := s.Executions(ctx, w.ID)
	if err != nil || len(execs) != 1 {
		t.Fatalf("executions = %+v, %v", execs, err)
	}
}

func TestResumeContinuesAPriorExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	agent := as("service:mctl-agent")
	first, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := s.Transition(ctx, TransitionInput{Mutation: agent, WorkItemID: w.ID, Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	resume := ResumeInput{Mutation: keyed("github:alice", "r1", "h"), WorkItemID: w.ID, ExpectedStateVersion: waiting.StateVersion, Engine: EngineTemporal, EngineRef: "run-2"}

	// Not while the prior execution is still running.
	_, _, _, err = s.Resume(ctx, resume)
	conflictCurrent(t, err, ErrExecutionActive)

	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseFailed}); err != nil {
		t.Fatal(err)
	}
	item, exec, created, err := s.Resume(ctx, resume)
	if err != nil || !created {
		t.Fatalf("resume: %v %v", created, err)
	}
	if item.State != StateActive || item.WaitingReason != "" || item.StateVersion != waiting.StateVersion+1 {
		t.Fatalf("resumed item = %+v", item)
	}
	if exec.Attempt != 2 || exec.ResumedFromExecutionID != first.ID || exec.Phase != PhasePending || exec.EngineRef != "run-2" {
		t.Fatalf("resumed execution = %+v", exec)
	}

	// A retry of the same resume returns the same execution, even though
	// its expected version is now stale.
	_, again, created, err := s.Resume(ctx, resume)
	if err != nil || created || again.ID != exec.ID {
		t.Fatalf("replay = %+v %v %v", again, created, err)
	}
	events, _ := s.Events(ctx, w.ID)
	last := events[len(events)-1]
	if last.Kind != EventResumed || last.FromState != StateWaiting || last.ToState != StateActive || last.ActorPrincipal != "github:alice" {
		t.Fatalf("last event = %+v", last)
	}
	for _, e := range events {
		if e.Kind == "resumed" && e.ToState == "resumed" {
			t.Fatal("resumed must never be a state")
		}
	}

	// A terminal item cannot be resumed.
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-2", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	done, err := s.Transition(ctx, TransitionInput{Mutation: agent, WorkItemID: w.ID, Action: ActionComplete, ExpectedStateVersion: item.StateVersion})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.Resume(ctx, ResumeInput{Mutation: as("github:alice"), WorkItemID: w.ID, ExpectedStateVersion: done.StateVersion, Engine: EngineTemporal, EngineRef: "run-3"})
	conflictCurrent(t, err, ErrInvalidTransition)
}

func TestResumeRejectsAForeignPriorExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a, b := open(t, s, CreateInput{}), open(t, s, CreateInput{})
	foreign, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: b.ID, Engine: EngineArgo, EngineRef: "wf", Phase: PhaseSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.Resume(ctx, ResumeInput{Mutation: as("github:alice"), WorkItemID: a.ID, ExpectedStateVersion: 1,
		ResumedFromExecutionID: foreign.ID, Engine: EngineArgo, EngineRef: "wf-2"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestIntentsAreBoundedAndNeverCarrySecrets(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	in := IntentInput{Mutation: as("github:alice"), WorkItemID: w.ID, Text: "please add a retry", Params: []byte(`{"service":"api"}`)}
	intent, created, err := s.AppendIntent(ctx, in)
	if err != nil || !created || intent.Text != in.Text || intent.ActorPrincipal != "github:alice" {
		t.Fatalf("intent = %+v %v %v", intent, created, err)
	}

	in.Text = strings.Repeat("x", MaxIntentBytes+1)
	if _, _, err := s.AppendIntent(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized intent: err = %v", err)
	}
	in.Text = "my token is ghp_" + strings.Repeat("a", 36)
	if _, _, err := s.AppendIntent(ctx, in); !errors.Is(err, ErrSecretInText) {
		t.Fatalf("secret intent: err = %v", err)
	}
	in.Text, in.Params = "ok", []byte(`["not","an","object"]`)
	if _, _, err := s.AppendIntent(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-object params: err = %v", err)
	}

	var stored int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM work_item_intents WHERE work_item_id=$1`, w.ID).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("stored intents = %d, %v; rejected ones must not persist", stored, err)
	}
	events, _ := s.Events(ctx, w.ID)
	for _, e := range events {
		if strings.Contains(string(e.Detail), "retry") {
			t.Fatalf("event %d copies intent text: %s", e.Seq, e.Detail)
		}
	}
}

func TestSurfaceRefsCorrelateWithoutCopyingIDsIntoHistory(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	m := as("service:mctl-telegram")
	m.Surface = "telegram"
	in := SurfaceRefInput{Mutation: m, WorkItemID: w.ID, ExternalID: "chat-42", ActorExternalID: "tg-777"}
	ref, created, err := s.LinkSurface(ctx, in)
	if err != nil || !created || ref.Surface != "telegram" || ref.ActorExternalID != "tg-777" {
		t.Fatalf("link = %+v %v %v", ref, created, err)
	}
	again, created, err := s.LinkSurface(ctx, in)
	if err != nil || created || !again.FirstSeenAt.Equal(ref.FirstSeenAt) || again.LastSeenAt.Before(ref.LastSeenAt) {
		t.Fatalf("relink = %+v %v %v", again, created, err)
	}
	events, _ := s.Events(ctx, w.ID)
	if len(events) != 2 || events[1].Kind != EventSurfaceLinked {
		t.Fatalf("events = %+v", events)
	}
	if strings.Contains(string(events[1].Detail), "chat-42") || strings.Contains(string(events[1].Detail), "tg-777") {
		t.Fatalf("surface_linked copies external ids: %s", events[1].Detail)
	}
}

func TestListDefaultsToOpenAndHidesOthersPrivateItems(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	shared := open(t, s, CreateInput{})
	private := open(t, s, CreateInput{Mutation: as("github:bob"), Visibility: VisibilityPrivate})
	done := open(t, s, CreateInput{})
	open(t, s, CreateInput{Tenant: "other"})
	if _, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: done.ID, Action: ActionArchive, ExpectedStateVersion: 1}); err != nil {
		t.Fatal(err)
	}
	ids := func(items []WorkItem) map[string]bool {
		out := map[string]bool{}
		for _, w := range items {
			out[w.ID] = true
		}
		return out
	}

	got, err := s.List(ctx, ListFilter{Tenants: []string{"acme"}, Viewer: "github:alice"})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]bool{shared.ID: true}; len(got) != 1 || !ids(got)[shared.ID] {
		t.Fatalf("alice sees %v, want %v", ids(got), want)
	}
	got, _ = s.List(ctx, ListFilter{Tenants: []string{"acme"}, Viewer: "github:bob"})
	if len(got) != 2 || !ids(got)[private.ID] {
		t.Fatalf("bob sees %v", ids(got))
	}
	got, _ = s.List(ctx, ListFilter{Tenants: []string{"acme"}, State: StateArchived})
	if len(got) != 1 || !ids(got)[done.ID] {
		t.Fatalf("archived = %v", ids(got))
	}
	got, _ = s.List(ctx, ListFilter{})
	if len(got) != 3 {
		t.Fatalf("every tenant, open = %d items, want 3", len(got))
	}
	if _, err := s.List(ctx, ListFilter{State: "resumed"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resumed filter: err = %v", err)
	}
}
