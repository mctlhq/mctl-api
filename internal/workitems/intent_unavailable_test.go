package workitems

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// mctl-api#871: a request may pin only an intent whose text is readable, at
// creation and again at fulfilment; executions carry the provenance of the
// request they fulfilled.

func appendIntent(t *testing.T, s *Store, w *WorkItem, text string) *Intent {
	t.Helper()
	intent, _, err := s.AppendIntent(context.Background(), IntentInput{Mutation: as("github:alice"), WorkItemID: w.ID, Text: text})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

// redact is the retention fixture: mctl-api#353's sweeper does not exist
// yet, so tests set the text to NULL the way it will.
func redact(t *testing.T, s *Store, intent *Intent) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `UPDATE work_item_intents SET text=NULL WHERE id=$1`, intent.ID); err != nil {
		t.Fatal(err)
	}
}

func pinned(w *WorkItem, kind string, intentID int64) ExecutionRequestInput {
	in := xrInput(w, kind, Mutation{})
	in.IntentID = &intentID
	return in
}

// T1: redacted before the request.
func TestIntentUnavailable_RefusedAtCreateLeavingNothing(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	intent := appendIntent(t, s, w, "run it")
	redact(t, s, intent)
	before := eventKinds(t, s, w.ID)

	in := pinned(w, ExecutionRequestStart, intent.ID)
	in.IdempotencyKey, in.RequestHash = "k1", "h1"
	_, _, err := s.CreateExecutionRequest(ctx, in)
	var unavailable *IntentUnavailableError
	if !errors.Is(err, ErrIntentUnavailable) || !errors.As(err, &unavailable) || unavailable.IntentID != intent.ID {
		t.Fatalf("create with a redacted intent = %v", err)
	}
	if strings.Contains(err.Error(), "run it") {
		t.Fatalf("error carries intent text: %v", err)
	}
	if xs, _ := s.ExecutionRequests(ctx, w.ID); len(xs) != 0 {
		t.Fatalf("requests after refusal = %+v", xs)
	}
	if got := eventKinds(t, s, w.ID); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Fatalf("events after refusal = %v, want %v", got, before)
	}
	// No idempotency entry either: the same key with a readable intent is a
	// fresh request, not idempotency_key_reused.
	fresh := appendIntent(t, s, w, "run it again")
	again := pinned(w, ExecutionRequestStart, fresh.ID)
	again.IdempotencyKey, again.RequestHash = "k1", "h2"
	if _, created, err := s.CreateExecutionRequest(ctx, again); err != nil || !created {
		t.Fatalf("same key after a refusal = %v %v", created, err)
	}
}

// T2 + T4: redacted after enqueue, then the replacement on a new request.
func TestIntentUnavailable_RefusedAtFulfilThenReplacedByANewRequest(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	intent := appendIntent(t, s, w, "run it")
	requestExecution(t, s, pinned(w, ExecutionRequestStart, intent.ID))
	x := claim(t, s)
	if x.IntentAvailable == nil || !*x.IntentAvailable {
		t.Fatalf("claim of a readable pin = %+v", x.IntentAvailable)
	}
	redact(t, s, intent)

	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1")); !errors.Is(err, ErrIntentUnavailable) {
		t.Fatalf("fulfil after redaction = %v", err)
	}
	if execs, _ := s.Executions(ctx, w.ID); len(execs) != 0 {
		t.Fatalf("executions after a refused fulfil = %+v", execs)
	}
	got, _ := s.ExecutionRequest(ctx, w.ID, x.ID)
	if got.State != ExecutionRequestClaimed {
		t.Fatalf("request after a refused fulfil = %+v", got)
	}
	// The holder's claim token still rejects it.
	ref := ClaimRef{Mutation: as(platform), RequestID: x.ID, ClaimToken: x.ClaimToken}
	if rejected, _, _, err := s.RejectExecutionRequest(ctx, RejectInput{ClaimRef: ref, Reason: "intent_unavailable"}); err != nil ||
		rejected.State != ExecutionRequestRejected {
		t.Fatalf("reject = %+v %v", rejected, err)
	}

	// T4: a replacement intent on a new request with a new key runs; the old
	// request keeps its own intent and nothing was substituted.
	replacement := appendIntent(t, s, w, "run it, version two")
	next := requestExecution(t, s, pinned(w, ExecutionRequestStart, replacement.ID))
	y := claim(t, s)
	if y.ID != next.ID {
		t.Fatalf("claimed %s, want %s", y.ID, next.ID)
	}
	done, _, ex, created, err := s.FulfilExecutionRequest(ctx, fulfil(y, y.ClaimToken, "run-2"))
	if err != nil || !created || done.IntentID == nil || *done.IntentID != replacement.ID {
		t.Fatalf("fulfil the replacement = %+v %v %v", done, created, err)
	}
	old, _ := s.ExecutionRequest(ctx, w.ID, x.ID)
	if old.IntentID == nil || *old.IntentID != intent.ID || old.State != ExecutionRequestRejected || old.ExecutionID != "" {
		t.Fatalf("old request = %+v", old)
	}
	if ex.Attempt != 1 {
		t.Fatalf("execution = %+v", ex)
	}
}

// The claim says false for a pin that is already redacted, and nothing for
// a request that pins no intent.
func TestIntentUnavailable_ClaimReportsAvailability(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{})
	intent := appendIntent(t, s, w, "run it")
	requestExecution(t, s, pinned(w, ExecutionRequestStart, intent.ID))
	redact(t, s, intent)
	x := claim(t, s)
	if x.IntentAvailable == nil || *x.IntentAvailable {
		t.Fatalf("claim of a redacted pin = %+v", x.IntentAvailable)
	}

	v := open(t, s, CreateInput{ExternalKey: "https://github.com/acme/repo/issues/2"})
	requestExecution(t, s, xrInput(v, ExecutionRequestStart, Mutation{}))
	y := claim(t, s)
	if y.IntentAvailable != nil {
		t.Fatalf("claim without a pin = %v", *y.IntentAvailable)
	}
	// Claim-only: never part of the request's own serialization.
	b, _ := json.Marshal(x)
	if strings.Contains(string(b), "intent_available") {
		t.Fatalf("request JSON carries intent_available: %s", b)
	}
}

// T3: a missing id and another item's intent are the same 404.
func TestIntentUnavailable_ForeignOrMissingIntentIsNotFound(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	other := open(t, s, CreateInput{ExternalKey: "https://github.com/acme/repo/issues/3"})
	foreign := appendIntent(t, s, other, "theirs")
	for _, id := range []int64{foreign.ID, foreign.ID + 1000} {
		if _, _, err := s.CreateExecutionRequest(ctx, pinned(w, ExecutionRequestStart, id)); !errors.Is(err, ErrIntentNotFound) ||
			errors.Is(err, ErrIntentUnavailable) {
			t.Fatalf("intent %d = %v", id, err)
		}
	}
}

// T5: a replay after redaction returns the original request; the same key
// with another intent is idempotency_key_reused.
func TestIntentUnavailable_ReplayAfterRedactionDoesNotFork(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	intent := appendIntent(t, s, w, "run it")
	in := pinned(w, ExecutionRequestStart, intent.ID)
	in.Mutation = keyed("github:alice", "k-replay", "h-replay")
	first := requestExecution(t, s, in)
	redact(t, s, intent)

	again, created, err := s.CreateExecutionRequest(ctx, in)
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("replay after redaction = %+v %v %v", again, created, err)
	}
	other := appendIntent(t, s, w, "something else")
	diff := pinned(w, ExecutionRequestStart, other.ID)
	diff.Mutation = keyed("github:alice", "k-replay", "h-different")
	if _, _, err := s.CreateExecutionRequest(ctx, diff); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("same key, other intent = %v", err)
	}
}

// T13: an execution lists the provenance of the request it fulfilled; an
// attached one lists none (absent, not empty).
func TestExecutionProvenance_FromTheFulfilledRequestOnly(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	relayed := as("github:alice")
	relayed.Surface, relayed.ActingPrincipal = "telegram", "surface:telegram"
	in := xrInput(w, ExecutionRequestStart, relayed)
	requestExecution(t, s, in)
	x := claim(t, s)
	if _, _, _, _, err := s.FulfilExecutionRequest(ctx, fulfil(x, x.ClaimToken, "run-1")); err != nil {
		t.Fatal(err)
	}
	// An execution attached directly, without a request (a DevLoop attach).
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "attached-run", Phase: PhaseRunning}); err != nil {
		t.Fatal(err)
	}

	execs, err := s.Executions(ctx, w.ID)
	if err != nil || len(execs) != 2 {
		t.Fatalf("executions = %+v %v", execs, err)
	}
	dispatched, attached := execs[0], execs[1]
	if dispatched.Surface != "telegram" || dispatched.RequestedBy != "github:alice" || dispatched.ActingPrincipal != "surface:telegram" {
		t.Fatalf("dispatched execution provenance = %+v", dispatched)
	}
	b, _ := json.Marshal(attached)
	for _, key := range []string{`"surface"`, `"requested_by"`, `"acting_principal"`} {
		if strings.Contains(string(b), key) {
			t.Fatalf("attached execution carries %s: %s", key, b)
		}
	}
}
