package workitems

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// twoExecutions opens an item with a finished first execution and a
// running second one.
func twoExecutions(t *testing.T, s *Store) (*WorkItem, *Execution, *Execution) {
	t.Helper()
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	agent := as("service:mctl-agent")
	attach := func(ref, phase string) *Execution {
		e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: ref, Phase: phase})
		if err != nil {
			t.Fatalf("attach %s %s: %v", ref, phase, err)
		}
		return e
	}
	first := attach("run-1", PhaseRunning)
	attach("run-1", PhaseSucceeded)
	second := attach("run-2", PhaseRunning)
	if first.Attempt != 1 || second.Attempt != 2 {
		t.Fatalf("attempts = %d, %d", first.Attempt, second.Attempt)
	}
	return w, first, second
}

func sealInput(w *WorkItem, e *Execution, canonical string) SnapshotInput {
	return SnapshotInput{
		Mutation:          as("service:mctl-agent"),
		WorkItemID:        w.ID,
		ExecutionID:       e.ID,
		ExecutionSequence: e.Attempt,
		Canonical:         []byte(canonical),
		ContentHash:       HashCanonical([]byte(canonical)),
		Strategy:          "investigator",
		StrategyVersion:   "v1",
	}
}

func TestSealSnapshotStoresVerifiedBytesAndReusesAReplay(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, _ := twoExecutions(t, s)
	in := sealInput(w, first, `{"b":1,"a":"x"}`)

	snap, created, err := s.SealSnapshot(ctx, in)
	if err != nil || !created {
		t.Fatalf("seal: %v %v", created, err)
	}
	if snap.ID != SnapshotIDFor(first.ID, in.ContentHash) || !strings.HasPrefix(snap.ID, SnapshotIDPrefix) ||
		snap.ExecutionID != first.ID || snap.ExecutionSequence != 1 || snap.SchemaVersion != SchemaVersion ||
		string(snap.Canonical) != `{"b":1,"a":"x"}` || snap.ProducedBy != "service:mctl-agent" {
		t.Fatalf("snapshot = %+v", snap)
	}

	// The same execution with the same bytes is the same snapshot.
	again, created, err := s.SealSnapshot(ctx, in)
	if err != nil || created || again.ID != snap.ID || !again.CreatedAt.Equal(snap.CreatedAt) {
		t.Fatalf("replay = %+v %v %v", again, created, err)
	}
	got, err := s.Snapshot(ctx, w.ID, snap.ID)
	if err != nil || !bytes.Equal(got.Canonical, in.Canonical) || got.ContentHash != in.ContentHash {
		t.Fatalf("get = %+v %v", got, err)
	}
	events, _ := s.Events(ctx, w.ID)
	sealed := 0
	for _, e := range events {
		if e.Kind == EventSnapshotSealed {
			sealed++
		}
	}
	if sealed != 1 {
		t.Fatalf("snapshot_sealed events = %d, want 1 (a replay records nothing)", sealed)
	}
}

func TestSealSnapshotRefusesDivergenceForTheSameExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, _ := twoExecutions(t, s)
	if _, _, err := s.SealSnapshot(ctx, sealInput(w, first, `{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.SealSnapshot(ctx, sealInput(w, first, `{"v":2}`))
	conflictCurrent(t, err, ErrSnapshotDivergence)

	// Same bytes, different claims about them: also a divergent seal.
	for name, mutate := range map[string]func(*SnapshotInput){
		"strategy":         func(in *SnapshotInput) { in.Strategy = "other" },
		"strategy version": func(in *SnapshotInput) { in.StrategyVersion = "v2" },
		"prior execution":  func(in *SnapshotInput) { in.PriorExecutionID = ExecutionIDPrefix + "x" },
		"prior snapshot":   func(in *SnapshotInput) { in.PriorSnapshotID = SnapshotIDPrefix + "x" },
	} {
		in := sealInput(w, first, `{"v":1}`)
		mutate(&in)
		if _, _, err := s.SealSnapshot(ctx, in); !errors.Is(err, ErrSnapshotDivergence) {
			t.Errorf("%s: err = %v, want ErrSnapshotDivergence", name, err)
		}
	}

	list, err := s.Snapshots(ctx, w.ID)
	if err != nil || len(list) != 1 || list[0].ContentHash != HashCanonical([]byte(`{"v":1}`)) {
		t.Fatalf("snapshots = %+v %v", list, err)
	}
}

func TestIdenticalBytesFromTwoExecutionsAreTwoSnapshots(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, second := twoExecutions(t, s)
	other, otherFirst, _ := twoExecutions(t, s)
	a, _, err := s.SealSnapshot(ctx, sealInput(w, first, `{"same":true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, created, err := s.SealSnapshot(ctx, sealInput(w, second, `{"same":true}`))
	if err != nil || !created || b.ID == a.ID || b.ContentHash != a.ContentHash {
		t.Fatalf("second execution, same bytes = %+v %v %v", b, created, err)
	}
	// Nor does another work item's (or tenant's) snapshot block the bytes.
	c, created, err := s.SealSnapshot(ctx, sealInput(other, otherFirst, `{"same":true}`))
	if err != nil || !created || c.ID == a.ID {
		t.Fatalf("other item, same bytes = %+v %v %v", c, created, err)
	}
}

func TestSealSnapshotRejectsBadInputBeforeTouchingTheStore(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, _ := twoExecutions(t, s)
	for name, mutate := range map[string]func(*SnapshotInput){
		"hash of other bytes": func(in *SnapshotInput) { in.ContentHash = HashCanonical([]byte(`{"x":2}`)) },
		"bare hex hash":       func(in *SnapshotInput) { in.ContentHash = strings.TrimPrefix(in.ContentHash, "sha256:") },
		"not an object": func(in *SnapshotInput) {
			in.Canonical = []byte(`[1]`)
			in.ContentHash = HashCanonical(in.Canonical)
		},
		"two documents": func(in *SnapshotInput) {
			in.Canonical = []byte(`{"a":1} {"b":2}`)
			in.ContentHash = HashCanonical(in.Canonical)
		},
		"empty": func(in *SnapshotInput) { in.Canonical, in.ContentHash = nil, HashCanonical(nil) },
		"json null": func(in *SnapshotInput) {
			in.Canonical = []byte(`null`)
			in.ContentHash = HashCanonical(in.Canonical)
		},
		"idempotency key":  func(in *SnapshotInput) { in.IdempotencyKey, in.RequestHash = "k", "h" },
		"no strategy":      func(in *SnapshotInput) { in.Strategy = "" },
		"no actor":         func(in *SnapshotInput) { in.Actor = "" },
		"zero sequence":    func(in *SnapshotInput) { in.ExecutionSequence = 0 },
		"not an execution": func(in *SnapshotInput) { in.ExecutionID = "run-1" },
		"bad prior":        func(in *SnapshotInput) { in.PriorSnapshotID = "snap-1" },
	} {
		in := sealInput(w, first, `{"x":1}`)
		mutate(&in)
		if _, _, err := s.SealSnapshot(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// The sequence is validated against the execution, never trusted.
	in := sealInput(w, first, `{"x":1}`)
	in.ExecutionSequence = 2
	if _, _, err := s.SealSnapshot(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong sequence: err = %v", err)
	}
	// An execution of another work item is not found on this one.
	_, otherExec, _ := twoExecutions(t, s)
	in = sealInput(w, otherExec, `{"x":1}`)
	if _, _, err := s.SealSnapshot(ctx, in); !errors.Is(err, ErrExecutionNotFound) {
		t.Fatalf("foreign execution: err = %v", err)
	}
	if list, _ := s.Snapshots(ctx, w.ID); len(list) != 0 {
		t.Fatalf("snapshots = %+v", list)
	}
}

func TestSealSnapshotNamesOnlyAnEarlierExecutionOfTheSameItem(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, second := twoExecutions(t, s)
	e1, _, err := s.SealSnapshot(ctx, sealInput(w, first, `{"execution":1}`))
	if err != nil {
		t.Fatal(err)
	}

	// Refused: a prior that does not exist, is this execution itself, or
	// is a snapshot of an execution other than the named one.
	for name, mutate := range map[string]func(*SnapshotInput){
		"unknown snapshot":  func(in *SnapshotInput) { in.PriorSnapshotID = SnapshotIDPrefix + "00000000000000000000000000000000" },
		"unknown execution": func(in *SnapshotInput) { in.PriorExecutionID = ExecutionIDPrefix + "missing" },
		"not earlier":       func(in *SnapshotInput) { in.PriorExecutionID = second.ID },
		"mismatched pair": func(in *SnapshotInput) {
			in.PriorSnapshotID, in.PriorExecutionID = e1.ID, second.ID
		},
	} {
		in := sealInput(w, second, `{"execution":2}`)
		mutate(&in)
		if _, _, err := s.SealSnapshot(ctx, in); !errors.Is(err, ErrPriorSnapshot) {
			t.Errorf("%s: err = %v, want ErrPriorSnapshot", name, err)
		}
	}

	in := sealInput(w, second, `{"execution":2}`)
	in.PriorSnapshotID = e1.ID
	e2, created, err := s.SealSnapshot(ctx, in)
	if err != nil || !created || e2.PriorSnapshotID != e1.ID || e2.ExecutionSequence != 2 {
		t.Fatalf("second seal = %+v %v %v", e2, created, err)
	}
	list, err := s.Snapshots(ctx, w.ID)
	if err != nil || len(list) != 2 || list[0].ID != e1.ID || list[1].ID != e2.ID {
		t.Fatalf("snapshots = %+v %v", list, err)
	}
	// The prior execution is stored resolved, so naming the same prior as
	// the consistent pair is the same seal, not a divergent one.
	if e2.PriorExecutionID != first.ID {
		t.Fatalf("prior execution not resolved: %+v", e2)
	}
	if again, created, err := s.SealSnapshot(ctx, in); err != nil || created || again.ID != e2.ID {
		t.Fatalf("plain replay = %+v %v %v", again, created, err)
	}
	in.PriorExecutionID = first.ID
	again, created, err := s.SealSnapshot(ctx, in)
	if err != nil || created || again.ID != e2.ID {
		t.Fatalf("replay naming the pair = %+v %v %v", again, created, err)
	}
	// A snapshot of another work item is not a prior here.
	other, otherFirst, otherSecond := twoExecutions(t, s)
	_, _, err = s.SealSnapshot(ctx, sealInput(other, otherFirst, `{"other":1}`))
	if err != nil {
		t.Fatal(err)
	}
	in = sealInput(other, otherSecond, `{"other":2}`)
	in.PriorSnapshotID = e1.ID
	_, _, err = s.SealSnapshot(ctx, in)
	conflictCurrent(t, err, ErrPriorSnapshot)
}

func TestSnapshotRowsAreImmutable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, _ := twoExecutions(t, s)
	snap, _, err := s.SealSnapshot(ctx, sealInput(w, first, `{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE work_item_context_snapshots SET canonical = '{"v":2}'::bytea WHERE id = $1`,
		`UPDATE work_item_context_snapshots SET strategy = 'other' WHERE id = $1`,
	} {
		if _, err := s.pool.Exec(ctx, stmt, snap.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: err = %v, want the immutability trigger", stmt, err)
		}
	}
	got, err := s.Snapshot(ctx, w.ID, snap.ID)
	if err != nil || string(got.Canonical) != `{"v":1}` {
		t.Fatalf("after refused updates = %+v %v", got, err)
	}
}

func TestConcurrentSealsOfOneExecutionStoreOneSnapshot(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, first, _ := twoExecutions(t, s)
	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	createdCount := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half replay the same bytes, half diverge.
			body := `{"v":1}`
			if i%2 == 1 {
				body = fmt.Sprintf(`{"v":%d}`, i+10)
			}
			_, createdCount[i], results[i] = s.SealSnapshot(ctx, sealInput(w, first, body))
		}(i)
	}
	wg.Wait()
	created := 0
	for i, err := range results {
		if createdCount[i] {
			created++
		}
		if err != nil && !errors.Is(err, ErrSnapshotDivergence) {
			t.Fatalf("seal %d: %v", i, err)
		}
	}
	list, err := s.Snapshots(ctx, w.ID)
	if err != nil || len(list) != 1 || created != 1 {
		t.Fatalf("snapshots = %d (created %d), %v", len(list), created, err)
	}
}
