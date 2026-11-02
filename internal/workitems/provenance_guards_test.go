package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func executionCount(t *testing.T, s *Store, itemID string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM work_item_executions WHERE work_item_id=$1`, itemID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// failProvenanceFor makes the provenance INSERT of one engine run fail. The
// trigger only fires for that marker, so no other test sharing the database
// is affected.
func failProvenanceFor(t *testing.T, s *Store, marker string) {
	t.Helper()
	ctx := context.Background()
	name := "t4_" + strings.ReplaceAll(marker, "-", "_")
	for _, q := range []string{
		`CREATE OR REPLACE FUNCTION ` + name + `() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected provenance failure'; END; $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON execution_provenance FOR EACH ROW WHEN (NEW.engine_run = '` + marker + `') EXECUTE FUNCTION ` + name + `()`,
	} {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+name+` ON execution_provenance`)
		_, _ = s.pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+name+`()`)
	})
}

// T4: the provenance record is written in the execution's own transaction. If
// it cannot be written, the execution must not survive.
func TestProvenanceFailureRollsBackAttachedExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	failProvenanceFor(t, s, "t4-attach")
	w := open(t, s, CreateInput{})
	_, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID,
		Engine: EngineTemporal, EngineRef: "t4-attach", Phase: PhaseRunning})
	if err == nil {
		t.Fatal("attach must fail when provenance cannot be written")
	}
	if n := executionCount(t, s, w.ID); n != 0 {
		t.Fatalf("%d execution row(s) survived a failed provenance insert", n)
	}
	// A healthy attach to the same item still works and has provenance.
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID,
		Engine: EngineTemporal, EngineRef: "t4-ok", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecutionProvenance(ctx, e.ID); err != nil {
		t.Fatalf("healthy attach lacks provenance: %v", err)
	}
}

func TestProvenanceFailureRollsBackResumedExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	failProvenanceFor(t, s, "t4-resume")
	w := open(t, s, CreateInput{})
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID,
		Engine: EngineTemporal, EngineRef: "t4-first", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Get(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := executionCount(t, s, w.ID)
	if _, _, _, err := s.Resume(ctx, ResumeInput{Mutation: keyed("github:alice", "t4r", "h"), WorkItemID: w.ID,
		ExpectedStateVersion: cur.StateVersion, Engine: EngineTemporal, EngineRef: "t4-resume"}); err == nil {
		t.Fatal("resume must fail when provenance cannot be written")
	}
	if n := executionCount(t, s, w.ID); n != before {
		t.Fatalf("executions = %d, want %d: a resumed execution survived a failed provenance insert", n, before)
	}
	after, err := s.Get(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.StateVersion != cur.StateVersion {
		t.Fatalf("state_version moved %d -> %d on a failed resume", cur.StateVersion, after.StateVersion)
	}
}

// T6: a store that cannot be read is unavailable, never absent.
func TestProvenanceReadFailureIsNotAbsent(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID,
		Engine: EngineTemporal, EngineRef: "t6", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecutionProvenance(ctx, "we_does-not-exist"); !errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("no record: %v, want ErrProvenanceAbsent", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ExecutionProvenance(cancelled, e.ID); err == nil || errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("unreadable store (existing id): %v, want a non-absent error", err)
	}
	if _, err := s.ExecutionProvenance(cancelled, "we_does-not-exist"); err == nil || errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("unreadable store (unknown id): %v, want a non-absent error", err)
	}
	if _, err := s.LineageAttempts(cancelled, "lr_x", []string{"at_x"}); err == nil {
		t.Fatal("LineageAttempts on an unreadable store must error, not answer an empty set")
	}
}

// Immutability: the UPDATE refusal comes from the trigger, not from a missing
// code path, and it names the reason.
func TestProvenanceUpdateRefusedByTrigger(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID,
		Engine: EngineTemporal, EngineRef: "imm", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ExecutionProvenance(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE execution_provenance SET attempt_id=attempt_id WHERE execution_id=$1`,
		`UPDATE execution_provenance SET lineage_root='lr_x' WHERE execution_id=$1`,
		`UPDATE execution_provenance SET attached_by_principal='prn_forged' WHERE execution_id=$1`,
	} {
		_, err := s.pool.Exec(ctx, q, e.ID)
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: err=%v, want an 'immutable' refusal", q, err)
		}
	}
	after, err := s.ExecutionProvenance(ctx, e.ID)
	if err != nil || *after != *before {
		t.Fatalf("row changed: %+v -> %+v (%v)", before, after, err)
	}
}
