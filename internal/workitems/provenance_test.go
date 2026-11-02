package workitems

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/executionprovenance"
)

func TestProvenanceWrittenFromStoredRowFields(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	agent := as("service:mctl-agent")
	agent.ActorPrincipalID = "prn_dev"
	w1 := open(t, s, CreateInput{})
	e1, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w1.ID, Engine: EngineArgo, EngineRef: "wf-1#xr_9", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ExecutionProvenance(ctx, e1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.AttemptID != executionprovenance.AttemptID(EngineArgo, "wf-1") || p.EngineRun != "wf-1" ||
		p.RootExecutionID != e1.ID || p.LineageRoot != executionprovenance.LineageRoot(e1.ID) ||
		p.ContractVersion != executionprovenance.ContractVersion {
		t.Fatalf("provenance = %+v", p)
	}
	if p.AttachedBy != "service:mctl-agent" || p.AttachedByPrincipal != "prn_dev" {
		t.Fatalf("attacher not recorded: %+v", p)
	}

	// The same engine run under another work item: same attempt, own lineage.
	w2 := open(t, s, CreateInput{})
	e2, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w2.ID, Engine: EngineArgo, EngineRef: "wf-1", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.ExecutionProvenance(ctx, e2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p2.AttemptID != p.AttemptID || p2.LineageRoot == p.LineageRoot {
		t.Fatalf("attempt/lineage = %s/%s vs %s/%s", p2.AttemptID, p2.LineageRoot, p.AttemptID, p.LineageRoot)
	}
}

func TestProvenanceLineageChainAndLegacyParent(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	agent := as("service:mctl-agent")
	w := open(t, s, CreateInput{})
	first, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.Get(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, err := s.Resume(ctx, ResumeInput{Mutation: keyed("github:alice", "r1", "h"), WorkItemID: w.ID, ExpectedStateVersion: cur.StateVersion, Engine: EngineTemporal, EngineRef: "run-2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: agent, WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-2", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	// The parent predates provenance: delete its row, the walk finds the root.
	if _, err := s.pool.Exec(ctx, `DELETE FROM execution_provenance WHERE execution_id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	cur, err = s.Get(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, third, _, err := s.Resume(ctx, ResumeInput{Mutation: keyed("github:alice", "r2", "h2"), WorkItemID: w.ID, ExpectedStateVersion: cur.StateVersion, Engine: EngineTemporal, EngineRef: "run-3"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ExecutionProvenance(ctx, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.RootExecutionID != first.ID || p.ParentExecutionID != second.ID || p.LineageRoot != executionprovenance.LineageRoot(first.ID) {
		t.Fatalf("provenance = %+v", p)
	}
	if _, err := s.ExecutionProvenance(ctx, second.ID); !errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("deleted row: %v", err)
	}
	known, err := s.LineageAttempts(ctx, p.LineageRoot, []string{p.AttemptID, executionprovenance.AttemptID(EngineArgo, "elsewhere")})
	if err != nil || !known[p.AttemptID] || len(known) != 1 {
		t.Fatalf("LineageAttempts = %v %v", known, err)
	}
}

func TestProvenanceImmutableAndAbsentVersusUnavailable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("service:mctl-agent"), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE execution_provenance SET attempt_id='at_x' WHERE execution_id=$1`, e.ID); err == nil {
		t.Fatal("UPDATE must be refused")
	}
	if _, err := s.ExecutionProvenance(ctx, "we_unknown"); !errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("unknown id: %v", err)
	}
	// A row failing re-validation is an error, never absent.
	if _, err := s.pool.Exec(ctx, `ALTER TABLE execution_provenance DISABLE TRIGGER execution_provenance_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE execution_provenance SET contract_version='v0' WHERE execution_id=$1`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `ALTER TABLE execution_provenance ENABLE TRIGGER execution_provenance_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecutionProvenance(ctx, e.ID); err == nil || errors.Is(err, ErrProvenanceAbsent) {
		t.Fatalf("bad row: %v", err)
	}
}
