package workitems

import (
	"context"
	"testing"
	"time"
)

// Phase 1 of mctl-api#373: every record that names an actor by string also
// records the actor's canonical principal id, and the relaying surface's.

func withPrincipals(m Mutation, actor, via string) Mutation {
	m.ActorPrincipalID, m.ViaPrincipalID = actor, via
	return m
}

func column(t *testing.T, s *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"|"+b)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWorkItemWritesRecordPrincipalIDs(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	alice := withPrincipals(as("github:alice"), "prn_ALICE", "prn_TELEGRAM")
	w := open(t, s, CreateInput{Mutation: alice})

	if got := column(t, s, `SELECT owner_principal_id, owner_principal FROM work_items WHERE id=$1`, w.ID); len(got) != 1 || got[0] != "prn_ALICE|github:alice" {
		t.Fatalf("work item owner = %v", got)
	}
	if _, _, err := s.AppendIntent(ctx, IntentInput{Mutation: alice, WorkItemID: w.ID, Text: "do it"}); err != nil {
		t.Fatal(err)
	}
	if got := column(t, s, `SELECT actor_principal_id, actor_principal FROM work_item_intents WHERE work_item_id=$1`, w.ID); len(got) != 1 || got[0] != "prn_ALICE|github:alice" {
		t.Fatalf("intent actor = %v", got)
	}

	x := requestExecution(t, s, xrInput(w, ExecutionRequestStart, alice))
	if _, _, err := s.ClaimExecutionRequest(ctx, ClaimInput{Mutation: withPrincipals(as(platform), "prn_AGENT", ""), Lease: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if got := column(t, s, `SELECT requested_by_principal_id || '/' || via_principal_id, claimed_by_principal_id
		FROM work_item_execution_requests WHERE id=$1`, x.ID); len(got) != 1 || got[0] != "prn_ALICE/prn_TELEGRAM|prn_AGENT" {
		t.Fatalf("execution request principals = %v", got)
	}

	// Every event carries its actor's principal and the relaying surface.
	events := column(t, s, `SELECT kind, actor_principal_id || '/' || via_principal_id FROM work_item_events
		WHERE work_item_id=$1 ORDER BY seq`, w.ID)
	want := map[string]string{
		EventCreated:                 "prn_ALICE/prn_TELEGRAM",
		EventIntentAppended:          "prn_ALICE/prn_TELEGRAM",
		EventExecutionRequestClaimed: "prn_AGENT/",
	}
	seen := map[string]bool{}
	for _, e := range events {
		for kind, principals := range want {
			if e == kind+"|"+principals {
				seen[kind] = true
			}
		}
	}
	for kind := range want {
		if !seen[kind] {
			t.Errorf("no %s event with principals %s in %v", kind, want[kind], events)
		}
	}
}

func TestActionApprovalRecordsPrincipalIDs(t *testing.T) {
	s := newStoreForTest(t)
	in := approvalInput(s, "prn-1")
	in.RequestedByPrincipalID, in.ViaPrincipalID = "prn_AGENT", ""
	a := createApproval(t, s, in)
	if _, err := s.DecideActionApproval(context.Background(), ActionDecisionInput{
		ID: a.ID, DecidedBy: "github:root", Decision: DecisionApprove,
		DecidedByPrincipalID: "prn_ROOT", DecidedViaPrincipalID: "prn_TELEGRAM",
	}); err != nil {
		t.Fatal(err)
	}
	got := column(t, s, `SELECT requested_by_principal_id || '/' || via_principal_id,
		decided_by_principal_id || '/' || decided_via_principal_id FROM action_approval_requests WHERE id=$1`, a.ID)
	if len(got) != 1 || got[0] != "prn_AGENT/|prn_ROOT/prn_TELEGRAM" {
		t.Fatalf("approval principals = %v", got)
	}
}
