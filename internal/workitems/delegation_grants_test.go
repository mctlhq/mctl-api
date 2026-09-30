package workitems

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/delegation"
)

// The four grant projections return exactly delegation.Record's fields,
// including a stored '' principal id verbatim (task 2's DoD) -- never a
// fallback to the adjacent principal string, and never touching the shared
// executionRequestColumns / actionApprovalColumns / itemColumns lists.

func TestExecutionRequestGrant_ProjectsTheGrantFields(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{})
	x := requestExecution(t, s, xrInput(w, ExecutionRequestStart, withPrincipals(as("github:alice"), "prn_ALICE", "")))

	rec, err := s.ExecutionRequestGrant(context.Background(), w.ID, x.ID)
	if err != nil {
		t.Fatalf("ExecutionRequestGrant: %v", err)
	}
	if rec.Subject != "github:alice" || rec.SubjectPrincipalID != "prn_ALICE" || rec.WorkItemID != w.ID || rec.ExecutionID != "" {
		t.Fatalf("record = %+v", rec)
	}

	// Narrowed by the wrong item id: not found.
	if _, err := s.ExecutionRequestGrant(context.Background(), "wi_other", x.ID); !errors.Is(err, delegation.ErrNotBound) {
		t.Fatalf("wrong item id: err = %v, want ErrNotBound", err)
	}
	// No narrowing at all still finds it.
	if rec, err := s.ExecutionRequestGrant(context.Background(), "", x.ID); err != nil || rec.Subject != "github:alice" {
		t.Fatalf("no narrowing: %+v %v", rec, err)
	}
	// Unknown id: not found.
	if _, err := s.ExecutionRequestGrant(context.Background(), "", "xr_doesnotexist"); !errors.Is(err, delegation.ErrNotBound) {
		t.Fatalf("unknown id: err = %v, want ErrNotBound", err)
	}
}

// A pending execution request's own execution_id column is ”, so the
// binding half a run token would compare against ExecutionID is empty until
// fulfilment -- the resolver's caller is expected to fall back to the work
// item id in that case (delegation.StoreResolver's own concern, not this
// projection's).
func TestExecutionRequestGrant_EmptyPrincipalIDVerbatim(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{})
	x := requestExecution(t, s, xrInput(w, ExecutionRequestStart, as("github:alice"))) // no principal id set

	rec, err := s.ExecutionRequestGrant(context.Background(), w.ID, x.ID)
	if err != nil {
		t.Fatalf("ExecutionRequestGrant: %v", err)
	}
	if rec.SubjectPrincipalID != "" {
		t.Fatalf("SubjectPrincipalID = %q, want '' verbatim", rec.SubjectPrincipalID)
	}
}

func TestActionApprovalGrant_ProjectsTheGrantFields(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{})
	in := approvalInput(s, "k-delegation")
	in.WorkItemID = w.ID
	in.RequestedByPrincipalID = "prn_AGENT"
	a := createApproval(t, s, in)

	// Undecided: no subject yet.
	rec, err := s.ActionApprovalGrant(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("ActionApprovalGrant: %v", err)
	}
	if rec.Subject != "" || rec.SubjectPrincipalID != "" || rec.WorkItemID != w.ID || rec.ExecutionID != storeTestExecution {
		t.Fatalf("undecided record = %+v", rec)
	}

	if _, err := s.DecideActionApproval(context.Background(), ActionDecisionInput{
		ID: a.ID, DecidedBy: "github:root", Decision: DecisionApprove,
		DecidedByPrincipalID: "prn_ROOT",
	}); err != nil {
		t.Fatal(err)
	}
	rec, err = s.ActionApprovalGrant(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("ActionApprovalGrant after decide: %v", err)
	}
	if rec.Subject != "github:root" || rec.SubjectPrincipalID != "prn_ROOT" || rec.ExecutionID != storeTestExecution || rec.WorkItemID != w.ID {
		t.Fatalf("decided record = %+v", rec)
	}

	if _, err := s.ActionApprovalGrant(context.Background(), "aar_doesnotexist"); !errors.Is(err, delegation.ErrNotBound) {
		t.Fatalf("unknown id: err = %v, want ErrNotBound", err)
	}
}

func TestWorkItemGrant_ProjectsTheOwnerAndHasNoExecutionID(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{Mutation: withPrincipals(as("github:alice"), "prn_ALICE", "")})

	rec, err := s.WorkItemGrant(context.Background(), w.ID)
	if err != nil {
		t.Fatalf("WorkItemGrant: %v", err)
	}
	if rec.Subject != "github:alice" || rec.SubjectPrincipalID != "prn_ALICE" || rec.WorkItemID != w.ID || rec.ExecutionID != "" {
		t.Fatalf("record = %+v", rec)
	}
	if _, err := s.WorkItemGrant(context.Background(), "wi_doesnotexist"); !errors.Is(err, delegation.ErrNotBound) {
		t.Fatalf("unknown id: err = %v, want ErrNotBound", err)
	}
}

func TestSurfaceRefBound_MatchesExactlyOneCorrelation(t *testing.T) {
	s := newStoreForTest(t)
	w := open(t, s, CreateInput{})
	if _, _, err := s.LinkSurface(context.Background(), SurfaceRefInput{
		Mutation: as("surface:telegram"), WorkItemID: w.ID, ExternalID: "chat-1", ActorExternalID: "555",
	}); err != nil {
		t.Fatal(err)
	}

	bound, err := s.SurfaceRefBound(context.Background(), w.ID, "telegram", "555")
	if err != nil {
		t.Fatalf("SurfaceRefBound: %v", err)
	}
	if !bound {
		t.Fatal("expected the correlation to be bound")
	}
	for _, tc := range []struct{ itemID, surface, actor string }{
		{w.ID, "telegram", "999"},       // wrong actor
		{w.ID, "portal", "555"},         // wrong surface
		{"wi_other", "telegram", "555"}, // wrong item
	} {
		bound, err := s.SurfaceRefBound(context.Background(), tc.itemID, tc.surface, tc.actor)
		if err != nil {
			t.Fatalf("SurfaceRefBound(%+v): %v", tc, err)
		}
		if bound {
			t.Errorf("SurfaceRefBound(%+v) = true, want false", tc)
		}
	}
}
