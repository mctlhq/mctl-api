package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// failingSubmit is the fake executor with a submit that fails with err.
type failingSubmit struct {
	*fakeExecutor
	err error
}

func (s failingSubmit) Submit(context.Context, operations.Operation, map[string]string, string, string) (*operations.SubmitResult, error) {
	return nil, s.err
}

// mctl-api#1047: an apply leaves one record of what was planned, who
// granted it and what was submitted; health stays unknown until observed.
func TestDeployApply_WritesTheDeploymentRecord(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	plan, err := f.store.Get(context.Background(), planID)
	if err != nil {
		t.Fatal(err)
	}
	grant := f.grant(t, planID)
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": grant})
	assertStatus(t, w, http.StatusAccepted)
	depID, _ := decodeJSON(t, w)["deployment_id"].(string)

	rec, n := f.records.only()
	if n != 1 || rec.ID != depID {
		t.Fatalf("records = %d, response deployment_id %q, record %+v", n, depID, rec)
	}
	want := deployplan.Record{
		ID: depID, PlanID: planID, PlanDigest: plan.Digest, Tenant: "acme", Service: "web", Environment: "preview",
		Revision: deploySHA, GitopsSHA: planBaseSHA, PreviewID: plan.PreviewID, Host: plan.Host,
		ApprovalID: grant, DecidedByPrincipalID: grantOwnerPRN, AppliedBy: grantDevPRN,
		Status: deployplan.RecordSubmitted, Health: deployplan.HealthUnknown,
	}
	if !strings.HasPrefix(rec.WorkflowRef, "preview-deploy-") || rec.Workflow != rec.WorkflowRef {
		t.Fatalf("workflow %q, ref %q: the record must name the workflow it was submitted under", rec.Workflow, rec.WorkflowRef)
	}
	want.Workflow, want.WorkflowRef = rec.Workflow, rec.WorkflowRef
	rec.CreatedAt, rec.UpdatedAt = want.CreatedAt, want.UpdatedAt
	if *rec != want {
		t.Fatalf("record =\n%+v\nwant\n%+v", *rec, want)
	}

	// Read back by its id and by the plan's, by a tenant member.
	for _, id := range []string{depID, planID} {
		w := getAs(t, f.router, "/api/v1/deploy/deployments/"+id, f.dev)
		assertStatus(t, w, http.StatusOK)
		got := decodeJSON(t, w)
		if got["id"] != depID || got["health"] != "unknown" || got["image_digest"] != nil {
			t.Fatalf("GET %s = %v", id, got)
		}
	}
	// Anyone outside the tenant gets the same 404 as an unknown id.
	outsider := f.human(t, "eve", "prn_grantoutsider")
	for _, id := range []string{depID, "dep_00000000-0000-0000-0000-000000000000", "nope"} {
		w := getAs(t, f.router, "/api/v1/deploy/deployments/"+id, outsider)
		if w.Code != http.StatusNotFound || errCode(t, w) != "deployment_not_found" {
			t.Fatalf("outsider GET %s = %d %s", id, w.Code, w.Body.String())
		}
	}
}

// An apply that cannot be recorded does not run; the grant is spent.
func TestDeployApply_UnrecordableApplyDoesNotRun(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	grant := f.grant(t, planID)
	f.records.insertErr = errors.New("db down")
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": grant})
	if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "deploy_apply_unavailable" {
		t.Fatalf("apply = %d %s", w.Code, w.Body.String())
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted without a record: %v", f.exec.submitted)
	}
	if f.state(t, grant) != workitems.ApprovalConsumed {
		t.Fatalf("grant is %s, want consumed", f.state(t, grant))
	}
}

// Without a record store nothing is spent.
func TestDeployApply_NoRecordStoreRefusesBeforeSpend(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, func(o *mctlapi.Options) { o.DeployRecords = nil })
	planID := f.newPlan(t, faithfulIntent())
	grant := f.grant(t, planID)
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": grant})
	if w.Code != http.StatusServiceUnavailable || len(f.exec.submitted) != 0 || f.state(t, grant) != workitems.ApprovalApproved {
		t.Fatalf("apply = %d %s, submitted %v, grant %s", w.Code, w.Body.String(), f.exec.submitted, f.state(t, grant))
	}
	w = getAs(t, f.router, "/api/v1/deploy/deployments/dep_x", f.dev)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET without a store = %d", w.Code)
	}
}

// A submit that certainly created nothing is recorded as failed; one whose
// create may have been accepted stays submitting, since the status moves
// only once and a guess could never be corrected.
func TestDeployApply_FailedSubmitIsRecordedOnlyWhenCertain(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"not created": {operations.NotCreated(errors.New("no cluster client")), deployplan.RecordSubmitFailed},
		"ambiguous":   {errors.New("context deadline exceeded"), deployplan.RecordSubmitting},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t, faithfulValues, func(o *mctlapi.Options) { o.Executor = failingSubmit{&fakeExecutor{}, tc.err} })
			planID := f.newPlan(t, faithfulIntent())
			grant := f.grant(t, planID)
			w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": grant})
			assertStatus(t, w, http.StatusBadGateway)
			rec, n := f.records.only()
			if n != 1 || rec.Status != tc.want || rec.Workflow != "" || rec.Health != deployplan.HealthUnknown {
				t.Fatalf("records = %d, %+v, want status %s", n, rec, tc.want)
			}
		})
	}
}

// A plan applies once. A second requester's grant for an applied plan is
// refused before it is spent; one that loses the race after the check is
// spent but answered 409, with nothing submitted. A record store that cannot
// be read refuses before the spend, never as "not applied".
func TestDeployApply_PlanAppliesOnce(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	f.members.roles["acme|prn_grantdev2"] = "developer"
	bob := f.human(t, "bob", "prn_grantdev2")
	planID := f.newPlan(t, faithfulIntent())
	aliceGrant := f.grant(t, planID)
	bobGrant := f.grantAs(t, bob, planID)
	if aliceGrant == bobGrant {
		t.Fatal("two requesters share one grant; the test needs two")
	}
	assertStatus(t, f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": aliceGrant}), http.StatusAccepted)

	w := f.apply(t, bob, map[string]any{"plan_id": planID, "approval_id": bobGrant})
	if w.Code != http.StatusConflict || errCode(t, w) != "deploy_plan_already_applied" {
		t.Fatalf("second apply = %d %s", w.Code, w.Body.String())
	}
	if f.state(t, bobGrant) != workitems.ApprovalApproved || len(f.exec.submitted) != 1 {
		t.Fatalf("refused apply spent %s or submitted %v", f.state(t, bobGrant), f.exec.submitted)
	}

	f.records.getErr = errors.New("db down")
	w = f.apply(t, bob, map[string]any{"plan_id": planID, "approval_id": bobGrant})
	if w.Code != http.StatusServiceUnavailable || f.state(t, bobGrant) != workitems.ApprovalApproved {
		t.Fatalf("unreadable store = %d %s, grant %s", w.Code, w.Body.String(), f.state(t, bobGrant))
	}
	f.records.getErr = nil

	f.records.missOnLookup = true
	w = f.apply(t, bob, map[string]any{"plan_id": planID, "approval_id": bobGrant})
	if w.Code != http.StatusConflict || errCode(t, w) != "deploy_plan_already_applied" {
		t.Fatalf("raced apply = %d %s", w.Code, w.Body.String())
	}
	if f.state(t, bobGrant) != workitems.ApprovalConsumed || len(f.exec.submitted) != 1 {
		t.Fatalf("raced apply: grant %s, submitted %v", f.state(t, bobGrant), f.exec.submitted)
	}
}

// A store that cannot be read answers 503, never 404.
func TestGetDeployment_StoreUnreadable(t *testing.T) {
	f := newPlanFixture(t)
	f.records.getErr = errors.New("db down")
	for _, id := range []string{"dep_x", "dpl_x"} {
		w := getAs(t, f.router, "/api/v1/deploy/deployments/"+id, planDev)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s = %d %s", id, w.Code, w.Body.String())
		}
	}
}

// Apply's execution branches (a refused preparation writes no record; a
// failed record insert ends the prepared execution; a preset workflow name
// is kept) cannot be reached through the router while preview-deploy needs
// no execution, and apply's input carries no issue_url to create one from.
// This trips when that changes, so those branches get tests that reach them
// (mctl-api#1077 review).
func TestDeployApply_PreviewDeployNeedsNoExecution(t *testing.T) {
	if operations.RequiresExecution("preview-deploy") {
		t.Fatal("preview-deploy now requires an execution: cover apply's execution branches (handlers_deploy_apply.go) before relying on them")
	}
}
