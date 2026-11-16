package api_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// failingSubmit is the fake executor with a submit that fails.
type failingSubmit struct{ *fakeExecutor }

func (failingSubmit) Submit(context.Context, operations.Operation, map[string]string, string, string) (*operations.SubmitResult, error) {
	return nil, errors.New("argo unavailable")
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
		Status: deployplan.RecordSubmitted, Workflow: "smoke-test-workflow-abc123", Health: deployplan.HealthUnknown,
	}
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

// A failed submit is recorded as failed, never as submitted.
func TestDeployApply_FailedSubmitIsRecorded(t *testing.T) {
	var f *grantFixture
	f = newGrantFixture(t, faithfulValues, func(o *mctlapi.Options) { o.Executor = failingSubmit{&fakeExecutor{}} })
	planID := f.newPlan(t, faithfulIntent())
	grant := f.grant(t, planID)
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": grant})
	assertStatus(t, w, http.StatusBadGateway)
	rec, n := f.records.only()
	if n != 1 || rec.Status != deployplan.RecordSubmitFailed || rec.Workflow != "" || rec.Health != deployplan.HealthUnknown {
		t.Fatalf("records = %d, %+v", n, rec)
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
