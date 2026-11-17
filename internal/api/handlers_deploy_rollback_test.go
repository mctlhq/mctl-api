package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	rollbackDepID  = "dep_33333333-3333-3333-3333-333333333333"
	rollbackCommit = "4444444444444444444444444444444444444444"
)

// seedProduction stores a healthy production deployment to roll back to.
func (f *grantFixture) seedProduction(t *testing.T, edit ...func(*deployplan.Record)) string {
	t.Helper()
	r := &deployplan.Record{
		ID: rollbackDepID, PlanID: "dpl_prod", PlanDigest: "sha256:" + strings.Repeat("d", 64),
		Tenant: "acme", Service: "web", Environment: deployplan.EnvironmentProduction, Revision: deploySHA,
		Status: deployplan.RecordSubmitted, RunResult: deployplan.RunSucceeded, Health: deployplan.HealthHealthy,
		ImageDigest: promoteDigest, CommitSHA: rollbackCommit,
	}
	for _, e := range edit {
		e(r)
	}
	f.records.mu.Lock()
	f.records.byID[r.ID] = r
	f.records.mu.Unlock()
	return r.ID
}

func (f *grantFixture) rollback(t *testing.T, depID string, want int) map[string]any {
	t.Helper()
	w := postAs(t, f.router, "/api/v1/deploy/rollback", map[string]any{"deployment_id": depID}, f.dev)
	assertStatus(t, w, want)
	return decodeJSON(t, w)
}

func TestDeployRollback_PlansTheRecordsCommit(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	body := f.rollback(t, f.seedProduction(t), http.StatusCreated)
	if body["environment"] != "production" || body["action"] != "rollback" {
		t.Fatalf("plan = %v", body)
	}
	if after, _ := body["values_after"].(string); !strings.Contains(after, rollbackCommit) {
		t.Fatalf("plan does not name the commit:\n%s", after)
	}
	ap := body["approval"].(map[string]any)
	if ap["required"] != true || ap["role"] != "owner" {
		t.Fatalf("approval = %v", ap)
	}
}

func TestDeployRollback_Refusals(t *testing.T) {
	for name, edit := range map[string]func(*deployplan.Record){
		"run failed":    func(r *deployplan.Record) { r.RunResult = deployplan.RunFailed },
		"not healthy":   func(r *deployplan.Record) { r.Health = deployplan.HealthUnknown },
		"no digest":     func(r *deployplan.Record) { r.ImageDigest = "" },
		"no commit":     func(r *deployplan.Record) { r.CommitSHA = "" },
		"not submitted": func(r *deployplan.Record) { r.Status = deployplan.RecordSubmitting },
		"a preview":     func(r *deployplan.Record) { r.Environment = deployplan.EnvironmentPreview },
	} {
		f := newGrantFixture(t, faithfulValues, promoteEnabled)
		w := postAs(t, f.router, "/api/v1/deploy/rollback", map[string]any{"deployment_id": f.seedProduction(t, edit)}, f.dev)
		if w.Code != http.StatusConflict && w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d %s", name, w.Code, w.Body.String())
		}
		if f.store.inserts != 0 {
			t.Errorf("%s: a plan was stored", name)
		}
	}
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	dep := f.seedProduction(t)
	for _, extra := range []string{"target_commit", "expected_digest", "image_digest"} {
		w := postAs(t, f.router, "/api/v1/deploy/rollback", map[string]any{"deployment_id": dep, extra: "x"}, f.dev)
		assertStatus(t, w, http.StatusBadRequest)
	}
}

func TestDeployRollback_TenantNotEnabled(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	f.rollback(t, f.seedProduction(t), http.StatusForbidden)
}

// The whole path: plan, owner grant, one apply running the record's commit.
func TestDeployApply_RollbackRunsTheRecordedCommitOnce(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	plan := f.rollback(t, f.seedProduction(t), http.StatusCreated)
	planID := plan["id"].(string)
	f.plans = append(f.plans, planID)

	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": "aar_none"})
	if w.Code == http.StatusAccepted || len(f.exec.submitted) != 0 {
		t.Fatalf("applied without a grant: %d %s", w.Code, w.Body.String())
	}
	id := f.grant(t, planID)
	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 || f.exec.submitted[0] != "rollback-revision" {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
	got := f.exec.submittedParams[0]
	for k, want := range map[string]string{
		"team_name": "acme", "component_name": "web", "target_commit": rollbackCommit, "expected_digest": promoteDigest,
	} {
		if got[k] != want {
			t.Errorf("rollback-revision %s = %q, want %q", k, got[k], want)
		}
	}
	res := decodeJSON(t, w)
	rec, err := f.records.GetRecord(context.Background(), res["deployment_id"].(string))
	if err != nil || rec.Environment != deployplan.EnvironmentProduction || rec.SourceDeploymentID != rollbackDepID {
		t.Fatalf("rollback record = %+v, %v", rec, err)
	}
	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code != http.StatusConflict || len(f.exec.submitted) != 1 {
		t.Fatalf("replay = %d %s", w.Code, w.Body.String())
	}
}

func TestDeployApply_RollbackNeedsItsOwnGrant(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	grant := f.grant(t, f.newPlan(t, faithfulIntent()))
	plan := f.rollback(t, f.seedProduction(t), http.StatusCreated)
	w := f.apply(t, f.dev, map[string]any{"plan_id": plan["id"], "approval_id": grant})
	if w.Code == http.StatusAccepted || len(f.exec.submitted) != 0 {
		t.Fatalf("a preview grant applied a rollback: %d %s", w.Code, w.Body.String())
	}
}

func TestDeployApply_RollbackRefusedWhenProductionMoved(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	plan := f.rollback(t, f.seedProduction(t), http.StatusCreated)
	planID := plan["id"].(string)
	f.plans = append(f.plans, planID)
	id := f.grant(t, planID)
	f.gitops.data = strings.Replace(faithfulValues, "tag: 1.0.0", "tag: 2.0.0", 1)
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code != http.StatusConflict || errCode(t, w) != "deploy_apply_not_reproducible" || len(f.exec.submitted) != 0 {
		t.Fatalf("stale apply = %d %s submitted %v", w.Code, w.Body.String(), f.exec.submitted)
	}
	if f.state(t, id) == workitems.ApprovalConsumed {
		t.Fatal("a refused stale apply spent the grant")
	}
}

// The ungoverned rollback-revision route must not restore production.
func TestRollbackRevision_ProductionNeedsAGrant(t *testing.T) {
	f := newRollbackFixture(t)
	f.put(func(r *deployplan.Record) { r.Environment = deployplan.EnvironmentProduction })
	code, out := f.post(rbBody(), authDev())
	if code != http.StatusForbidden || !strings.Contains(out, "rollback_requires_grant") || len(f.exec.submittedParams) != 0 {
		t.Fatalf("generic rollback of a production deployment = %d %s", code, out)
	}
}

func authDev() *auth.User { return auth.NewGitHubUser("dan-dev", []string{"erpact"}) }
