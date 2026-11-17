package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/deployplan"
)

const promoteDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func promoteEnabled(o *mctlapi.Options) { o.PromoteTenants = []string{"acme"} }

// seedPreview stores a verified preview record and returns its id.
func (f *grantFixture) seedPreview(t *testing.T, edit ...func(*deployplan.Record)) string {
	t.Helper()
	r := &deployplan.Record{
		ID: "dep_11111111-1111-1111-1111-111111111111", PlanID: "dpl_seed", PlanDigest: "sha256:" + strings.Repeat("c", 64),
		Tenant: "acme", Service: "web", Environment: deployplan.EnvironmentPreview, Revision: deploySHA,
		Status: deployplan.RecordSubmitted, RunResult: deployplan.RunSucceeded, Health: deployplan.HealthHealthy,
		ImageDigest: promoteDigest, PreviewID: "abc123", Host: "web-abc123.mctl.ai",
	}
	for _, e := range edit {
		e(r)
	}
	f.records.mu.Lock()
	f.records.byID[r.ID] = r
	f.records.mu.Unlock()
	return r.ID
}

func (f *grantFixture) promote(t *testing.T, depID string, want int) map[string]any {
	t.Helper()
	w := postAs(t, f.router, "/api/v1/deploy/promote", map[string]any{"deployment_id": depID}, f.dev)
	assertStatus(t, w, want)
	return decodeJSON(t, w)
}

func TestDeployPromote_PlansTheRecordsDigest(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	body := f.promote(t, f.seedPreview(t), http.StatusCreated)
	if body["environment"] != "production" || body["action"] != "promote" {
		t.Fatalf("plan = %v", body)
	}
	diff, _ := body["diff"].(string)
	if !strings.Contains(diff, promoteDigest) || !strings.Contains(diff, "rev-"+deploySHA) {
		t.Fatalf("diff does not pin the preview's image:\n%s", diff)
	}
	ap := body["approval"].(map[string]any)
	if ap["required"] != true || ap["role"] != "owner" {
		t.Fatalf("approval = %v", ap)
	}
	// The same preview gives the same plan again.
	if again := f.promote(t, "dep_11111111-1111-1111-1111-111111111111", http.StatusCreated); again["digest"] != body["digest"] {
		t.Fatalf("digest changed: %v vs %v", again["digest"], body["digest"])
	}
}

func TestDeployPromote_Refusals(t *testing.T) {
	for name, edit := range map[string]func(*deployplan.Record){
		"run failed":      func(r *deployplan.Record) { r.RunResult = deployplan.RunFailed },
		"not healthy":     func(r *deployplan.Record) { r.Health = deployplan.HealthUnknown },
		"no digest":       func(r *deployplan.Record) { r.ImageDigest = "" },
		"not submitted":   func(r *deployplan.Record) { r.Status = deployplan.RecordSubmitting },
		"production only": func(r *deployplan.Record) { r.Environment = deployplan.EnvironmentProduction },
	} {
		f := newGrantFixture(t, faithfulValues, promoteEnabled)
		f.promote(t, f.seedPreview(t, edit), http.StatusConflict)
		if f.store.inserts != 0 {
			t.Errorf("%s: a plan was stored", name)
		}
	}
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	f.promote(t, "dep_22222222-2222-2222-2222-222222222222", http.StatusNotFound)
	f.promote(t, "nonsense", http.StatusNotFound)
	// A caller-supplied digest, tag or revision is not a field.
	dep := f.seedPreview(t)
	for _, extra := range []string{"image_digest", "image_tag", "revision"} {
		w := postAs(t, f.router, "/api/v1/deploy/promote", map[string]any{"deployment_id": dep, extra: "x"}, f.dev)
		assertStatus(t, w, http.StatusBadRequest)
	}
}

func TestDeployPromote_TenantNotEnabled(t *testing.T) {
	f := newGrantFixture(t, faithfulValues) // no PromoteTenants
	f.promote(t, f.seedPreview(t), http.StatusForbidden)
}

func TestDeployPromote_UnknownTenantMemberSeesNothing(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	dep := f.seedPreview(t, func(r *deployplan.Record) { r.Tenant = "other" })
	f.promote(t, dep, http.StatusNotFound)
}

func TestDeployPromote_ValuesNeedAnImage(t *testing.T) {
	f := newGrantFixture(t, "replicaCount: 1\n", promoteEnabled)
	f.promote(t, f.seedPreview(t), http.StatusUnprocessableEntity)
}

// The whole path: plan, owner grant, one apply that runs the record's digest.
func TestDeployApply_PromoteRunsTheRecordedDigestOnce(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	plan := f.promote(t, f.seedPreview(t), http.StatusCreated)
	planID := plan["id"].(string)
	f.plans = append(f.plans, planID)

	// No grant, no apply.
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": "aar_none"})
	if w.Code == http.StatusAccepted || len(f.exec.submitted) != 0 {
		t.Fatalf("applied without a grant: %d %s", w.Code, w.Body.String())
	}
	id := f.grant(t, planID)
	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 || f.exec.submitted[0] != "promote-deployment" {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
	got := f.exec.submittedParams[0]
	for k, want := range map[string]string{
		"team_name": "acme", "component_name": "web", "image_tag": "rev-" + deploySHA, "image_digest": promoteDigest,
	} {
		if got[k] != want {
			t.Errorf("promote-deployment %s = %q, want %q", k, got[k], want)
		}
	}
	res := decodeJSON(t, w)
	rec, err := f.records.GetRecord(context.Background(), res["deployment_id"].(string))
	if err != nil || rec.Environment != deployplan.EnvironmentProduction {
		t.Fatalf("promotion record = %+v, %v", rec, err)
	}
	// Replay.
	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code != http.StatusConflict || len(f.exec.submitted) != 1 {
		t.Fatalf("replay = %d %s", w.Code, w.Body.String())
	}
}

// A grant decided for a preview plan does not apply a promotion.
func TestDeployApply_PromoteNeedsItsOwnGrant(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	previewPlan := f.newPlan(t, faithfulIntent())
	grant := f.grant(t, previewPlan)
	plan := f.promote(t, f.seedPreview(t), http.StatusCreated)
	w := f.apply(t, f.dev, map[string]any{"plan_id": plan["id"], "approval_id": grant})
	if w.Code == http.StatusAccepted || len(f.exec.submitted) != 0 {
		t.Fatalf("a preview grant applied a promotion: %d %s", w.Code, w.Body.String())
	}
}

func TestOperationsExecute_RefusesPromoteDeployment(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, promoteEnabled)
	w := postAs(t, f.router, "/api/v1/operations/promote-deployment/execute", map[string]any{
		"team_name": "acme", "component_name": "web", "image_tag": "x", "image_digest": promoteDigest,
	}, f.dev)
	// 405 is the HandlerOnly refusal itself, not some later check.
	if w.Code != http.StatusMethodNotAllowed || len(f.exec.submitted) != 0 {
		t.Fatalf("generic execute ran the promotion: %d %s", w.Code, w.Body.String())
	}
}
