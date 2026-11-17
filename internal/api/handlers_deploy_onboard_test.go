package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func unzipB64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// A service with no values.yaml in gitops is planned as an onboard: values
// compiled over the platform base, owner approval, redacted in the plan.
func TestDeployPlan_OnboardsAServiceNotInGitops(t *testing.T) {
	f := newPlanFixture(t)
	f.gitops.exists = false
	f.gitops.data = ""
	f.gitops.sourceRepo = ""
	w := f.plan(t, planDev, planIntent(nil), "")
	assertStatus(t, w, http.StatusCreated)
	got := decodeJSON(t, w)
	if got["action"] != "onboard" || got["requires_approval"] != true || got["required_role"] != "owner" {
		t.Fatalf("plan = %v", got)
	}
	if ap := got["approval"].(map[string]any); ap["reason"] != "preview_onboard_requires_approval" {
		t.Fatalf("approval = %v", ap)
	}
	stored, err := f.store.Get(context.Background(), got["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"repository: ghcr.io/mctlhq/web", "name: ghcr-credentials", "port: 8080", "FEATURE"} {
		if !strings.Contains(stored.ValuesAfter, want) {
			t.Errorf("values_after lacks %q:\n%s", want, stored.ValuesAfter)
		}
	}
	if strings.Contains(stored.ValuesAfter, "teams/acme/web") {
		t.Errorf("a Vault path is in the stored plan:\n%s", stored.ValuesAfter)
	}
	// An existing service is still planned as an update.
	g := newPlanFixture(t)
	if r := decodeJSON(t, g.plan(t, planDev, planIntent(nil), "")); r["action"] != "update" {
		t.Fatalf("existing service action = %v", r["action"])
	}
}

// No image organization configured: refused, never guessed.
func TestDeployPlan_OnboardWithoutImageOrgIsRefused(t *testing.T) {
	f := newPlanFixture(t, func(o *mctlapi.Options) { o.PlatformImageOrg = "" })
	f.gitops.exists = false
	w := f.plan(t, planDev, planIntent(nil), "")
	if w.Code != http.StatusInternalServerError || errCode(t, w) != "deploy_plan_failed" {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if f.store.inserts != 0 {
		t.Fatal("a plan was stored")
	}
}

// An approved onboard plan applies once with the values it bound: the apply
// hands preview-deploy the compiled values and their hash, built from the
// plan, and the caller cannot supply either.
func TestDeployApply_OnboardPassesTheApprovedValues(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	f.gitops.exists = false
	f.gitops.data = ""
	planID := f.newPlan(t, planIntent(nil))
	plan, err := f.store.Get(context.Background(), planID)
	if err != nil || plan.Action != deployplan.ActionOnboard {
		t.Fatalf("plan %v action %v", err, plan)
	}
	first := f.request(t, f.dev, planID, http.StatusCreated)
	id := first["approval"].(map[string]any)["id"].(string)
	digest := first["decision_context"].(map[string]any)["context_digest"].(string)
	if _, err := f.wi.DecideDeployApproval(context.Background(), workitems.ActionDecisionInput{
		ID: id, DecidedBy: "github:olga", DecidedByPrincipalID: grantOwnerPRN,
		Decision: workitems.DecisionApprove, ContextDigest: digest, FreshFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submittedParams) != 1 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
	got := f.exec.submittedParams[0]
	values := unzipB64(t, got["compiled_values"])
	sum := sha256.Sum256([]byte(values))
	if got["values_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("values_sha256 %q is not the hash of compiled_values", got["values_sha256"])
	}
	for _, want := range []string{"repository: ghcr.io/mctlhq/web", "remoteKey: teams/acme/web/preview", "mctl.ai/preview-id: " + plan.PreviewID} {
		if !strings.Contains(values, want) {
			t.Errorf("compiled values lack %q:\n%s", want, values)
		}
	}
	if got["gitops_ref"] != planBaseSHA || got["preview_id"] != plan.PreviewID {
		t.Errorf("gitops_ref/preview_id = %q/%q", got["gitops_ref"], got["preview_id"])
	}
}

// An update plan carries no compiled values: preview-deploy reads the
// service's values.yaml as before.
func TestDeployApply_UpdateCarriesNoCompiledValues(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	first := f.request(t, f.dev, planID, http.StatusCreated)
	id := first["approval"].(map[string]any)["id"].(string)
	digest := first["decision_context"].(map[string]any)["context_digest"].(string)
	if _, err := f.wi.DecideDeployApproval(context.Background(), workitems.ActionDecisionInput{
		ID: id, DecidedBy: "github:olga", DecidedByPrincipalID: grantOwnerPRN,
		Decision: workitems.DecisionApprove, ContextDigest: digest, FreshFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id}), http.StatusAccepted)
	got := f.exec.submittedParams[0]
	if got["compiled_values"] != "" || got["values_sha256"] != "" {
		t.Fatalf("an update carried compiled values: %v", got)
	}
}
