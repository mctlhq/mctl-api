package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const (
	rbCommit = "1111111111111111111111111111111111111111"
	rbDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	rbDepID  = "dep_00000000-0000-0000-0000-000000000001"
)

type rbFixture struct {
	*roleFixture
	records *fakeRecordStore
	t       *testing.T
}

func newRollbackFixture(t *testing.T) *rbFixture {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	f := &rbFixture{roleFixture: &roleFixture{
		git: &fakeGitReader{tenants: []gitops.Tenant{
			{Name: "erpact", Members: []gitops.TenantMember{{UserID: "dan-dev", Role: "developer"}, {UserID: "vic-viewer", Role: "viewer"}}},
			{Name: "other", Members: []gitops.TenantMember{{UserID: "oscar", Role: "owner"}}},
		}, services: []gitops.Service{{Team: "erpact", Name: "web"}, {Team: "erpact", Name: "api"}, {Team: "other", Name: "web"}}},
		exec: &fakeExecutor{}, audit: audit.NewLogger(),
	}, records: newFakeRecordStore(), t: t}
	f.router = mctlapi.NewRouter(mctlapi.Options{Registry: operations.NewRegistry(), GitReader: f.git,
		AuditLog: f.audit, Executor: f.exec, DeployRecords: f.records})
	return f
}

func (f *rbFixture) put(mut func(r *deployplan.Record)) {
	r := &deployplan.Record{ID: rbDepID, Tenant: "erpact", Service: "web", Status: deployplan.RecordSubmitted,
		RunResult: "succeeded", Health: deployplan.HealthHealthy, CommitSHA: rbCommit, ImageDigest: rbDigest}
	if mut != nil {
		mut(r)
	}
	f.records.byID[r.ID] = r
}

func rbBody() map[string]string {
	return map[string]string{"team_name": "erpact", "component_name": "web", "deployment_id": rbDepID}
}

func (f *rbFixture) post(body map[string]string, u *auth.User) (int, string) {
	w := postAsRaw(f.t, f.router, "/api/v1/operations/rollback-revision/execute", body, u)
	return w.Code, w.Body.String()
}

func TestRollbackRevision_SubmitsRecordValues(t *testing.T) {
	f := newRollbackFixture(t)
	f.put(nil)
	code, out := f.post(rbBody(), auth.NewGitHubUser("dan-dev", []string{"erpact"}))
	if code != http.StatusOK && code != http.StatusAccepted {
		t.Fatalf("status %d: %s", code, out)
	}
	if len(f.exec.submittedParams) != 1 {
		t.Fatalf("submitted %d", len(f.exec.submittedParams))
	}
	p := f.exec.submittedParams[0]
	if p["target_commit"] != rbCommit || p["expected_digest"] != rbDigest {
		t.Fatalf("workflow params not from the record: %v", p)
	}
	if _, leaked := p["deployment_id"]; leaked {
		t.Fatalf("deployment_id reached Argo: %v", p)
	}
}

func TestRollbackRevision_Refusals(t *testing.T) {
	dev := auth.NewGitHubUser("dan-dev", []string{"erpact"})
	cases := []struct {
		name   string
		mut    func(r *deployplan.Record)
		body   func(m map[string]string)
		user   *auth.User
		status int
		code   string
	}{
		{"another service of the tenant", func(r *deployplan.Record) { r.Service = "api" }, nil, dev, 404, "rollback_deployment_not_found"},
		{"another tenant's record", func(r *deployplan.Record) { r.Tenant = "other" }, nil, dev, 404, "rollback_deployment_not_found"},
		{"unknown deployment", nil, func(m map[string]string) { m["deployment_id"] = "dep_00000000-0000-0000-0000-0000000000ff" }, dev, 404, "rollback_deployment_not_found"},
		{"failed run", func(r *deployplan.Record) { r.RunResult = "failed" }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"unknown health", func(r *deployplan.Record) { r.Health = deployplan.HealthUnknown }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"unhealthy", func(r *deployplan.Record) { r.Health = deployplan.HealthUnhealthy }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"no commit recorded", func(r *deployplan.Record) { r.CommitSHA = "" }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"no digest recorded", func(r *deployplan.Record) { r.ImageDigest = "" }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"not yet submitted", func(r *deployplan.Record) { r.Status = deployplan.RecordSubmitting }, nil, dev, 409, "rollback_deployment_not_usable"},
		{"commit named in the body", nil, func(m map[string]string) { m["target_commit"] = strings.Repeat("a", 40) }, dev, 400, "rollback_target_is_server_set"},
		{"digest named in the body", nil, func(m map[string]string) { m["expected_digest"] = rbDigest }, dev, 400, "rollback_target_is_server_set"},
		{"viewer", nil, nil, auth.NewGitHubUser("vic-viewer", []string{"erpact"}), 403, ""},
		{"non-member of the tenant", nil, nil, auth.NewGitHubUser("oscar", []string{"other"}), 403, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRollbackFixture(t)
			f.put(c.mut)
			b := rbBody()
			if c.body != nil {
				c.body(b)
			}
			code, out := f.post(b, c.user)
			if code != c.status || (c.code != "" && !strings.Contains(out, c.code)) {
				t.Fatalf("status %d (want %d, %q): %s", code, c.status, c.code, out)
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("a workflow was submitted: %v", f.exec.submittedParams)
			}
		})
	}
}

func TestRollbackRevision_StoreErrorRefuses(t *testing.T) {
	f := newRollbackFixture(t)
	f.put(nil)
	f.records.getErr = errors.New("db down")
	code, out := f.post(rbBody(), auth.NewGitHubUser("dan-dev", []string{"erpact"}))
	if code != http.StatusServiceUnavailable || len(f.exec.submitted) != 0 {
		t.Fatalf("status %d, submitted %d: %s", code, len(f.exec.submitted), out)
	}
}

// The 404 for a record of another service hides its owner; the audit row is
// filed under the caller's team and readable by its members, so it must not
// name the owner either.
func TestRollbackRevision_AuditDoesNotNameTheRecordOwner(t *testing.T) {
	for _, owner := range []struct{ tenant, service string }{{"other", "web"}, {"erpact", "secret-svc"}} {
		f := newRollbackFixture(t)
		f.put(func(r *deployplan.Record) { r.Tenant, r.Service = owner.tenant, owner.service })
		code, out := f.post(rbBody(), auth.NewGitHubUser("dan-dev", []string{"erpact"}))
		if code != http.StatusNotFound {
			t.Fatalf("status %d: %s", code, out)
		}
		pair := owner.tenant + "/" + owner.service
		for _, e := range f.audit.List(50) {
			if strings.Contains(e.Message, pair) {
				t.Fatalf("audit row names the record owner: %q", e.Message)
			}
		}
		if strings.Contains(out, pair) {
			t.Fatalf("response names the record owner: %s", out)
		}
	}
}

func TestRollbackRevision_ServerSetParamsAreNotAdvertisedAsRequired(t *testing.T) {
	op, _ := operations.NewRegistry().Get("rollback-revision")
	for _, p := range op.Parameters {
		if (p.Name == "target_commit" || p.Name == "expected_digest") && p.Required {
			t.Fatalf("%s is advertised as a required caller input", p.Name)
		}
	}
}
