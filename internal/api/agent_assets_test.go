package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

type snapshotReader struct {
	GitReader
	snap *gitops.AgentPlatformSnapshot
	err  error
}

func (s snapshotReader) ReadAgentPlatformSnapshot() (*gitops.AgentPlatformSnapshot, error) {
	return s.snap, s.err
}

func f64(v float64) *float64 { return &v }
func bptr(v bool) *bool      { return &v }

func testPolicy() *gitops.AgentPlatformPolicy {
	p := &gitops.AgentPlatformPolicy{
		KnownTools:            []string{"Read", "mcp__mctl__*"},
		KnownSkills:           []string{"mctl-platform"},
		KnownModelPolicyTasks: []string{"service_agent"},
		KnownPolicies:         []string{"pr-shepherd"},
		KnownApprovalGates:    []string{"merge", "code-authoring"},
		KnownEvidenceKinds:    []string{"diff"},
		KnownMutationScopes: []gitops.MutationScope{
			{Name: "pull-request-merge", Mutating: true, RequiresApproval: "merge"},
			{Name: "issue-comment", Mutating: true},
		},
		ApprovedSandboxes: map[string][]string{"argo": {"cwft-a"}},
	}
	p.Limits.MaxBudgetUsd = f64(25)
	p.Limits.MaxTimeoutSeconds = f64(7200)
	return p
}

func goodSpec() gitops.ExecutionProfileSpec {
	var s gitops.ExecutionProfileSpec
	s.Version = "1.0.0"
	s.ModelPolicyRef.Task = "service_agent"
	s.Skills = []string{"mctl-platform"}
	s.Tools = []string{"Read", "mcp__mctl__*"}
	s.PolicyRef = "pr-shepherd"
	s.Permissions.MutationScopes = []string{"pull-request-merge"}
	s.BudgetUsd = f64(10)
	s.TimeoutSeconds = f64(600)
	s.Runtime.Sandbox.Backend = "argo"
	s.Runtime.Sandbox.ClusterWorkflowTemplate = "cwft-a"
	s.Runtime.Sandbox.Approved = bptr(true)
	s.Approval.RequiredBefore = []string{"merge"}
	s.Evidence.Required = []string{"diff"}
	return s
}

func statusOf(checks []PreflightCheck, id string) string {
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "missing"
}

func TestEvaluatePreflight_AllPassAndRegistryUnknown(t *testing.T) {
	spec := goodSpec()
	checks := evaluatePreflight(&spec, nil, testPolicy(), nil, &registryFacts{})
	if len(checks) != 9 {
		t.Fatalf("want 9 checks, got %d", len(checks))
	}
	if got := statusOf(checks, "binding.lifecycle"); got != statusUnknown {
		t.Errorf("binding.lifecycle = %s, want unknown", got)
	}
	if v := verdict(checks); v != statusUnknown {
		t.Errorf("verdict = %s, want unknown", v)
	}
	for _, id := range []string{"profile.budget", "profile.timeout", "profile.sandbox", "profile.model_policy_task", "profile.refs", "profile.approval_gates", "profile.capability_discovery"} {
		if got := statusOf(checks, id); got != statusPass {
			t.Errorf("%s = %s, want pass", id, got)
		}
	}
	sat := true
	checks = evaluatePreflight(&spec, nil, testPolicy(), nil, &registryFacts{defLifecycle: "published", profLifecycle: "deprecated", compatSatisfied: &sat})
	if v := verdict(checks); v != statusPass {
		t.Errorf("verdict = %s, want pass: %+v", v, checks)
	}
}

func TestEvaluatePreflight_Failures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*gitops.ExecutionProfileSpec)
		id     string
		want   string
	}{
		{"budget over", func(s *gitops.ExecutionProfileSpec) { s.BudgetUsd = f64(30) }, "profile.budget", statusFail},
		{"budget absent", func(s *gitops.ExecutionProfileSpec) { s.BudgetUsd = nil }, "profile.budget", statusUnknown},
		{"timeout over", func(s *gitops.ExecutionProfileSpec) { s.TimeoutSeconds = f64(9000) }, "profile.timeout", statusFail},
		{"sandbox unapproved", func(s *gitops.ExecutionProfileSpec) { s.Runtime.Sandbox.Approved = bptr(false) }, "profile.sandbox", statusFail},
		{"sandbox unknown cwft", func(s *gitops.ExecutionProfileSpec) { s.Runtime.Sandbox.ClusterWorkflowTemplate = "x" }, "profile.sandbox", statusFail},
		{"task unknown", func(s *gitops.ExecutionProfileSpec) { s.ModelPolicyRef.Task = "nope" }, "profile.model_policy_task", statusFail},
		{"tool unknown", func(s *gitops.ExecutionProfileSpec) { s.Tools = append(s.Tools, "Bash") }, "profile.refs", statusFail},
		{"skills absent", func(s *gitops.ExecutionProfileSpec) { s.Skills = nil }, "profile.refs", statusUnknown},
		{"merge gate missing", func(s *gitops.ExecutionProfileSpec) { s.Approval.RequiredBefore = []string{"code-authoring"} }, "profile.approval_gates", statusFail},
		{"scope unknown", func(s *gitops.ExecutionProfileSpec) { s.Permissions.MutationScopes = []string{"zzz"} }, "profile.approval_gates", statusFail},
		{"discovery bad alias", func(s *gitops.ExecutionProfileSpec) {
			s.CapabilityDiscovery = &gitops.CapabilityDiscoverySpec{Enabled: bptr(false)}
			s.CapabilityDiscovery.Providers = append(s.CapabilityDiscovery.Providers, struct {
				Type     string `json:"type" yaml:"type"`
				ID       string `json:"id" yaml:"id"`
				Alias    string `json:"alias" yaml:"alias"`
				Endpoint string `json:"endpoint,omitempty" yaml:"endpoint"`
			}{Type: "mcp", ID: "mctl-api", Alias: "other"})
		}, "profile.capability_discovery", statusFail},
		{"discovery enabled without tool", func(s *gitops.ExecutionProfileSpec) {
			s.Tools = []string{"Read"}
			s.CapabilityDiscovery = &gitops.CapabilityDiscoverySpec{Enabled: bptr(true)}
		}, "profile.capability_discovery", statusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := goodSpec()
			tc.mutate(&spec)
			checks := evaluatePreflight(&spec, nil, testPolicy(), nil, &registryFacts{})
			if got := statusOf(checks, tc.id); got != tc.want {
				t.Errorf("%s = %s, want %s", tc.id, got, tc.want)
			}
		})
	}
}

func TestEvaluatePreflight_BindingChecks(t *testing.T) {
	spec := goodSpec()
	yes, no := true, false
	cases := []struct {
		facts     registryFacts
		lifecycle string
		compat    string
	}{
		{registryFacts{defLifecycle: "disabled", profLifecycle: "published", compatSatisfied: &yes}, statusFail, statusPass},
		{registryFacts{defLifecycle: "published", profLifecycle: "published", compatSatisfied: &no}, statusPass, statusFail},
		{registryFacts{defLifecycle: "published", profLifecycle: "published", versionMismatch: "x"}, statusPass, statusUnknown},
		{registryFacts{err: errors.New("db down")}, statusUnknown, statusUnknown},
	}
	for i, c := range cases {
		checks := evaluatePreflight(&spec, nil, testPolicy(), nil, &c.facts)
		if got := statusOf(checks, "binding.lifecycle"); got != c.lifecycle {
			t.Errorf("case %d lifecycle = %s, want %s", i, got, c.lifecycle)
		}
		if got := statusOf(checks, "binding.compatibility"); got != c.compat {
			t.Errorf("case %d compat = %s, want %s", i, got, c.compat)
		}
	}
}

func TestVerdict(t *testing.T) {
	p, f, u := PreflightCheck{Status: statusPass}, PreflightCheck{Status: statusFail}, PreflightCheck{Status: statusUnknown}
	for _, tc := range []struct {
		in   []PreflightCheck
		want string
	}{
		{[]PreflightCheck{p, f}, statusFail},
		{[]PreflightCheck{p, u}, statusUnknown},
		{[]PreflightCheck{p, p}, statusPass},
		{nil, statusUnknown},
	} {
		if got := verdict(tc.in); got != tc.want {
			t.Errorf("verdict(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func assetsRequest(h *Handlers, route http.HandlerFunc, pattern, target string, user *auth.User) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Get(pattern, route)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if user != nil {
		req = req.WithContext(auth.WithUser(context.Background(), user))
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func profileNamed(name string, mutate func(*gitops.ExecutionProfileSpec)) gitops.AgentPlatformProfile {
	s := goodSpec()
	if mutate != nil {
		mutate(&s)
	}
	return gitops.AgentPlatformProfile{Name: name, Spec: s}
}

func TestPreflightAgent_AdminOnlyAndSelectors(t *testing.T) {
	snap := &gitops.AgentPlatformSnapshot{Revision: "abc", Policy: testPolicy(),
		Profiles: []gitops.AgentPlatformProfile{profileNamed("x-default", nil)}}
	h := &Handlers{opts: Options{GitReader: snapshotReader{snap: snap}}}

	if rec := assetsRequest(h, h.PreflightAgent, "/agents/{name}/preflight", "/agents/x/preflight?environment=production", auth.NewGitHubUser("u", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin = %d, want 403", rec.Code)
	}
	for _, q := range []string{"", "?environment=production&profile=p", "?definition_version=1"} {
		rec := assetsRequest(h, h.PreflightAgent, "/agents/{name}/preflight", "/agents/x/preflight"+q, auth.NewServiceUser())
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q = %d, want 400", q, rec.Code)
		}
	}
	rec := assetsRequest(h, h.PreflightAgent, "/agents/{name}/preflight", "/agents/y/preflight?environment=production", auth.NewServiceUser())
	if rec.Code != http.StatusNotFound {
		t.Errorf("no profile = %d, want 404", rec.Code)
	}

	rec = assetsRequest(h, h.PreflightAgent, "/agents/{name}/preflight", "/agents/x/preflight?environment=production", auth.NewServiceUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Source, Selection, Verdict string
		GitopsRevision             string `json:"gitops_revision"`
		Checks                     []PreflightCheck
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "gitops" || out.Selection != "naming-convention" || out.GitopsRevision != "abc" || len(out.Checks) != 9 || out.Verdict != statusUnknown {
		t.Errorf("unexpected response: %+v", out)
	}
}

func TestPreflightAgent_PolicyUnavailableIsNotPass(t *testing.T) {
	snap := &gitops.AgentPlatformSnapshot{Revision: "abc", PolicyErr: errors.New("boom"),
		Profiles: []gitops.AgentPlatformProfile{profileNamed("x-default", nil)}}
	h := &Handlers{opts: Options{GitReader: snapshotReader{snap: snap}}}
	rec := assetsRequest(h, h.PreflightAgent, "/agents/{name}/preflight", "/agents/x/preflight?environment=production", auth.NewServiceUser())
	var out struct {
		Verdict string
		Checks  []PreflightCheck
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"profile.budget", "profile.timeout", "profile.sandbox", "profile.model_policy_task", "profile.refs", "profile.approval_gates"} {
		if got := statusOf(out.Checks, id); got != statusUnknown {
			t.Errorf("%s = %s, want unknown", id, got)
		}
	}
	if out.Verdict == statusPass {
		t.Error("verdict must not be pass")
	}
}

func TestListAgentAssets_RefsAndUnavailableSources(t *testing.T) {
	snap := &gitops.AgentPlatformSnapshot{Revision: "rev1", PolicyErr: errors.New("no policy"),
		Profiles: []gitops.AgentPlatformProfile{profileNamed("a-default", nil), profileNamed("b-default", nil)},
		Releases: []gitops.AgentPlatformRelease{}}
	h := &Handlers{opts: Options{GitReader: snapshotReader{snap: snap}}}

	if rec := assetsRequest(h, h.ListAgentAssets, "/agent-assets", "/agent-assets", auth.NewGitHubUser("u", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin = %d, want 403", rec.Code)
	}
	rec := assetsRequest(h, h.ListAgentAssets, "/agent-assets", "/agent-assets", auth.NewServiceUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if string(out["policy"]) != "null" || string(out["registry"]) != "null" {
		t.Errorf("unavailable sources must be null: policy=%s registry=%s", out["policy"], out["registry"])
	}
	var refs struct {
		Skills     map[string][]string `json:"skills"`
		PolicyRefs map[string][]string `json:"policyRefs"`
	}
	if err := json.Unmarshal(out["refs"], &refs); err != nil {
		t.Fatal(err)
	}
	if len(refs.Skills["mctl-platform"]) != 2 || len(refs.PolicyRefs["pr-shepherd"]) != 2 {
		t.Errorf("reverse refs wrong: %+v", refs)
	}
	var sources map[string]sourceStatus
	_ = json.Unmarshal(out["sources"], &sources)
	if sources["gitops_policy"].Status != "unavailable" || sources["gitops_profiles"].Status != "ok" || sources["registry"].Status != "unavailable" {
		t.Errorf("sources: %+v", sources)
	}
}
