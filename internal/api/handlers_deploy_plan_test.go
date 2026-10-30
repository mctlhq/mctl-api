package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployanalyze"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const planBaseSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Secret-looking values the scan must never find in any response or audit row.
const (
	secretRemoteKey = "teams/acme/web"
	secretVaultPath = "secret/data/teams/acme/web/database"
	secretEnvValue  = "ghp_FIXTURESECRETVALUE0123456789"
)

const planBaseValues = `
image:
  repository: ghcr.io/acme/web
  tag: 1.0.0
env:
  LOG_LEVEL: info
externalSecret:
  targetSecret: web-secrets
  data:
    - secretKey: API_KEY
      remoteKey: teams/acme/web
      property: API_KEY
dbSecret:
  secretName: web-db
  vaultPath: secret/data/teams/acme/web/database
`

// repoBindings binds only acme/web to tenant acme.
type repoBindings struct{}

func (repoBindings) ServicesBySourceRepo(repo string) ([]gitops.SourceRepoBinding, error) {
	if repo == "acme/web" {
		return []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}}, nil
	}
	return nil, nil
}

type fakePlanGitops struct {
	data       string
	sourceRepo string
	exists     bool
	rev        string
	err        error
}

func (f *fakePlanGitops) ServiceValuesAt(string, string) ([]byte, string, bool, string, error) {
	return []byte(f.data), f.sourceRepo, f.exists, f.rev, f.err
}

// fakePlanStore reproduces the real store's idempotency semantics.
type fakePlanStore struct {
	mu      sync.Mutex
	plans   map[string]*deployplan.Plan
	byKey   map[string]string
	inserts int
	getErr  error
	putErr  error
}

func newFakePlanStore() *fakePlanStore {
	return &fakePlanStore{plans: map[string]*deployplan.Plan{}, byKey: map[string]string{}}
}

func (s *fakePlanStore) Insert(_ context.Context, p *deployplan.Plan) (*deployplan.Plan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return nil, false, s.putErr
	}
	if p.IdempotencyKey != "" {
		if id, ok := s.byKey[p.CreatedBy+"|"+p.IdempotencyKey]; ok {
			ex := s.plans[id]
			if ex.Digest != p.Digest {
				return nil, false, &deployplan.IdempotencyConflictError{PlanID: ex.ID}
			}
			return ex, true, nil
		}
		s.byKey[p.CreatedBy+"|"+p.IdempotencyKey] = p.ID
	}
	cp := *p
	s.plans[p.ID] = &cp
	s.inserts++
	return &cp, false, nil
}

func (s *fakePlanStore) Get(_ context.Context, id string) (*deployplan.Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	p, ok := s.plans[id]
	if !ok {
		return nil, deployplan.ErrNotFound
	}
	cp := *p
	return &cp, nil
}

type planFixture struct {
	router  http.Handler
	log     *audit.Logger
	content *fakeContent
	gitops  *fakePlanGitops
	store   *fakePlanStore
	exec    *fakeExecutor
	now     time.Time
}

func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	f := &planFixture{
		log: audit.NewLogger(), content: &fakeContent{}, store: newFakePlanStore(), exec: &fakeExecutor{},
		gitops: &fakePlanGitops{data: planBaseValues, sourceRepo: "acme/web", exists: true, rev: planBaseSHA},
		now:    time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	git := &fakeGitReader{tenants: []gitops.Tenant{{Name: "acme", Members: []gitops.TenantMember{
		{UserID: "alice", Role: "developer"}, {UserID: "vic", Role: "viewer"}, {UserID: "olga", Role: "owner"},
	}}}}
	portal := httptest.NewServer(http.HandlerFunc(bindingAnswer(false)))
	t.Cleanup(portal.Close)
	f.router = mctlapi.NewRouter(mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: git, ArgoCD: &fakeArgoCD{}, AuditLog: f.log, Executor: f.exec,
		BackstageInternalURL: portal.URL, BackstageGithubAppConnectToken: "tok",
		SourceRepoBindings:  repoBindings{},
		DeployContentReader: f.content, DeployPlans: f.store, DeployGitops: f.gitops,
		PlatformDomain: "mctl.ai", Clock: func() time.Time { return f.now },
	})
	return f
}

var (
	planDev    = auth.NewGitHubUser("alice", []string{"acme"})
	planViewer = auth.NewGitHubUser("vic", []string{"acme"})
	planOwner  = auth.NewGitHubUser("olga", []string{"acme"})
	planOther  = auth.NewGitHubUser("bob", []string{"other"})
)

func planIntent(mutate func(map[string]any)) map[string]any {
	in := map[string]any{
		"apiVersion": "deploy.mctl.ai/v1alpha1", "kind": "DeployIntent",
		"metadata": map[string]any{"tenant": "acme", "service": "web"},
		"spec": map[string]any{
			"environment": "preview",
			"source":      map[string]any{"repository": "acme/web", "revision": deploySHA},
			"detection":   map[string]any{"tier": "tier0"},
			"runtime":     map[string]any{"port": 8080, "healthPath": "/healthz"},
			"exposure":    map[string]any{"mode": "public"},
			"env":         map[string]any{"FEATURE": "on"},
			"secretRefs":  []any{map[string]any{"env": "DB_PASSWORD", "property": "password"}},
		},
	}
	if mutate != nil {
		mutate(in)
	}
	return in
}

func spec(in map[string]any) map[string]any { return in["spec"].(map[string]any) }

func (f *planFixture) post(t *testing.T, user *auth.User, body any) *httptest.ResponseRecorder {
	t.Helper()
	return postAs(t, f.router, "/api/v1/deploy/plan", body, user)
}

func (f *planFixture) plan(t *testing.T, user *auth.User, intent map[string]any, key string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"intent": intent}
	if key != "" {
		body["idempotency_key"] = key
	}
	return f.post(t, user, body)
}

func (f *planFixture) auditRows(op string) []audit.Entry {
	var out []audit.Entry
	for _, e := range f.log.List(1000) {
		if e.Operation == op {
			out = append(out, e)
		}
	}
	return out
}

// requireOneAudit asserts exactly one row for op since the call and returns it.
func (f *planFixture) requireOneAudit(t *testing.T, op string, before int) audit.Entry {
	t.Helper()
	rows := f.auditRows(op)
	if len(rows) != before+1 {
		t.Fatalf("%s audit rows: %d, want %d", op, len(rows), before+1)
	}
	return rows[0] // List is newest first
}

// T1: round trip, determinism and replay.
func TestDeployPlan_RoundTrip(t *testing.T) {
	f := newPlanFixture(t)
	w := f.plan(t, planDev, planIntent(nil), "")
	assertStatus(t, w, http.StatusCreated)
	first := decodeJSON(t, w)
	if first["action"] != "update" || first["requires_approval"] != true || first["required_role"] != "owner" ||
		first["environment"] != "preview" || first["gitops_base_sha"] != planBaseSHA || first["revision"] != deploySHA {
		t.Fatalf("plan = %v", first)
	}
	id, _ := first["id"].(string)
	host, _ := first["host"].(string)
	if !strings.HasPrefix(id, "dpl_") || !strings.HasPrefix(host, "web-") || !strings.HasSuffix(host, ".mctl.ai") {
		t.Fatalf("id=%q host=%q", id, host)
	}
	digest, _ := first["digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") || first["diff"] == "" || first["expired"] != false {
		t.Fatalf("digest=%q diff=%v expired=%v", digest, first["diff"], first["expired"])
	}
	ap := first["approval"].(map[string]any)
	if ap["required"] != true || ap["role"] != "owner" || ap["reason"] != "preview_update_requires_approval_until_build_sandbox" {
		t.Fatalf("approval = %v", ap)
	}
	if !strings.Contains(first["diff"].(string), "FEATURE") {
		t.Errorf("the diff does not show the intent's env:\n%v", first["diff"])
	}

	// Again with no key: a new id, the same digest.
	second := decodeJSON(t, f.plan(t, planDev, planIntent(nil), ""))
	if second["id"] == id || second["digest"] != digest {
		t.Fatalf("second plan: id=%v digest=%v want a new id and %s", second["id"], second["digest"], digest)
	}

	// With a key: stored plan on replay.
	k1 := decodeJSON(t, f.plan(t, planDev, planIntent(nil), "key-1"))
	w = f.plan(t, planDev, planIntent(nil), "key-1")
	assertStatus(t, w, http.StatusOK)
	replay := decodeJSON(t, w)
	if replay["id"] != k1["id"] || replay["replayed"] != true {
		t.Fatalf("replay = %v", replay)
	}
	if f.store.inserts != 3 {
		t.Fatalf("inserts = %d, want 3 (the replay stores nothing)", f.store.inserts)
	}
	if e := f.auditRows("deploy.plan"); e[0].Message != "replayed" {
		t.Errorf("replay audit = %+v", e[0])
	}

	// Writes nothing but the plan row.
	if len(f.exec.submitted) != 0 {
		t.Fatalf("a workflow was submitted: %v", f.exec.submitted)
	}

	// Reading it back.
	w = getAs(t, f.router, "/api/v1/deploy/plans/"+id, planDev)
	assertStatus(t, w, http.StatusOK)
	if got := decodeJSON(t, w); got["digest"] != digest || got["expired"] != false {
		t.Fatalf("GET = %v", got)
	}
}

// T2: each refusal, with its audit row.
func TestDeployPlan_Refusals(t *testing.T) {
	type tc struct {
		name   string
		user   *auth.User
		mutate func(*planFixture, map[string]any)
		body   func(map[string]any) any
		status int
		code   string
	}
	intentBody := func(in map[string]any) any { return map[string]any{"intent": in} }
	cases := []tc{
		{"extraObjects top level", planDev, func(_ *planFixture, in map[string]any) { in["extraObjects"] = []any{} }, intentBody, 422, "deploy_intent_invalid"},
		{"extraObjects under spec", planDev, func(_ *planFixture, in map[string]any) { spec(in)["extraObjects"] = []any{} }, intentBody, 422, "deploy_intent_invalid"},
		{"revision is a branch", planDev, func(_ *planFixture, in map[string]any) { spec(in)["source"].(map[string]any)["revision"] = "main" }, intentBody, 422, "deploy_revision_not_a_sha"},
		{"production", planDev, func(_ *planFixture, in map[string]any) { spec(in)["environment"] = "production" }, intentBody, 422, "prod_requires_promote"},
		{"unbound repository", planDev, func(_ *planFixture, in map[string]any) {
			spec(in)["source"].(map[string]any)["repository"] = "acme/other"
		}, intentBody, 403, "deploy_repository_not_bound"},
		{"non-member", planOther, nil, intentBody, 403, ""},
		{"viewer", planViewer, nil, intentBody, 403, ""},
		{"nonexistent sha", planDev, func(f *planFixture, _ map[string]any) { f.content.commitErr = deployanalyze.ErrRevisionUnreadable }, intentBody, 422, "deploy_revision_unreadable"},
		{"github 5xx", planDev, func(f *planFixture, _ map[string]any) { f.content.commitErr = deployanalyze.ErrGitHubUnavailable }, intentBody, 502, "deploy_github_unavailable"},
		{"github malformed", planDev, func(f *planFixture, _ map[string]any) { f.content.commitErr = deployanalyze.ErrGitHubMalformed }, intentBody, 502, "deploy_github_malformed"},
		{"service absent", planDev, func(f *planFixture, _ map[string]any) { f.gitops.exists = false }, intentBody, 422, "onboard_requires_preview_onboard"},
		{"gitops unreadable is not onboard", planDev, func(f *planFixture, _ map[string]any) {
			f.gitops.err = errors.New("stale checkout")
			f.gitops.exists = false
		}, intentBody, 503, "deploy_gitops_unavailable"},
		{"service bound to another repo", planDev, func(f *planFixture, _ map[string]any) { f.gitops.sourceRepo = "acme/another" }, intentBody, 403, "deploy_service_not_bound"},
		{"service without annotation", planDev, func(f *planFixture, _ map[string]any) { f.gitops.sourceRepo = "" }, intentBody, 403, "deploy_service_not_bound"},
		{"unparseable values", planDev, func(f *planFixture, _ map[string]any) { f.gitops.data = "- a\n- b\n" }, intentBody, 500, "deploy_values_unparseable"},
		{"refused rewrite", planDev, func(f *planFixture, _ map[string]any) {
			f.gitops.data = "externalSecret:\n  data:\n    - {secretKey: A, remoteKey: platform/x}\n    - {secretKey: B, remoteKey: teams/acme/web}\n"
		}, intentBody, 422, "deploy_preview_values_refused"},
		{"unknown envelope key", planDev, nil, func(in map[string]any) any { return map[string]any{"intent": in, "evil": 1} }, 400, "deploy_plan_invalid_input"},
		{"missing intent", planDev, nil, func(map[string]any) any { return map[string]any{} }, 400, "deploy_plan_invalid_input"},
		{"ttl too small", planDev, nil, func(in map[string]any) any { return map[string]any{"intent": in, "ttl_seconds": 59} }, 400, "deploy_plan_invalid_input"},
		{"ttl too large", planDev, nil, func(in map[string]any) any { return map[string]any{"intent": in, "ttl_seconds": 86401} }, 400, "deploy_plan_invalid_input"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPlanFixture(t)
			in := planIntent(nil)
			if c.mutate != nil {
				c.mutate(f, in)
			}
			w := f.post(t, c.user, c.body(in))
			if w.Code != c.status {
				t.Fatalf("status %d, want %d; body %s", w.Code, c.status, w.Body.String())
			}
			if c.code != "" && codeOf(t, w) != c.code {
				t.Fatalf("code %q, want %q; body %s", codeOf(t, w), c.code, w.Body.String())
			}
			if f.store.inserts != 0 {
				t.Fatal("a refused request stored a plan")
			}
			e := f.requireOneAudit(t, "deploy.plan", 0)
			if e.UserID != c.user.ID || e.Status == "succeeded" || e.Status == "submitted" {
				t.Fatalf("audit = %+v", e)
			}
			if c.code != "" && !strings.HasSuffix(e.Message, ":"+c.code) {
				t.Fatalf("audit message %q does not carry the code %s", e.Message, c.code)
			}
		})
	}
}

func TestDeployPlan_RefusesBeforeReadingExternalState(t *testing.T) {
	f := newPlanFixture(t)
	in := planIntent(nil)
	spec(in)["extraObjects"] = []any{}
	f.post(t, planDev, map[string]any{"intent": in})
	if f.content.calls != 0 {
		t.Fatal("a schema-invalid intent reached GitHub")
	}
}

func TestDeployPlan_IdempotencyConflict(t *testing.T) {
	f := newPlanFixture(t)
	first := decodeJSON(t, f.plan(t, planDev, planIntent(nil), "same"))
	other := planIntent(func(in map[string]any) { spec(in)["runtime"].(map[string]any)["port"] = 9090 })
	w := f.plan(t, planDev, other, "same")
	assertStatus(t, w, http.StatusConflict)
	body := decodeJSON(t, w)
	if body["code"] != "deploy_plan_idempotency_conflict" || body["details"].(map[string]any)["plan_id"] != first["id"] {
		t.Fatalf("conflict = %v", body)
	}
	if got := f.requireOneAudit(t, "deploy.plan", 1); got.Status != "denied" {
		t.Errorf("audit = %+v", got)
	}
}

func TestDeployPlan_StoreUnavailable(t *testing.T) {
	f := newPlanFixture(t)
	f.store.putErr = errors.New("db down")
	w := f.plan(t, planDev, planIntent(nil), "")
	assertStatus(t, w, http.StatusServiceUnavailable)
	if codeOf(t, w) != "deploy_plan_store_unavailable" {
		t.Fatal(w.Body.String())
	}

	// No store configured at all.
	t.Setenv("AUTH_REQUIRED", "false")
	r := mctlapi.NewRouter(mctlapi.Options{Registry: operations.NewRegistry(), GitReader: &fakeGitReader{tenants: []gitops.Tenant{{Name: "acme", Members: []gitops.TenantMember{{UserID: "alice", Role: "developer"}}}}},
		AuditLog: audit.NewLogger(), Executor: &fakeExecutor{}, SourceRepoBindings: fakeBindings{items: []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}}},
		DeployContentReader: &fakeContent{}, DeployGitops: f.gitops, PlatformDomain: "mctl.ai"})
	w = postAs(t, r, "/api/v1/deploy/plan", map[string]any{"intent": planIntent(nil)}, planDev)
	assertStatus(t, w, http.StatusServiceUnavailable)
	w = getAs(t, r, "/api/v1/deploy/plans/dpl_x", planDev)
	assertStatus(t, w, http.StatusServiceUnavailable)
	if codeOf(t, w) != "deploy_plan_store_unavailable" {
		t.Fatal(w.Body.String())
	}
}

// T10: who can read a plan.
func TestGetDeployPlan_Visibility(t *testing.T) {
	f := newPlanFixture(t)
	id := decodeJSON(t, f.plan(t, planDev, planIntent(nil), ""))["id"].(string)

	for name, u := range map[string]*auth.User{"member": planViewer, "admin": adminUser} {
		before := len(f.auditRows("deploy.plan.read"))
		w := getAs(t, f.router, "/api/v1/deploy/plans/"+id, u)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d", name, w.Code)
		}
		f.requireOneAudit(t, "deploy.plan.read", before)
	}
	var bodies []string
	for name, path := range map[string]string{"other tenant": id, "unknown id": "dpl_does-not-exist", "wrong prefix": "x"} {
		w := getAs(t, f.router, "/api/v1/deploy/plans/"+path, planOther)
		if w.Code != http.StatusNotFound || codeOf(t, w) != "deploy_plan_not_found" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
		bodies = append(bodies, strings.ReplaceAll(w.Body.String(), path, "ID"))
	}
	if bodies[0] != bodies[1] && len(bodies) > 1 {
		// The messages must not differ between "not a member" and "no such id".
		for _, b := range bodies[1:] {
			if b != bodies[0] {
				t.Errorf("not-found bodies differ: %q vs %q", bodies[0], b)
			}
		}
	}

	// Expiry is computed on read.
	f.now = f.now.Add(time.Hour)
	if got := decodeJSON(t, getAs(t, f.router, "/api/v1/deploy/plans/"+id, planDev)); got["expired"] != true {
		t.Errorf("expired = %v after the TTL", got["expired"])
	}
}

func TestDeployPlan_TTL(t *testing.T) {
	f := newPlanFixture(t)
	p := decodeJSON(t, f.plan(t, planDev, planIntent(nil), ""))
	if p["expires_at"] != f.now.Add(30*time.Minute).Format(time.RFC3339Nano) && p["expires_at"] != "2026-10-30T12:30:00Z" {
		t.Errorf("default expiry = %v", p["expires_at"])
	}
	w := f.post(t, planDev, map[string]any{"intent": planIntent(nil), "ttl_seconds": 86400})
	assertStatus(t, w, http.StatusCreated)
}

// T11: no Vault path, token or secret value in any response or audit row.
func TestDeployPlan_NoSecretsAnywhere(t *testing.T) {
	f := newPlanFixture(t)
	f.gitops.data = planBaseValues + "extraExternalSecrets:\n  mail:\n    targetSecret: mail\n    data:\n      - {secretKey: P, remoteKey: teams/acme/web/mail, property: p}\n"
	var responses []string
	collect := func(w *httptest.ResponseRecorder) { responses = append(responses, w.Body.String()) }

	w := f.plan(t, planDev, planIntent(nil), "k")
	assertStatus(t, w, http.StatusCreated)
	collect(w)
	id := decodeJSON(t, w)["id"].(string)
	collect(f.plan(t, planDev, planIntent(nil), "k"))
	collect(getAs(t, f.router, "/api/v1/deploy/plans/"+id, planDev))
	collect(getAs(t, f.router, "/api/v1/deploy/plans/"+id, planOther))
	collect(f.plan(t, planDev, planIntent(func(in map[string]any) { spec(in)["environment"] = "production" }), ""))
	collect(f.plan(t, planOther, planIntent(nil), ""))
	f.gitops.data = "externalSecret:\n  data:\n    - {secretKey: A, remoteKey: platform/x}\n    - {secretKey: B, remoteKey: teams/acme/web}\n"
	collect(f.plan(t, planDev, planIntent(nil), ""))
	f.gitops.data = "externalSecret:\n  data:\n    - {secretKey: A, remoteKey: teams/other/leaky-service}\n"
	collect(f.plan(t, planDev, planIntent(nil), ""))
	f.gitops.err = errors.New("open /checkout/platform-gitops/services/acme/web/values.yaml: teams/acme/web denied")
	collect(f.plan(t, planDev, planIntent(nil), ""))

	for _, e := range f.log.List(1000) {
		b, _ := json.Marshal(e)
		responses = append(responses, string(b))
	}
	// The key "vaultPath" is a field name of the chart, not a path.
	for i, text := range responses {
		scan := strings.ReplaceAll(text, "vaultPath", "")
		for _, banned := range []string{"teams/", "secret/data", "vault", "Vault", "ghp_", "ghs_", "gho_", secretRemoteKey, secretVaultPath, secretEnvValue, "leaky-service"} {
			if strings.Contains(scan, banned) {
				t.Errorf("item %d contains %q:\n%s", i, banned, text)
			}
		}
	}
	if !strings.Contains(responses[0], "redacted:sha256:") {
		t.Errorf("remoteKey is not shown redacted:\n%s", responses[0])
	}
}
