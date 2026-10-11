package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The build workflow checks out dockerfile_repo with a GitHub App token for
// whatever repository it is given. A non-admin may only build a repository
// connected to their team (asked of the portal) or a public one (asked of
// GitHub), and every unreadable answer refuses.

type gateFixture struct {
	mu          sync.Mutex
	bindingHits []string
	githubHits  []string
	binding     func(w http.ResponseWriter, r *http.Request)
	github      func(w http.ResponseWriter, r *http.Request)
}

func (f *gateFixture) bindingCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bindingHits...)
}

func (f *gateFixture) githubCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.githubHits...)
}

func bindingAnswer(bound bool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team": r.URL.Query().Get("team"), "repo": r.URL.Query().Get("repo"), "bound": bound,
		})
	}
}

func githubAnswer(status int, body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newGateRouter(t *testing.T, token string) (http.Handler, *fakeExecutor, *gateFixture) {
	t.Helper()
	return newGateRouterWith(t, token, &fakeGitReader{tenants: []gitops.Tenant{
		{Name: "tests", DisplayName: "Tests", Quotas: map[string]string{"pods": "10"}, Members: []gitops.TenantMember{{UserID: "test-owner", Role: "owner"}}},
	}})
}

func newGateRouterWith(t *testing.T, token string, git *fakeGitReader) (http.Handler, *fakeExecutor, *gateFixture) {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	f := &gateFixture{binding: bindingAnswer(false), github: githubAnswer(404, `{"message":"Not Found"}`)}
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.bindingHits = append(f.bindingHits, r.URL.Path+"?"+r.URL.RawQuery+" auth="+r.Header.Get("Authorization"))
		f.mu.Unlock()
		f.binding(w, r)
	}))
	t.Cleanup(portal.Close)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.githubHits = append(f.githubHits, r.URL.Path+" auth="+r.Header.Get("Authorization"))
		f.mu.Unlock()
		f.github(w, r)
	}))
	t.Cleanup(github.Close)

	exec := &fakeExecutor{}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:                       operations.NewRegistry(),
		GitReader:                      git,
		ArgoCD:                         &fakeArgoCD{},
		AuditLog:                       audit.NewLogger(),
		Executor:                       exec,
		BackstageInternalURL:           portal.URL,
		BackstageGithubAppConnectToken: token,
		GitHubAPIBaseURL:               github.URL,
	})
	return router, exec, f
}

func onboard(repo string) map[string]string {
	return map[string]string{
		"action": "onboard", "team_name": "tests", "component_name": "my-app",
		"dockerfile_repo": repo, "git_tag": "v1.0.0",
	}
}

const deployPath = "/api/v1/operations/deploy-service/execute"

func TestBuildRepoGate_BoundRepoDeploys(t *testing.T) {
	router, exec, f := newGateRouter(t, "gac-token")
	f.binding = bindingAnswer(true)

	w := postAs(t, router, deployPath, onboard("myorg/my-app"), ownerUser)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 {
		t.Fatalf("expected one submission, got %d", len(exec.submittedParams))
	}
	calls := f.bindingCalls()
	if len(calls) != 1 || !strings.Contains(calls[0], "/api/github-app-connect/repo-binding?repo=myorg%2Fmy-app&team=tests") ||
		!strings.HasSuffix(calls[0], "auth=Bearer gac-token") {
		t.Errorf("binding check calls = %v", calls)
	}
	if len(f.githubCalls()) != 0 {
		t.Errorf("a bound repo must not need the public check: %v", f.githubCalls())
	}
}

func TestBuildRepoGate_UnboundPublicRepoDeploysWithoutCredentials(t *testing.T) {
	router, exec, f := newGateRouter(t, "gac-token")
	f.github = githubAnswer(200, `{"private":false}`)

	w := postAs(t, router, deployPath, onboard("openclaw/openclaw"), ownerUser)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 {
		t.Fatal("expected a submission")
	}
	gh := f.githubCalls()
	if len(gh) != 1 || gh[0] != "/repos/openclaw/openclaw auth=" {
		t.Errorf("public check calls = %v (must be unauthenticated)", gh)
	}
}

func TestBuildRepoGate_RefusesUnboundNonPublic(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"404":                            githubAnswer(404, `{"message":"Not Found"}`),
		"private":                        githubAnswer(200, `{"private":true}`),
		"no private flag":                githubAnswer(200, `{}`),
		"malformed":                      githubAnswer(200, `not json`),
		"rate limited, body says public": githubAnswer(403, `{"private":false}`),
		"error":                          githubAnswer(502, ``),
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			router, exec, f := newGateRouter(t, "gac-token")
			f.github = answer
			w := postAs(t, router, deployPath, onboard("victim-org/secret"), ownerUser)
			assertStatus(t, w, http.StatusForbidden)
			if len(exec.submittedParams) != 0 {
				t.Errorf("refused build reached the executor: %v", exec.submittedParams)
			}
		})
	}
}

func TestBuildRepoGate_BindingLookupFailureRefusesWithoutPublicFallback(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"500":       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"401":       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) },
		"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"no bound field": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"team":"tests","repo":"openclaw/openclaw"}`))
		},
		"403 with a bound body": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"team":"tests","repo":"openclaw/openclaw","bound":true}`))
		},
		"other repo echoed": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"team":"tests","repo":"myorg/connected-one","bound":true}`))
		},
		"other team echoed": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"team":"admins","repo":"openclaw/openclaw","bound":true}`))
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			router, exec, f := newGateRouter(t, "gac-token")
			f.binding = answer
			// Public on GitHub: a lookup failure must still refuse, not fall through to this.
			f.github = githubAnswer(200, `{"private":false}`)
			w := postAs(t, router, deployPath, onboard("openclaw/openclaw"), ownerUser)
			assertStatus(t, w, http.StatusForbidden)
			if len(exec.submittedParams) != 0 {
				t.Error("refused build reached the executor")
			}
			if len(f.githubCalls()) != 0 {
				t.Errorf("a failed binding lookup fell through to the public check: %v", f.githubCalls())
			}
		})
	}
}

func TestBuildRepoGate_UnconfiguredTokenRefuses(t *testing.T) {
	router, exec, f := newGateRouter(t, "")
	f.github = githubAnswer(200, `{"private":false}`)
	w := postAs(t, router, deployPath, onboard("openclaw/openclaw"), ownerUser)
	assertStatus(t, w, http.StatusForbidden)
	if len(exec.submittedParams) != 0 || len(f.bindingCalls()) != 0 {
		t.Error("an unconfigured binding check must refuse without calling anything")
	}
}

func TestBuildRepoGate_RefusesMalformedRepo(t *testing.T) {
	// Padded values are refused as received, not trimmed: the repository
	// checked must be the one the workflow builds. The operation's parameter
	// pattern now refuses these first (400); the gate's own name check
	// (403) is covered directly in build_repo_gate_internal_test.go.
	for _, repo := range []string{"../etc", "owner", "a/b/c", "owner/..", "../..", " myorg/my-app", "myorg/my-app ", "myorg/my-app\n"} {
		t.Run(repo, func(t *testing.T) {
			router, exec, f := newGateRouter(t, "gac-token")
			f.binding = bindingAnswer(true)
			w := postAs(t, router, deployPath, onboard(repo), ownerUser)
			if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
				t.Fatalf("expected 400 or 403, got %d; body: %s", w.Code, w.Body.String())
			}
			if len(exec.submittedParams) != 0 || len(f.bindingCalls()) != 0 || len(f.githubCalls()) != 0 {
				t.Error("a malformed repository must be refused before any lookup")
			}
		})
	}
}

func TestBuildRepoGate_CoversPreviewDeploy(t *testing.T) {
	router, exec, _ := newGateRouter(t, "gac-token")
	w := postAs(t, router, "/api/v1/operations/preview-deploy/execute", map[string]string{
		"team_name": "tests", "component_name": "my-app", "git_ref": "main", "dockerfile_repo": "victim-org/secret",
	}, ownerUser)
	assertStatus(t, w, http.StatusForbidden)
	if len(exec.submittedParams) != 0 {
		t.Error("refused preview build reached the executor")
	}
}

func TestBuildRepoGate_AdminsAreNotChecked(t *testing.T) {
	router, exec, f := newGateRouter(t, "")
	w := postAs(t, router, deployPath, onboard("victim-org/secret"), adminUser)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 || len(f.bindingCalls()) != 0 || len(f.githubCalls()) != 0 {
		t.Error("admin build should pass without lookups")
	}
}

func TestBuildRepoGate_NoBuildRepoNoLookup(t *testing.T) {
	router, exec, f := newGateRouter(t, "")
	w := postAs(t, router, deployPath, map[string]string{
		"action": "deploy", "team_name": "tests", "component_name": "my-app", "image_tag": "1.2.3",
	}, ownerUser)
	if w.Code == http.StatusForbidden {
		t.Fatalf("a deploy without dockerfile_repo was refused: %s", w.Body.String())
	}
	if len(f.bindingCalls()) != 0 || len(f.githubCalls()) != 0 {
		t.Error("no build repository, so no lookup expected")
	}
	_ = exec
}
