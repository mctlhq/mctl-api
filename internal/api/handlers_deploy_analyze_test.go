package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployanalyze"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const deploySHA = "0123456789abcdef0123456789abcdef01234567"

type fakeBindings struct {
	items []gitops.SourceRepoBinding
	err   error
}

func (f fakeBindings) ServicesBySourceRepo(string) ([]gitops.SourceRepoBinding, error) {
	return f.items, f.err
}

type fakeContent struct {
	mu        sync.Mutex
	calls     int
	commitErr error
	fileErr   error
	files     map[string]deployanalyze.FileResult
}

func (f *fakeContent) Commit(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.commitErr
}

func (f *fakeContent) File(_ context.Context, _, _, p string, _ int) (deployanalyze.FileResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fileErr != nil {
		return deployanalyze.FileResult{}, f.fileErr
	}
	if r, ok := f.files[p]; ok {
		return r, nil
	}
	return deployanalyze.FileResult{Absent: true}, nil
}

const deployDockerfile = "FROM node:20\nEXPOSE 3000\nUSER node\nHEALTHCHECK CMD curl -f http://localhost:3000/healthz\n"

type deployFixture struct {
	router  http.Handler
	log     *audit.Logger
	content *fakeContent
	portal  *int
}

func newDeployFixture(t *testing.T, b mctlapi.SourceRepoBindingReader, portalBound bool, portalStatus int) *deployFixture {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	hits := 0
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if portalStatus != 200 {
			w.WriteHeader(portalStatus)
			return
		}
		bindingAnswer(portalBound)(w, r)
	}))
	t.Cleanup(portal.Close)
	f := &deployFixture{log: audit.NewLogger(), portal: &hits, content: &fakeContent{files: map[string]deployanalyze.FileResult{
		"Dockerfile": {Kind: "file", Data: []byte(deployDockerfile)},
	}}}
	f.router = mctlapi.NewRouter(mctlapi.Options{
		Registry:                       operations.NewRegistry(),
		GitReader:                      &fakeGitReader{},
		ArgoCD:                         &fakeArgoCD{},
		AuditLog:                       f.log,
		Executor:                       &fakeExecutor{},
		BackstageInternalURL:           portal.URL,
		BackstageGithubAppConnectToken: "tok",
		SourceRepoBindings:             b,
		DeployContentReader:            f.content,
	})
	return f
}

func analyzeURL(kv ...string) string {
	q := url.Values{"tenant": {"acme"}, "repository": {"Acme/App"}, "revision": {deploySHA}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			q.Del(kv[i])
		} else {
			q.Set(kv[i], kv[i+1])
		}
	}
	return "/api/v1/deploy/analyze?" + q.Encode()
}

var deployMember = auth.NewGitHubUser("alice", []string{"acme"})
var deployOutsider = auth.NewGitHubUser("bob", []string{"other"})

func lastAudit(t *testing.T, f *deployFixture, op string, want int) audit.Entry {
	t.Helper()
	var got []audit.Entry
	for _, e := range f.log.List(100) {
		if e.Operation == op {
			got = append(got, e)
		}
	}
	if len(got) != want {
		t.Fatalf("want %d %s audit rows, got %d", want, op, len(got))
	}
	return got[0]
}

func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	c, _ := decodeJSON(t, w)["code"].(string)
	return c
}

func TestDeployAnalyze_Supported(t *testing.T) {
	f := newDeployFixture(t, fakeBindings{items: []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}, {Tenant: "zzz", Service: "x"}}}, false, 200)
	w := getAs(t, f.router, analyzeURL(), deployMember)
	assertStatus(t, w, 200)
	body := decodeJSON(t, w)
	if body["supported"] != true || body["draft_intent"] == nil {
		t.Fatalf("%v", body)
	}
	b := body["binding"].(map[string]any)
	if b["tenant"] != "acme" || len(b["services"].([]any)) != 1 {
		t.Fatalf("binding %v", b)
	}
	if *f.portal != 0 {
		t.Error("gitops binding must not need the portal")
	}
	e := lastAudit(t, f, "deploy.analyze", 1)
	if e.Status != "succeeded" || e.Parameters["tenant"] != "acme" || e.Parameters["revision"] != deploySHA {
		t.Fatalf("%+v", e)
	}
}

func TestDeployAnalyze_UnsupportedIs200(t *testing.T) {
	f := newDeployFixture(t, fakeBindings{items: []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}}}, false, 200)
	delete(f.content.files, "Dockerfile")
	w := getAs(t, f.router, analyzeURL(), deployMember)
	assertStatus(t, w, 200)
	body := decodeJSON(t, w)
	if body["supported"] != false || body["reason"] != "no_dockerfile" || body["draft_intent"] != nil {
		t.Fatalf("%v", body)
	}
	if e := lastAudit(t, f, "deploy.analyze", 1); e.Message != "unsupported:no_dockerfile" {
		t.Fatalf("%+v", e)
	}
}

func TestDeployAnalyze_InvalidInput(t *testing.T) {
	f := newDeployFixture(t, fakeBindings{}, true, 200)
	bad := []string{
		analyzeURL("revision", "main"),
		analyzeURL("revision", strings.Repeat("a", 39)),
		analyzeURL("revision", strings.ToUpper(deploySHA)),
		analyzeURL("dockerfile", "../Dockerfile"),
		analyzeURL("dockerfile", "/Dockerfile"),
		analyzeURL("repository", "owner/.."),
		analyzeURL("tenant", ""),
		analyzeURL() + "&revision=" + deploySHA,
	}
	for i, u := range bad {
		assertStatus(t, getAs(t, f.router, u, deployMember), 400)
		_ = i
	}
	if len(f.log.List(100)) != len(bad) || f.content.calls != 0 || *f.portal != 0 {
		t.Fatalf("audit %d calls %d portal %d", len(f.log.List(100)), f.content.calls, *f.portal)
	}
}

func TestDeployAnalyze_Authorization(t *testing.T) {
	f := newDeployFixture(t, fakeBindings{items: []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}}}, false, 200)
	w := getAs(t, f.router, analyzeURL(), deployOutsider)
	assertStatus(t, w, 403)
	if codeOf(t, w) != "deploy_tenant_access_denied" || f.content.calls != 0 {
		t.Fatal("tenant denial")
	}
	if e := lastAudit(t, f, "deploy.analyze", 1); e.Status != "denied" {
		t.Fatalf("%+v", e)
	}

	// Not bound in gitops nor portal.
	f = newDeployFixture(t, fakeBindings{}, false, 200)
	w = getAs(t, f.router, analyzeURL(), deployMember)
	assertStatus(t, w, 403)
	if codeOf(t, w) != "deploy_repository_not_bound" || f.content.calls != 0 {
		t.Fatal("not bound")
	}
	if e := lastAudit(t, f, "deploy.analyze", 1); e.Status != "denied" {
		t.Fatalf("%+v", e)
	}

	// Bound only in the portal.
	f = newDeployFixture(t, fakeBindings{}, true, 200)
	assertStatus(t, getAs(t, f.router, analyzeURL(), deployMember), 200)
}

func TestDeployAnalyze_BindingFailsClosed(t *testing.T) {
	f := newDeployFixture(t, fakeBindings{err: errors.New("checkout gone")}, true, 200)
	w := getAs(t, f.router, analyzeURL(), deployMember)
	assertStatus(t, w, 503)
	if codeOf(t, w) != "deploy_binding_unavailable" || f.content.calls != 0 {
		t.Fatal("gitops error")
	}
	lastAudit(t, f, "deploy.analyze", 1)

	f = newDeployFixture(t, fakeBindings{}, true, 500)
	w = getAs(t, f.router, analyzeURL(), deployMember)
	assertStatus(t, w, 503)
	if codeOf(t, w) != "deploy_binding_unavailable" {
		t.Fatal("portal error")
	}
	lastAudit(t, f, "deploy.analyze", 1)

	w = getAs(t, newDeployFixture(t, fakeBindings{err: errors.New("x")}, true, 200).router, "/api/v1/deploy/bindings?repository=acme/app", deployMember)
	assertStatus(t, w, 503)
}

func TestDeployAnalyze_GitHubErrors(t *testing.T) {
	cases := []struct {
		commit, file error
		status       int
		code         string
	}{
		{commitErr, nil, 422, "deploy_revision_unreadable"},
		{nil, deployanalyze.ErrGitHubUnavailable, 502, "deploy_github_unavailable"},
		{deployanalyze.ErrGitHubMalformed, nil, 502, "deploy_github_malformed"},
	}
	for _, c := range cases {
		f := newDeployFixture(t, fakeBindings{items: []gitops.SourceRepoBinding{{Tenant: "acme", Service: "web"}}}, false, 200)
		f.content.commitErr, f.content.fileErr = c.commit, c.file
		w := getAs(t, f.router, analyzeURL(), deployMember)
		assertStatus(t, w, c.status)
		if codeOf(t, w) != c.code {
			t.Errorf("%s: got %s", c.code, codeOf(t, w))
		}
		if e := lastAudit(t, f, "deploy.analyze", 1); e.Status != "error" {
			t.Errorf("%+v", e)
		}
	}
}

var commitErr = deployanalyze.ErrRevisionUnreadable

func TestDeployBindings_Visibility(t *testing.T) {
	items := []gitops.SourceRepoBinding{{Tenant: "a", Service: "s1"}, {Tenant: "a", Service: "s2"}, {Tenant: "b", Service: "s3"}}
	f := newDeployFixture(t, fakeBindings{items: items}, false, 200)
	w := getAs(t, f.router, "/api/v1/deploy/bindings?repository=Acme/App", auth.NewGitHubUser("u", []string{"a"}))
	assertStatus(t, w, 200)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 2 {
		t.Fatalf("%v", body)
	}
	w = getAs(t, f.router, "/api/v1/deploy/bindings?repository=Acme/App", adminUser)
	if decodeJSON(t, w)["count"].(float64) != 3 {
		t.Fatal("admin must see all")
	}
	assertStatus(t, getAs(t, f.router, "/api/v1/deploy/bindings?repository=bad", adminUser), 400)
	lastAudit(t, f, "deploy.bindings", 3)
}
