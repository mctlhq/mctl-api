// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

// The registry-publisher principal (mctlhq/mctl-agents#470) may create a
// definition, publish a version and promote or roll back a release. These
// tests pin that it can do exactly that, that every row it writes names it,
// that it can do nothing else, and that nobody else's access moved.

func registryPublisher(t *testing.T) *auth.User {
	t.Helper()
	u := auth.NewRegistryPublisherUser()
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_registrypublisher"), u); err != nil {
		t.Fatalf("AttachPrincipal: %v", err)
	}
	return u
}

// registryPublisherRoutes is the complete set of routes the registry
// publisher may call, as chi registers them.
var registryPublisherRoutes = []string{
	"POST /api/v1/agents",
	"POST /api/v1/agents/{name}/releases",
	"POST /api/v1/agents/{name}/versions",
}

const authenticatedMarker = "X-Test-Authenticated-Route"

// markAndInject is the auth middleware of the sweep below: it injects the
// user, and marks the response so the test can tell a route that sits behind
// authentication from a public one (health, OAuth, webhooks), which no
// principal's gate ever sees.
func markAndInject(u *auth.User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(authenticatedMarker, "1")
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
}

var routeParam = regexp.MustCompile(`\{[^}]+\}`)

// concretePath turns a chi route pattern into a path that matches it.
func concretePath(pattern string) string {
	path := routeParam.ReplaceAllString(pattern, "x")
	return strings.ReplaceAll(path, "*", "x")
}

// sweepRouter calls every route the router registers as u and reports, for
// each authenticated route, the status and error code it answered with.
func sweepRouter(t *testing.T, u *auth.User) map[string]struct {
	status int
	code   string
} {
	t.Helper()
	handler := NewRouter(Options{
		AuthMiddleware: markAndInject(u),
		// Mounted so /mcp is a real route: its tools act with the caller's
		// token, and the publisher must not reach them either.
		MCPServer: mctlmcp.NewServer("http://127.0.0.1:1", ""),
	})
	routes, ok := handler.(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	got := map[string]struct {
		status int
		code   string
	}{}
	if err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, concretePath(route), bytes.NewReader([]byte("{}"))))
		if rec.Header().Get(authenticatedMarker) == "" {
			return nil
		}
		got[method+" "+strings.TrimSuffix(route, "/")] = struct {
			status int
			code   string
		}{rec.Code, bodyCode(rec)}
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	return got
}

// The route sweep. Every authenticated route the router registers is called
// as the registry publisher, and each one outside the allowlist must answer
// 403 from the gate. Walking the router rather than listing paths is the
// point: a route added next month is covered without anyone remembering this
// test exists.
func TestRegistryPublisher_IsConfinedToThePublicationRoutes(t *testing.T) {
	got := sweepRouter(t, registryPublisher(t))

	// The sweep must not pass by seeing nothing: the authenticated group is
	// most of the API, and it must include routes of every shape the gate
	// has to refuse.
	if len(got) < 100 {
		t.Fatalf("the sweep saw only %d authenticated routes; it is not walking the API", len(got))
	}
	for _, mustSee := range []string{
		"GET /api/v1/agents", "GET /api/v1/agents/{name}/versions", "GET /api/v1/agents/{name}/resolve",
		"POST /api/v1/agents/executions", "POST /api/v1/agents/{name}/definition-versions",
		"POST /api/v1/agents/{name}/bindings", "POST /api/v1/agents/{name}/bindings/rollback",
		"POST /api/v1/agent-profiles/{profile}/versions", "POST /api/v1/agents/dev-loop/start",
		"GET /api/v1/whoami", "GET /api/v1/tenants", "POST /api/v1/usage/records",
		"POST /api/v1/evidence/records", "POST /mcp", "GET /mcp",
	} {
		if _, ok := got[mustSee]; !ok {
			t.Errorf("the sweep never reached %s", mustSee)
		}
	}

	allowed := map[string]bool{}
	for _, route := range registryPublisherRoutes {
		allowed[route] = true
	}
	var passed []string
	for route, res := range got {
		gated := res.status == http.StatusForbidden && res.code == codeRegistryPublisherForbidden
		switch {
		case allowed[route] && gated:
			t.Errorf("%s: the gate refused a publication route", route)
		case !allowed[route] && !gated:
			t.Errorf("%s: got %d %q, want 403 %s", route, res.status, res.code, codeRegistryPublisherForbidden)
		}
		if !gated {
			passed = append(passed, route)
		}
	}
	sort.Strings(passed)
	if strings.Join(passed, "\n") != strings.Join(registryPublisherRoutes, "\n") {
		t.Errorf("routes that passed the gate:\n%s\nwant exactly:\n%s",
			strings.Join(passed, "\n"), strings.Join(registryPublisherRoutes, "\n"))
	}
	// The three that pass reach their handler: with no registry configured
	// it answers 503, which only a request that got through can see.
	for _, route := range registryPublisherRoutes {
		if res := got[route]; res.status != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503 from the handler", route, res.status)
		}
	}
}

// Spellings near the allowed routes that the sweep's one-request-per-route
// cannot produce.
func TestRegistryPublisherGate_RefusesNearMisses(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(registryPublisher(t))})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents"},
		{http.MethodGet, "/api/v1/agents/mentor"},
		{http.MethodGet, "/api/v1/agents/mentor/versions"},
		{http.MethodGet, "/api/v1/agents/mentor/resolve?environment=production"},
		{http.MethodGet, "/api/v1/agents/executions"},
		{http.MethodPost, "/api/v1/agents/executions"},
		{http.MethodPost, "/api/v1/agents/mentor/definition-versions"},
		{http.MethodPost, "/api/v1/agents/mentor/bindings"},
		{http.MethodPost, "/api/v1/agents/mentor/bindings/rollback"},
		{http.MethodPost, "/api/v1/agent-profiles/standard/versions"},
		{http.MethodPost, "/api/v1/agents/dev-loop/start"},
		{http.MethodPost, "/api/v1/agents/dev-loop/wf-1/approve"},
		{http.MethodPost, "/api/v1/agents/mentor/run-tokens"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		// A path with no route at all is chi's 404, which is a refusal too;
		// what must never happen is a handler answering.
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			continue
		}
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeRegistryPublisherForbidden {
			t.Errorf("%s %s: got %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), codeRegistryPublisherForbidden)
		}
	}
}

func TestRegistryPublisherRouteAllowed(t *testing.T) {
	for _, c := range []struct {
		method, target string
		want           bool
	}{
		{http.MethodPost, "/api/v1/agents", true},
		{http.MethodPost, "/api/v1/agents/mentor/versions", true},
		{http.MethodPost, "/api/v1/agents/mentor/releases", true},
		{http.MethodPost, "/api/v1/agents?x=1", true},

		{http.MethodGet, "/api/v1/agents", false},
		{http.MethodGet, "/api/v1/agents/mentor/versions", false},
		{http.MethodPut, "/api/v1/agents/mentor/versions", false},
		{http.MethodPatch, "/api/v1/agents/mentor/releases", false},
		{http.MethodDelete, "/api/v1/agents/mentor/releases", false},
		{http.MethodPost, "/api/v1/agents/", false},
		{http.MethodPost, "/api/v1/agents/mentor", false},
		{http.MethodPost, "/api/v1/agents/mentor/", false},
		{http.MethodPost, "/api/v1/agents//versions", false},
		{http.MethodPost, "/api/v1/agents/mentor/versions/", false},
		{http.MethodPost, "/api/v1/agents/mentor/versions/1.0.0", false},
		{http.MethodPost, "/api/v1/agents/mentor/resolve", false},
		{http.MethodPost, "/api/v1/agents/mentor/bindings", false},
		{http.MethodPost, "/api/v1/agents/mentor/definition-versions", false},
		{http.MethodPost, "/api/v1/agents/mentor/bindings/rollback", false},
		{http.MethodPost, "/api/v1/agentsx", false},
		{http.MethodPost, "/api/v1/agents-x/mentor/versions", false},
		{http.MethodPost, "/api/v1/agent-profiles/p/versions", false},
		{http.MethodPost, "/api/v2/agents", false},
		{http.MethodPost, "/mcp", false},
		// An encoded spelling: chi would route on the raw form, so the gate
		// refuses rather than judge the decoded one.
		{http.MethodPost, "/api/v1/agents/mentor/version%73", false},
		{http.MethodPost, "/api/v1/agents/a%2Fb/versions", false},
		{http.MethodPost, "/api/v1/agents%2Fmentor/versions", false},
	} {
		if got := registryPublisherRouteAllowed(httptest.NewRequest(c.method, c.target, nil)); got != c.want {
			t.Errorf("%s %s: allowed = %v, want %v", c.method, c.target, got, c.want)
		}
	}
}

// Nobody else is touched by the gate. In particular the agent service
// principal, which publishes today, is passed through on every route the
// router registers, publication routes included. The gate is exercised
// directly here, not through the router: the question is whether it steps
// aside, and running every handler as an admin would answer a different one.
func TestRegistryPublisherGate_LeavesOtherCallersAlone(t *testing.T) {
	routes, ok := NewRouter(Options{MCPServer: mctlmcp.NewServer("http://127.0.0.1:1", "")}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	type route struct{ method, path string }
	var all []route
	if err := chi.Walk(routes, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		all = append(all, route{method, concretePath(pattern)})
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(all) < 100 {
		t.Fatalf("walked only %d routes", len(all))
	}
	for name, u := range map[string]*auth.User{
		"agent service":   auth.NewServiceUser(),
		"human admin":     {ID: "root", Groups: []string{"admins"}},
		"tenant member":   {ID: "t", Groups: []string{"some-tenant"}},
		"usage writer":    auth.NewUsageWriterUser(),
		"evidence writer": auth.NewEvidenceWriterUser(),
		"surface":         auth.NewSurfaceUser("telegram"),
		"agent run":       auth.NewAgentUser("mentor", auth.AgentRun{}),
		"unauthenticated": nil,
	} {
		for _, rt := range all {
			reached := false
			req := httptest.NewRequest(rt.method, rt.path, nil)
			if u != nil {
				req = req.WithContext(auth.WithUser(req.Context(), u))
			}
			rec := httptest.NewRecorder()
			registryPublisherGate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(rec, req)
			if !reached {
				t.Errorf("%s: %s %s was refused by the registry-publisher gate (%d)", name, rt.method, rt.path, rec.Code)
			}
		}
	}
	// And the gate is not simply inert: the same walk as the publisher is
	// refused everywhere but on the publication routes.
	passed := 0
	for _, rt := range all {
		reached := false
		req := httptest.NewRequest(rt.method, rt.path, nil)
		req = req.WithContext(auth.WithUser(req.Context(), auth.NewRegistryPublisherUser()))
		registryPublisherGate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(httptest.NewRecorder(), req)
		if reached {
			passed++
		}
	}
	if passed != len(registryPublisherRoutes) {
		t.Fatalf("the gate passed %d routes for the publisher, want %d", passed, len(registryPublisherRoutes))
	}
}

// On the three publication routes a human admin and the publisher are
// admitted and nobody else is. The agent service principal is the case that
// matters: it carries the admins group and was admitted until the release
// pipeline moved to the publisher (mctlhq/mctl-agents#470).
func TestAgentRegistryPublication_AdmitsHumanAdminsAndThePublisherOnly(t *testing.T) {
	for name, c := range map[string]struct {
		u    *auth.User
		want bool
	}{
		"registry publisher": {auth.NewRegistryPublisherUser(), true},
		"agent service":      {auth.NewServiceUser(), false},
		"human admin":        {&auth.User{ID: "root", Groups: []string{"admins"}}, true},
		"tenant member":      {&auth.User{ID: "t", Groups: []string{"some-tenant"}}, false},
		"usage writer":       {auth.NewUsageWriterUser(), false},
		"evidence writer":    {auth.NewEvidenceWriterUser(), false},
		"surface":            {auth.NewSurfaceUser("telegram"), false},
		"relayed admin":      {auth.NewRelayedUser("root", []string{"admins"}, auth.NewSurfaceUser("telegram")), false},
		"agent run":          {auth.NewAgentUser("mentor", auth.AgentRun{}), false},
	} {
		if got := mayPublishToAgentRegistry(c.u); got != c.want {
			t.Errorf("%s: mayPublishToAgentRegistry = %v, want %v", name, got, c.want)
		}
	}
}

// The handlers' own guards, with the gate out of the picture: the publisher
// is admitted by the three publication handlers and refused by every other
// registry handler, so the confinement does not rest on the gate alone.
func TestRegistryPublisher_HandlerGuards(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	call := func(u *auth.User, fn http.HandlerFunc, method, target string, params map[string]string) int {
		req := httptest.NewRequest(method, target, bytes.NewBufferString("{}"))
		rctx := chi.NewRouteContext()
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		fn(rec, req.WithContext(auth.WithUser(ctx, u)))
		return rec.Code
	}
	name := map[string]string{"name": "mentor", "profile": "standard", "version": "1.0.0", "revision": "1"}

	// Reads, and the execution record the worker writes: the publisher is
	// refused, the agent service principal still gets past the guard (any
	// answer but 401/403).
	for label, fn := range map[string]http.HandlerFunc{
		"ListAgentVersions":      h.ListAgentVersions,
		"ResolveAgentRelease":    h.ResolveAgentRelease,
		"RecordAgentExecution":   h.RecordAgentExecution,
		"ListAgentExecutions":    h.ListAgentExecutions,
		"ListAgents":             h.ListAgents,
		"GetAgent":               h.GetAgent,
		"ListDefinitionVersions": h.ListDefinitionVersions,
		"ListProfileVersions":    h.ListProfileVersions,
		"ListBindings":           h.ListBindings,
		"GetBinding":             h.GetBinding,
		"ResolveBinding":         h.ResolveBinding,
	} {
		if code := call(registryPublisher(t), fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code != http.StatusForbidden {
			t.Errorf("%s as the registry publisher: got %d, want 403", label, code)
		}
		if code := call(auth.NewServiceUser(), fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("%s as the agent service: got %d, want it past the guard", label, code)
		}
	}
	// The v1alpha2 mutations: a human admin only. The publisher and the
	// agent service principal are both refused; the human gets past the
	// guard.
	for label, fn := range map[string]http.HandlerFunc{
		"PublishDefinitionVersion":      h.PublishDefinitionVersion,
		"SetDefinitionVersionLifecycle": h.SetDefinitionVersionLifecycle,
		"PublishProfileVersion":         h.PublishProfileVersion,
		"SetProfileVersionLifecycle":    h.SetProfileVersionLifecycle,
		"CreateBinding":                 h.CreateBinding,
		"RollbackBinding":               h.RollbackBinding,
	} {
		for who, u := range map[string]*auth.User{"registry publisher": registryPublisher(t), "agent service": auth.NewServiceUser()} {
			if code := call(u, fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code != http.StatusForbidden {
				t.Errorf("%s as the %s: got %d, want 403", label, who, code)
			}
		}
		if code := call(adminUser(), fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("%s as a human admin: got %d, want it past the guard", label, code)
		}
	}
	for label, fn := range map[string]http.HandlerFunc{
		"CreateAgentDefinition": h.CreateAgentDefinition,
		"PublishAgentVersion":   h.PublishAgentVersion,
		"UpdateAgentRelease":    h.UpdateAgentRelease,
	} {
		// "{}" fails each handler's own validation with 400, which only a
		// caller past the guard can see.
		for who, u := range map[string]*auth.User{"registry publisher": registryPublisher(t), "human admin": adminUser()} {
			if code := call(u, fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code != http.StatusBadRequest {
				t.Errorf("%s as %s: got %d, want 400 from the handler", label, who, code)
			}
		}
		// The agent service principal carries the admins group and is
		// refused all the same (mctlhq/mctl-agents#470).
		if code := call(auth.NewServiceUser(), fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code != http.StatusForbidden {
			t.Errorf("%s as the agent service: got %d, want 403", label, code)
		}
		if code := call(&auth.User{ID: "t", Groups: []string{"some-tenant"}}, fn, http.MethodPost, "/api/v1/agents/mentor/x", name); code != http.StatusForbidden {
			t.Errorf("%s as a tenant member: got %d, want 403", label, code)
		}
	}
}

// The whole release, through the real router and a real Postgres, as the
// registry publisher: create, publish, promote, publish again, promote,
// roll back. Every row that names an actor names the publisher -- not the
// agent service principal, which is what the same calls record today.
func TestRegistryPublisher_PublishesAndIsRecordedAsItself(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	routerAs := func(u *auth.User) http.Handler {
		return NewRouter(Options{AuthMiddleware: injectUser(u), AgentRegistry: store})
	}
	do := func(h http.Handler, method, path, body string, want int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
		if rec.Code != want {
			t.Fatalf("%s %s: got %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
		}
		return rec.Body.Bytes()
	}
	version := func(v string) string {
		return `{"version":"` + v + `","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/mctlhq/mctl-agents","prompt_hash":"sha256:x"}`
	}
	release := func(h http.Handler, agent, body string) agentregistry.AgentRelease {
		t.Helper()
		var rel agentregistry.AgentRelease
		if err := json.Unmarshal(do(h, http.MethodPost, "/api/v1/agents/"+agent+"/releases", body, http.StatusOK), &rel); err != nil {
			t.Fatalf("release body: %v", err)
		}
		return rel
	}

	publisher := routerAs(registryPublisher(t))
	// The tool's first publish for a new agent: 404, which is how it learns
	// there is no definition yet; then create; then publish again.
	do(publisher, http.MethodPost, "/api/v1/agents/pub-agent/versions", version("1.0.0"), http.StatusNotFound)
	do(publisher, http.MethodPost, "/api/v1/agents", `{"name":"pub-agent","owner":"mctl-agents"}`, http.StatusCreated)
	var v1 agentregistry.AgentVersion
	if err := json.Unmarshal(do(publisher, http.MethodPost, "/api/v1/agents/pub-agent/versions", version("1.0.0"), http.StatusCreated), &v1); err != nil {
		t.Fatalf("version body: %v", err)
	}
	if v1.CreatedBy != auth.RegistryPublisherUserID {
		t.Fatalf("version created_by = %q, want %q", v1.CreatedBy, auth.RegistryPublisherUserID)
	}
	// Re-running a release is a no-op the tool relies on.
	do(publisher, http.MethodPost, "/api/v1/agents/pub-agent/versions", version("1.0.0"), http.StatusConflict)
	if rel := release(publisher, "pub-agent", `{"environment":"production","version":"1.0.0"}`); rel.UpdatedBy != auth.RegistryPublisherUserID {
		t.Fatalf("release updated_by = %q, want %q", rel.UpdatedBy, auth.RegistryPublisherUserID)
	}
	do(publisher, http.MethodPost, "/api/v1/agents/pub-agent/versions", version("2.0.0"), http.StatusCreated)
	release(publisher, "pub-agent", `{"environment":"production","version":"2.0.0"}`)
	if rel := release(publisher, "pub-agent", `{"environment":"production","rollback":true,"reason":"test"}`); rel.Version != "1.0.0" || rel.UpdatedBy != auth.RegistryPublisherUserID {
		t.Fatalf("rollback = %+v, want 1.0.0 by the publisher", rel)
	}

	ctx := context.Background()
	versions, err := store.ListVersions(ctx, "pub-agent")
	if err != nil || len(versions) != 2 {
		t.Fatalf("ListVersions: %v %+v", err, versions)
	}
	for _, v := range versions {
		if v.CreatedBy != auth.RegistryPublisherUserID {
			t.Errorf("stored version %s created_by = %q, want %q", v.Version, v.CreatedBy, auth.RegistryPublisherUserID)
		}
	}
	promotions, err := store.ListPromotions(ctx, "pub-agent", "production")
	if err != nil || len(promotions) != 3 {
		t.Fatalf("ListPromotions: %v %+v", err, promotions)
	}
	for _, p := range promotions {
		if p.Actor != auth.RegistryPublisherUserID {
			t.Errorf("promotion %d (%s -> %s) actor = %q, want %q", p.ID, p.FromVersion, p.ToVersion, p.Actor, auth.RegistryPublisherUserID)
		}
	}

	// The same calls as the agent service principal are refused, and leave
	// nothing behind: no definition, no version, no release.
	service := routerAs(auth.NewServiceUser())
	do(service, http.MethodPost, "/api/v1/agents", `{"name":"svc-agent","owner":"mctl-agents"}`, http.StatusForbidden)
	do(service, http.MethodPost, "/api/v1/agents/pub-agent/versions", version("9.9.9"), http.StatusForbidden)
	do(service, http.MethodPost, "/api/v1/agents/pub-agent/releases", `{"environment":"production","version":"1.0.0"}`, http.StatusForbidden)
	if versions, err := store.ListVersions(ctx, "svc-agent"); err != nil || len(versions) != 0 {
		t.Fatalf("the refused service calls left versions behind: %v %+v", err, versions)
	}
	after, err := store.ListPromotions(ctx, "pub-agent", "production")
	if err != nil || len(after) != len(promotions) {
		t.Fatalf("the refused service promotion changed the ledger: %v, %d rows, want %d", err, len(after), len(promotions))
	}

	// With the registry real, the publisher still reads nothing back.
	for _, path := range []string{"/api/v1/agents", "/api/v1/agents/pub-agent", "/api/v1/agents/pub-agent/versions", "/api/v1/agents/pub-agent/resolve?environment=production"} {
		rec := httptest.NewRecorder()
		publisher.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeRegistryPublisherForbidden {
			t.Errorf("GET %s as the publisher: got %d %s, want 403 %s", path, rec.Code, rec.Body.String(), codeRegistryPublisherForbidden)
		}
	}
}
