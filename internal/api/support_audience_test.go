// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
)

const testSupportResource = "https://support.mctl.ai"

// supportEnv is a router whose bearer is verified by a real OAuthServer, so
// the audience reaches the gate the way it does in production.
type supportEnv struct {
	oauth  *auth.OAuthServer
	router http.Handler
}

func newSupportEnv(t *testing.T) *supportEnv {
	t.Helper()
	o := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"),
		[]string{testClientRedirect}, auth.NewGitHubValidator(nil))
	o.SupportResource = testSupportResource
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok == "pat" {
				next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), auth.NewGitHubUser("dan", []string{"labs"}))))
				return
			}
			u, err := o.ValidateJWT(tok)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	return &supportEnv{oauth: o, router: NewRouter(Options{OAuthServer: o, AuthMiddleware: mw,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})}
}

// token redeems a code issued for resource through the real token endpoint.
func (e *supportEnv) token(t *testing.T, resource string) string {
	t.Helper()
	code, err := e.oauth.IssueCodeWithAuthMethod(context.Background(), "dan", "", "client", testClientRedirect, testChallenge(), nil, "", resource)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier},
		"client_id": {"client"}, "redirect_uri": {testClientRedirect}}
	rec := e.post("/oauth/token", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.AccessToken
}

func (e *supportEnv) post(path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *supportEnv) call(method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// T5: a support token passes the gate on each allowlisted route.
func TestSupportAudienceGate_AllowsTheRelayedRoutes(t *testing.T) {
	e := newSupportEnv(t)
	tok := e.token(t, testSupportResource)
	for _, rt := range supportAudienceRoutes {
		path := strings.NewReplacer("^", "", "$", "", "[^/]+", "wi_1").Replace(rt.path.String())
		path = strings.ReplaceAll(path, `\`, "")
		if rec := e.call(rt.method, path, tok); rec.Code == http.StatusUnauthorized {
			t.Errorf("%s %s = 401 for a support token: %s", rt.method, path, rec.Body.String())
		}
	}
}

// T6: everything else, /mcp included, is refused for a support token and not
// by the gate for an API token.
func TestSupportAudienceGate_RefusesEverythingElse(t *testing.T) {
	e := newSupportEnv(t)
	support := e.token(t, testSupportResource)
	api := e.token(t, "")
	for _, rt := range [][2]string{
		{"GET", "/api/v1/services"},
		{"POST", "/api/v1/operations/deploy-service/execute"},
		{"PATCH", "/api/v1/work-items/wi_1"},
		{"GET", "/api/v1/work-items"},
		{"POST", "/mcp"},
		{"GET", "/mcp"},
		{"DELETE", "/mcp"},
	} {
		rec := e.call(rt[0], rt[1], support)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("support token on %s %s = %d, want 401", rt[0], rt[1], rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `"invalid_token"`) || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("%s %s: body %q, header %q; want invalid_token", rt[0], rt[1], rec.Body.String(), rec.Header().Get("WWW-Authenticate"))
		}
		// Only /mcp is probed with an API token: the stub handler answers 200,
		// where the other routes have no backends in this harness.
		if rt[1] == "/mcp" {
			if rec := e.call(rt[0], rt[1], api); rec.Code != http.StatusOK {
				t.Errorf("api token on %s /mcp = %d, want it past the gate", rt[0], rec.Code)
			}
		}
	}
}

// T7: whoami reports the audience as an array, and only for local tokens.
func TestWhoamiReportsAudience(t *testing.T) {
	e := newSupportEnv(t)
	aud := func(bearer string) (any, bool) {
		rec := e.call(http.MethodGet, "/api/v1/whoami", bearer)
		if rec.Code != http.StatusOK {
			t.Fatalf("whoami = %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		v, ok := body["audience"]
		return v, ok
	}
	for bearer, want := range map[string]string{e.token(t, testSupportResource): testSupportResource, e.token(t, ""): "https://api.example"} {
		v, ok := aud(bearer)
		arr, isArr := v.([]any)
		if !ok || !isArr || len(arr) != 1 || arr[0] != want {
			t.Errorf("audience = %#v, want [%q]", v, want)
		}
	}
	if v, ok := aud("pat"); ok {
		t.Errorf("a PAT reported audience %#v", v)
	}
}

// T9: every allowlisted route is registered in the chi tree.
func TestSupportAudienceRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	var routes []struct{ method, route string }
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, struct{ method, route string }{method, strings.TrimSuffix(route, "/")})
		return nil
	})
	for _, rt := range supportAudienceRoutes {
		found := false
		for _, r := range routes {
			if r.method != rt.method {
				continue
			}
			concrete := strings.ReplaceAll(strings.ReplaceAll(r.route, "{id}", "wi_1"), "{workItemID}", "wi_1")
			if rt.path.MatchString(concrete) {
				found = true
			}
		}
		if !found {
			t.Errorf("allowlisted route %s %s is not registered; was it renamed?", rt.method, rt.path)
		}
	}
}

// T1: /authorize validates resource after client_id and redirect_uri.
func TestAuthorizeResource(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamGitHub, nil)
	h.oauth.SupportResource = testSupportResource

	rec := h.get(authorizeQuery("&resource=" + url.QueryEscape("https://evil.example")))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, testClientRedirect) || !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("unknown resource = %d %q; want a redirect with invalid_target", rec.Code, loc)
	}
	rec = h.get(authorizeQuery("&resource=" + testSupportResource + "&resource=" + testSupportResource))
	if !strings.Contains(rec.Header().Get("Location"), "error=invalid_target") {
		t.Fatalf("repeated resource = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// An untrusted redirect_uri is never redirected to, whatever the resource.
	rec = h.get("/oauth/authorize?client_id=client&redirect_uri=https://evil.example/cb&resource=https://evil.example")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad redirect_uri = %d, want 400", rec.Code)
	}
	for _, extra := range []string{"", "&resource=" + url.QueryEscape("https://api.example/mcp"), "&resource=" + testSupportResource} {
		rec = h.get(authorizeQuery(extra))
		if strings.Contains(rec.Header().Get("Location"), "invalid_target") || rec.Code != http.StatusFound {
			t.Errorf("authorize%s = %d %q; want it to proceed", extra, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// T2: /token refuses an unknown or different resource without burning the code.
func TestTokenResource(t *testing.T) {
	e := newSupportEnv(t)
	code, err := e.oauth.IssueCodeWithAuthMethod(context.Background(), "dan", "", "client", testClientRedirect, testChallenge(), nil, "", testSupportResource)
	if err != nil {
		t.Fatal(err)
	}
	form := func(resource string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier},
			"client_id": {"client"}, "redirect_uri": {testClientRedirect}, "resource": {resource}}
	}
	rec := e.post("/oauth/token", form("https://evil.example"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_target"`) {
		t.Fatalf("unknown resource = %d %s; want 400 invalid_target", rec.Code, rec.Body.String())
	}
	if rec := e.post("/oauth/token", form(testSupportResource)); rec.Code != http.StatusOK {
		t.Fatalf("the code was burned by a refused resource: %d %s", rec.Code, rec.Body.String())
	}

	// A known resource other than the authorized one mints nothing.
	other, err := e.oauth.IssueCodeWithAuthMethod(context.Background(), "dan", "", "client", testClientRedirect, testChallenge(), nil, "", testSupportResource)
	if err != nil {
		t.Fatal(err)
	}
	f := form("https://api.example")
	f.Set("code", other)
	if rec := e.post("/oauth/token", f); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_target"`) {
		t.Fatalf("different resource = %d %s; want 400 invalid_target", rec.Code, rec.Body.String())
	}
}
