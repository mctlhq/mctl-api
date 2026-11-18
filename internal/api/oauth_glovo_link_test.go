// Copyright 2026 MCTL Authors
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/cimd"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore/refreshstoretest"
)

const (
	linkTestRes = "https://glovo.mctl.ai/link"
	linkTestPRN = "prn_01JTESTAAAAAAAAAAAAAAAAAAA"
)

type allTeams struct{}

func (allTeams) Eligible(context.Context, string) ([]string, error) { return []string{"acme"}, nil }
func (allTeams) Has(context.Context, string, string) (bool, error)  { return true, nil }

// makeLinkReady turns the Glovo feature on with the link resource set, on
// the in-memory transactional stores.
func makeLinkReady(o *auth.OAuthServer, link string) {
	o.GlovoResource, o.GlovoEnabled, o.PrincipalMode = auth.GlovoResourceIntended, true, true
	o.SupportResource = "https://support.mctl.ai"
	grants := refreshstoretest.NewTxGrants()
	o.RefreshStore, o.TeamGrants, o.TeamEligibility = refreshstoretest.NewBound(grants), grants, allTeams{}
	o.GlovoLinkResource = link
}

func newLinkOAuthHarness(t *testing.T, link string) *upstreamHarness {
	t.Helper()
	h := newPrincipalModeHarness(t, linkedTo("mashkovd"), signinResolver{prn: linkTestPRN})
	makeLinkReady(h.oauth, link)
	return h
}

// zitadelAuthorizeParams starts an authorization for resource and returns what
// ZITADEL was sent, recording the nonce and challenge as the harness does.
func (h *upstreamHarness) zitadelAuthorizeParams(resource string) (state string, q url.Values) {
	h.t.Helper()
	extra := ""
	if resource != "" {
		extra = "&resource=" + url.QueryEscape(resource)
	}
	rec := h.get(authorizeQuery(extra))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, h.idp.srv.URL+"/authorize") {
		h.t.Fatalf("authorize = %d Location=%q: %s", rec.Code, loc, rec.Body.String())
	}
	u, _ := url.Parse(loc)
	q = u.Query()
	h.idp.mu.Lock()
	h.idp.challenge, h.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	h.idp.mu.Unlock()
	return q.Get("state"), q
}

func TestLinkAuthorizeForcesAFreshLoginOnlyForTheLinkResource(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	for _, tc := range []struct {
		name, resource string
		fresh          bool
	}{
		{"link", linkTestRes, true},
		{"default", "", false},
		{"support", "https://support.mctl.ai", false},
		{"glovo mcp", auth.GlovoResourceIntended, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, q := h.zitadelAuthorizeParams(tc.resource)
			if tc.fresh {
				if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
					t.Fatalf("link authorize: prompt=%q max_age=%q, want login and 0", q.Get("prompt"), q.Get("max_age"))
				}
				return
			}
			if _, has := q["prompt"]; has {
				t.Fatalf("prompt sent for %s: %v", tc.name, q)
			}
			if _, has := q["max_age"]; has {
				t.Fatalf("max_age sent for %s: %v", tc.name, q)
			}
		})
	}
}

func TestLinkAuthorizeRefusals(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	for _, prompt := range []string{"none", "login none", "none consent"} {
		rec := h.get(authorizeQuery("&resource=" + url.QueryEscape(linkTestRes) + "&prompt=" + url.QueryEscape(prompt)))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" || !strings.HasPrefix(loc.String(), testClientRedirect) {
			t.Fatalf("prompt=%q: %d %q, want invalid_request to the client", prompt, rec.Code, loc)
		}
	}
	// prompt=none is still fine for every other resource.
	rec := h.get(authorizeQuery("&prompt=none"))
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, h.idp.srv.URL+"/authorize") {
		t.Fatalf("prompt=none on the default resource: %d %q", rec.Code, loc)
	}
	// Only ZITADEL can be told to re-authenticate.
	gh := newUpstreamHarness(t, OAuthUpstreamGitHub, nil)
	makeLinkReady(gh.oauth, linkTestRes)
	rec = gh.get(authorizeQuery("&resource=" + url.QueryEscape(linkTestRes)))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("github upstream: %d %q, want invalid_request", rec.Code, loc)
	}
	// Unset: the resource is an unknown target.
	dark := newLinkOAuthHarness(t, "")
	rec = dark.get(authorizeQuery("&resource=" + url.QueryEscape(linkTestRes)))
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("unset link resource: %q, want invalid_target", loc)
	}
}

func TestLinkCallbackChecksAuthTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*fakeIdP)
		accept bool
	}{
		{"fresh", func(i *fakeIdP) { i.authTime = time.Now() }, true},
		{"within the skew", func(i *fakeIdP) { i.authTime = time.Now().Add(-30 * time.Second) }, true},
		{"missing", func(i *fakeIdP) { i.omitAuthTime = true }, false},
		{"zero", func(i *fakeIdP) { i.authTime = time.Unix(0, 0) }, false},
		{"stale", func(i *fakeIdP) { i.authTime = time.Now().Add(-10 * time.Minute) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLinkOAuthHarness(t, linkTestRes)
			tc.set(h.idp)
			state, _ := h.zitadelAuthorizeParams(linkTestRes)
			rec := h.callback(state)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if tc.accept {
				// A fresh sign-in reaches the consent page; no code yet.
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Authorize this application?") {
					t.Fatalf("fresh sign-in = %d, want the consent page: %s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusFound {
				t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
			}
			if loc.Query().Get("code") != "" || loc.Query().Get("error") != "access_denied" {
				t.Fatalf("sign-in without a fresh auth_time: %s, want access_denied and no code", loc)
			}
		})
	}
}

// Every other flow is indifferent to auth_time.
func TestNonLinkCallbackIgnoresAuthTime(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	h.idp.omitAuthTime = true
	state, _ := h.zitadelAuthorizeParams("")
	loc, _ := url.Parse(h.callback(state).Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("default flow refused without auth_time: %s", loc)
	}
}

// linkCode drives authorize, fresh sign-in and the consent approval for
// clientID and returns the authorization code.
func linkCode(t *testing.T, h *upstreamHarness, clientID string) string {
	t.Helper()
	token, cookie, _ := linkConsentPage(t, h, clientID)
	rec := h.decideLinkConsent(token, "approve", cookie)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("approve = %d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
	return loc.Query().Get("code")
}

// The full path: authorize, fresh sign-in, consent, code, token.
func linkToken(t *testing.T, h *upstreamHarness) (access, refresh string) {
	t.Helper()
	code := linkCode(t, h, "client")
	access, refresh, err := h.oauth.ExchangeCodeForResource(context.Background(), code, testVerifier, "client", testClientRedirect, auth.ClientAssertion{}, []string{linkTestRes})
	if err != nil {
		t.Fatal(err)
	}
	return access, refresh
}

func TestLinkEndToEndTokenShape(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	before := time.Now().Add(-time.Minute).Unix()
	access, refresh := linkToken(t, h)
	if refresh != "" {
		t.Fatalf("refresh token %q for the link audience", refresh)
	}
	c := jwtClaims(t, access)
	if c["aud"] != linkTestRes {
		t.Fatalf("aud = %v", c["aud"])
	}
	if at, _ := c["auth_time"].(float64); int64(at) < before {
		t.Fatalf("auth_time = %v, want the ID token's fresh one", c["auth_time"])
	}
	if c["pid"] != linkTestPRN {
		t.Fatalf("pid = %v", c["pid"])
	}

	// A default token minted by the same flow has no auth_time.
	state, _ := h.zitadelAuthorizeParams("")
	loc, _ := url.Parse(h.callback(state).Header().Get("Location"))
	mcp, _, err := h.oauth.ExchangeCode(context.Background(), loc.Query().Get("code"), testVerifier, "client", testClientRedirect)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := jwtClaims(t, mcp)["auth_time"]; has {
		t.Fatal("MCP token carries auth_time")
	}
}

func TestLinkTokenEndpointOmitsRefreshAndRefuseRefreshGrant(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {linkCode(t, h, "client")}, "code_verifier": {testVerifier},
		"client_id": {"client"}, "redirect_uri": {testClientRedirect}, "resource": {linkTestRes}}
	post := func(f url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		return rec
	}
	rec := post(form)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "refresh_token") || !strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("token = %d %s, want an access token and no refresh_token member", rec.Code, rec.Body.String())
	}
	// A refresh grant naming the link resource, with any token, is refused.
	rec = post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"whatever"}, "client_id": {"client"}, "resource": {linkTestRes}})
	if rec.Code == http.StatusOK {
		t.Fatalf("refresh grant for the link resource = %d: %s", rec.Code, rec.Body.String())
	}
}

// The API and the MCP endpoint share one bearer verifier; neither accepts a
// link token, while a default token still passes.
func TestLinkTokenIsRefusedByAPIAndMCP(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	o := h.oauth
	link, _ := linkToken(t, h)
	def, err := o.IssueJWT("", linkTestPRN, nil)
	if err != nil {
		t.Fatal(err)
	}
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := o.ValidateJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	router := NewRouter(Options{OAuthServer: o, AuthMiddleware: mw,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})
	call := func(method, path, bearer string) int {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, rt := range [][2]string{{"GET", "/api/v1/whoami"}, {"GET", "/api/v1/services"}, {"POST", "/mcp"}, {"GET", "/mcp"}} {
		if code := call(rt[0], rt[1], link); code != http.StatusUnauthorized {
			t.Errorf("link token on %s %s = %d, want 401", rt[0], rt[1], code)
		}
	}
	if code := call("POST", "/mcp", def); code != http.StatusOK {
		t.Errorf("default token on /mcp = %d, want 200", code)
	}
}

// linkConsentPage drives a link authorization for clientID to the consent
// page and returns the consent token, the flow cookie and the page body. It
// fails the test if a code was issued without the page.
func linkConsentPage(t *testing.T, h *upstreamHarness, clientID string) (token string, cookie *http.Cookie, body string) {
	t.Helper()
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testClientRedirect)
	q.Set("response_type", "code")
	q.Set("state", "client-state")
	q.Set("code_challenge", testChallenge())
	q.Set("code_challenge_method", "S256")
	q.Set("resource", linkTestRes)
	rec0 := h.get("/oauth/authorize?" + q.Encode())
	loc0 := rec0.Header().Get("Location")
	if rec0.Code != http.StatusFound || !strings.HasPrefix(loc0, h.idp.srv.URL+"/authorize") {
		t.Fatalf("authorize = %d Location=%q: %s", rec0.Code, loc0, rec0.Body.String())
	}
	u0, _ := url.Parse(loc0)
	h.idp.mu.Lock()
	h.idp.challenge, h.idp.nonce = u0.Query().Get("code_challenge"), u0.Query().Get("nonce")
	h.idp.mu.Unlock()
	state := u0.Query().Get("state")
	rec := h.callback(state)
	if rec.Code != http.StatusOK || strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("link flow for %q = %d Location=%q: a code must not be issued before the consent page", clientID, rec.Code, rec.Header().Get("Location"))
	}
	body = rec.Body.String()
	const marker = `name="token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no consent form: %s", body)
	}
	token = body[i+len(marker):]
	token = token[:strings.Index(token, `"`)]
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, consentCookie) {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no consent cookie")
	}
	return token, cookie, body
}

func (h *upstreamHarness) decideLinkConsent(token, decision string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(url.Values{"token": {token}, "decision": {decision}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// linkConsentToken approves the consent page and exchanges the code for the
// link token of clientID.
func linkConsentToken(t *testing.T, h *upstreamHarness, clientID, kind string) string {
	t.Helper()
	access, refresh, err := h.oauth.ExchangeCodeForResource(context.Background(), linkCode(t, h, clientID), testVerifier, clientID, testClientRedirect, auth.ClientAssertion{}, []string{linkTestRes})
	if err != nil {
		t.Fatal(err)
	}
	if refresh != "" {
		t.Fatalf("refresh token for the link audience via %s client", kind)
	}
	return access
}

// A DCR, static or allowlisted client on the link resource is shown the
// consent page before any code exists, and the code carries the fresh login.
func TestLinkFlowShowsConsentToEveryNonCIMDClientKind(t *testing.T) {
	for _, kind := range []string{"allowlisted", "dcr", "static"} {
		t.Run(kind, func(t *testing.T) {
			h := newLinkOAuthHarness(t, linkTestRes)
			clientID := "client"
			switch kind {
			case "dcr":
				clientID = h.oauth.RegisterClient("Link Helper", []string{testClientRedirect}).ClientID
			case "static":
				clientID = "static-link-helper"
				if err := h.oauth.AddPreregisteredClient(clientID, "Static Helper", []string{testClientRedirect}); err != nil {
					t.Fatal(err)
				}
			}
			before := time.Now().Add(-time.Minute).Unix()
			_, _, body := linkConsentPage(t, h, clientID)
			if !strings.Contains(body, clientID) {
				t.Fatalf("page does not name the client %q: %s", clientID, body)
			}
			c := jwtClaims(t, linkConsentToken(t, h, clientID, kind))
			if at, _ := c["auth_time"].(float64); int64(at) < before {
				t.Fatalf("auth_time = %v after consent", c["auth_time"])
			}
		})
	}
}

func TestLinkConsentDenyIssuesNoCode(t *testing.T) {
	h := newLinkOAuthHarness(t, linkTestRes)
	token, cookie, _ := linkConsentPage(t, h, "client")
	rec := h.decideLinkConsent(token, "deny", cookie)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(loc, "error=access_denied") || strings.Contains(loc, "code=") {
		t.Fatalf("deny = %d Location=%q", rec.Code, loc)
	}
}

// A CIMD client in the link flow: requestConsent stores the fresh login time
// in the ConsentEntry, takeConsentDecision hands it to issueGrant, and the
// token carries it. Dropping the threading must fail this test.
func TestLinkFlowCIMDConsentRoundTripKeepsAuthTime(t *testing.T) {
	const id = "https://app.example.com/client.json"
	doc, _ := json.Marshal(map[string]any{
		"client_id": id, "client_name": "CIMD Helper",
		"redirect_uris": []string{testClientRedirect}, "token_endpoint_auth_method": "none",
	})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cl := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, n, srv.Listener.Addr().String())
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	h := newLinkOAuthHarness(t, linkTestRes)
	h.oauth.CIMD = cimd.NewResolver(cimd.Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: cl})

	before := time.Now().Add(-time.Minute).Unix()
	_, _, body := linkConsentPage(t, h, id)
	if !strings.Contains(body, "CIMD Helper") {
		t.Fatalf("page does not name the CIMD client: %s", body)
	}
	c := jwtClaims(t, linkConsentToken(t, h, id, "cimd"))
	if at, _ := c["auth_time"].(float64); int64(at) < before {
		t.Fatalf("auth_time = %v after the CIMD consent round trip", c["auth_time"])
	}
	if c["aud"] != linkTestRes {
		t.Fatalf("aud = %v", c["aud"])
	}
}
