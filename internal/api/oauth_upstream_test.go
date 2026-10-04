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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const (
	testOAuthZClientID, testOAuthZClientSecret = "oauth-client", "oauth-secret"
	testClientRedirect                         = "https://claude.ai/api/mcp/auth_callback"
	testVerifier                               = "client-verifier-0123456789012345678901234567890123"
)

func testChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type fakeLinkedStore struct {
	mu    sync.Mutex
	calls []auth.Identity
	p     *principals.Principal
	gh    *principals.ExternalIdentity
	err   error
}

func (f *fakeLinkedStore) LinkedGitHub(_ context.Context, id auth.Identity) (*principals.Principal, *principals.ExternalIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	return f.p, f.gh, f.err
}

func linkedTo(login string) *fakeLinkedStore {
	return &fakeLinkedStore{
		p:  &principals.Principal{ID: "prn_1", Kind: auth.KindHuman, Status: principals.StatusActive},
		gh: &principals.ExternalIdentity{ID: "xid_gh", PrincipalID: "prn_1", Provider: auth.ProviderGitHub, Subject: "42", Display: login},
	}
}

type fakeTenants map[string][]string

func (f fakeTenants) GetTenantsForUser(login string) ([]string, error) { return f[login], nil }

type upstreamHarness struct {
	t      *testing.T
	router http.Handler
	oauth  *auth.OAuthServer
	idp    *fakeIdP
	store  *fakeLinkedStore
}

// newUpstreamHarness builds the router for mode. store nil means a
// deployment without a principal store.
func newUpstreamHarness(t *testing.T, mode OAuthUpstreamMode, store *fakeLinkedStore) *upstreamHarness {
	t.Helper()
	idp := newFakeIdP(t)
	idp.clientID, idp.clientSecret = testOAuthZClientID, testOAuthZClientSecret
	o := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"),
		[]string{testClientRedirect}, auth.NewGitHubValidator([]string{"mashkovd"}))
	o.TenantResolver = fakeTenants{"mashkovd": {"acme"}}
	zopts := &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: idp.srv.URL, ClientID: testOAuthZClientID, ClientSecret: testOAuthZClientSecret}
	if store != nil {
		zopts.Store = store
	}
	return &upstreamHarness{t: t, oauth: o, idp: idp, store: store,
		router: NewRouter(Options{OAuthServer: o, OAuthUpstream: mode, OAuthZitadel: zopts})}
}

func (h *upstreamHarness) get(target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func authorizeQuery(extra string) string {
	q := url.Values{}
	q.Set("client_id", "client")
	q.Set("redirect_uri", testClientRedirect)
	q.Set("response_type", "code")
	q.Set("state", "client-state")
	q.Set("code_challenge", testChallenge())
	q.Set("code_challenge_method", "S256")
	return "/oauth/authorize?" + q.Encode() + extra
}

// toZitadel follows an authorize response to the fake IdP, records the
// PKCE challenge and nonce it was sent with, and returns the state.
func (h *upstreamHarness) toZitadel(rec *httptest.ResponseRecorder) string {
	h.t.Helper()
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, h.idp.srv.URL+"/authorize") {
		h.t.Fatalf("authorize = %d Location=%q, want a redirect to ZITADEL: %s", rec.Code, loc, rec.Body.String())
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("client_id") != testOAuthZClientID || q.Get("redirect_uri") != "https://api.example"+oauthZitadelCallbackPath ||
		q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		h.t.Fatalf("ZITADEL authorize params: %v", q)
	}
	// Sign-in is single sign-on: an existing ZITADEL session must be usable.
	if q.Get("prompt") != "" || q.Get("max_age") != "" {
		h.t.Fatalf("ZITADEL authorize forces re-authentication: %v", q)
	}
	if q.Get("state") == "client-state" || strings.Contains(q.Get("state"), "client-state") {
		h.t.Fatalf("the client's state was sent to ZITADEL: %q", q.Get("state"))
	}
	h.idp.mu.Lock()
	h.idp.challenge, h.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	h.idp.mu.Unlock()
	return q.Get("state")
}

func (h *upstreamHarness) callback(state string) *httptest.ResponseRecorder {
	return h.get(oauthZitadelCallbackPath + "?code=z-code&state=" + url.QueryEscape(state))
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "iat")
	delete(m, "exp")
	return m
}

// ─── mode ─────────────────────────────────────────────────────────────────

func TestParseOAuthUpstreamMode(t *testing.T) {
	for in, want := range map[string]OAuthUpstreamMode{"": OAuthUpstreamGitHub, "github": OAuthUpstreamGitHub, "zitadel": OAuthUpstreamZitadel, "both": OAuthUpstreamBoth} {
		if got, err := ParseOAuthUpstreamMode(in); err != nil || got != want {
			t.Errorf("ParseOAuthUpstreamMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ZITADEL", "gitlab", " github", "github,zitadel"} {
		if _, err := ParseOAuthUpstreamMode(in); err == nil || !strings.Contains(err.Error(), "OAUTH_UPSTREAM") {
			t.Errorf("ParseOAuthUpstreamMode(%q) = %v, want an error naming OAUTH_UPSTREAM", in, err)
		}
	}
}

// The default is today's behaviour: GitHub, even with the ZITADEL upstream
// configured, and an upstream= parameter cannot change that.
func TestAuthorizeDefaultsToGitHub(t *testing.T) {
	for _, mode := range []OAuthUpstreamMode{"", OAuthUpstreamGitHub} {
		h := newUpstreamHarness(t, mode, linkedTo("mashkovd"))
		for _, extra := range []string{"", "&upstream=zitadel"} {
			rec := h.get(authorizeQuery(extra))
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != http.StatusFound || loc.Host != "github.com" || loc.Query().Get("client_id") != "gh-client" ||
				loc.Query().Get("redirect_uri") != "https://api.example/oauth/github/callback" {
				t.Fatalf("mode %q%s: authorize = %d %s, want the GitHub redirect", mode, extra, rec.Code, loc)
			}
		}
	}
}

// ─── ZITADEL sign-in ──────────────────────────────────────────────────────

// A linked ZITADEL user gets exactly what a GitHub sign-in of the linked
// principal's login gets: same subject, same groups (tenants and admin).
func TestZitadelSigninIssuesTheLinkedGitHubLoginsCode(t *testing.T) {
	store := linkedTo("mashkovd")
	h := newUpstreamHarness(t, OAuthUpstreamZitadel, store)
	before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued"))

	state := h.toZitadel(h.get(authorizeQuery("&upstream=github"))) // the parameter is ignored outside "both"
	rec := h.callback(state)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc.String(), testClientRedirect) {
		t.Fatalf("callback = %d %q, want a redirect to the client: %s", rec.Code, loc, rec.Body.String())
	}
	if loc.Query().Get("state") != "client-state" || loc.Query().Get("code") == "" {
		t.Fatalf("client redirect = %s, want code and the client's state", loc)
	}
	want := auth.Identity{Provider: "zitadel", Issuer: h.idp.srv.URL, Subject: "z-sub", Display: "dmitrii", Kind: auth.KindHuman}
	if len(store.calls) != 1 || store.calls[0] != want {
		t.Fatalf("store looked up %+v, want %+v", store.calls, want)
	}

	access, _, err := h.oauth.ExchangeCode(loc.Query().Get("code"), testVerifier, "client", testClientRedirect)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := h.oauth.IssueJWT("mashkovd", h.oauth.ResolveGroups("mashkovd"))
	if err != nil {
		t.Fatal(err)
	}
	got, wantClaims := jwtClaims(t, access), jwtClaims(t, ref)
	if !reflect.DeepEqual(got, wantClaims) {
		t.Fatalf("ZITADEL sign-in JWT claims = %v, want the GitHub sign-in's %v", got, wantClaims)
	}
	if g := got["groups"].([]any); len(g) != 2 {
		t.Fatalf("groups = %v, want the tenant and admins", g)
	}
	if after := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued")); after != before+1 {
		t.Errorf("issued counter moved %v, want 1", after-before)
	}

	// The state is single use.
	if rec := h.callback(state); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback = %d, want 400", rec.Code)
	}
}

var linkHref = regexp.MustCompile(`href="` + regexp.QuoteMeta(linkStartPath) + `"`)

// "Not linked" is answered with a way to link, and nothing else: no code,
// no redirect, no provisioning (the store interface cannot provision).
func TestZitadelSigninOfAnUnlinkedUser(t *testing.T) {
	cases := map[string]struct {
		store    *fakeLinkedStore
		mentions string
	}{
		"no identity row": {&fakeLinkedStore{err: principals.ErrNotFound}, "not linked"},
		"own principal": {&fakeLinkedStore{
			p: &principals.Principal{ID: "prn_own", Status: principals.StatusActive}, err: principals.ErrNoGitHubIdentity,
		}, "prn_own"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newUpstreamHarness(t, OAuthUpstreamZitadel, tc.store)
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
				t.Fatalf("callback = %d Location=%q, want a 403 page", rec.Code, rec.Header().Get("Location"))
			}
			body := html.UnescapeString(rec.Body.String())
			if !linkHref.MatchString(rec.Body.String()) || !strings.Contains(body, tc.mentions) {
				t.Fatalf("page does not offer linking or lacks %q: %s", tc.mentions, body)
			}
		})
	}
}

// Only the store's documented refusals mean "not linked". A failed read,
// or no store at all, is 503 and never the link page.
func TestZitadelSigninStoreFailureIsNotUnlinked(t *testing.T) {
	for name, store := range map[string]*fakeLinkedStore{
		"store error": {err: errors.New("connection refused")},
		"no store":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			h := newUpstreamHarness(t, OAuthUpstreamZitadel, store)
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != http.StatusServiceUnavailable || linkHref.MatchString(rec.Body.String()) || rec.Header().Get("Location") != "" {
				t.Fatalf("callback = %d, want 503 without the link page: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "connection refused") {
				t.Fatal("store error text reached the browser")
			}
		})
	}
}

// preferred_username is chosen by whoever owns the ZITADEL account; the
// page must carry it escaped. Asserted on the raw body.
func TestZitadelSigninPageEscapesTheUsername(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamZitadel, &fakeLinkedStore{err: principals.ErrNotFound})
	h.idp.username = `<script>alert(1)</script>`
	rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "<script>") ||
		!strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Fatalf("callback = %d, want the username escaped: %s", rec.Code, rec.Body.String())
	}
}

// The refusals that name a principal need one: a store that returns them
// without it broke its contract, which is a failed read (503), not a panic.
func TestZitadelSigninRefusalWithoutAPrincipalIsAFailedRead(t *testing.T) {
	for _, err := range []error{principals.ErrNoGitHubIdentity, principals.ErrGitHubLoginUnknown, principals.ErrAmbiguousGitHubIdentity} {
		t.Run(err.Error(), func(t *testing.T) {
			h := newUpstreamHarness(t, OAuthUpstreamZitadel, &fakeLinkedStore{err: err})
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != http.StatusServiceUnavailable || linkHref.MatchString(rec.Body.String()) {
				t.Fatalf("callback = %d, want 503 without the link page", rec.Code)
			}
		})
	}
}

// The canary reads this metric: ZITADEL being unreachable must not share a
// bucket with mctl failing.
func TestZitadelSigninMetricSeparatesFailures(t *testing.T) {
	count := func(result string) float64 {
		return testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, result))
	}
	t.Run("upstream_unreachable", func(t *testing.T) {
		h := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
		state := h.toZitadel(h.get(authorizeQuery("")))
		// The pending authorization stays in h.oauth; a fresh router over it
		// has not discovered yet, and the IdP is gone.
		h.idp.srv.Close()
		before := count("upstream_unreachable")
		h3 := &upstreamHarness{t: t, oauth: h.oauth, idp: h.idp,
			router: NewRouter(Options{OAuthServer: h.oauth, OAuthUpstream: OAuthUpstreamZitadel, OAuthZitadel: &OAuthZitadelOptions{
				ProviderName: "zitadel", Issuer: h.idp.srv.URL, ClientID: testOAuthZClientID, ClientSecret: testOAuthZClientSecret, Store: linkedTo("mashkovd"),
			}})}
		if rec := h3.callback(state); rec.Code != http.StatusBadGateway || count("upstream_unreachable")-before != 1 {
			t.Fatalf("callback = %d, upstream_unreachable +%v, want 502 and +1", rec.Code, count("upstream_unreachable")-before)
		}
	})
	t.Run("exchange_failed", func(t *testing.T) {
		h := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
		state := h.toZitadel(h.get(authorizeQuery("")))
		h.idp.clientSecret = "rotated"
		before := count("exchange_failed")
		if rec := h.callback(state); rec.Code != http.StatusBadGateway || count("exchange_failed")-before != 1 {
			t.Fatalf("callback = %d, exchange_failed +%v, want 502 and +1", rec.Code, count("exchange_failed")-before)
		}
	})
}

func TestZitadelSigninRefusals(t *testing.T) {
	p := &principals.Principal{ID: "prn_1", Status: principals.StatusActive}
	// The principal is returned as principals.Store.LinkedGitHub does:
	// not with a revoked identity or a disabled principal.
	cases := map[string]struct {
		p    *principals.Principal
		err  error
		code int
	}{
		"revoked identity":    {nil, auth.ErrIdentityRefused, http.StatusForbidden},
		"disabled principal":  {nil, auth.ErrPrincipalDisabled, http.StatusForbidden},
		"login unknown":       {p, principals.ErrGitHubLoginUnknown, http.StatusConflict},
		"two GitHub accounts": {p, principals.ErrAmbiguousGitHubIdentity, http.StatusConflict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "refused"))
			h := newUpstreamHarness(t, OAuthUpstreamZitadel, &fakeLinkedStore{p: tc.p, err: tc.err})
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != tc.code || rec.Header().Get("Location") != "" {
				t.Fatalf("callback = %d Location=%q, want %d and no code", rec.Code, rec.Header().Get("Location"), tc.code)
			}
			if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "refused")) - before; n != 1 {
				t.Fatalf("refused +%v, want +1", n)
			}
		})
	}
}

// The ID token must be for this client and this authorization.
func TestZitadelSigninRefusesAForeignIDToken(t *testing.T) {
	t.Run("nonce", func(t *testing.T) {
		store := linkedTo("mashkovd")
		h := newUpstreamHarness(t, OAuthUpstreamZitadel, store)
		state := h.toZitadel(h.get(authorizeQuery("")))
		h.idp.nonceOverride = "another-authorization"
		if rec := h.callback(state); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("callback = %d, want 400", rec.Code)
		}
		if len(store.calls) != 0 {
			t.Fatal("a refused ID token reached the principal store")
		}
	})
	t.Run("audience", func(t *testing.T) {
		store := linkedTo("mashkovd")
		h := newUpstreamHarness(t, OAuthUpstreamZitadel, store)
		state := h.toZitadel(h.get(authorizeQuery("")))
		h.idp.audOverride = testLinkClientID // a token minted for the link client
		if rec := h.callback(state); rec.Code != http.StatusBadGateway || rec.Header().Get("Location") != "" {
			t.Fatalf("callback = %d, want 502", rec.Code)
		}
		if len(store.calls) != 0 {
			t.Fatal("a refused ID token reached the principal store")
		}
	})
}

func TestZitadelSigninUpstreamErrorGoesBackToTheClient(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	state := h.toZitadel(h.get(authorizeQuery("")))
	rec := h.get(oauthZitadelCallbackPath + "?error=access_denied&state=" + url.QueryEscape(state))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc.String(), testClientRedirect) ||
		loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "client-state" || loc.Query().Get("code") != "" {
		t.Fatalf("callback = %d %s, want access_denied to the client", rec.Code, loc)
	}
}

// ─── states are bound to their upstream ───────────────────────────────────

func TestUpstreamStatesDoNotCross(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamBoth, linkedTo("mashkovd"))

	// A GitHub authorization cannot be completed by a ZITADEL callback.
	h.oauth.StorePendingAuth("gh-state|client-state", "client", testClientRedirect, testChallenge())
	if rec := h.callback("gh-state|client-state"); rec.Code != http.StatusBadRequest || len(h.store.calls) != 0 {
		t.Fatalf("ZITADEL callback on a GitHub state = %d, want 400", rec.Code)
	}

	// A ZITADEL authorization cannot be completed by a GitHub callback.
	zState := h.toZitadel(h.get(authorizeQuery("&upstream=zitadel")))
	if rec := h.get(githubCallbackPath + "?code=gh-code&state=" + url.QueryEscape(zState)); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "invalid or expired state") {
		t.Fatalf("GitHub callback on a ZITADEL state = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// A mode without GitHub refuses the GitHub callback for sign-in even with a
// GitHub authorization pending (one started before the mode changed). With
// GitHub allowed, the same request goes on to the code exchange, which a
// cancelled context fails without touching the network.
func TestGitHubCallbackFollowsTheMode(t *testing.T) {
	for mode, want := range map[OAuthUpstreamMode]int{
		OAuthUpstreamZitadel: http.StatusBadRequest,
		OAuthUpstreamGitHub:  http.StatusBadGateway,
		OAuthUpstreamBoth:    http.StatusBadGateway,
	} {
		h := newUpstreamHarness(t, mode, linkedTo("mashkovd"))
		h.oauth.StorePendingAuth("gh-state|client-state", "client", testClientRedirect, testChallenge())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest(http.MethodGet, githubCallbackPath+"?code=gh-code&state=gh-state%7Cclient-state", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("mode %s: GitHub callback = %d %s, want %d", mode, rec.Code, rec.Body.String(), want)
		}
	}
}

// ─── both ─────────────────────────────────────────────────────────────────

var chooserLink = regexp.MustCompile(`href="([^"]*upstream=(zitadel|github)[^"]*)"`)

func TestBothShowsAChooserWithZitadelFirst(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamBoth, linkedTo("mashkovd"))
	for _, extra := range []string{"", "&upstream=gitlab"} {
		rec := h.get(authorizeQuery(extra))
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
			t.Fatalf("authorize%s = %d, want the chooser page", extra, rec.Code)
		}
		m := chooserLink.FindAllStringSubmatch(rec.Body.String(), -1)
		if len(m) != 2 || m[0][2] != "zitadel" || m[1][2] != "github" {
			t.Fatalf("chooser links = %v, want ZITADEL then GitHub", m)
		}
		if !strings.Contains(rec.Body.String(), "legacy") {
			t.Error("the GitHub option is not marked legacy")
		}
		// Each choice is the same authorization plus upstream=.
		for _, l := range m {
			u, _ := url.Parse(html.UnescapeString(l[1]))
			if u.Path != "/oauth/authorize" || u.Query().Get("code_challenge") != testChallenge() || u.Query().Get("state") != "client-state" {
				t.Fatalf("choice %s does not carry the authorization", u)
			}
		}
	}
	h.toZitadel(h.get(authorizeQuery("&upstream=zitadel")))
	loc, _ := url.Parse(h.get(authorizeQuery("&upstream=github")).Header().Get("Location"))
	if loc.Host != "github.com" {
		t.Fatalf("upstream=github went to %s", loc)
	}
}

// The chooser is reached only after the request is validated: an
// unallowlisted redirect_uri is still refused directly.
func TestBothValidatesBeforeTheChooser(t *testing.T) {
	h := newUpstreamHarness(t, OAuthUpstreamBoth, linkedTo("mashkovd"))
	rec := h.get(strings.Replace(authorizeQuery(""), url.QueryEscape(testClientRedirect), url.QueryEscape("https://evil.example/cb"), 1))
	if rec.Code != http.StatusBadRequest || chooserLink.MatchString(rec.Body.String()) {
		t.Fatalf("authorize with a foreign redirect_uri = %d, want 400 and no chooser", rec.Code)
	}
}

// The same for ZITADEL: a ZITADEL authorization still pending when the mode
// went back to github (the rollback) does not complete.
func TestZitadelCallbackFollowsTheMode(t *testing.T) {
	for mode, want := range map[OAuthUpstreamMode]int{
		OAuthUpstreamGitHub:  http.StatusBadRequest,
		OAuthUpstreamZitadel: http.StatusFound,
		OAuthUpstreamBoth:    http.StatusFound,
	} {
		store := linkedTo("mashkovd")
		h := newUpstreamHarness(t, mode, store)
		h.idp.mu.Lock()
		h.idp.challenge, h.idp.nonce = testChallenge(), "n1"
		h.idp.mu.Unlock()
		h.oauth.StorePendingOIDCAuth("z-state", auth.PendingOIDCAuth{
			Upstream: auth.UpstreamZitadel, ClientID: "client", RedirectURI: testClientRedirect,
			CodeChallenge: testChallenge(), ClientState: "client-state", Nonce: "n1", Verifier: testVerifier,
		})
		if rec := h.callback("z-state"); rec.Code != want {
			t.Errorf("mode %s: ZITADEL callback = %d %s, want %d", mode, rec.Code, rec.Body.String(), want)
		}
		if want == http.StatusBadRequest && len(store.calls) != 0 {
			t.Errorf("mode %s: a refused callback reached the principal store", mode)
		}
	}
}
