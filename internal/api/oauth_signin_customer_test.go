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
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const testCustomersOrg = "395272528420931285"

func customerIDClaims() map[string]any {
	return map[string]any{
		auth.ClaimResourceOwnerID:     testCustomersOrg,
		auth.ClaimCustomerOrg:         "customers",
		auth.ClaimCustomerIdP:         "github",
		auth.ClaimCustomerGitHubID:    "268260640",
		auth.ClaimCustomerGitHubLogin: "mctl-reviewer",
	}
}

// recordingResolver answers like signinResolver and records what it was
// asked.
type recordingResolver struct {
	signinResolver
	mu  sync.Mutex
	ids []auth.Identity
}

func (r *recordingResolver) ResolvePrincipal(ctx context.Context, id auth.Identity) (string, error) {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
	return r.signinResolver.ResolvePrincipal(ctx, id)
}

// newCustomerHarness is the ZITADEL upstream with a customers organization
// configured, in principal mode or not, with the ID token carrying claims.
func newCustomerHarness(t *testing.T, principalMode bool, claims map[string]any, pr auth.PrincipalResolver) *upstreamHarness {
	t.Helper()
	return newCustomerHarnessWith(t, OAuthUpstreamZitadel, "", principalMode, claims, pr)
}

// newCustomerHarnessWith is newCustomerHarness under mode, with the
// customers organization's GitHub IdP id set to idpID ("" for none).
func newCustomerHarnessWith(t *testing.T, mode OAuthUpstreamMode, idpID string, principalMode bool, claims map[string]any, pr auth.PrincipalResolver) *upstreamHarness {
	t.Helper()
	store := &fakeLinkedStore{err: principals.ErrNotFound}
	h := newUpstreamHarness(t, mode, store)
	h.idp.extra = claims
	zopts := &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: h.idp.srv.URL, ClientID: testOAuthZClientID,
		ClientSecret: testOAuthZClientSecret, Store: store, CustomersOrgID: testCustomersOrg, CustomersGitHubIdPID: idpID}
	opts := Options{OAuthServer: h.oauth, OAuthUpstream: mode, OAuthZitadel: zopts, Principals: pr}
	if principalMode {
		h.oauth.PrincipalMode = true
		opts.TenantAuthzMode = TenantAuthzPrincipal
	}
	h.router = NewRouter(opts)
	return h
}

// With customers configured the sign-in asks ZITADEL to name the user's
// organization: without it a customer cannot be told from anyone else.
func TestZitadelSigninAsksForTheResourceOwner(t *testing.T) {
	h := newCustomerHarness(t, true, nil, nil)
	loc, _ := url.Parse(h.get(authorizeQuery("")).Header().Get("Location"))
	if scopes := strings.Fields(loc.Query().Get("scope")); !contains(scopes, auth.ScopeResourceOwner) {
		t.Fatalf("scope = %v, want %s", scopes, auth.ScopeResourceOwner)
	}
	// Without a customers organization the sign-in is unchanged.
	plain := newUpstreamHarness(t, OAuthUpstreamZitadel, &fakeLinkedStore{err: principals.ErrNotFound})
	loc, _ = url.Parse(plain.get(authorizeQuery("")).Header().Get("Location"))
	if scopes := strings.Fields(loc.Query().Get("scope")); contains(scopes, auth.ScopeResourceOwner) || !contains(scopes, "openid") {
		t.Fatalf("scope without customers = %v, want openid and no %s", scopes, auth.ScopeResourceOwner)
	}
}

// A customer signs in as the principal of the GitHub id the hook proved:
// the resolver is asked with that proof, the link store is never read, and
// the token carries the principal and no login or groups.
func TestZitadelSigninOfACustomer(t *testing.T) {
	const prn = "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"
	pr := &recordingResolver{signinResolver: signinResolver{prn: prn}}
	h := newCustomerHarness(t, true, customerIDClaims(), pr)
	staffBefore := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued"))
	before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "issued"))
	rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("callback = %d %q, want a code: %s", rec.Code, loc, rec.Body.String())
	}
	// A customer sign-in is counted apart from a staff one.
	if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "issued")) - before; n != 1 {
		t.Errorf("zitadel_customer issued +%v, want +1", n)
	}
	if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued")) - staffBefore; n != 0 {
		t.Errorf("zitadel issued +%v for a customer, want +0", n)
	}
	if len(h.store.calls) != 0 {
		t.Fatalf("the link store was read for a customer: %+v", h.store.calls)
	}
	if len(pr.ids) != 1 || pr.ids[0].Customer == nil || pr.ids[0].Customer.GitHubID != "268260640" ||
		pr.ids[0].Provider != "zitadel" || pr.ids[0].Subject != "z-sub" {
		t.Fatalf("resolver asked %+v, want the ZITADEL identity with its GitHub proof", pr.ids)
	}
	access, _, err := h.oauth.ExchangeCode(context.Background(), loc.Query().Get("code"), testVerifier, "client", testClientRedirect)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwtClaims(t, access)
	if claims["sub"] != prn || claims["pid"] != prn {
		t.Fatalf("sub=%v pid=%v, want %s", claims["sub"], claims["pid"], prn)
	}
	if g, _ := claims["groups"].([]any); len(g) != 0 {
		t.Fatalf("groups %v minted for a customer", g)
	}
}

func TestZitadelSigninOfACustomerRefusals(t *testing.T) {
	without := func(k string) map[string]any {
		c := customerIDClaims()
		delete(c, k)
		return c
	}
	refused := customerIDClaims()
	refused[auth.ClaimCustomerRefused] = "login_reserved"
	cases := map[string]struct {
		principalMode bool
		claims        map[string]any
		resolver      signinResolver
		code          int
		result        string
		resolved      bool // the resolver was asked
		label         string
	}{
		"organization not named":  {true, without(auth.ClaimResourceOwnerID), signinResolver{prn: "prn_x"}, http.StatusBadGateway, "invalid_token", false, auth.UpstreamZitadel},
		"no github id":            {true, without(auth.ClaimCustomerGitHubID), signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_unproven", false, oauthUpstreamZitadelCustomer},
		"hook refused":            {true, refused, signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_unproven", false, oauthUpstreamZitadelCustomer},
		"not in principal mode":   {false, customerIDClaims(), signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_not_enabled", false, oauthUpstreamZitadelCustomer},
		"subject owned elsewhere": {true, customerIDClaims(), signinResolver{err: fmt.Errorf("%w: %w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict, principals.ErrIdentityOwnedElsewhere)}, http.StatusConflict, "customer_conflict", true, oauthUpstreamZitadelCustomer},
		"principal disabled":      {true, customerIDClaims(), signinResolver{err: auth.ErrPrincipalDisabled}, http.StatusForbidden, "principal_refused", true, oauthUpstreamZitadelCustomer},
		"store down":              {true, customerIDClaims(), signinResolver{err: errors.New("db down")}, http.StatusServiceUnavailable, "principal_unavailable", true, oauthUpstreamZitadelCustomer},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pr := &recordingResolver{signinResolver: tc.resolver}
			h := newCustomerHarness(t, tc.principalMode, tc.claims, pr)
			before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(tc.label, tc.result))
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != tc.code || rec.Header().Get("Location") != "" {
				t.Fatalf("callback = %d Location=%q, want %d and no code: %s", rec.Code, rec.Header().Get("Location"), tc.code, rec.Body.String())
			}
			if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(tc.label, tc.result)) - before; n != 1 {
				t.Errorf("%s +%v, want +1", tc.result, n)
			}
			if tc.result == "customer_conflict" && !strings.Contains(html.UnescapeString(rec.Body.String()), `choose "Sign in with MCTL account"`) {
				t.Errorf("the conflict page does not point to Sign in with MCTL account: %s", rec.Body.String())
			}
			if len(h.store.calls) != 0 {
				t.Fatalf("a customers token fell through to the link store: %+v", h.store.calls)
			}
			if got := len(pr.ids) > 0; got != tc.resolved {
				t.Fatalf("resolver asked = %v, want %v", got, tc.resolved)
			}
		})
	}
}

// A user of another organization signs in exactly as before: through the
// link store, with no customer proof.
func TestZitadelSigninOfAnotherOrganizationIsUnchanged(t *testing.T) {
	pr := &recordingResolver{signinResolver: signinResolver{prn: "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"}}
	h := newCustomerHarness(t, true, map[string]any{auth.ClaimResourceOwnerID: "393497610436019469"}, pr)
	staff := oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued")
	customer := oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "issued")
	staffBefore, customerBefore := testutil.ToFloat64(staff), testutil.ToFloat64(customer)
	rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	if ds, dc := testutil.ToFloat64(staff)-staffBefore, testutil.ToFloat64(customer)-customerBefore; ds != 1 || dc != 0 {
		t.Errorf("issued: zitadel +%v, zitadel_customer +%v; want +1 and +0", ds, dc)
	}
	if len(h.store.calls) != 1 || len(pr.ids) != 1 || pr.ids[0].Customer != nil {
		t.Fatalf("store calls %+v, resolver %+v; want the link path without a customer proof", h.store.calls, pr.ids)
	}
}

// ─── customer GitHub entry (mctl-web#158) ──────────────────────────────────

const testCustomersGitHubIdP = "395272528420931999"

var choiceLink = regexp.MustCompile(`href="[^"]*upstream=(customer|zitadel|github)[^"]*"`)

func choices(body string) []string {
	var out []string
	for _, m := range choiceLink.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func authorizeScopes(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil {
		t.Fatalf("authorize = %d %q, want a redirect: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	return strings.Fields(loc.Query().Get("scope"))
}

// With the customers organization and its GitHub IdP configured, the
// chooser offers customers "Sign in with GitHub", which asks ZITADEL for
// that organization and IdP, next to the unchanged staff entry; under
// "both" the legacy GitHub upstream stays last.
func TestCustomerGitHubEntry(t *testing.T) {
	orgScope, idpScope := auth.ScopeOrgIDPrefix+testCustomersOrg, auth.ScopeIdPIDPrefix+testCustomersGitHubIdP
	for mode, want := range map[OAuthUpstreamMode][]string{
		OAuthUpstreamZitadel: {"customer", "zitadel"},
		OAuthUpstreamBoth:    {"customer", "zitadel", "github"},
	} {
		h := newCustomerHarnessWith(t, mode, testCustomersGitHubIdP, true, nil, nil)
		rec := h.get(authorizeQuery(""))
		if got := choices(rec.Body.String()); rec.Code != http.StatusOK || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("mode %s: authorize = %d, choices %v, want the chooser with %v", mode, rec.Code, got, want)
		}
		if !strings.Contains(rec.Body.String(), "Sign in with GitHub</a>") {
			t.Errorf("mode %s: the customer entry is not labelled Sign in with GitHub", mode)
		}
		// Partner organizations use the other entry too, so it must not
		// read as staff-only.
		if !strings.Contains(rec.Body.String(), "Sign in with MCTL account</a>") || strings.Contains(rec.Body.String(), "staff,") || !strings.Contains(rec.Body.String(), "Customers: sign in with your GitHub account.") || !strings.Contains(rec.Body.String(), "MCTL staff and partner accounts: use Sign in with MCTL account.") || strings.Contains(rec.Body.String(), "at auth.mctl.ai") {
			t.Errorf("mode %s: the account entry is not labelled Sign in with MCTL account", mode)
		}
		scopes := authorizeScopes(t, h.get(authorizeQuery("&upstream=customer")))
		if !contains(scopes, orgScope) || !contains(scopes, idpScope) || !contains(scopes, auth.ScopeResourceOwner) || !contains(scopes, "openid") {
			t.Fatalf("mode %s: customer scopes = %v, want %s and %s", mode, scopes, orgScope, idpScope)
		}
		// The staff entry is the sign-in it always was.
		scopes = authorizeScopes(t, h.get(authorizeQuery("&upstream=zitadel")))
		for _, sc := range scopes {
			if strings.HasPrefix(sc, auth.ScopeOrgIDPrefix) || strings.HasPrefix(sc, auth.ScopeIdPIDPrefix) {
				t.Fatalf("mode %s: staff scopes = %v, want no organization or IdP", mode, scopes)
			}
		}
	}
}

// The customer entry ends in the existing customer sign-in.
func TestCustomerGitHubEntrySignsInTheCustomer(t *testing.T) {
	const prn = "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"
	pr := &recordingResolver{signinResolver: signinResolver{prn: prn}}
	h := newCustomerHarnessWith(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, true, customerIDClaims(), pr)
	rec := h.callback(h.toZitadel(h.get(authorizeQuery("&upstream=customer"))))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("callback = %d %q, want a code: %s", rec.Code, loc, rec.Body.String())
	}
	if len(h.store.calls) != 0 || len(pr.ids) != 1 || pr.ids[0].Customer == nil || pr.ids[0].Customer.GitHubID != "268260640" {
		t.Fatalf("store calls %+v, resolver %+v; want the customer path", h.store.calls, pr.ids)
	}
}

// Without both ids, or where ZITADEL is not an upstream, no customer entry
// is offered and a forged choice is refused rather than sent to ZITADEL
// with an empty organization or IdP, or quietly made a staff sign-in.
func TestCustomerGitHubEntryFailsClosed(t *testing.T) {
	plain := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	noOrg := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	noOrg.router = NewRouter(Options{OAuthServer: noOrg.oauth, OAuthUpstream: OAuthUpstreamZitadel, OAuthZitadel: &OAuthZitadelOptions{
		ProviderName: "zitadel", Issuer: noOrg.idp.srv.URL, ClientID: testOAuthZClientID, ClientSecret: testOAuthZClientSecret,
		Store: noOrg.store, CustomersGitHubIdPID: testCustomersGitHubIdP}})
	for name, h := range map[string]*upstreamHarness{
		"no IdP id":       newCustomerHarnessWith(t, OAuthUpstreamZitadel, "", true, nil, nil),
		"no organization": noOrg,
		"no customers":    plain,
		"github mode":     newCustomerHarnessWith(t, OAuthUpstreamGitHub, testCustomersGitHubIdP, true, nil, nil),
	} {
		rec := h.get(authorizeQuery("&upstream=customer"))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: forged customer choice = %d Location=%q, want 400 and no redirect", name, rec.Code, rec.Header().Get("Location"))
		}
		rec = h.get(authorizeQuery(""))
		if strings.Contains(rec.Body.String(), "upstream=customer") {
			t.Errorf("%s: the customer entry is offered: %s", name, rec.Body.String())
		}
	}
	// Under zitadel without the entry there is nothing to choose: staff go
	// straight to ZITADEL, as before.
	for name, h := range map[string]*upstreamHarness{"no IdP id": newCustomerHarnessWith(t, OAuthUpstreamZitadel, "", true, nil, nil), "no organization": noOrg} {
		for _, sc := range authorizeScopes(t, h.get(authorizeQuery(""))) {
			if strings.HasPrefix(sc, auth.ScopeOrgIDPrefix) || strings.HasPrefix(sc, auth.ScopeIdPIDPrefix) {
				t.Errorf("%s: scope %s sent without the customer entry", name, sc)
			}
		}
	}
}

// startZitadelAuthorize holds the same line on its own: a customer start
// without both ids never reaches ZITADEL, whoever calls it.
func TestCustomerGitHubStartNeedsBothIDs(t *testing.T) {
	plain := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	h := &Handlers{opts: Options{OAuthServer: plain.oauth, OAuthUpstream: OAuthUpstreamZitadel}}
	h.oauthZitadel = &oauthZitadel{
		opts: &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: plain.idp.srv.URL, ClientID: testOAuthZClientID,
			ClientSecret: testOAuthZClientSecret, CustomersOrgID: testCustomersOrg},
		lazyOIDCProvider: lazyOIDCProvider{issuer: plain.idp.srv.URL},
	}
	rec := httptest.NewRecorder()
	h.startZitadelAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil),
		"client", testClientRedirect, "client-state", testChallenge(), true)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Location") != "" {
		t.Fatalf("customer start without an IdP id = %d Location=%q, want 503 and no redirect", rec.Code, rec.Header().Get("Location"))
	}
}
