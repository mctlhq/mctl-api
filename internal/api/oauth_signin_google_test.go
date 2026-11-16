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
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Customer sign-in with Google (mctl-api#1079, slice 2).

const (
	testCustomersGoogleIdP = "395272528420932777"
	testGoogleSub          = "109876543210987654321"
)

func googleCustomerClaims() map[string]any {
	return map[string]any{
		auth.ClaimResourceOwnerID:   testCustomersOrg,
		auth.ClaimCustomerOrg:       "customers",
		auth.ClaimCustomerIdP:       "google",
		auth.ClaimCustomerGoogleSub: testGoogleSub,
	}
}

// googleChoiceLink tells the Google entry from the GitHub one, which
// choiceLink cannot: "customer" is a prefix of "customer_google".
var googleChoiceLink = regexp.MustCompile(`href="[^"]*upstream=(customer_google|customer|zitadel|github)[^"&]*"`)

func googleChoices(body string) []string {
	var out []string
	for _, m := range googleChoiceLink.FindAllStringSubmatch(html.UnescapeString(body), -1) {
		out = append(out, m[1])
	}
	return out
}

// newGoogleCustomerHarness is newCustomerHarnessWith with the customers
// organization's GitHub and Google IdP ids set ("" for none).
func newGoogleCustomerHarness(t *testing.T, mode OAuthUpstreamMode, githubIdP, googleIdP string, claims map[string]any, pr auth.PrincipalResolver) *upstreamHarness {
	t.Helper()
	store := &fakeLinkedStore{err: principals.ErrNotFound}
	h := newUpstreamHarness(t, mode, store)
	h.idp.extra = claims
	zopts := &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: h.idp.srv.URL, ClientID: testOAuthZClientID,
		ClientSecret: testOAuthZClientSecret, Store: store, CustomersOrgID: testCustomersOrg,
		CustomersGitHubIdPID: githubIdP, CustomersGoogleIdPID: googleIdP}
	h.oauth.PrincipalMode = true
	h.router = NewRouter(Options{OAuthServer: h.oauth, OAuthUpstream: mode, OAuthZitadel: zopts, Principals: pr,
		TenantAuthzMode: TenantAuthzPrincipal})
	return h
}

// With both IdPs configured the chooser offers GitHub, then Google, then
// the account entry; the Google entry asks ZITADEL for the customers
// organization and the Google IdP, never the GitHub one.
func TestCustomerGoogleEntry(t *testing.T) {
	orgScope := auth.ScopeOrgIDPrefix + testCustomersOrg
	for mode, want := range map[OAuthUpstreamMode][]string{
		OAuthUpstreamZitadel: {"customer", "customer_google", "zitadel"},
		OAuthUpstreamBoth:    {"customer", "customer_google", "zitadel", "github"},
	} {
		h := newGoogleCustomerHarness(t, mode, testCustomersGitHubIdP, testCustomersGoogleIdP, nil, nil)
		rec := h.get(authorizeQuery(""))
		body := rec.Body.String()
		if got := googleChoices(body); rec.Code != http.StatusOK || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("mode %s: authorize = %d, choices %v, want %v", mode, rec.Code, got, want)
		}
		if !strings.Contains(body, "Sign in with Google</a>") || !strings.Contains(body, "Customers: sign in with your GitHub or Google account.") {
			t.Errorf("mode %s: the Google entry or its line is missing: %s", mode, body)
		}
		scopes := authorizeScopes(t, h.get(authorizeQuery("&upstream=customer_google")))
		if !contains(scopes, orgScope) || !contains(scopes, auth.ScopeIdPIDPrefix+testCustomersGoogleIdP) ||
			contains(scopes, auth.ScopeIdPIDPrefix+testCustomersGitHubIdP) || !contains(scopes, auth.ScopeResourceOwner) {
			t.Fatalf("mode %s: Google scopes = %v, want the organization and the Google IdP only", mode, scopes)
		}
		scopes = authorizeScopes(t, h.get(authorizeQuery("&upstream=customer")))
		if !contains(scopes, auth.ScopeIdPIDPrefix+testCustomersGitHubIdP) || contains(scopes, auth.ScopeIdPIDPrefix+testCustomersGoogleIdP) {
			t.Fatalf("mode %s: GitHub scopes = %v, want the GitHub IdP only", mode, scopes)
		}
	}
}

// Google alone is offered as the primary customer entry, and the GitHub
// choice it does not offer is refused.
func TestCustomerGoogleEntryAlone(t *testing.T) {
	h := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, "", testCustomersGoogleIdP, nil, nil)
	rec := h.get(authorizeQuery(""))
	if got := googleChoices(rec.Body.String()); strings.Join(got, ",") != "customer_google,zitadel" {
		t.Fatalf("choices %v, want customer_google,zitadel", got)
	}
	if !strings.Contains(rec.Body.String(), "Customers: sign in with your Google account.") {
		t.Errorf("the line does not name Google alone: %s", rec.Body.String())
	}
	if rec := h.get(authorizeQuery("&upstream=customer")); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("GitHub choice without its IdP = %d Location=%q, want 400", rec.Code, rec.Header().Get("Location"))
	}
}

// Dark by default: without the Google IdP id the chooser is exactly the
// GitHub one, and a forged Google choice is refused, never sent to ZITADEL
// with another IdP or made a staff sign-in.
func TestCustomerGoogleEntryFailsClosed(t *testing.T) {
	for name, h := range map[string]*upstreamHarness{
		"no Google IdP":    newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, "", nil, nil),
		"no customers IdP": newGoogleCustomerHarness(t, OAuthUpstreamZitadel, "", "", nil, nil),
		"GitHub upstream":  newGoogleCustomerHarness(t, OAuthUpstreamGitHub, testCustomersGitHubIdP, testCustomersGoogleIdP, nil, nil),
	} {
		rec := h.get(authorizeQuery(""))
		if strings.Contains(rec.Body.String(), "customer_google") || strings.Contains(rec.Body.String(), "Google") {
			t.Errorf("%s: the Google entry is offered: %s", name, rec.Body.String())
		}
		rec = h.get(authorizeQuery("&upstream=customer_google"))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("%s: forged Google choice = %d Location=%q, want 400 and no redirect", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	// A Google IdP id without the customers organization is offered nowhere
	// either: its scope would name no organization.
	noOrg := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	noOrg.router = NewRouter(Options{OAuthServer: noOrg.oauth, OAuthUpstream: OAuthUpstreamZitadel, OAuthZitadel: &OAuthZitadelOptions{
		ProviderName: "zitadel", Issuer: noOrg.idp.srv.URL, ClientID: testOAuthZClientID, ClientSecret: testOAuthZClientSecret,
		Store: noOrg.store, CustomersGoogleIdPID: testCustomersGoogleIdP}})
	if rec := noOrg.get(authorizeQuery("&upstream=customer_google")); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("Google choice without the customers organization = %d Location=%q, want 400", rec.Code, rec.Header().Get("Location"))
	}
	gh := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, "", nil, nil)
	if body := gh.get(authorizeQuery("")).Body.String(); !strings.Contains(body, "Customers: sign in with your GitHub account.") {
		t.Errorf("the GitHub-only chooser changed: %s", body)
	}
}

// startZitadelAuthorize sends only an IdP the server offers.
func TestCustomerStartRefusesAnIdPNotOffered(t *testing.T) {
	plain := newUpstreamHarness(t, OAuthUpstreamZitadel, linkedTo("mashkovd"))
	h := &Handlers{opts: Options{OAuthServer: plain.oauth, OAuthUpstream: OAuthUpstreamZitadel}}
	h.oauthZitadel = &oauthZitadel{
		opts: &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: plain.idp.srv.URL, ClientID: testOAuthZClientID,
			ClientSecret: testOAuthZClientSecret, CustomersOrgID: testCustomersOrg, CustomersGitHubIdPID: testCustomersGitHubIdP},
		lazyOIDCProvider: lazyOIDCProvider{issuer: plain.idp.srv.URL},
	}
	for _, idp := range []string{testCustomersGoogleIdP, "1"} {
		rec := httptest.NewRecorder()
		h.startZitadelAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil),
			"client", testClientRedirect, "client-state", testChallenge(), "", idp)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Location") != "" {
			t.Fatalf("start at IdP %s = %d Location=%q, want 503 and no redirect", idp, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// A Google customer signs in as the principal of the Google subject the
// hook proved: the resolver gets the Google proof, the link store is never
// read, and the token names the principal with no login or groups.
func TestZitadelSigninOfAGoogleCustomer(t *testing.T) {
	const prn = "prn_01JDDDDDDDDDDDDDDDDDDDDDDD"
	pr := &recordingResolver{signinResolver: signinResolver{prn: prn}}
	h := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, testCustomersGoogleIdP, googleCustomerClaims(), pr)
	before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "issued"))
	rec := h.callback(h.toZitadel(h.get(authorizeQuery("&upstream=customer_google"))))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("callback = %d %q, want a code: %s", rec.Code, loc, rec.Body.String())
	}
	if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "issued")) - before; n != 1 {
		t.Errorf("zitadel_customer issued +%v, want +1", n)
	}
	if len(h.store.calls) != 0 {
		t.Fatalf("the link store was read for a customer: %+v", h.store.calls)
	}
	if len(pr.ids) != 1 || pr.ids[0].Customer == nil || pr.ids[0].Customer.Provider != auth.ProviderGoogle ||
		pr.ids[0].Customer.GoogleSub != testGoogleSub || pr.ids[0].Customer.GitHubID != "" || pr.ids[0].Provider != "zitadel" {
		t.Fatalf("resolver asked %+v, want the ZITADEL identity with its Google proof", pr.ids)
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

// Until the Google IdP is configured, a Google customer token is as
// unproven as one without any identity, whichever entry started it.
func TestZitadelSigninOfAGoogleCustomerIsDarkByDefault(t *testing.T) {
	pr := &recordingResolver{signinResolver: signinResolver{prn: "prn_x"}}
	h := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, "", googleCustomerClaims(), pr)
	before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "customer_unproven"))
	rec := h.callback(h.toZitadel(h.get(authorizeQuery("&upstream=customer"))))
	if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
		t.Fatalf("callback = %d Location=%q, want 403 and no code", rec.Code, rec.Header().Get("Location"))
	}
	if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(oauthUpstreamZitadelCustomer, "customer_unproven")) - before; n != 1 {
		t.Errorf("customer_unproven +%v, want +1", n)
	}
	if len(pr.ids) != 0 || len(h.store.calls) != 0 {
		t.Fatalf("resolver %+v, store %+v; want neither asked", pr.ids, h.store.calls)
	}
}

// A Google token that also carries GitHub claims is refused, not resolved
// by either identity.
func TestZitadelSigninOfAMixedGoogleTokenIsRefused(t *testing.T) {
	c := googleCustomerClaims()
	c[auth.ClaimCustomerGitHubID] = "268260640"
	pr := &recordingResolver{signinResolver: signinResolver{prn: "prn_x"}}
	h := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, testCustomersGoogleIdP, c, pr)
	rec := h.callback(h.toZitadel(h.get(authorizeQuery("&upstream=customer_google"))))
	if rec.Code != http.StatusForbidden || len(pr.ids) != 0 {
		t.Fatalf("callback = %d, resolver %+v; want 403 and no resolution", rec.Code, pr.ids)
	}
}

// The conflict page names the Google entry and the Google subject, not
// GitHub.
func TestZitadelSigninOfAGoogleCustomerConflict(t *testing.T) {
	conflict := fmt.Errorf("%w: %w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict, principals.ErrIdentityOwnedElsewhere)
	pr := &recordingResolver{signinResolver: signinResolver{err: conflict}}
	h := newGoogleCustomerHarness(t, OAuthUpstreamZitadel, testCustomersGitHubIdP, testCustomersGoogleIdP, googleCustomerClaims(), pr)
	rec := h.callback(h.toZitadel(h.get(authorizeQuery("&upstream=customer_google"))))
	body := html.UnescapeString(rec.Body.String())
	if rec.Code != http.StatusConflict {
		t.Fatalf("callback = %d, want 409: %s", rec.Code, body)
	}
	if !strings.Contains(body, `instead of "Sign in with Google"`) || !strings.Contains(body, "Google account id "+testGoogleSub) ||
		strings.Contains(body, "GitHub") {
		t.Fatalf("the conflict page does not speak of Google: %s", body)
	}
}
