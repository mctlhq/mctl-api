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
	"net/http"
	"net/url"
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
	store := &fakeLinkedStore{err: principals.ErrNotFound}
	h := newUpstreamHarness(t, OAuthUpstreamZitadel, store)
	h.idp.extra = claims
	zopts := &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: h.idp.srv.URL, ClientID: testOAuthZClientID,
		ClientSecret: testOAuthZClientSecret, Store: store, CustomersOrgID: testCustomersOrg}
	opts := Options{OAuthServer: h.oauth, OAuthUpstream: OAuthUpstreamZitadel, OAuthZitadel: zopts, Principals: pr}
	if principalMode {
		h.oauth.PrincipalMode = true
		opts.TenantAuthzMode = TenantAuthzPrincipal
	}
	h.router = NewRouter(opts)
	return h
}

// The sign-in asks ZITADEL to name the user's organization: without it a
// customer cannot be told from anyone else.
func TestZitadelSigninAsksForTheResourceOwner(t *testing.T) {
	h := newCustomerHarness(t, true, nil, nil)
	loc, _ := url.Parse(h.get(authorizeQuery("")).Header().Get("Location"))
	if scopes := strings.Fields(loc.Query().Get("scope")); !contains(scopes, auth.ScopeResourceOwner) {
		t.Fatalf("scope = %v, want %s", scopes, auth.ScopeResourceOwner)
	}
}

// A customer signs in as the principal of the GitHub id the hook proved:
// the resolver is asked with that proof, the link store is never read, and
// the token carries the principal and no login or groups.
func TestZitadelSigninOfACustomer(t *testing.T) {
	const prn = "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"
	pr := &recordingResolver{signinResolver: signinResolver{prn: prn}}
	h := newCustomerHarness(t, true, customerIDClaims(), pr)
	before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued"))
	rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("callback = %d %q, want a code: %s", rec.Code, loc, rec.Body.String())
	}
	if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "issued")) - before; n != 1 {
		t.Errorf("issued +%v, want +1", n)
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
	}{
		"organization not named":  {true, without(auth.ClaimResourceOwnerID), signinResolver{prn: "prn_x"}, http.StatusBadGateway, "invalid_token", false},
		"no github id":            {true, without(auth.ClaimCustomerGitHubID), signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_unproven", false},
		"hook refused":            {true, refused, signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_unproven", false},
		"not in principal mode":   {false, customerIDClaims(), signinResolver{prn: "prn_x"}, http.StatusForbidden, "customer_not_enabled", false},
		"subject owned elsewhere": {true, customerIDClaims(), signinResolver{err: fmt.Errorf("%w: %w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict, principals.ErrIdentityOwnedElsewhere)}, http.StatusConflict, "customer_conflict", true},
		"principal disabled":      {true, customerIDClaims(), signinResolver{err: auth.ErrPrincipalDisabled}, http.StatusForbidden, "principal_refused", true},
		"store down":              {true, customerIDClaims(), signinResolver{err: errors.New("db down")}, http.StatusServiceUnavailable, "principal_unavailable", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pr := &recordingResolver{signinResolver: tc.resolver}
			h := newCustomerHarness(t, tc.principalMode, tc.claims, pr)
			before := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, tc.result))
			rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
			if rec.Code != tc.code || rec.Header().Get("Location") != "" {
				t.Fatalf("callback = %d Location=%q, want %d and no code: %s", rec.Code, rec.Header().Get("Location"), tc.code, rec.Body.String())
			}
			if n := testutil.ToFloat64(oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, tc.result)) - before; n != 1 {
				t.Errorf("%s +%v, want +1", tc.result, n)
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
	rec := h.callback(h.toZitadel(h.get(authorizeQuery(""))))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	if len(h.store.calls) != 1 || len(pr.ids) != 1 || pr.ids[0].Customer != nil {
		t.Fatalf("store calls %+v, resolver %+v; want the link path without a customer proof", h.store.calls, pr.ids)
	}
}
