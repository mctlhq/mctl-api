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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const (
	surfaceZitadelPath = "/api/v1/surface-principals/zitadel"
	testWebClient      = "web-client"
	testPortalClient   = "portal-client"
	testWebDevClient   = "web-dev-client"
	testCustomerPID    = "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"
)

// idToken signs an ID token for the fake IdP: issued to client (aud and
// azp), for subject z-sub, with the customer claims unless over replaces
// them (a nil value deletes the claim).
func (f *fakeIdP) idToken(t *testing.T, client string, over map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": f.srv.URL, "sub": "z-sub", "aud": []string{client, "project-id"}, "azp": client,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "preferred_username": "mctl-reviewer@mctl.ai",
	}
	for k, v := range customerIDClaims() {
		claims[k] = v
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := f.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sig.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type surfaceZitadelEnv struct {
	*sidEnv
	idp *fakeIdP
	pr  *recordingResolver
}

func newSurfaceZitadelEnv(t *testing.T, resolver signinResolver, mutate func(*SurfaceZitadelOptions)) *surfaceZitadelEnv {
	t.Helper()
	idp := newFakeIdP(t)
	pr := &recordingResolver{signinResolver: resolver}
	e := newSIDEnvOpts(t, pr, func(o *Options) {
		o.SurfaceZitadel = &SurfaceZitadelOptions{
			ProviderName: "zitadel", Issuer: idp.srv.URL, CustomersOrgID: testCustomersOrg,
			CreateClientID: testWebClient, SigninClientID: testPortalClient,
		}
		if mutate != nil {
			mutate(o.SurfaceZitadel)
		}
	})
	return &surfaceZitadelEnv{sidEnv: e, idp: idp, pr: pr}
}

func (e *surfaceZitadelEnv) resolve(token, purpose string) (int, map[string]any) {
	e.t.Helper()
	return e.do("portal", "POST", surfaceZitadelPath, map[string]any{"idToken": token, "purpose": purpose},
		SurfaceActorHeader, "zitadel:z-sub")
}

// The portal gets the principal of the GitHub id the token proved, for the
// site's token when creating and the portal's own when signing in.
func TestResolveZitadelPrincipal_CustomerByProvenGitHubID(t *testing.T) {
	for purpose, client := range map[string]string{"create": testWebClient, "signin": testPortalClient} {
		t.Run(purpose, func(t *testing.T) {
			e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, nil)
			code, body := e.resolve(e.idp.idToken(t, client, nil), purpose)
			if code != http.StatusOK || body["principalId"] != testCustomerPID || body["githubId"] != "268260640" || body["githubLogin"] != "mctl-reviewer" {
				t.Fatalf("resolve = %d %v", code, body)
			}
			if len(e.pr.ids) != 1 {
				t.Fatalf("resolver asked %+v", e.pr.ids)
			}
			id := e.pr.ids[0]
			if id.Provider != "zitadel" || id.Issuer != e.idp.srv.URL || id.Subject != "z-sub" || id.Kind != auth.KindHuman ||
				id.Customer == nil || id.Customer.GitHubID != "268260640" {
				t.Fatalf("resolver asked %+v, want the ZITADEL identity with its GitHub proof", id)
			}
			found := false
			for _, entry := range e.audit.List(100) {
				if entry.Operation == "principal.resolve_zitadel" && entry.Status == "succeeded" &&
					entry.Parameters["principal_id"] == testCustomerPID && entry.Parameters["github_id"] == "268260640" &&
					entry.Parameters["purpose"] == purpose {
					found = true
				}
			}
			if !found {
				t.Error("no audit entry for the resolution")
			}
		})
	}
}

// A token is accepted only for the purpose of the client it was issued to:
// the site's token cannot sign in, the portal's cannot create, the dev
// client's does neither, and a token whose azp names another client of
// the same project is refused even when the audience matches.
func TestResolveZitadelPrincipal_TokenMustMatchThePurpose(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, nil)
	expired := map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}
	otherIdP := newFakeIdP(t)
	cases := map[string]struct {
		token, purpose string
	}{
		"portal token to create":      {e.idp.idToken(t, testPortalClient, nil), "create"},
		"site token to sign in":       {e.idp.idToken(t, testWebClient, nil), "signin"},
		"dev client to create":        {e.idp.idToken(t, testWebDevClient, nil), "create"},
		"dev client to sign in":       {e.idp.idToken(t, testWebDevClient, nil), "signin"},
		"azp names another client":    {e.idp.idToken(t, testWebClient, map[string]any{"azp": testWebDevClient}), "create"},
		"no azp":                      {e.idp.idToken(t, testWebClient, map[string]any{"azp": nil}), "create"},
		"expired":                     {e.idp.idToken(t, testWebClient, expired), "create"},
		"signed by another key":       {otherIdP.idToken(t, testWebClient, map[string]any{"iss": e.idp.srv.URL}), "create"},
		"not a JWT":                   {"not-a-token", "create"},
		"organization not named":      {e.idp.idToken(t, testWebClient, map[string]any{auth.ClaimResourceOwnerID: nil}), "create"},
		"organization of wrong shape": {e.idp.idToken(t, testWebClient, map[string]any{auth.ClaimResourceOwnerID: 42}), "create"},
	}
	for name, tc := range cases {
		if code, body := e.resolve(tc.token, tc.purpose); code != http.StatusUnauthorized || body["code"] != sidCodeTokenInvalid {
			t.Errorf("%s = %d %v, want 401 %s", name, code, body, sidCodeTokenInvalid)
		}
	}
	if len(e.pr.ids) != 0 {
		t.Fatalf("resolver reached with a refused token: %+v", e.pr.ids)
	}
}

func TestResolveZitadelPrincipal_Refusals(t *testing.T) {
	refusedByHook := map[string]any{auth.ClaimCustomerRefused: "login_reserved"}
	cases := map[string]struct {
		resolver signinResolver
		over     map[string]any
		code     int
		errCode  string
		resolved bool
	}{
		"another organization":   {signinResolver{prn: testCustomerPID}, map[string]any{auth.ClaimResourceOwnerID: "393497610436019469"}, http.StatusBadRequest, sidCodeNotCustomer, false},
		"no github id":           {signinResolver{prn: testCustomerPID}, map[string]any{auth.ClaimCustomerGitHubID: nil}, http.StatusForbidden, sidCodeCustomerUnproven, false},
		"refused by the hook":    {signinResolver{prn: testCustomerPID}, refusedByHook, http.StatusForbidden, sidCodeCustomerUnproven, false},
		"owned elsewhere":        {signinResolver{err: fmt.Errorf("%w: %w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict, principals.ErrIdentityOwnedElsewhere)}, nil, http.StatusConflict, sidCodeCustomerConflict, true},
		"GitHub id revoked":      {signinResolver{err: auth.ErrIdentityRefused}, nil, http.StatusForbidden, sidCodeIdentityRefused, true},
		"principal disabled":     {signinResolver{err: auth.ErrPrincipalDisabled}, nil, http.StatusForbidden, sidCodePrincipalDisabled, true},
		"store down":             {signinResolver{err: errors.New("db down")}, nil, http.StatusServiceUnavailable, sidCodeUnavailable, true},
		"resolver returns no id": {signinResolver{}, nil, http.StatusServiceUnavailable, sidCodeUnavailable, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSurfaceZitadelEnv(t, tc.resolver, nil)
			code, body := e.resolve(e.idp.idToken(t, testWebClient, tc.over), "create")
			if code != tc.code || body["code"] != tc.errCode {
				t.Fatalf("resolve = %d %v, want %d %s", code, body, tc.code, tc.errCode)
			}
			if got := len(e.pr.ids) > 0; got != tc.resolved {
				t.Fatalf("resolver asked = %v, want %v", got, tc.resolved)
			}
		})
	}
}

func TestResolveZitadelPrincipal_BadRequests(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, func(o *SurfaceZitadelOptions) { o.SigninClientID = "" })
	tok := e.idp.idToken(t, testWebClient, nil)
	cases := map[string]struct {
		who, actor string
		body       map[string]any
		code       int
	}{
		"telegram surface":      {"telegram", "4242", map[string]any{"idToken": tok, "purpose": "create"}, http.StatusForbidden},
		"a human":               {"alice", "", map[string]any{"idToken": tok, "purpose": "create"}, http.StatusForbidden},
		"actor of another sub":  {"portal", "zitadel:other", map[string]any{"idToken": tok, "purpose": "create"}, http.StatusBadRequest},
		"no actor":              {"portal", "", map[string]any{"idToken": tok, "purpose": "create"}, http.StatusBadRequest},
		"unknown purpose":       {"portal", "zitadel:z-sub", map[string]any{"idToken": tok, "purpose": "admin"}, http.StatusBadRequest},
		"no token":              {"portal", "zitadel:z-sub", map[string]any{"purpose": "create"}, http.StatusBadRequest},
		"identity field":        {"portal", "zitadel:z-sub", map[string]any{"idToken": tok, "purpose": "create", "principal": "prn_x"}, http.StatusBadRequest},
		"unknown field":         {"portal", "zitadel:z-sub", map[string]any{"idToken": tok, "purpose": "create", "extra": 1}, http.StatusBadRequest},
		"signin not configured": {"portal", "zitadel:z-sub", map[string]any{"idToken": tok, "purpose": "signin"}, http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		var headers []string
		if tc.actor != "" {
			headers = []string{SurfaceActorHeader, tc.actor}
		}
		if code, body := e.do(tc.who, "POST", surfaceZitadelPath, tc.body, headers...); code != tc.code {
			t.Errorf("%s = %d %v, want %d", name, code, body, tc.code)
		}
	}
	if len(e.pr.ids) != 0 {
		t.Fatalf("resolver reached on a bad request: %+v", e.pr.ids)
	}
}

// Not configured: 503, never a guess.
func TestResolveZitadelPrincipal_NotConfigured(t *testing.T) {
	idp := newFakeIdP(t)
	e := newSIDEnvWith(t, signinResolver{prn: testCustomerPID})
	code, body := e.do("portal", "POST", surfaceZitadelPath, map[string]any{"idToken": idp.idToken(t, testWebClient, nil), "purpose": "create"},
		SurfaceActorHeader, "zitadel:z-sub")
	if code != http.StatusServiceUnavailable || body["code"] != sidCodeUnavailable {
		t.Fatalf("resolve = %d %v", code, body)
	}
}

// A whole ID token fits: one padded well past what ZITADEL issues today is
// accepted, and only a body past the route's own limit is refused.
func TestResolveZitadelPrincipal_BodyLimitFitsAnIDToken(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, nil)
	big := e.idp.idToken(t, testWebClient, map[string]any{"padding": strings.Repeat("x", 8<<10)})
	if code, body := e.resolve(big, "create"); code != http.StatusOK {
		t.Fatalf("%d-byte token = %d %v, want 200", len(big), code, body)
	}
	huge := e.idp.idToken(t, testWebClient, map[string]any{"padding": strings.Repeat("x", 16<<10)})
	if code, body := e.resolve(huge, "create"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d-byte token = %d %v, want 413", len(huge), code, body)
	}
}

// Every refusal after the token verified leaves an audit entry naming its
// reason, the misconfigurations included.
func TestResolveZitadelPrincipal_RefusalsAreAudited(t *testing.T) {
	for reason, over := range map[string]map[string]any{
		sidCodeTokenInvalid:     {auth.ClaimResourceOwnerID: nil},
		sidCodeNotCustomer:      {auth.ClaimResourceOwnerID: "393497610436019469"},
		sidCodeCustomerUnproven: {auth.ClaimCustomerGitHubID: nil},
	} {
		e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, nil)
		if code, _ := e.resolve(e.idp.idToken(t, testWebClient, over), "create"); code == http.StatusOK {
			t.Fatalf("%s: resolved", reason)
		}
		found := false
		for _, entry := range e.audit.List(100) {
			if entry.Operation == "principal.resolve_zitadel_refused" && entry.Parameters["reason"] == reason &&
				entry.Parameters["zitadel_subject"] == "z-sub" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no audit entry", reason)
		}
	}
}

// googleTokenClaims turns idToken's GitHub customer into a Google one.
func googleTokenClaims() map[string]any {
	over := googleCustomerClaims()
	over[auth.ClaimCustomerGitHubID], over[auth.ClaimCustomerGitHubLogin] = nil, nil
	over["preferred_username"] = "google." + testGoogleSub + "@mctl.ai"
	return over
}

// With Google accepted, the portal gets the principal of the Google subject
// the token proved, for both purposes, and the answer names the provider
// instead of carrying an empty GitHub id.
func TestResolveZitadelPrincipal_CustomerByProvenGoogleSubject(t *testing.T) {
	for purpose, client := range map[string]string{"create": testWebClient, "signin": testPortalClient} {
		t.Run(purpose, func(t *testing.T) {
			e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, func(o *SurfaceZitadelOptions) { o.CustomersGoogle = true })
			code, body := e.resolve(e.idp.idToken(t, client, googleTokenClaims()), purpose)
			if code != http.StatusOK || body["principalId"] != testCustomerPID || body["provider"] != "google" || body["googleSub"] != testGoogleSub {
				t.Fatalf("resolve = %d %v", code, body)
			}
			if _, ok := body["githubId"]; ok {
				t.Fatalf("a Google customer answered with a githubId: %v", body)
			}
			if _, ok := body["githubLogin"]; ok {
				t.Fatalf("a Google customer answered with a githubLogin: %v", body)
			}
			if len(e.pr.ids) != 1 {
				t.Fatalf("resolver asked %+v", e.pr.ids)
			}
			id := e.pr.ids[0]
			if id.Provider != "zitadel" || id.Subject != "z-sub" || id.Customer == nil ||
				id.Customer.Provider != auth.ProviderGoogle || id.Customer.GoogleSub != testGoogleSub || id.Customer.GitHubID != "" {
				t.Fatalf("resolver asked %+v, want the ZITADEL identity with its Google proof", id)
			}
			found := false
			for _, entry := range e.audit.List(100) {
				if entry.Operation == "principal.resolve_zitadel" && entry.Status == "succeeded" &&
					entry.Parameters["customer_provider"] == "google" && entry.Parameters["google_sub"] == testGoogleSub &&
					entry.Parameters["github_id"] == "" {
					found = true
				}
			}
			if !found {
				t.Error("no audit entry naming the Google subject")
			}
		})
	}
}

// A GitHub customer's answer names its provider too, and keeps the GitHub
// fields existing clients read.
func TestResolveZitadelPrincipal_GitHubAnswerNamesItsProvider(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, func(o *SurfaceZitadelOptions) { o.CustomersGoogle = true })
	code, body := e.resolve(e.idp.idToken(t, testWebClient, nil), "create")
	if code != http.StatusOK || body["provider"] != "github" || body["githubId"] != "268260640" || body["githubLogin"] != "mctl-reviewer" {
		t.Fatalf("resolve = %d %v", code, body)
	}
	if _, ok := body["googleSub"]; ok {
		t.Fatalf("a GitHub customer answered with a googleSub: %v", body)
	}
}

// Dark by default: without CustomersGoogle a Google customer is unproven and
// never reaches the resolver.
func TestResolveZitadelPrincipal_GoogleIsDarkByDefault(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, nil)
	code, body := e.resolve(e.idp.idToken(t, testWebClient, googleTokenClaims()), "create")
	if code != http.StatusForbidden || body["code"] != sidCodeCustomerUnproven {
		t.Fatalf("resolve = %d %v, want 403 %s", code, body, sidCodeCustomerUnproven)
	}
	if msg, _ := body["error"].(string); strings.Contains(msg, "Google") {
		t.Errorf("dark refusal names Google: %q", msg)
	}
	if len(e.pr.ids) != 0 {
		t.Fatalf("resolver reached: %+v", e.pr.ids)
	}
}

// A token proving both providers, or naming one and proving the other, is
// unproven with Google on.
func TestResolveZitadelPrincipal_MixedGoogleTokensAreRefused(t *testing.T) {
	e := newSurfaceZitadelEnv(t, signinResolver{prn: testCustomerPID}, func(o *SurfaceZitadelOptions) { o.CustomersGoogle = true })
	both := googleCustomerClaims()
	github := map[string]any{auth.ClaimCustomerGoogleSub: testGoogleSub}
	for name, over := range map[string]map[string]any{"google idp with GitHub claims": both, "github idp with a Google sub": github} {
		code, body := e.resolve(e.idp.idToken(t, testWebClient, over), "create")
		if msg, _ := body["error"].(string); code != http.StatusForbidden || body["code"] != sidCodeCustomerUnproven || !strings.Contains(msg, "GitHub or Google") {
			t.Errorf("%s = %d %v, want 403 %s naming both providers", name, code, body, sidCodeCustomerUnproven)
		}
	}
	if len(e.pr.ids) != 0 {
		t.Fatalf("resolver reached: %+v", e.pr.ids)
	}
}

// The conflict page names the key the principal is held by.
func TestResolveZitadelPrincipal_GoogleConflictNamesTheSubject(t *testing.T) {
	conflict := signinResolver{err: fmt.Errorf("%w: %w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict, principals.ErrIdentityOwnedElsewhere)}
	e := newSurfaceZitadelEnv(t, conflict, func(o *SurfaceZitadelOptions) { o.CustomersGoogle = true })
	code, body := e.resolve(e.idp.idToken(t, testWebClient, googleTokenClaims()), "create")
	if msg, _ := body["error"].(string); code != http.StatusConflict || body["code"] != sidCodeCustomerConflict || !strings.Contains(msg, "Google subject") {
		t.Fatalf("resolve = %d %v", code, body)
	}
}
