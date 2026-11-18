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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// The real path of the Glovo consent gate with a ZITADEL machine user: a
// signed JWT-profile access token (iss, sub = machine user id, aud = project
// id, no resourceowner claim) is verified by the real go-oidc verifier against
// a discovery document and JWKS served over HTTP, resolved by the real
// registry built from an MCTL_OIDC_PROVIDERS entry configured like the live
// zitadel entry (customers_org_id + service_subjects), turned into a User by
// the real auth.Middleware, and then handled by the real consent gate and
// read handler. Nothing here builds a service identity by hand.

const (
	fedCustomersOrg = "395272528420931285"
	fedOtherOrg     = "395272528420931999"
	fedClientID     = "290000000000000001@mctl"
	fedProjectID    = "290000000000000000"
	fedMachine      = "290000000000000077"
	fedHuman        = "290000000000000042"
)

type fedIssuer struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFedIssuer(t *testing.T) *fedIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fedIssuer{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/keys",
			"authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// sign issues a token the way ZITADEL signs a machine-user JWT-profile access
// token. iss overrides the issuer claim; key overrides the signing key.
func (f *fedIssuer) sign(iss, sub string, aud []string, extra map[string]any, key *rsa.PrivateKey) string {
	f.t.Helper()
	if key == nil {
		key = f.key
	}
	if iss == "" {
		iss = f.srv.URL
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		f.t.Fatal(err)
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": aud,
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// fedEntryJSON is the zitadel entry as zitadel-iac renders it for the live
// configuration: customers_org_id plus service_subjects, enforcing audiences.
// grant_groups is switched on here, which the live entry does not do: it is
// the worst case for the "no groups" requirement, so the test fails if a
// service subject ever receives the groups a human of this entry would.
func fedEntryJSON(issuer string) string {
	return `[{"name":"zitadel","issuer":"` + issuer + `","audiences":["` + fedClientID + `"],` +
		`"customers_org_id":"` + fedCustomersOrg + `","grant_groups":true,"service_subjects":{"` + fedMachine + `":"` + fedProjectID + `"}}]`
}

type fedEnv struct {
	iss    *fedIssuer
	router http.Handler
	got    *auth.User // the user the middleware resolved for the last request
}

func newFedEnv(t *testing.T) *fedEnv {
	t.Helper()
	iss := newFedIssuer(t)
	reg, err := auth.BuildFederationRegistry(context.Background(),
		auth.FederationProvidersConfig{OIDCProvidersRaw: fedEntryJSON(iss.srv.URL)}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildFederationRegistry: %v", err)
	}
	e := &fedEnv{iss: iss}
	authMW := auth.Middleware(nil, nil, nil, nil, auth.WithFederationRegistry(reg))
	capture := func(next http.Handler) http.Handler {
		return authMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.got = auth.UserFromContext(r.Context())
			next.ServeHTTP(w, r)
		}))
	}
	g := mountedConsent(newMemConsentStore(), consentCap)
	g.ServiceProvider, g.ServiceSubject = "zitadel", fedMachine
	e.router = NewRouter(Options{AuthMiddleware: capture, GlovoConsent: g,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})
	return e
}

func (e *fedEnv) get(path, token string) int {
	e.got = nil
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec.Code
}

func customerExtra() map[string]any {
	return map[string]any{
		auth.ClaimResourceOwnerID: fedCustomersOrg, auth.ClaimCustomerOrg: "customers", auth.ClaimCustomerIdP: "github",
		auth.ClaimCustomerGitHubID: "268260640", auth.ClaimCustomerGitHubLogin: "someone",
	}
}

// Allowed: the configured machine user, JWT-profile shaped (no resourceowner),
// reads consent through the gate, as kind service with no customer, no groups
// and no tenant or admin access.
// Mutations: restore the blanket refusal (the registry does not build), drop
// the resourceowner skip for the service subject (token refused: 401).
func TestGlovoConsentGateRealPathAllowsTheMachineUser(t *testing.T) {
	e := newFedEnv(t)
	tok := e.iss.sign("", fedMachine, []string{fedProjectID}, nil, nil)
	if code := e.get(consentReadURL(consentPIDA), tok); code != http.StatusOK {
		t.Fatalf("machine user JWT-profile token = %d, want 200", code)
	}
	u := e.got
	id, ok := u.Identity()
	if u == nil || !ok || id.Kind != auth.KindService || id.Provider != "zitadel" || id.Subject != fedMachine || id.Customer != nil {
		t.Fatalf("resolved identity = %+v (ok=%v), want zitadel service, no customer", id, ok)
	}
	if len(u.Groups) != 0 || u.IsAdmin() || u.HasTenantAccess("any-tenant") || u.IsService() || u.IsAgent() || u.IsCI() {
		t.Fatalf("service subject carries groups/admin/tenant access: %+v", u)
	}
	// Even carrying a customers-org resourceowner and customer claims: still
	// service, never a customer (mutation: grant a customers identity).
	tok = e.iss.sign("", fedMachine, []string{fedProjectID}, customerExtra(), nil)
	if code := e.get(consentReadURL(consentPIDA), tok); code != http.StatusOK {
		t.Fatalf("machine user with a customers resourceowner = %d, want 200", code)
	}
	if id, _ := e.got.Identity(); id.Kind != auth.KindService || id.Customer != nil {
		t.Fatalf("identity = %+v, want service and no customer", id)
	}
	// Groups claims (the project roles claim included) never reach it.
	tok = e.iss.sign("", fedMachine, []string{fedProjectID}, map[string]any{"groups": []string{"some-tenant", "admins"},
		"urn:zitadel:iam:org:project:roles": map[string]any{"admins": map[string]string{"1": "x"}}}, nil)
	if code := e.get(consentReadURL(consentPIDA), tok); code != http.StatusOK || len(e.got.Groups) != 0 || e.got.IsAdmin() {
		t.Fatalf("with groups claims = %d, groups %v", code, e.got.Groups)
	}
	// The reader reaches only its prefix.
	for _, p := range []string{"/api/v1/glovo/link-consent", "/api/v1/whoami", "/mcp"} {
		if code := e.get(p, tok); code != http.StatusUnauthorized {
			t.Errorf("service on %s = %d, want 401", p, code)
		}
	}
}

// Refused: every escalation attempt, through the same real path.
// Mutations: drop the pinned-audience check (rows 1-4), grant customers
// identity or groups (rows reaching the gate as non-service), drop the
// resourceowner check for ordinary users (row "user without resourceowner").
func TestGlovoConsentGateRealPathRefusesEscalation(t *testing.T) {
	e := newFedEnv(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token string
	}{
		{"human with the service subject id and the entry audience, customers claims",
			e.iss.sign("", fedMachine, []string{fedClientID}, customerExtra(), nil)},
		{"service subject with the entry's normal audience instead of the pinned one",
			e.iss.sign("", fedMachine, []string{fedClientID}, nil, nil)},
		{"service subject with the entry audience and a customers resourceowner",
			e.iss.sign("", fedMachine, []string{fedClientID}, map[string]any{auth.ClaimResourceOwnerID: fedCustomersOrg}, nil)},
		{"service subject with a foreign audience",
			e.iss.sign("", fedMachine, []string{"other"}, nil, nil)},
		{"service subject with no audience",
			e.iss.sign("", fedMachine, nil, nil, nil)},
		{"service subject, wrong issuer",
			e.iss.sign("https://other.example.test", fedMachine, []string{fedProjectID}, nil, nil)},
		{"service subject signed by another key",
			e.iss.sign("", fedMachine, []string{fedProjectID}, nil, otherKey)},
		{"unlisted machine user on the pinned audience",
			e.iss.sign("", "290000000000000078", []string{fedProjectID}, nil, nil)},
		{"padded service subject",
			e.iss.sign("", " "+fedMachine, []string{fedProjectID}, nil, nil)},
		{"service subject with a suffix",
			e.iss.sign("", fedMachine+"1", []string{fedProjectID}, nil, nil)},
		{"empty subject on the pinned audience",
			e.iss.sign("", "", []string{fedProjectID}, nil, nil)},
		{"sub and aud swapped",
			e.iss.sign("", fedProjectID, []string{fedMachine}, nil, nil)},
		{"user without a resourceowner claim",
			e.iss.sign("", fedHuman, []string{fedClientID}, nil, nil)},
	}
	for _, tc := range cases {
		if code := e.get(consentReadURL(consentPIDA), tc.token); code != http.StatusUnauthorized {
			t.Errorf("%s: = %d, want 401", tc.name, code)
		}
	}
	// Authenticated but not the reader: a customer and an operator of another
	// organization pass authentication as humans and the gate refuses them.
	for name, extra := range map[string]map[string]any{
		"customer":            customerExtra(),
		"user of another org": {auth.ClaimResourceOwnerID: fedOtherOrg},
	} {
		tok := e.iss.sign("", fedHuman, []string{fedClientID}, extra, nil)
		code := e.get(consentReadURL(consentPIDA), tok)
		if code != http.StatusUnauthorized || e.got == nil {
			t.Errorf("%s: = %d (user resolved: %v), want authenticated human refused by the gate", name, code, e.got != nil)
		}
		if e.got != nil {
			if id, _ := e.got.Identity(); id.Kind != auth.KindHuman {
				t.Errorf("%s: kind %q, want human", name, id.Kind)
			}
		}
	}
	// Control after the whole table: the machine user still reads.
	if code := e.get(consentReadURL(consentPIDA), e.iss.sign("", fedMachine, []string{fedProjectID}, nil, nil)); code != http.StatusOK {
		t.Fatalf("control read = %d", code)
	}
}

// A customer of the entry still resolves as a customer human through the same
// path (requirement 2: the customers enforcement is unchanged).
func TestRealPathCustomerEnforcementUnchanged(t *testing.T) {
	e := newFedEnv(t)
	tok := e.iss.sign("", fedHuman, []string{fedClientID}, customerExtra(), nil)
	if code := e.get("/api/v1/whoami", tok); code == http.StatusUnauthorized && e.got == nil {
		t.Fatalf("customer token refused at authentication")
	}
	if e.got == nil {
		t.Fatal("no user resolved for the customer token")
	}
	id, _ := e.got.Identity()
	if id.Kind != auth.KindHuman || id.Customer == nil || id.Customer.GitHubID != "268260640" {
		t.Fatalf("customer identity = %+v, want human with the proven GitHub id", id)
	}
	// And an ordinary user without the claim never authenticates.
	tok = e.iss.sign("", fedHuman, []string{fedClientID}, nil, nil)
	e.get("/api/v1/whoami", tok)
	if e.got != nil {
		t.Fatalf("user without resourceowner authenticated: %+v", e.got)
	}
}
