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

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// tpChecker is a principal resolver that can also check a token's
// principal, the way principals.Resolver does.
type tpChecker struct {
	fakePrincipals
	status  map[string]error // principal -> CheckPrincipal answer; absent = active
	checked []string
}

func (c *tpChecker) CheckPrincipal(_ context.Context, id string) error {
	c.checked = append(c.checked, id)
	return c.status[id]
}

func tpServer(principalMode bool) *OAuthServer {
	return &OAuthServer{BaseURL: "https://api.example", JWTSecret: []byte("test-secret-key-material"), PrincipalMode: principalMode}
}

// tpRun authenticates token through the middleware, by the legacy chain or
// the federation registry, with principal mode on when pa is set.
func tpRun(t *testing.T, registry bool, o *OAuthServer, pr PrincipalResolver, pa *PrincipalAuthz, token string) (int, *User) {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "true")
	if registry {
		t.Setenv("MCTL_FEDERATION_DISABLED", "")
	} else {
		t.Setenv("MCTL_FEDERATION_DISABLED", "true")
	}
	var got *User
	h := Middleware(NewGitHubValidator([]string{"alice"}), nil, nil, o,
		WithPrincipalResolver(pr), WithPrincipalAuthz(pa))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = UserFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, got
}

func mustToken(t *testing.T, o *OAuthServer, login, pid string, groups ...string) string {
	t.Helper()
	tok, err := o.IssueJWT(login, pid, groups)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestIssueJWT_PrincipalClaim(t *testing.T) {
	o := tpServer(false)
	if _, err := o.IssueJWT("alice", "prn_bad", nil); err == nil {
		t.Fatal("a malformed pid was minted")
	}
	if _, err := o.IssueJWT("", "", nil); err == nil {
		t.Fatal("a token with neither login nor principal was minted")
	}
	// A malformed pid is refused at sign-in, before the code is spent.
	if _, err := o.IssueCode(context.Background(), "alice", "prn_bad", "client", "https://client/cb", "challenge", nil); err == nil {
		t.Fatal("a code was issued for a malformed pid")
	}
	payload, err := verifyJWT(mustToken(t, o, "", pzZitadel), o.JWTSecret, o.BaseURL)
	if err != nil || payload.Subject != pzZitadel || payload.PID != pzZitadel {
		t.Fatalf("principal-only token: %+v, %v", payload, err)
	}
	payload, err = verifyJWT(mustToken(t, o, "alice", pzMember), o.JWTSecret, o.BaseURL)
	if err != nil || payload.Subject != "alice" || payload.PID != pzMember {
		t.Fatalf("linked token: %+v, %v", payload, err)
	}
}

// B3: in principal mode the pid claim is the caller's principal. It is
// checked, not re-derived from the login, and a token without one is
// refused. Both authentication paths agree.
func TestLocalToken_PrincipalMode(t *testing.T) {
	o := tpServer(true)
	pa := &PrincipalAuthz{
		Members: pzMembers{tenants: map[string][]string{pzMember: {"labs"}, pzZitadel: {"commerce-proof"}}},
		Admins:  map[string]bool{pzAdmin: true},
	}
	for _, registry := range []bool{false, true} {
		name := fmt.Sprintf("registry=%v", registry)
		pr := &tpChecker{
			fakePrincipals: fakePrincipals{answers: map[string]string{"login:alice": pzOther}},
			status: map[string]error{
				pzOther: ErrPrincipalDisabled,
				pzAdmin: fmt.Errorf("%w: gone", ErrIdentityRefused),
			},
		}

		code, u := tpRun(t, registry, o, pr, pa, mustToken(t, o, "alice", pzMember, "admins", "mctl"))
		if code != http.StatusOK || u.PrincipalID() != pzMember || !slices.Equal(u.Groups, []string{"labs"}) || u.IsAdmin() {
			t.Fatalf("%s: linked token: %d %+v", name, code, u)
		}
		if login, ok := u.GitHubLogin(); !ok || login != "alice" {
			t.Fatalf("%s: linked token lost its login", name)
		}
		if len(pr.seen) != 0 {
			t.Fatalf("%s: the principal was re-derived from the login: %v", name, pr.seen)
		}

		code, u = tpRun(t, registry, o, pr, pa, mustToken(t, o, "", pzZitadel))
		if code != http.StatusOK || u.PrincipalID() != pzZitadel || !u.HasTenantAccess("commerce-proof") {
			t.Fatalf("%s: principal-only token: %d %+v", name, code, u)
		}
		if _, ok := u.GitHubLogin(); ok {
			t.Fatalf("%s: a principal-only token claims a GitHub login", name)
		}
		if id, _ := u.Identity(); id.Provider != ProviderPrincipal || id.Kind != KindHuman {
			t.Fatalf("%s: identity %+v", name, id)
		}

		if code, _ := tpRun(t, registry, o, pr, pa, mustToken(t, o, "alice", "")); code != http.StatusUnauthorized {
			t.Fatalf("%s: token without pid: %d, want 401", name, code)
		}
		if code, _ := tpRun(t, registry, o, pr, pa, mustToken(t, o, "alice", pzOther)); code != http.StatusForbidden {
			t.Fatalf("%s: disabled principal: %d, want 403", name, code)
		}
		if code, _ := tpRun(t, registry, o, pr, pa, mustToken(t, o, "alice", pzAdmin)); code != http.StatusUnauthorized {
			t.Fatalf("%s: principal that does not exist: %d, want 401", name, code)
		}
		pr.status[pzMember] = errors.New("store down")
		if code, _ := tpRun(t, registry, o, pr, pa, mustToken(t, o, "alice", pzMember)); code != http.StatusServiceUnavailable {
			t.Fatalf("%s: unchecked principal: %d, want 503", name, code)
		}
		// No checker at all: the claim is never taken unchecked.
		if code, _ := tpRun(t, registry, o, &fakePrincipals{}, pa, mustToken(t, o, "", pzZitadel)); code != http.StatusServiceUnavailable {
			t.Fatalf("%s: no checker: %d, want 503", name, code)
		}
		if code, _ := tpRun(t, registry, o, nil, pa, mustToken(t, o, "", pzZitadel)); code != http.StatusServiceUnavailable {
			t.Fatalf("%s: no resolver: %d, want 503", name, code)
		}
	}
}

func TestValidateJWT_PrincipalModeRefusals(t *testing.T) {
	o := tpServer(true)
	forged, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: pzZitadel, PID: pzMember, ExpiresAt: 1 << 40}, o.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateJWT(forged); err == nil {
		t.Fatal("a token whose subject and pid name different principals was accepted")
	}
	if _, err := o.ValidateJWT(mustToken(t, o, "alice", "")); !errors.Is(err, ErrTokenWithoutPrincipal) {
		t.Fatalf("token without pid: %v", err)
	}
}

// Outside principal mode the claim decides nothing: groups come from the
// login as before, a principal-only token is refused, and a pid that
// disagrees with the resolved principal is counted.
func TestLocalToken_OutsidePrincipalMode(t *testing.T) {
	o := tpServer(false)
	for _, registry := range []bool{false, true} {
		name := fmt.Sprintf("registry=%v", registry)
		pr := &tpChecker{fakePrincipals: fakePrincipals{answers: map[string]string{"login:alice": pzMember}}}
		before := testutil.ToFloat64(tokenPrincipalMismatch)

		code, u := tpRun(t, registry, o, pr, nil, mustToken(t, o, "alice", pzMember, "labs"))
		if code != http.StatusOK || u.PrincipalID() != pzMember || len(pr.checked) != 0 || len(pr.seen) != 1 {
			t.Fatalf("%s: %d %+v checked=%v seen=%v", name, code, u, pr.checked, pr.seen)
		}
		if got := testutil.ToFloat64(tokenPrincipalMismatch); got != before {
			t.Fatalf("%s: agreeing pid counted as a mismatch", name)
		}
		if code, u := tpRun(t, registry, o, pr, nil, mustToken(t, o, "alice", pzOther)); code != http.StatusOK || u.PrincipalID() != pzMember {
			t.Fatalf("%s: mismatching pid changed the principal: %d %+v", name, code, u)
		}
		if got := testutil.ToFloat64(tokenPrincipalMismatch); got != before+1 {
			t.Fatalf("%s: mismatch counter moved %v, want 1", name, got-before)
		}
		if code, _ := tpRun(t, registry, o, pr, nil, mustToken(t, o, "", pzZitadel)); code != http.StatusUnauthorized {
			t.Fatalf("%s: principal-only token outside principal mode: %d, want 401", name, code)
		}
	}
}

// No configured provider may mint into the principal namespace: its
// subject is taken as the principal itself.
func TestRegistryRefusesThePrincipalNamespace(t *testing.T) {
	p := &fakeProvider{name: ProviderPrincipal, issuer: "https://issuer-p", claims: matchIssuer("https://issuer-p")}
	if _, err := NewRegistry(nil, []Provider{p}, nil); err == nil {
		t.Fatal("a provider named principal was accepted")
	}
}

// Only the local-OAuth provider may return the principal namespace; any
// other provider doing so could name any principal it liked.
func TestOtherProviderCannotReturnThePrincipalNamespace(t *testing.T) {
	for name, v := range map[string]*Verified{
		"principal namespace": {Identity: Identity{Provider: ProviderPrincipal, Subject: "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ", Kind: KindHuman}},
		// Nor may it carry the token-principal claim in its own namespace.
		"token principal claim": {Identity: Identity{Provider: "acme", Subject: "s-1", Kind: KindHuman},
			Claims: Claims{TokenPrincipal: "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"}},
	} {
		t.Run(name, func(t *testing.T) {
			bad := &fakeProvider{
				name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer"),
				verify: func(context.Context, string) (*Verified, error) { return v, nil },
			}
			r, err := NewRegistry(nil, []Provider{bad}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Verify(context.Background(), fakeJWT("https://issuer")); !errors.Is(err, ErrProviderContractViolation) {
				t.Fatalf("expected ErrProviderContractViolation, got %v", err)
			}
		})
	}
}

// A refresh mints for the principal the session was signed in for, on both
// refresh paths, and in principal mode refuses a session that recorded
// none instead of re-deriving it from the login.
func TestRefresh_CarriesThePrincipal(t *testing.T) {
	for _, store := range []bool{false, true} {
		for _, principalMode := range []bool{false, true} {
			t.Run(fmt.Sprintf("store=%v/principalMode=%v", store, principalMode), func(t *testing.T) {
				o := tpServer(principalMode)
				if store {
					o.RefreshStore = newFakeRefreshStore()
				}
				for _, tc := range []struct{ login, pid string }{{"alice", pzMember}, {"", pzZitadel}} {
					rt, err := o.IssueRefreshToken(tc.login, tc.pid, []string{"acme"}, "c")
					if err != nil {
						t.Fatal(err)
					}
					// Twice: the successor must carry the principal too.
					for hop := range 2 {
						var at string
						at, rt, err = o.RefreshAccessToken(rt, "c")
						if err != nil {
							t.Fatalf("%q hop %d: %v", tc.login, hop, err)
						}
						payload, err := verifyJWT(at, o.JWTSecret, o.BaseURL)
						if err != nil || payload.PID != tc.pid {
							t.Fatalf("%q hop %d: pid %q, %v; want %q", tc.login, hop, payload.PID, err, tc.pid)
						}
						if principalMode && len(payload.Groups) != 0 {
							t.Fatalf("%q hop %d: groups %q minted in principal mode", tc.login, hop, payload.Groups)
						}
					}
				}

				rt, err := o.IssueRefreshToken("alice", "", []string{"acme"}, "c")
				if err != nil {
					t.Fatal(err)
				}
				_, _, err = o.RefreshAccessToken(rt, "c")
				if principalMode != (err != nil) {
					t.Fatalf("pid-less session: refresh error %v, want one only in principal mode", err)
				}
			})
		}
	}
}
