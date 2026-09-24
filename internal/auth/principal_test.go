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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakePrincipals answers from a table keyed by provider|issuer|subject (or
// "login:<login>" for a login-only GitHub identity) and records what it saw.
type fakePrincipals struct {
	answers map[string]string
	err     error
	seen    []Identity
}

func (f *fakePrincipals) ResolvePrincipal(_ context.Context, id Identity) (string, error) {
	f.seen = append(f.seen, id)
	if f.err != nil {
		return "", f.err
	}
	key := id.Provider + "|" + id.Issuer + "|" + id.Subject
	if id.GitHubLoginOnly() {
		key = "login:" + id.Display
	}
	return f.answers[key], nil
}

func runWithPrincipals(t *testing.T, v *GitHubValidator, pr PrincipalResolver, token string) (*httptest.ResponseRecorder, *User) {
	t.Helper()
	var got *User
	h := Middleware(v, nil, nil, nil, WithPrincipalResolver(pr))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, got
}

// The GitHub token path keys the principal on the numeric id, never on the
// login: the login is display only.
func TestGitHubCallerResolvesByNumericID(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	v := NewGitHubValidator(nil)
	v.cache["gho_alice"] = &githubUserInfo{Login: "alice", ID: 4242, CachedAt: time.Now()}
	pr := &fakePrincipals{answers: map[string]string{"github||4242": "prn_ALICE"}}

	rr, u := runWithPrincipals(t, v, pr, "gho_alice")
	if rr.Code != http.StatusOK || u == nil {
		t.Fatalf("status %d, user %v", rr.Code, u)
	}
	if u.PrincipalID() != "prn_ALICE" {
		t.Fatalf("PrincipalID = %q", u.PrincipalID())
	}
	if got := pr.seen[0]; got.Provider != ProviderGitHub || got.Subject != "4242" || got.Display != "alice" || got.Kind != KindHuman {
		t.Fatalf("identity = %+v", got)
	}
}

func TestServiceAndSurfaceCallersAreServicePrincipals(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", tgToken)
	pr := &fakePrincipals{answers: map[string]string{
		"service||mctl-agent":       "prn_AGENT",
		"service||surface:telegram": "prn_TG",
	}}
	for token, want := range map[string]string{"svc-token-123": "prn_AGENT", tgToken: "prn_TG"} {
		_, u := runWithPrincipals(t, NewGitHubValidator(nil), pr, token)
		if u == nil || u.PrincipalID() != want {
			t.Fatalf("%s: principal %q, want %q", token, u.PrincipalID(), want)
		}
	}
	for _, id := range pr.seen {
		if id.Kind != KindService || id.Provider != ProviderService {
			t.Fatalf("service caller resolved as %+v", id)
		}
	}
}

// A disabled principal is refused at authentication already in phase 1.
func TestDisabledPrincipalIsRefused(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	rr, u := runWithPrincipals(t, NewGitHubValidator(nil), &fakePrincipals{err: ErrPrincipalDisabled}, "svc-token-123")
	if rr.Code != http.StatusForbidden || u != nil {
		t.Fatalf("status %d, user %v; want 403 and no handler", rr.Code, u)
	}
}

// Phase 1 degrades: a principal that cannot be resolved (the store is down)
// leaves the request without one instead of failing it.
func TestUnresolvedPrincipalDegrades(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	rr, u := runWithPrincipals(t, NewGitHubValidator(nil), &fakePrincipals{err: errors.New("connection refused")}, "svc-token-123")
	if rr.Code != http.StatusOK || u == nil {
		t.Fatalf("status %d, user %v; want 200", rr.Code, u)
	}
	if u.PrincipalID() != "" {
		t.Fatalf("PrincipalID = %q, want none", u.PrincipalID())
	}
}

// The dev identity only exists without AUTH_REQUIRED, and a resolver that
// refuses it (dev not allowed) refuses the request.
func TestDevIdentityIsResolvedAsDevAndCanBeRefused(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "false")
	pr := &fakePrincipals{answers: map[string]string{"dev||dev-user": "prn_DEV"}}
	rr, u := runWithPrincipals(t, NewGitHubValidator(nil), pr, "")
	if rr.Code != http.StatusOK || u.PrincipalID() != "prn_DEV" {
		t.Fatalf("status %d, principal %q", rr.Code, u.PrincipalID())
	}
	if pr.seen[0].Provider != ProviderDev {
		t.Fatalf("dev caller resolved as %+v", pr.seen[0])
	}
	rr, u = runWithPrincipals(t, NewGitHubValidator(nil), &fakePrincipals{err: ErrIdentityRefused}, "")
	if rr.Code != http.StatusUnauthorized || u != nil {
		t.Fatalf("status %d; want 401", rr.Code)
	}
}

// A Dex caller is keyed on (issuer, sub). Its username, however spelled, is
// display only, so a Dex user named like a GitHub login is not that login.
func TestDexIdentityIsIssuerAndSubject(t *testing.T) {
	u := &User{ID: "alice", dexIssuer: "https://dex.example", dexSubject: "CgVhbGljZRIFbG9jYWw"}
	id, ok := u.Identity()
	if !ok || id.Provider != ProviderDex || id.Issuer != "https://dex.example" || id.Subject != "CgVhbGljZRIFbG9jYWw" {
		t.Fatalf("identity = %+v", id)
	}
	if id.GitHubLoginOnly() {
		t.Fatal("a Dex identity must never be treated as a GitHub login")
	}
	if _, ok := (&User{ID: "alice"}).Identity(); ok {
		t.Fatal("a bare User proves no identity")
	}
}

// A relayed human is resolved by their (GitHub-proven) login, and carries
// the relaying surface's principal as via.
func TestRelayedUserCarriesSurfacePrincipalAsVia(t *testing.T) {
	surface := NewSurfaceUser("telegram")
	surface.principalID = "prn_TG"
	relayed := NewRelayedUser("alice", nil, surface)
	pr := &fakePrincipals{answers: map[string]string{"login:alice": "prn_ALICE"}}
	if err := AttachPrincipal(context.Background(), pr, relayed); err != nil {
		t.Fatal(err)
	}
	if relayed.PrincipalID() != "prn_ALICE" || relayed.ViaPrincipalID() != "prn_TG" {
		t.Fatalf("principal %q via %q", relayed.PrincipalID(), relayed.ViaPrincipalID())
	}
}

func TestNoResolverLeavesUserUnchanged(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	rr, u := runWithPrincipals(t, NewGitHubValidator(nil), nil, "svc-token-123")
	if rr.Code != http.StatusOK || u.PrincipalID() != "" {
		t.Fatalf("status %d principal %q", rr.Code, u.PrincipalID())
	}
}
