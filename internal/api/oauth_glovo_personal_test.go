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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// personalKinds is the principal store: every principal is an active human
// unless listed as an agent.
type personalKinds struct {
	agents map[string]bool
	err    error
}

func (p *personalKinds) CheckPrincipal(context.Context, string) error { return p.err }
func (p *personalKinds) CheckHumanPrincipal(_ context.Context, prn string) error {
	if p.err != nil {
		return p.err
	}
	if p.agents[prn] {
		return auth.ErrIdentityRefused
	}
	return nil
}

// noMembership is a membership reader with no team; the personal path never
// reads it.
type noMembership struct{}

func (noMembership) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return gitops.PrincipalMembership{}, true, nil
}
func (noMembership) MemberRolesForPrincipal(string, string) ([][]string, error) { return nil, nil }

type noAllowlist struct{}

func (noAllowlist) IsAllowlisted(context.Context, string, string) (bool, error) { return false, nil }

type personalEnv struct {
	*glovoConsentEnv
	consent  *memConsentStore
	kinds    *personalKinds
	resolver *scope.Resolver
}

// newPersonalEnv wires GLOVO_CONSENT_ENABLED the way main does: the OAuth
// server and the resolver read the same consent table. teams are the
// principal's eligible teams; the principal has recorded the consent.
func newPersonalEnv(t *testing.T, teams ...string) *personalEnv {
	t.Helper()
	e := newGlovoConsentEnv(t, teams...)
	cs := newMemConsentStore()
	if _, _, err := cs.Record(context.Background(), testPRN, testPRN, 10); err != nil {
		t.Fatal(err)
	}
	src := glovoconsent.ConsentGrants{Store: cs}
	kinds := &personalKinds{agents: map[string]bool{}}
	e.o.GlovoConsent, e.o.TokenPrincipalChecker = src, kinds
	r := &scope.Resolver{Grants: e.store.Grants, Elig: &scope.Eligibility{Membership: noMembership{}, Allowlist: noAllowlist{}},
		Resource: glovoRes, Ready: e.o.GlovoReady, Consent: src}
	return &personalEnv{glovoConsentEnv: e, consent: cs, kinds: kinds, resolver: r}
}

func (e *personalEnv) token(t *testing.T, v url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.handleOAuthToken(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *personalEnv) exchangeCode(t *testing.T, code string) (int, map[string]any) {
	return e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {glovoVerifier},
		"client_id": {"client-1"}, "redirect_uri": {glovoCB}, "resource": {glovoRes}})
}

func (e *personalEnv) refresh(t *testing.T, tok string) (int, map[string]any) {
	return e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {"client-1"}})
}

func (e *personalEnv) resolve(t *testing.T, access string) (scope.Scope, *glovo.Error) {
	t.Helper()
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	return e.resolver.Resolve(context.Background(), u)
}

func resolveCode(ge *glovo.Error) glovo.Code {
	if ge == nil {
		return ""
	}
	return ge.Code
}

// Consent and no team yields a personal grant, end to end; withdrawing the
// consent then refuses the next scope resolve of the tokens already issued
// (original and refreshed) and their refresh, and consenting again does not
// revive them.
func TestGlovoPersonalGrantFlow(t *testing.T) {
	e := newPersonalEnv(t)
	rec, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || token == "" || cookie == nil {
		t.Fatalf("%d %s", rec.Code, body)
	}
	if strings.Contains(body, `name="tenant"`) || !strings.Contains(body, "for you alone") {
		t.Fatalf("the personal page must offer no team: %s", body)
	}
	p := locationParams(t, e.decide(token, "approve", cookie))
	code := p.Get("code")
	if code == "" {
		t.Fatalf("%v", p)
	}
	status, tok := e.exchangeCode(t, code)
	access, _ := tok["access_token"].(string)
	refreshTok, _ := tok["refresh_token"].(string)
	if status != http.StatusOK || access == "" || refreshTok == "" {
		t.Fatalf("%d %v", status, tok)
	}
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.PersonalGrant(); !ok {
		t.Fatal("no personal grant on the issued token")
	}
	if _, _, ok := u.TeamGrant(); ok {
		t.Fatal("the issued token names a team")
	}
	sc, ge := e.resolve(t, access)
	if ge != nil || !sc.Personal || sc.PrincipalID != testPRN || sc.Tenant != "" || sc.RefreshFamilyID == "" {
		t.Fatalf("%+v %v", sc, ge)
	}
	// A refresh while the consent holds yields another personal token.
	status, tok = e.refresh(t, refreshTok)
	child, _ := tok["access_token"].(string)
	childRefresh, _ := tok["refresh_token"].(string)
	if status != http.StatusOK || child == "" || childRefresh == "" {
		t.Fatalf("%d %v", status, tok)
	}
	if sc, ge := e.resolve(t, child); ge != nil || !sc.Personal {
		t.Fatalf("refreshed token: %+v %v", sc, ge)
	}

	// The human withdraws the consent (DELETE /api/v1/glovo/link-consent).
	if _, err := e.consent.Revoke(context.Background(), testPRN, testPRN); err != nil {
		t.Fatal(err)
	}
	for name, tk := range map[string]string{"issued": access, "refreshed": child} {
		if _, ge := e.resolve(t, tk); resolveCode(ge) != glovo.CodeNotAuthorized {
			t.Fatalf("%s token after withdrawal: %v", name, ge)
		}
	}
	if status, tok := e.refresh(t, childRefresh); status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Fatalf("refresh after withdrawal: %d %v", status, tok)
	}
	if e.store.Live() != 0 {
		t.Fatalf("live refresh tokens after withdrawal: %d", e.store.Live())
	}
	// Consenting again records a new consent; the old grant stays dead.
	if _, _, err := e.consent.Record(context.Background(), testPRN, testPRN, 10); err != nil {
		t.Fatal(err)
	}
	if _, ge := e.resolve(t, child); ge == nil {
		t.Fatal("a later consent revived the grant")
	}
}

func TestGlovoPersonalGrantRefusals(t *testing.T) {
	t.Run("no consent and no team", func(t *testing.T) {
		e := newPersonalEnv(t)
		if _, err := e.consent.Revoke(context.Background(), testPRN, testPRN); err != nil {
			t.Fatal(err)
		}
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if p := locationParams(t, rec); p.Get("error") != "access_denied" || token != "" {
			t.Fatalf("%v", p)
		}
	})
	t.Run("consent store error at the page is a retry, never a grant", func(t *testing.T) {
		e := newPersonalEnv(t)
		e.consent.activeErr = errors.New("db down")
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if rec.Code != http.StatusServiceUnavailable || token != "" {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("principal store error at the page is a retry", func(t *testing.T) {
		e := newPersonalEnv(t)
		e.kinds.err = errors.New("db down")
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if rec.Code != http.StatusServiceUnavailable || token != "" {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("agent or service principal", func(t *testing.T) {
		e := newPersonalEnv(t)
		e.kinds.agents[testPRN] = true
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if p := locationParams(t, rec); p.Get("error") != "access_denied" || token != "" {
			t.Fatalf("%v", p)
		}
	})
	decideRefused := func(t *testing.T, mutate func(*personalEnv), wantErr string, tenants ...string) {
		t.Helper()
		e := newPersonalEnv(t)
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		if token == "" {
			t.Fatal("no personal consent page")
		}
		mutate(e)
		p := locationParams(t, e.decide(token, "approve", cookie, tenants...))
		if p.Get("code") != "" || p.Get("error") != wantErr {
			t.Fatalf("%v", p)
		}
	}
	t.Run("consent store error at the decision", func(t *testing.T) {
		decideRefused(t, func(e *personalEnv) { e.consent.activeErr = errors.New("db down") }, "temporarily_unavailable")
	})
	t.Run("consent withdrawn between page and decision", func(t *testing.T) {
		decideRefused(t, func(e *personalEnv) { _, _ = e.consent.Revoke(context.Background(), testPRN, testPRN) }, "access_denied")
	})
	t.Run("team gained between page and decision", func(t *testing.T) {
		decideRefused(t, func(e *personalEnv) { e.teams.teams = []string{"alpha"} }, "access_denied")
	})
	t.Run("team posted on a personal decision", func(t *testing.T) {
		decideRefused(t, func(*personalEnv) {}, "access_denied", "alpha")
	})
	t.Run("consent store error at the exchange", func(t *testing.T) {
		e := newPersonalEnv(t)
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		code := locationParams(t, e.decide(token, "approve", cookie)).Get("code")
		e.consent.activeErr = errors.New("db down")
		if status, tok := e.exchangeCode(t, code); status == http.StatusOK || tok["access_token"] != nil {
			t.Fatalf("%d %v", status, tok)
		}
		if e.store.Live() != 0 {
			t.Fatal("a refresh token was committed")
		}
	})
	t.Run("consent store error at resolve and refresh revokes nothing", func(t *testing.T) {
		e := newPersonalEnv(t)
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		code := locationParams(t, e.decide(token, "approve", cookie)).Get("code")
		_, tok := e.exchangeCode(t, code)
		access, _ := tok["access_token"].(string)
		refreshTok, _ := tok["refresh_token"].(string)
		e.consent.activeErr = errors.New("db down")
		if _, ge := e.resolve(t, access); resolveCode(ge) != glovo.CodeUnavailable {
			t.Fatalf("resolve on a store error: %v", ge)
		}
		if status, _ := e.refresh(t, refreshTok); status == http.StatusOK {
			t.Fatal("refreshed on a store error")
		}
		if e.store.Live() != 1 {
			t.Fatal("an outage revoked the session")
		}
	})
}

// A principal with an eligible team keeps the team path even when it holds
// the consent: the team page, a team grant, a team scope.
func TestGlovoPersonalTeamMemberKeepsTeamPath(t *testing.T) {
	e := newPersonalEnv(t, "alpha")
	rec, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
	if !strings.Contains(rec.Body.String(), `type="radio" name="tenant" value="alpha" required`) {
		t.Fatalf("team member not shown the team page: %s", rec.Body.String())
	}
	// No team posted is refused, never turned into a personal grant.
	if p := locationParams(t, e.decide(token, "approve", cookie)); p.Get("code") != "" || p.Get("error") != "access_denied" {
		t.Fatalf("%v", p)
	}
	_, token, cookie = e.startConsent(t, glovoCompletion("client-1"))
	code := locationParams(t, e.decide(token, "approve", cookie, "alpha")).Get("code")
	_, tok := e.exchangeCode(t, code)
	access, _ := tok["access_token"].(string)
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.PersonalGrant(); ok {
		t.Fatal("team member got a personal grant")
	}
	if _, tenant, ok := u.TeamGrant(); !ok || tenant != "alpha" {
		t.Fatalf("team grant: %q %v", tenant, ok)
	}
}

// The facade acts for a team's installation: an issued personal token
// resolves, and the facade refuses it as scope_unsupported, never reading
// an install for an empty tenant.
func TestGlovoFacadeRefusesPersonalScope(t *testing.T) {
	e := newPersonalEnv(t)
	_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
	code := locationParams(t, e.decide(token, "approve", cookie)).Get("code")
	_, tok := e.exchangeCode(t, code)
	access, _ := tok["access_token"].(string)
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{opts: Options{Glovo: &GlovoRoutes{Resolver: e.resolver}}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/glovo/facade/context", nil)
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	if _, ok := h.glovoFacadeScope(rec, req, "facade_context"); ok {
		t.Fatal("facade accepted a personal scope")
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != string(glovo.CodeScopeUnsupported) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// With GLOVO_CONSENT_ENABLED off nothing wires the consent source, and a
// principal with no team is refused exactly as before, consent or not.
func TestGlovoPersonalGrantFlagOffIsUnchanged(t *testing.T) {
	base := newGlovoConsentEnv(t)
	want, _, _ := base.startConsent(t, glovoCompletion("client-1"))
	e := newPersonalEnv(t)
	e.o.GlovoConsent = nil
	got, token, _ := e.startConsent(t, glovoCompletion("client-1"))
	if p := locationParams(t, want); p.Get("error") != "access_denied" || p.Get("error_description") != "no team is available for this account" {
		t.Fatalf("baseline refusal changed: %v", p)
	}
	if token != "" || got.Code != want.Code || got.Header().Get("Location") != want.Header().Get("Location") || got.Body.String() != want.Body.String() {
		t.Fatalf("flag off differs: %d %q vs %d %q", got.Code, got.Header().Get("Location"), want.Code, want.Header().Get("Location"))
	}
}
