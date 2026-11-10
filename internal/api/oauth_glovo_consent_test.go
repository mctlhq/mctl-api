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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore/refreshstoretest"
)

const (
	glovoRes      = "https://glovo.mctl.ai/mcp"
	glovoVerifier = "verifier-verifier-verifier-verifier-1234"
	glovoCB       = "https://claude.ai/api/mcp/auth_callback"
)

type fakeTeams struct {
	teams []string
	err   error
}

func (f *fakeTeams) Eligible(context.Context, string) ([]string, error) { return f.teams, f.err }
func (f *fakeTeams) Has(_ context.Context, _, tenant string) (bool, error) {
	for _, t := range f.teams {
		if t == tenant {
			return true, f.err
		}
	}
	return false, f.err
}

type glovoConsentEnv struct {
	h     *Handlers
	o     *auth.OAuthServer
	log   *audit.Logger
	teams *fakeTeams
	store *refreshstoretest.Bound
}

func newGlovoConsentEnv(t *testing.T, teams ...string) *glovoConsentEnv {
	t.Helper()
	o := auth.NewOAuthServer("https://api.mctl.ai", "gh", "sec", []byte("secret"), []string{glovoCB}, nil)
	o.GlovoResource, o.PrincipalMode, o.GlovoEnabled = glovoRes, true, true
	g := refreshstoretest.NewTxGrants()
	st := refreshstoretest.NewBound(g)
	ft := &fakeTeams{teams: teams}
	o.RefreshStore, o.TeamGrants, o.TeamEligibility = st, g, ft
	log := audit.NewLogger()
	return &glovoConsentEnv{h: &Handlers{opts: Options{OAuthServer: o, AuditLog: log}}, o: o, log: log, teams: ft, store: st}
}

func glovoCompletion(clientID string) authzCompletion {
	h := sha256.Sum256([]byte(glovoVerifier))
	return authzCompletion{
		Login: "alice", PrincipalID: testPRN, ClientID: clientID, RedirectURI: glovoCB,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(h[:]), ClientState: "st", Upstream: auth.UpstreamZitadel, Resource: glovoRes,
	}
}

// startConsent runs finishAuthorization and returns the response, the token
// and cookie when the consent page was shown.
func (e *glovoConsentEnv) startConsent(t *testing.T, c authzCompletion) (*httptest.ResponseRecorder, string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c)
	body := rec.Body.String()
	var token string
	if i := strings.Index(body, `name="token" value="`); i >= 0 {
		token = body[i+len(`name="token" value="`):]
		token = token[:strings.Index(token, `"`)]
	}
	var cookie *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if strings.HasPrefix(ck.Name, consentCookie) {
			cookie = ck
		}
	}
	return rec, token, cookie
}

func (e *glovoConsentEnv) decide(token, decision string, cookie *http.Cookie, tenants ...string) *httptest.ResponseRecorder {
	v := url.Values{"token": {token}, "decision": {decision}}
	for _, tn := range tenants {
		v.Add("tenant", tn)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.h.handleOAuthConsent(rec, req)
	return rec
}

func locationParams(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound {
		t.Fatalf("not a redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	return u.Query()
}

func TestGlovoConsentListsEligibleUnselected(t *testing.T) {
	e := newGlovoConsentEnv(t, "alpha")
	rec, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || token == "" || cookie == nil {
		t.Fatalf("%d", rec.Code)
	}
	if !strings.Contains(body, `type="radio" name="tenant" value="alpha"`) || strings.Contains(body, "checked") {
		t.Fatalf("one eligible team must be listed and not preselected: %s", body)
	}
	// T1: approve without a team is refused, no code.
	p := locationParams(t, e.decide(token, "approve", cookie))
	if p.Get("error") != "access_denied" || p.Get("code") != "" {
		t.Fatalf("%v", p)
	}
}

func TestGlovoConsentSelection(t *testing.T) {
	for name, tc := range map[string]struct {
		tenants []string
		ok      bool
	}{
		"listed team":   {[]string{"beta"}, true},
		"foreign team":  {[]string{"gamma"}, false},
		"repeated":      {[]string{"alpha", "alpha"}, false},
		"two teams":     {[]string{"alpha", "beta"}, false},
		"empty":         {[]string{""}, false},
		"none":          {nil, false},
		"case variance": {[]string{"Beta"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGlovoConsentEnv(t, "alpha", "beta")
			rec, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
			if strings.Contains(rec.Body.String(), "gamma") {
				t.Fatal("a non-eligible team was listed")
			}
			p := locationParams(t, e.decide(token, "approve", cookie, tc.tenants...))
			if tc.ok {
				if p.Get("code") == "" {
					t.Fatalf("no code: %v", p)
				}
				entries := e.log.List(10)
				last := entries[len(entries)-1]
				if last.Parameters["tenant"] != "beta" || !strings.HasPrefix(last.Parameters["team_grant_id"], "tgr_") {
					t.Fatalf("audit %+v", last.Parameters)
				}
				return
			}
			if p.Get("code") != "" || p.Get("error") != "access_denied" {
				t.Fatalf("%v", p)
			}
		})
	}
}

func TestGlovoConsentRefusals(t *testing.T) {
	t.Run("zero eligible", func(t *testing.T) {
		e := newGlovoConsentEnv(t)
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if p := locationParams(t, rec); p.Get("error") != "access_denied" || token != "" {
			t.Fatalf("%v", p)
		}
	})
	t.Run("login without a principal", func(t *testing.T) {
		e := newGlovoConsentEnv(t, "alpha")
		c := glovoCompletion("client-1")
		c.PrincipalID = ""
		rec, _, _ := e.startConsent(t, c)
		if p := locationParams(t, rec); p.Get("error") != "access_denied" {
			t.Fatalf("%v", p)
		}
	})
	t.Run("eligibility unreadable is a retry page, not an empty list", func(t *testing.T) {
		e := newGlovoConsentEnv(t, "alpha")
		e.teams.err = errors.New("checkout stale")
		rec, token, _ := e.startConsent(t, glovoCompletion("client-1"))
		if rec.Code != http.StatusServiceUnavailable || token != "" {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("eligibility lost between page and decision", func(t *testing.T) {
		e := newGlovoConsentEnv(t, "alpha")
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		e.teams.teams = nil
		if p := locationParams(t, e.decide(token, "approve", cookie, "alpha")); p.Get("code") != "" || p.Get("error") != "access_denied" {
			t.Fatalf("%v", p)
		}
	})
	t.Run("deny", func(t *testing.T) {
		e := newGlovoConsentEnv(t, "alpha")
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		if p := locationParams(t, e.decide(token, "deny", cookie, "alpha")); p.Get("error") != "access_denied" {
			t.Fatalf("%v", p)
		}
	})
	t.Run("switch off", func(t *testing.T) {
		e := newGlovoConsentEnv(t, "alpha")
		_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
		e.o.GlovoEnabled = false
		if p := locationParams(t, e.decide(token, "approve", cookie, "alpha")); p.Get("code") != "" {
			t.Fatalf("code issued with the switch off: %v", p)
		}
	})
}

// T13 and the full flow: one consent token yields at most one grant and one
// code, the code is exchanged once, and the tokens carry the selected team.
func TestGlovoConsentToTokenFlow(t *testing.T) {
	e := newGlovoConsentEnv(t, "alpha", "beta")
	_, token, cookie := e.startConsent(t, glovoCompletion("client-1"))
	p := locationParams(t, e.decide(token, "approve", cookie, "alpha"))
	code := p.Get("code")
	if code == "" {
		t.Fatalf("%v", p)
	}
	if rec := e.decide(token, "approve", cookie, "beta"); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("replayed consent token: %d", rec.Code)
	}
	exchange := func(extra url.Values) *httptest.ResponseRecorder {
		v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {glovoVerifier},
			"client_id": {"client-1"}, "redirect_uri": {glovoCB}, "resource": {glovoRes}}
		for k, vs := range extra {
			v[k] = vs
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.h.handleOAuthToken(rec, req)
		return rec
	}
	// A team parameter at the token endpoint is refused and spends nothing.
	if rec := exchange(url.Values{"tenant": {"beta"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec := exchange(nil)
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	access, _ := tok["access_token"].(string)
	if rec.Code != http.StatusOK || access == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	if _, tenant, ok := u.TeamGrant(); !ok || tenant != "alpha" {
		t.Fatalf("tenant %q", tenant)
	}
	if rec := exchange(nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("code redeemed twice: %d", rec.Code)
	}
	if e.store.Live() != 1 {
		t.Fatalf("live tokens %d", e.store.Live())
	}
}

func TestGlovoAuthorizeRefusesTeamParameters(t *testing.T) {
	e := newGlovoConsentEnv(t, "alpha")
	for _, p := range []string{"tenant", "selected_tenant"} {
		q := url.Values{"client_id": {"client-1"}, "redirect_uri": {glovoCB}, "response_type": {"code"}, "state": {"s"},
			"code_challenge": {"c"}, "code_challenge_method": {"S256"}, "resource": {glovoRes}, p: {"alpha"}}
		rec := httptest.NewRecorder()
		e.h.handleOAuthAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("%s: %d %q", p, rec.Code, loc)
		}
	}
}

// With the switch off the resource is not admitted and nothing else changes.
func TestGlovoSwitchOffRefusesAtAuthorize(t *testing.T) {
	e := newGlovoConsentEnv(t, "alpha")
	e.o.GlovoEnabled = false
	q := url.Values{"client_id": {"client-1"}, "redirect_uri": {glovoCB}, "response_type": {"code"}, "state": {"s"},
		"code_challenge": {"c"}, "code_challenge_method": {"S256"}, "resource": {glovoRes}}
	rec := httptest.NewRecorder()
	e.h.handleOAuthAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("%d %q", rec.Code, loc)
	}
}

func TestGlovoRevokeEndpointSurfacesFailure(t *testing.T) {
	e := newGlovoConsentEnv(t, "alpha")
	e.store.FailRevoke = errors.New("db down")
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {"t"}, "client_id": {"c"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The token is unknown to the fake, so RevokeFamily is not reached: the
	// store must be asked, and its failure must not read as 200.
	_ = e.store.Insert("t", "c", refreshSession(), futureTime())
	rec := httptest.NewRecorder()
	e.h.handleOAuthRevoke(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a failed revoke answered %d", rec.Code)
	}
}

func refreshSession() refreshstore.Session {
	return refreshstore.Session{PrincipalID: testPRN, Resource: glovoRes, TeamGrantID: "tgr_x"}
}

func futureTime() time.Time { return time.Now().Add(time.Hour) }
