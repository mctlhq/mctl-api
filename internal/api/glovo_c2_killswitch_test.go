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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoc2control"
)

type fakeKillSetter struct {
	calls  []bool
	err    error
	ignore bool // returns a state different from the request
}

func (f *fakeKillSetter) SetKilled(_ context.Context, killed bool) (glovoc2control.State, error) {
	f.calls = append(f.calls, killed)
	if f.err != nil {
		return glovoc2control.State{}, f.err
	}
	if f.ignore {
		return glovoc2control.State{Killed: !killed}, nil
	}
	return glovoc2control.State{Killed: killed}, nil
}

func killReq(u *auth.User, body string) (*Handlers, *http.Request) {
	h := &Handlers{}
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r = r.WithContext(auth.WithUser(r.Context(), u))
	return h, r
}

func TestGlovoC2KillSwitchRefusesNonAdmin(t *testing.T) {
	admin := signupAdminUser(t)
	federatedService := auth.NewFederatedUser("oidc", "https://issuer.example", "service-subject", "service", auth.KindService)
	federatedService.Groups = []string{"admins"}
	if err := auth.AttachPrincipal(context.Background(), signupAdminResolver{}, federatedService); err != nil {
		t.Fatal(err)
	}
	users := []*auth.User{nil, federatedService, auth.NewServiceUser(), auth.NewSurfaceUser("portal"), auth.NewGitHubUser("customer", nil), auth.NewAgentUser("implementer", auth.AgentRun{}), auth.NewRelayedPrincipalUser("root", admin.PrincipalID(), auth.NewSurfaceUser("portal"))}
	for _, u := range users {
		f := &fakeKillSetter{}
		h, r := killReq(u, `{"killed":true}`)
		h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: f}
		w := httptest.NewRecorder()
		h.SetGlovoC2KillSwitch(w, r)
		if w.Code != 403 {
			t.Fatalf("user %+v status %d", u, w.Code)
		}
		if len(f.calls) != 0 {
			t.Fatalf("non-admin reached upstream: %v", f.calls)
		}
	}
}

func TestGlovoC2KillSwitchRefusesMalformedBody(t *testing.T) {
	for _, body := range []string{``, `{}`, `null`, `[]`, `{"killed":"true"}`, `{"killed":null}`, `{"killed":true,"x":1}`, `{"killed":true}{"killed":false}`, `not json`, `{"killed":1}`} {
		f := &fakeKillSetter{}
		h, r := killReq(signupAdminUser(t), body)
		h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: f}
		w := httptest.NewRecorder()
		h.SetGlovoC2KillSwitch(w, r)
		if w.Code != 400 {
			t.Fatalf("body %q status %d", body, w.Code)
		}
		if len(f.calls) != 0 {
			t.Fatalf("malformed body %q reached upstream", body)
		}
	}
}

func TestGlovoC2KillSwitchUpstreamFailureIsNeverSwitchedOff(t *testing.T) {
	cases := map[string]*fakeKillSetter{
		"error":    {err: errors.New("boom")},
		"unknown":  {err: glovoc2control.ErrUnknown},
		"mismatch": {ignore: true},
	}
	for name, f := range cases {
		for _, want := range []string{`{"killed":true}`, `{"killed":false}`} {
			h, r := killReq(signupAdminUser(t), want)
			h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: f}
			w := httptest.NewRecorder()
			h.SetGlovoC2KillSwitch(w, r)
			if w.Code != http.StatusBadGateway {
				t.Fatalf("%s %s status %d", name, want, w.Code)
			}
			b := w.Body.String()
			if strings.Contains(b, `"confirmed":true`) || strings.Contains(b, `"killed"`) || !strings.Contains(b, `"unknown"`) {
				t.Fatalf("%s: failure body reads as a state: %s", name, b)
			}
		}
	}
}

func TestGlovoC2KillSwitchConfirmedFlip(t *testing.T) {
	for _, killed := range []bool{true, false} {
		f := &fakeKillSetter{}
		body := `{"killed":false}`
		if killed {
			body = `{"killed":true}`
		}
		h, r := killReq(signupAdminUser(t), body)
		h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: f}
		w := httptest.NewRecorder()
		h.SetGlovoC2KillSwitch(w, r)
		if w.Code != 200 || len(f.calls) != 1 || f.calls[0] != killed {
			t.Fatalf("status %d calls %v", w.Code, f.calls)
		}
		want := `"killed":false`
		if killed {
			want = `"killed":true`
		}
		if !strings.Contains(w.Body.String(), want) || !strings.Contains(w.Body.String(), `"confirmed":true`) {
			t.Fatalf("body %s", w.Body.String())
		}
	}
}

func TestGlovoC2KillSwitchUnconfiguredIsUnavailable(t *testing.T) {
	h, r := killReq(signupAdminUser(t), `{"killed":true}`)
	w := httptest.NewRecorder()
	h.SetGlovoC2KillSwitch(w, r)
	if w.Code != 503 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestGlovoC2KillSwitchDarkByDefault(t *testing.T) {
	var g *GlovoC2KillSwitch
	if g.mounted() {
		t.Fatal("nil options must not mount the route")
	}
	if !(&GlovoC2KillSwitch{}).mounted() {
		t.Fatal("configured options must mount the route")
	}
}

// killRouter builds the real router with an auth middleware that injects u, so
// the mount decision in NewRouter is exercised, not just the nil helper.
func killRouter(u *auth.User, k *GlovoC2KillSwitch) http.Handler {
	return NewRouter(Options{
		GlovoC2KillSwitch: k,
		AuthMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
			})
		},
	})
}

func killRouterPost(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1"+glovoC2KillSwitchPath, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGlovoC2KillSwitchRouteNotRegisteredWhenDark(t *testing.T) {
	// Even an admin must see the router's own not-found: the route does not exist.
	w := killRouterPost(killRouter(signupAdminUser(t), nil), `{"killed":true}`)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("dark router answered %d, want 404/405: %s", w.Code, w.Body.String())
	}
}

func TestGlovoC2KillSwitchRouteEnabledGatesByPrincipal(t *testing.T) {
	f := &fakeKillSetter{}
	k := &GlovoC2KillSwitch{Setter: f}

	w := killRouterPost(killRouter(auth.NewGitHubUser("customer", nil), k), `{"killed":true}`)
	if w.Code != http.StatusForbidden || len(f.calls) != 0 {
		t.Fatalf("non-admin: status %d calls %v body %s", w.Code, f.calls, w.Body.String())
	}

	w = killRouterPost(killRouter(signupAdminUser(t), k), `{"killed":true}`)
	if w.Code != http.StatusOK || len(f.calls) != 1 || !f.calls[0] {
		t.Fatalf("admin: status %d calls %v body %s", w.Code, f.calls, w.Body.String())
	}
}

func TestGlovoC2KillSwitchAuditsSuccessAndFailure(t *testing.T) {
	cases := map[string]struct {
		setter *fakeKillSetter
		status string
		state  string
	}{
		"success":  {&fakeKillSetter{}, "succeeded", "confirmed"},
		"error":    {&fakeKillSetter{err: errors.New("boom")}, "failed", "unknown"},
		"mismatch": {&fakeKillSetter{ignore: true}, "failed", "unknown"},
	}
	for name, tc := range cases {
		log := audit.NewLogger()
		admin := signupAdminUser(t)
		h, r := killReq(admin, `{"killed":true}`)
		h.opts.AuditLog = log
		h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: tc.setter}
		h.SetGlovoC2KillSwitch(httptest.NewRecorder(), r)
		entries := log.List(10)
		if len(entries) != 1 {
			t.Fatalf("%s: %d audit entries", name, len(entries))
		}
		e := entries[0]
		if e.Operation != glovoC2KillSwitchOperation || e.Status != tc.status || e.RiskLevel != "high" || e.UserID != admin.ID ||
			e.Parameters["requested"] != "true" || e.Parameters["state"] != tc.state {
			t.Fatalf("%s: entry %+v", name, e)
		}
	}
}

func TestGlovoC2KillSwitchRefusalWritesNoAudit(t *testing.T) {
	log := audit.NewLogger()
	h, r := killReq(auth.NewGitHubUser("customer", nil), `{"killed":true}`)
	h.opts.AuditLog = log
	h.opts.GlovoC2KillSwitch = &GlovoC2KillSwitch{Setter: &fakeKillSetter{}}
	h.SetGlovoC2KillSwitch(httptest.NewRecorder(), r)
	if n := len(log.List(10)); n != 0 {
		t.Fatalf("refused caller wrote %d entries", n)
	}
}
