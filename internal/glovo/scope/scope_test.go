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

package scope

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

const (
	prnA   = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	prnB   = "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"
	res    = "https://glovo.mctl.ai/mcp"
	base   = "https://api.mctl.ai"
	client = "client-1"
)

type fakeGrants struct {
	g   teamgrant.Grant
	err error
}

func (f *fakeGrants) Check(_ context.Context, id, prn, cl, r string) (teamgrant.Grant, error) {
	if f.err != nil {
		return teamgrant.Grant{}, f.err
	}
	if id != f.g.ID || prn != f.g.PrincipalID || cl != f.g.ClientID || r != f.g.Resource {
		return teamgrant.Grant{}, teamgrant.ErrGrantInvalid
	}
	return f.g, nil
}

type fakeMembership struct {
	roles map[string][][]string // tenant|prn -> roles
	err   error
	ns    gitops.PrincipalMembership
}

func (f *fakeMembership) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return f.ns, true, f.err
}

func (f *fakeMembership) MemberRolesForPrincipal(tenant, prn string) ([][]string, error) {
	return f.roles[tenant+"|"+prn], f.err
}

type fakeAllow struct {
	rows map[string]bool
	err  error
}

func (f *fakeAllow) IsAllowlisted(_ context.Context, tenant, prn string) (bool, error) {
	return f.rows[tenant+"|"+prn], f.err
}

type env struct {
	r  *Resolver
	g  *fakeGrants
	m  *fakeMembership
	al *fakeAllow
	o  *auth.OAuthServer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	o := auth.NewOAuthServer(base, "gh", "sec", []byte("secret"), nil, nil)
	o.GlovoResource, o.PrincipalMode = res, true
	g := &fakeGrants{g: teamgrant.Grant{ID: "tgr_1", PrincipalID: prnA, Tenant: "alpha", ClientID: client, Resource: res, State: teamgrant.StateActive}}
	m := &fakeMembership{roles: map[string][][]string{"alpha|" + prnA: {{"developer"}}, "labs|" + prnA: {{"owner"}}}}
	al := &fakeAllow{rows: map[string]bool{"alpha|" + prnA: true, "labs|" + prnA: true}}
	return &env{r: &Resolver{Grants: g, Elig: &Eligibility{Membership: m, Allowlist: al, NonSelectable: NonSelectable("admins")}, Resource: res, Ready: func() bool { return true }}, g: g, m: m, al: al, o: o}
}

// user mints a Glovo-audience token with the given claims and validates it.
func (e *env) user(t *testing.T, aud, pid, tgr, stn string) *auth.User {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(map[string]any{"iss": base, "sub": pid, "pid": pid, "aud": aud, "client_id": client, "groups": []string{},
		"tgr": tgr, "stn": stn, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(in))
	u, err := e.o.ValidateJWT(in + "." + enc.EncodeToString(mac.Sum(nil)))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func code(e *glovo.Error) glovo.Code {
	if e == nil {
		return ""
	}
	return e.Code
}

func TestResolveHappyPath(t *testing.T) {
	e := newEnv(t)
	sc, err := e.r.Resolve(context.Background(), e.user(t, res, prnA, "tgr_1", "alpha"))
	if err != nil || sc != (Scope{PrincipalID: prnA, Tenant: "alpha", Role: "developer", GrantID: "tgr_1"}) {
		t.Fatalf("%+v %v", sc, err)
	}
}

func TestResolveRefusals(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mutate func(*env)
		user   func(*env, *testing.T) *auth.User
		want   glovo.Code
	}{
		"not ready":                     {func(e *env) { e.r.Ready = func() bool { return false } }, nil, glovo.CodeNotReady},
		"no claims":                     {nil, func(e *env, t *testing.T) *auth.User { return e.user(t, res, prnA, "", "") }, glovo.CodeAmbiguousTenant},
		"unknown grant":                 {nil, func(e *env, t *testing.T) *auth.User { return e.user(t, res, prnA, "tgr_forged", "alpha") }, glovo.CodeAmbiguousTenant},
		"tenant differs from the grant": {nil, func(e *env, t *testing.T) *auth.User { return e.user(t, res, prnA, "tgr_1", "labs") }, glovo.CodeAmbiguousTenant},
		"another user's grant": {func(e *env) {
			e.m.roles["alpha|"+prnB], e.al.rows["alpha|"+prnB] = [][]string{{"developer"}}, true
		}, func(e *env, t *testing.T) *auth.User { return e.user(t, res, prnB, "tgr_1", "alpha") }, glovo.CodeAmbiguousTenant},
		"api audience":     {nil, func(e *env, t *testing.T) *auth.User { return e.user(t, base, prnA, "tgr_1", "alpha") }, glovo.CodeNotAuthorized},
		"grant invalid":    {func(e *env) { e.g.err = teamgrant.ErrGrantInvalid }, nil, glovo.CodeAmbiguousTenant},
		"grant store down": {func(e *env) { e.g.err = errors.New("down") }, nil, glovo.CodeUnavailable},
		"non-selectable": {func(e *env) {
			e.g.g.Tenant = "admins"
			e.m.roles["admins|"+prnA] = [][]string{{"owner"}}
		}, func(e *env, t *testing.T) *auth.User { return e.user(t, res, prnA, "tgr_1", "admins") }, glovo.CodeScopeUnsupported},
		"membership removed":    {func(e *env) { delete(e.m.roles, "alpha|"+prnA) }, nil, glovo.CodeNoTenant},
		"membership unreadable": {func(e *env) { e.m.err = errors.New("checkout stale") }, nil, glovo.CodeUnavailable},
		"not allowlisted":       {func(e *env) { delete(e.al.rows, "alpha|"+prnA) }, nil, glovo.CodeNotInPilot},
		"allowlist unreadable":  {func(e *env) { e.al.err = errors.New("down") }, nil, glovo.CodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if tc.mutate != nil {
				tc.mutate(e)
			}
			u := e.user(t, res, prnA, "tgr_1", "alpha")
			if tc.user != nil {
				u = tc.user(e, t)
			}
			if _, err := e.r.Resolve(ctx, u); code(err) != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
	if _, err := newEnv(t).r.Resolve(ctx, nil); code(err) != glovo.CodeNotAuthorized {
		t.Fatalf("nil user: %v", err)
	}
}

// A grant for labs may be selected explicitly by an allowlisted member, and
// resolves to labs only because the grant names it.
func TestLabsOnlyByExplicitGrant(t *testing.T) {
	e := newEnv(t)
	e.g.g.Tenant = "labs"
	sc, err := e.r.Resolve(context.Background(), e.user(t, res, prnA, "tgr_1", "labs"))
	if err != nil || sc.Tenant != "labs" {
		t.Fatalf("%+v %v", sc, err)
	}
	e.al.rows = map[string]bool{"alpha|" + prnA: true}
	if _, err := e.r.Resolve(context.Background(), e.user(t, res, prnA, "tgr_1", "labs")); code(err) != glovo.CodeNotInPilot {
		t.Fatalf("labs without an allowlist row: %v", err)
	}
}

func TestEligibility(t *testing.T) {
	e := newEnv(t)
	e.m.ns = gitops.PrincipalMembership{Namespaces: []string{"labs", "alpha", "admins", "beta"}}
	e.m.roles["admins|"+prnA] = [][]string{{"owner"}}
	e.m.roles["beta|"+prnA] = [][]string{{"viewer"}} // member, not allowlisted
	got, err := e.r.Elig.Eligible(context.Background(), prnA)
	if err != nil || len(got) != 2 || got[0] != "alpha" || got[1] != "labs" {
		t.Fatalf("%v %v", got, err)
	}
	// A failed read never shrinks the list.
	e.m.ns.Unreadable = []string{"gamma"}
	if _, err := e.r.Elig.Eligible(context.Background(), prnA); err == nil {
		t.Fatal("unreadable tenant shrank the list")
	}
	e.m.ns.Unreadable = nil
	e.al.err = errors.New("down")
	if _, err := e.r.Elig.Eligible(context.Background(), prnA); err == nil {
		t.Fatal("allowlist failure shrank the list")
	}
}

func TestRequireScopeMiddleware(t *testing.T) {
	e := newEnv(t)
	var seen Scope
	h := RequireScope(e.r)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	serve := func(u *auth.User, hdr map[string]string, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/x"+query, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if u != nil {
			req = req.WithContext(auth.WithUser(req.Context(), u))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Forged inputs never change the scope.
	rec := serve(e.user(t, res, prnA, "tgr_1", "alpha"), map[string]string{"X-Mctl-Selected-Tenant": "labs"}, "?tenant=labs&namespace=labs")
	if rec.Code != http.StatusNoContent || seen.Tenant != "alpha" {
		t.Fatalf("%d %+v", rec.Code, seen)
	}
	if rec := serve(nil, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no user: %d", rec.Code)
	}
	rec = serve(e.user(t, res, prnA, "", ""), nil, "")
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || body["error"] != "ambiguous_tenant" {
		t.Fatalf("%d %v", rec.Code, body)
	}
}

func TestNonSelectable(t *testing.T) {
	m := NonSelectable(" admins, ,labs ,")
	if len(m) != 2 || !m["admins"] || !m["labs"] {
		t.Fatalf("%v", m)
	}
}
