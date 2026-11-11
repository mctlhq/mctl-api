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
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

type fakeAllowlist struct {
	rows map[string]bool
	err  error
}

func (f *fakeAllowlist) AllowlistAdd(_ context.Context, tenant, prn, by string) error {
	if f.err != nil {
		return f.err
	}
	if by == "" {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	f.rows[tenant+"|"+prn] = true
	return nil
}

func (f *fakeAllowlist) AllowlistRemove(_ context.Context, tenant, prn string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.rows, tenant+"|"+prn)
	return nil
}

const allowPRN = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"

// allowGit is a GitReader that knows only which tenants exist.
type allowGit struct {
	GitReader
	tenants map[string]bool
	err     error
}

func (g *allowGit) TenantExists(name string) (bool, error) { return g.tenants[name], g.err }

func newAllowGit(names ...string) *allowGit {
	g := &allowGit{tenants: map[string]bool{}}
	for _, n := range names {
		g.tenants[n] = true
	}
	return g
}

// allowPrincipal gives u the principal the auth middleware would resolve.
func allowPrincipal(t *testing.T, u *auth.User, prn string) *auth.User {
	t.Helper()
	pr := &relayPrincipals{byLogin: map[string]string{u.ID: prn}}
	if err := auth.AttachPrincipal(context.Background(), pr, u); err != nil {
		t.Fatal(err)
	}
	return u
}

func allowlistCall(t *testing.T, al *fakeAllowlist, git *allowGit, user *auth.User, method, tenant, prn string) int {
	t.Helper()
	h := &Handlers{opts: Options{GlovoAllowlist: al, GitReader: git}}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithUser(req.Context(), user)))
		})
	})
	r.Put("/api/v1/glovo/pilot/{tenant}/principals/{principal_id}", h.GlovoAllowlistAdd)
	r.Delete("/api/v1/glovo/pilot/{tenant}/principals/{principal_id}", h.GlovoAllowlistRemove)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/glovo/pilot/"+tenant+"/principals/"+prn, nil))
	return rec.Code
}

func TestGlovoAllowlistAdminOnly(t *testing.T) {
	git := newAllowGit("alpha")
	owner := allowPrincipal(t, auth.NewGitHubUser("owner", []string{"alpha"}), "prn_01JCCCCCCCCCCCCCCCCCCCCCCC")
	svc := allowPrincipal(t, auth.NewServiceUser(), "prn_01JDDDDDDDDDDDDDDDDDDDDDDD")
	agent := auth.NewAgentUser("implementer", auth.AgentRun{})
	relayed := auth.NewRelayedUser("root", []string{"admins"}, auth.NewSurfaceUser("telegram"))
	for name, u := range map[string]*auth.User{"tenant owner who is not an admin": owner, "service user": svc, "agent token": agent, "relayed surface": relayed} {
		for _, m := range []string{http.MethodPut, http.MethodDelete} {
			al := &fakeAllowlist{rows: map[string]bool{}}
			if got := allowlistCall(t, al, git, u, m, "alpha", allowPRN); got != http.StatusForbidden {
				t.Errorf("%s %s: %d", name, m, got)
			}
			if len(al.rows) != 0 {
				t.Errorf("%s %s: wrote a row", name, m)
			}
		}
	}
}

func TestGlovoAllowlistAddRemove(t *testing.T) {
	git := newAllowGit("alpha")
	admin := allowPrincipal(t, auth.NewGitHubUser("root", []string{"admins"}), "prn_01JEEEEEEEEEEEEEEEEEEEEEEE")
	al := &fakeAllowlist{rows: map[string]bool{}}
	if got := allowlistCall(t, al, git, admin, http.MethodPut, "alpha", allowPRN); got != http.StatusNoContent || !al.rows["alpha|"+allowPRN] {
		t.Fatalf("add: %d", got)
	}
	if got := allowlistCall(t, al, git, admin, http.MethodDelete, "alpha", allowPRN); got != http.StatusNoContent || len(al.rows) != 0 {
		t.Fatalf("remove: %d", got)
	}
	// No wildcard and no malformed principal.
	for _, prn := range []string{"*", "usr_1", "prn_short", ""} {
		if got := allowlistCall(t, al, git, admin, http.MethodPut, "alpha", prn); got != http.StatusBadRequest && got != http.StatusNotFound && got != http.StatusMethodNotAllowed {
			t.Errorf("principal %q: %d", prn, got)
		}
	}
	if len(al.rows) != 0 {
		t.Fatal("a malformed principal was written")
	}
}

func TestGlovoAllowlistTenantAndStoreFailures(t *testing.T) {
	admin := allowPrincipal(t, auth.NewGitHubUser("root", []string{"admins"}), "prn_01JEEEEEEEEEEEEEEEEEEEEEEE")
	al := &fakeAllowlist{rows: map[string]bool{}}
	if got := allowlistCall(t, al, newAllowGit(), admin, http.MethodPut, "ghost", allowPRN); got != http.StatusNotFound {
		t.Fatalf("unknown tenant: %d", got)
	}
	if got := allowlistCall(t, al, &allowGit{err: errors.New("stale checkout")}, admin, http.MethodPut, "alpha", allowPRN); got != http.StatusServiceUnavailable {
		t.Fatalf("lookup failure: %d", got)
	}
	git := newAllowGit("alpha")
	al.err = errors.New("db down")
	if got := allowlistCall(t, al, git, admin, http.MethodPut, "alpha", allowPRN); got != http.StatusServiceUnavailable {
		t.Fatalf("store failure: %d", got)
	}
}

// A Glovo-audience token is refused by the audience gate before any handler.
func TestGlovoAllowlistRouteBehindAudienceGate(t *testing.T) {
	h := &Handlers{}
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/glovo/pilot/alpha/principals/"+allowPRN, nil)
	u := auth.NewGitHubUser("root", []string{"admins"})
	req = req.WithContext(auth.WithUser(req.Context(), u))
	h.glovoAudienceGate(next).ServeHTTP(rec, req)
	if !called {
		t.Fatal("a non-glovo caller must pass the gate")
	}
}
