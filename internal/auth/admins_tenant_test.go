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
	"slices"
	"testing"
	"time"
)

// A tenant may be named "admins" (one is). Membership of it must never make
// a platform admin: only ADMIN_USERS does (mctl-api#377, PR-0). These pin
// both GitHub-token entry points, the federation registry's
// legacyGroupSource and the MCTL_FEDERATION_DISABLED middleware branch,
// which share resolveGroups.

func adminsTenantResolver() *stubTenantResolver {
	r := &stubTenantResolver{}
	r.setTenants("member", []string{"admins", "mctl"})
	r.setTenants("boss", []string{"admins", "mctl"})
	return r
}

func TestResolveGroupsAdminsTenantIsNotAdmin(t *testing.T) {
	v := NewGitHubValidator([]string{"boss"})
	r := adminsTenantResolver()

	got := resolveGroups("member", v, r)
	if !slices.Equal(got, []string{"mctl"}) {
		t.Fatalf("groups for a member of the admins tenant = %v, want [mctl]", got)
	}
	u := NewGitHubUser("member", got)
	if u.IsAdmin() {
		t.Fatal("a member of the tenant named admins is a platform admin")
	}
	if u.HasTenantAccess("labs") {
		t.Fatal("a member of the tenant named admins reaches a tenant it is not in")
	}

	// An ADMIN_USERS login that is also in the tenant gets exactly one
	// "admins", from ADMIN_USERS.
	got = resolveGroups("boss", v, r)
	if !slices.Equal(got, []string{"admins", "mctl"}) {
		t.Fatalf("groups for an ADMIN_USERS login = %v, want [admins mctl]", got)
	}
	if !NewGitHubUser("boss", got).IsAdmin() {
		t.Fatal("an ADMIN_USERS login is not an admin")
	}

	// A failed lookup still grants no tenant.
	r.setErr(errors.New("gitops unavailable"))
	if got := resolveGroups("member", v, r); len(got) != 0 {
		t.Fatalf("groups after a resolver error = %v, want none", got)
	}
}

func TestGitHubProviderAdminsTenantIsNotAdmin(t *testing.T) {
	v := NewGitHubValidator([]string{"boss"})
	const token = "gho_adminstenantmember" // #nosec G101 -- fake test token
	v.cache[token] = &githubUserInfo{Login: "member", ID: 4242, CachedAt: time.Now()}
	p := newGitHubProvider(v, legacyGroupSource{validator: v, resolver: adminsTenantResolver()})

	got, err := p.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if slices.Contains(got.Claims.Groups, "admins") {
		t.Fatalf("registry GitHub provider groups = %v; the admins tenant leaked in as admin", got.Claims.Groups)
	}
	if !slices.Contains(got.Claims.Groups, "mctl") {
		t.Fatalf("registry GitHub provider groups = %v, want mctl kept", got.Claims.Groups)
	}
}

func TestMiddlewareGitHubTokenAdminsTenantIsNotAdmin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		federated string
	}{
		{"registry", ""},
		{"federation disabled", "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTH_REQUIRED", "true")
			t.Setenv("MCTL_FEDERATION_DISABLED", tc.federated)
			v := NewGitHubValidator([]string{"boss"})
			v.cache["gho_mwmember"] = &githubUserInfo{Login: "member", ID: 4243, CachedAt: time.Now()}

			var seen *User
			h := Middleware(v, adminsTenantResolver(), nil, nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = UserFromContext(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
			req.Header.Set("Authorization", "Bearer gho_mwmember")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if seen == nil {
				t.Fatalf("request not authenticated: %d %s", rec.Code, rec.Body.String())
			}
			if seen.IsAdmin() {
				t.Fatalf("member of the admins tenant is a platform admin (groups %v)", seen.Groups)
			}
			if !seen.HasTenantAccess("mctl") {
				t.Fatalf("member lost its real tenant (groups %v)", seen.Groups)
			}
		})
	}
}
