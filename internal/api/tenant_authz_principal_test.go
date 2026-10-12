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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const zitadelOnlyPRN = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"

// principalUser is a caller as principal mode leaves it: authorization
// decided by principal, groups from GitOps membership.
func principalUser(t *testing.T, u *auth.User, prn string, tenants map[string][]string) *auth.User {
	t.Helper()
	withPrincipal(t, u, prn)
	p := &auth.PrincipalAuthz{Members: tenantsByPrincipal(tenants), Admins: map[string]bool{}}
	if err := p.Apply(u); err != nil {
		t.Fatal(err)
	}
	return u
}

type tenantsByPrincipal map[string][]string

func (m tenantsByPrincipal) PrincipalTenants(prn string) ([]string, []string, error) {
	return m[prn], nil, nil
}

// B4: in principal mode the role is read by principal and never by login.
// The legacy reader is wired with the opposite answer for every case, so a
// login comparison re-introduced anywhere in the path fails one of them.
func TestCheckTenantRole_PrincipalMode(t *testing.T) {
	inErpact := map[string][]string{shadowPRN: {"erpact"}, zitadelOnlyPRN: {"erpact"}}
	dev := func() *auth.User { return principalUser(t, erpactMember("dan-dev"), shadowPRN, inErpact) }
	zitadelOnly := func() *auth.User {
		return principalUser(t, auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "z-1", "dan@example.com", auth.KindHuman), zitadelOnlyPRN, inErpact)
	}
	// By login, dan-dev is an owner of erpact; by principal, a developer.
	legacy := rolesOf("erpact/dan-dev=owner")
	byPrincipal := &stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}
	tests := []struct {
		name string
		user *auth.User
		min  operations.Role
		pm   PrincipalMembershipReader
		want int
	}{
		{"principal role satisfies", dev(), operations.RoleDeveloper, byPrincipal, 0},
		{"login role is not consulted", dev(), operations.RoleOwner, byPrincipal, http.StatusForbidden},
		{"no principal entry, owner by login", dev(), operations.RoleViewer, &stubPrincipalMembership{}, http.StatusForbidden},
		{"ZITADEL-only principal, no GitHub login", zitadelOnly(), operations.RoleDeveloper, byPrincipal, 0},
		{"principal roles unreadable", dev(), operations.RoleDeveloper, &stubPrincipalMembership{rolesErr: errors.New("stale")}, http.StatusServiceUnavailable},
		{"no membership reader", dev(), operations.RoleDeveloper, nil, http.StatusServiceUnavailable},
		{"human without a principal", erpactMember("dan-dev"), operations.RoleDeveloper, byPrincipal, http.StatusServiceUnavailable},
		{"agent holds no tenant role", auth.NewAgentUser("implementer", auth.AgentRun{}), operations.RoleViewer, byPrincipal, http.StatusForbidden},
		{"admin-only action", dev(), operations.RoleAdmin, byPrincipal, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{GitReader: legacy, TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: tt.pm}}
			if d := h.checkTenantRole(tt.user, "erpact", tt.min, "test"); d.status != tt.want {
				t.Fatalf("status = %d (%s), want %d", d.status, d.detail, tt.want)
			}
		})
	}
}

// The nil-reader refusal names the reader principal mode actually needed,
// not the login-keyed one.
func TestCheckTenantRole_PrincipalModeNamesItsReader(t *testing.T) {
	user := principalUser(t, erpactMember("dan-dev"), shadowPRN, map[string][]string{shadowPRN: {"erpact"}})
	h := &Handlers{opts: Options{TenantAuthzMode: TenantAuthzPrincipal}}
	d := h.checkTenantRole(user, "erpact", operations.RoleDeveloper, "test")
	if d.status != http.StatusServiceUnavailable || !strings.Contains(d.detail, "principal membership reader not configured") {
		t.Fatalf("got %d %q", d.status, d.detail)
	}
}

// B6 (API side): a ZITADEL-only principal gets developer on its tenant;
// removing its entry removes the role; an unlinked identity with the same
// email is another principal and gets nothing.
func TestZitadelOnlyPrincipal_TenantRole(t *testing.T) {
	const unlinked = "prn_01JQQQQQQQQQQQQQQQQQQQQQQQ"
	sign := func(prn string, tenants map[string][]string) *auth.User {
		return principalUser(t, auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "z", "dan@example.com", auth.KindHuman), prn, tenants)
	}
	written := map[string][][]string{"commerce-proof": {{"developer"}}}
	pm := &principalRoles{byPRN: map[string]map[string][][]string{zitadelOnlyPRN: written}}
	h := &Handlers{opts: Options{TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: pm}}
	listed := map[string][]string{zitadelOnlyPRN: {"commerce-proof"}}

	u := sign(zitadelOnlyPRN, listed)
	if !u.HasTenantAccess("commerce-proof") || h.checkTenantRole(u, "commerce-proof", operations.RoleDeveloper, "test").refused() {
		t.Fatal("ZITADEL-only member was refused")
	}
	other := sign(unlinked, listed)
	if other.HasTenantAccess("commerce-proof") || !h.checkTenantRole(other, "commerce-proof", operations.RoleViewer, "test").refused() {
		t.Fatal("unlinked same-email identity was let in")
	}
	delete(pm.byPRN, zitadelOnlyPRN)
	removed := sign(zitadelOnlyPRN, map[string][]string{})
	if removed.HasTenantAccess("commerce-proof") || !h.checkTenantRole(removed, "commerce-proof", operations.RoleViewer, "test").refused() {
		t.Fatal("access survived removal of the GitOps entry")
	}
}

type principalRoles struct {
	byPRN map[string]map[string][][]string
}

func (p *principalRoles) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return gitops.PrincipalMembership{}, true, nil
}

func (p *principalRoles) MemberRolesForPrincipal(namespace, prn string) ([][]string, error) {
	return p.byPRN[prn][namespace], nil
}

// Shadow compares platform admin once ADMIN_PRINCIPALS is set, and only then.
func TestTenantAuthzShadow_AdminMismatch(t *testing.T) {
	admin := func() *auth.User {
		return withPrincipal(t, auth.NewGitHubUser("root", []string{"admins", "labs"}), shadowPRN)
	}
	member := func() *auth.User { return withPrincipal(t, auth.NewGitHubUser("dev", []string{"labs"}), shadowPRN) }
	pm := &stubPrincipalMembership{namespaces: []string{"labs"}}
	tests := []struct {
		name   string
		user   *auth.User
		admins map[string]bool
		want   []string
	}{
		{"not configured: admin is not compared", admin(), nil, []string{"result:match"}},
		{"both admin", admin(), map[string]bool{shadowPRN: true}, []string{"result:match"}},
		{"admin only by login", admin(), map[string]bool{"prn_01JAAAAAAAAAAAAAAAAAAAAAAA": true}, []string{"result:diff", "kind:admin_mismatch"}},
		{"admin only by principal", member(), map[string]bool{shadowPRN: true}, []string{"result:diff", "kind:admin_mismatch"}},
		{"neither", member(), map[string]bool{"prn_01JAAAAAAAAAAAAAAAAAAAAAAA": true}, []string{"result:match"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{TenantAuthzMode: TenantAuthzShadow, PrincipalMembership: pm, AdminPrincipals: tt.admins}}
			before := snapshotShadow()
			h.shadowTenantSet(httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil), tt.user)
			assertDelta(t, before.delta(), tt.want...)
		})
	}
}

// Platform skill role bindings: the "admins" role is platform admin, not a
// tenant that happens to share the name.
func TestPlatformSkillRoleBinding_AdminsIsPlatformAdmin(t *testing.T) {
	tenantMember := principalUser(t, auth.NewGitHubUser("dev", nil), shadowPRN, map[string][]string{shadowPRN: {"admins"}})
	a := platformSkillAccess{user: tenantMember, roleBindings: []gitops.PlatformSkillBinding{{Role: "admins", EnabledSkills: []string{"ops"}}}}
	if a.enabledForUserTenant("ops") {
		t.Fatal("a member of the tenant \"admins\" got the admins role binding")
	}
	a.user = auth.NewServiceUser()
	if !a.enabledForUserTenant("ops") {
		t.Fatal("a platform admin lost the admins role binding")
	}
}
