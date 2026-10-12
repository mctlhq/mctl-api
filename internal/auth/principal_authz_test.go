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

const (
	pzAdmin   = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	pzMember  = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	pzZitadel = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	pzOther   = "prn_01JQQQQQQQQQQQQQQQQQQQQQQQ"
)

// pzMembers answers principal -> tenants, or fails the way a stale checkout
// (err) or a broken tenant (unreadable) does.
type pzMembers struct {
	tenants    map[string][]string
	unreadable []string
	err        error
}

func (m pzMembers) PrincipalTenants(prn string) ([]string, []string, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.tenants[prn], m.unreadable, nil
}

func pzHuman(prn string, groups ...string) *User {
	u := NewGitHubUser("someone", groups)
	u.principalID = prn
	return u
}

func TestParseAdminPrincipals(t *testing.T) {
	got, err := ParseAdminPrincipals(" " + pzAdmin + " ,," + pzMember)
	if err != nil || len(got) != 2 || !got[pzAdmin] || !got[pzMember] {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := ParseAdminPrincipals(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
	for _, bad := range []string{"mashkovd", "prn_short", pzAdmin + ",admins", "prn_01JAAAAAAAAAAAAAAAAAAAAAAI"} {
		if _, err := ParseAdminPrincipals(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// B1: in principal mode nothing but ADMIN_PRINCIPALS makes an admin: not a
// tenant named "admins", not a provider group "admins", not a Groups entry
// "admins" left over from the legacy resolution.
func TestPrincipalAuthz_NoGroupMakesAnAdmin(t *testing.T) {
	p := &PrincipalAuthz{
		Members: pzMembers{tenants: map[string][]string{pzMember: {"admins", "labs"}}},
		Admins:  map[string]bool{pzAdmin: true},
	}

	// Legacy groups say admin; GitOps lists the tenant "admins".
	member := pzHuman(pzMember, "admins", "mctl")
	if err := p.Apply(member); err != nil {
		t.Fatal(err)
	}
	if member.IsAdmin() {
		t.Fatal("a member of the tenant \"admins\" is a platform admin in principal mode")
	}
	if !slices.Equal(member.Groups, []string{"admins", "labs"}) {
		t.Fatalf("groups = %v, want GitOps membership only (legacy \"mctl\" dropped)", member.Groups)
	}
	if !member.HasTenantAccess("admins") || member.HasTenantAccess("mctl") {
		t.Fatal("tenant access must follow principal membership")
	}
	if member.HasRole("admins") {
		t.Fatal("the admins role binding matched a tenant named admins")
	}

	// A federated identity whose provider asserted "admins".
	fed := NewFederatedUser("zitadel", "https://auth.example", "sub-1", "f@example", KindHuman)
	fed.Groups = []string{"admins"}
	fed.principalID = pzOther
	if err := p.Apply(fed); err != nil {
		t.Fatal(err)
	}
	if fed.IsAdmin() || len(fed.Groups) != 0 {
		t.Fatalf("provider group survived: admin=%v groups=%v", fed.IsAdmin(), fed.Groups)
	}

	admin := pzHuman(pzAdmin)
	if err := p.Apply(admin); err != nil {
		t.Fatal(err)
	}
	if !admin.IsAdmin() || !admin.HasRole("admins") || !admin.HasTenantAccess("anything") {
		t.Fatal("an ADMIN_PRINCIPALS principal is not an admin")
	}
}

// Could not read is never "member of nothing": 503 for anyone but an admin,
// whose access does not depend on membership.
func TestPrincipalAuthz_UnreadableMembership(t *testing.T) {
	admins := map[string]bool{pzAdmin: true}
	for name, m := range map[string]PrincipalMembershipSource{
		"stale checkout": pzMembers{err: errors.New("checkout is stale")},
		"broken tenant":  pzMembers{tenants: map[string][]string{pzMember: {"labs"}, pzAdmin: {"labs"}}, unreadable: []string{"erpact"}},
		"no source":      nil,
	} {
		p := &PrincipalAuthz{Members: m, Admins: admins}
		if err := p.Apply(pzHuman(pzMember, "labs")); !errors.Is(err, ErrPrincipalAuthzUnavailable) {
			t.Errorf("%s: member got %v, want ErrPrincipalAuthzUnavailable", name, err)
		}
		admin := pzHuman(pzAdmin, "mctl")
		if err := p.Apply(admin); err != nil || !admin.IsAdmin() {
			t.Errorf("%s: admin got %v, admin=%v", name, err, admin.IsAdmin())
		}
		if len(admin.Groups) != 0 {
			t.Errorf("%s: admin kept legacy groups %v", name, admin.Groups)
		}
	}
	p := &PrincipalAuthz{Members: pzMembers{}, Admins: admins}
	if err := p.Apply(pzHuman("", "labs")); !errors.Is(err, ErrPrincipalAuthzUnavailable) {
		t.Fatalf("unresolved principal: %v", err)
	}
}

// A caller that matches no identity shape is not a proven non-human: it is
// refused like an unresolved human, never served with no tenants.
func TestPrincipalAuthz_UnrecognisedIdentity(t *testing.T) {
	p := &PrincipalAuthz{Members: pzMembers{}, Admins: map[string]bool{}}
	if err := p.Apply(&User{ID: "dex-without-sub", Groups: []string{"labs"}}); !errors.Is(err, ErrPrincipalAuthzUnavailable) {
		t.Fatalf("got %v, want ErrPrincipalAuthzUnavailable", err)
	}
}

func TestPrincipalAuthz_NonHumanCallers(t *testing.T) {
	p := &PrincipalAuthz{Members: pzMembers{tenants: map[string][]string{pzOther: {"labs"}}}, Admins: map[string]bool{}}
	svc := NewServiceUser()
	dev := &User{ID: "dev-user", Groups: []string{"admins"}, dev: true}
	for _, u := range []*User{svc, dev} {
		if err := p.Apply(u); err != nil || !u.IsAdmin() {
			t.Fatalf("%s: err %v admin %v", u.ID, err, u.IsAdmin())
		}
	}
	machine := NewFederatedUser("partner", "https://idp.example", "svc-1", "robot", KindService)
	machine.Groups = []string{"labs", "admins"}
	machine.principalID = pzOther
	for _, u := range []*User{NewSurfaceUser("telegram"), NewAgentUser("implementer", AgentRun{}), NewCIUser("mctlhq/x", "1"), machine} {
		if err := p.Apply(u); err != nil || u.IsAdmin() || len(u.Groups) != 0 {
			t.Fatalf("%s: err %v admin %v groups %v", u.ID, err, u.IsAdmin(), u.Groups)
		}
	}
}

// B6 (auth side): a ZITADEL-only principal, no GitHub identity anywhere,
// gets exactly its GitOps tenants; once the entry is gone it gets none; an
// unlinked ZITADEL identity with the same email is a different principal
// and gets nothing.
func TestPrincipalAuthz_ZitadelOnlyPrincipal(t *testing.T) {
	members := pzMembers{tenants: map[string][]string{pzZitadel: {"commerce-proof"}}}
	p := &PrincipalAuthz{Members: members, Admins: map[string]bool{pzAdmin: true}}
	resolver := &fakePrincipals{answers: map[string]string{
		"zitadel|https://auth.mctl.ai|z-1": pzZitadel,
		"zitadel|https://auth.mctl.ai|z-2": pzOther, // same email, never linked
	}}
	sign := func(sub string) *User {
		u := NewFederatedUser("zitadel", "https://auth.mctl.ai", sub, "dev@example.com", KindHuman)
		if err := AttachPrincipal(context.Background(), resolver, u); err != nil {
			t.Fatal(err)
		}
		if err := p.Apply(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	if u := sign("z-1"); !u.HasTenantAccess("commerce-proof") || u.IsAdmin() {
		t.Fatalf("ZITADEL-only member: groups %v admin %v", u.Groups, u.IsAdmin())
	}
	if _, linked := sign("z-1").GitHubLogin(); linked {
		t.Fatal("the ZITADEL-only caller claims a GitHub login")
	}
	if u := sign("z-2"); u.HasTenantAccess("commerce-proof") || len(u.Groups) != 0 {
		t.Fatalf("unlinked same-email identity got %v", u.Groups)
	}
	delete(members.tenants, pzZitadel)
	if u := sign("z-1"); u.HasTenantAccess("commerce-proof") {
		t.Fatal("access survived removal of the GitOps entry")
	}
}

// The middleware applies principal mode after the principal is attached, and
// refuses with 503 when it cannot decide; without the option it is legacy.
func TestMiddleware_PrincipalMode(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	v := NewGitHubValidator([]string{"alice"}) // ADMIN_USERS: ignored in principal mode
	v.cache["gho_alice"] = &githubUserInfo{Login: "alice", ID: 4242, CachedAt: time.Now()}
	run := func(pr PrincipalResolver, pa *PrincipalAuthz) (int, *User) {
		var got *User
		h := Middleware(v, nil, nil, nil, WithPrincipalResolver(pr), WithPrincipalAuthz(pa))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = UserFromContext(r.Context())
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer gho_alice")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code, got
	}
	resolved := &fakePrincipals{answers: map[string]string{"github||4242": pzMember}}
	pa := &PrincipalAuthz{Members: pzMembers{tenants: map[string][]string{pzMember: {"labs"}}}, Admins: map[string]bool{pzAdmin: true}}

	if code, u := run(resolved, nil); code != http.StatusOK || !u.IsAdmin() {
		t.Fatalf("legacy: %d admin=%v", code, u != nil && u.IsAdmin())
	}
	code, u := run(resolved, pa)
	if code != http.StatusOK || u.IsAdmin() || !slices.Equal(u.Groups, []string{"labs"}) {
		t.Fatalf("principal: %d admin=%v groups=%v; ADMIN_USERS must not count", code, u != nil && u.IsAdmin(), u)
	}
	if code, u := run(&fakePrincipals{err: errors.New("store down")}, pa); code != http.StatusServiceUnavailable || u != nil {
		t.Fatalf("unresolved principal: %d, handler reached=%v", code, u != nil)
	}
	stale := &PrincipalAuthz{Members: pzMembers{err: errors.New("stale")}, Admins: pa.Admins}
	if code, _ := run(resolved, stale); code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable membership: %d", code)
	}
}
