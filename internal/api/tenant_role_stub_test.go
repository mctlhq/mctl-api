package api

import (
	"strings"
	"sync/atomic"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// stubRoles is a GitReader that answers MemberRoles only: every other
// method is the embedded nil interface and panics if a test reaches it. It
// is what an in-package handler test wires so a non-admin caller has a role
// to be checked against (mctl-api#478).
type stubRoles struct {
	GitReader
	// roles is tenant -> login -> one list of members[].role values per
	// members list naming the login, as written.
	roles map[string]map[string][][]string
	err   error
	calls atomic.Int64
}

func (s *stubRoles) MemberRoles(namespace, login string) ([][]string, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	for l, roles := range s.roles[namespace] {
		if strings.EqualFold(l, login) {
			return roles, nil
		}
	}
	return nil, nil
}

// rolesOf builds a stubRoles from "tenant/login=role" entries. Repeating a
// login lists it twice in the tenant's one members list; a role written
// "a|b" puts a in the tenant-level list and b in a team's list.
func rolesOf(entries ...string) *stubRoles {
	s := &stubRoles{roles: map[string]map[string][][]string{}}
	for _, e := range entries {
		key, role, _ := strings.Cut(e, "=")
		tenant, login, _ := strings.Cut(key, "/")
		if s.roles[tenant] == nil {
			s.roles[tenant] = map[string][][]string{}
		}
		have := s.roles[tenant][login]
		for i, r := range strings.Split(role, "|") {
			if i >= len(have) {
				have = append(have, nil)
			}
			have[i] = append(have[i], r)
		}
		s.roles[tenant][login] = have
	}
	return s
}

// ownerEverywhere is a GitReader that lists every login as an owner of every
// tenant, for harnesses whose subject is not the tenant-role decision.
type ownerEverywhere struct{ GitReader }

func (ownerEverywhere) MemberRoles(_, _ string) ([][]string, error) {
	return [][]string{{"owner"}}, nil
}

// developerByPrincipal is a router option for the surface identity
// harness: it runs the router in principal mode, the live mode, with each
// of prns a member of the harness tenant and every principal a developer
// of it, for tests whose subject is not the tenant-role decision. A
// delegated or ZITADEL-only subject has no GitHub login, so the login-keyed
// rollback modes would refuse it a role.
func developerByPrincipal(prns ...string) func(*Options) {
	return func(o *Options) {
		o.TenantAuthzMode = TenantAuthzPrincipal
		tenant := o.TenantResolver.(sidTenants)["carol"][0]
		members := tenantsByPrincipal{}
		for _, prn := range prns {
			members[prn] = []string{tenant}
		}
		o.PrincipalAuthz = &auth.PrincipalAuthz{Members: members}
		o.PrincipalMembership = &stubPrincipalMembership{
			namespaces: []string{tenant},
			roles:      map[string][][]string{tenant: {{"developer"}}},
		}
	}
}
