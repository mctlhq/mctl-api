package api

import (
	"strings"
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
	calls int
}

func (s *stubRoles) MemberRoles(namespace, login string) ([][]string, error) {
	s.calls++
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
