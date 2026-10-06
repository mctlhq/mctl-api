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
	// roles is tenant -> login -> members[].role values, as written.
	roles map[string]map[string][]string
	err   error
	calls int
}

func (s *stubRoles) MemberRoles(namespace, login string) ([]string, error) {
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

// rolesOf builds a stubRoles from "tenant/login=role" entries.
func rolesOf(entries ...string) *stubRoles {
	s := &stubRoles{roles: map[string]map[string][]string{}}
	for _, e := range entries {
		key, role, _ := strings.Cut(e, "=")
		tenant, login, _ := strings.Cut(key, "/")
		if s.roles[tenant] == nil {
			s.roles[tenant] = map[string][]string{}
		}
		s.roles[tenant][login] = append(s.roles[tenant][login], role)
	}
	return s
}
