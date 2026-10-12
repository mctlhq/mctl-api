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
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Principal mode (TENANT_AUTHZ_MODE=principal, mctl-api#377 PR-B).
//
// In principal mode a human caller's tenants are the ones GitOps lists its
// canonical principal under (members[].principalId), and platform admin is
// ADMIN_PRINCIPALS and nothing else. No login, group claim or tenant name
// takes part in either decision: User.Groups is replaced, never merged, and
// IsAdmin stops reading it.

// principalIDPattern is the canonical principal id. gitops keeps its own
// copy for member keys; the two packages do not import each other.
var principalIDPattern = regexp.MustCompile(`^prn_[0-9A-HJKMNP-TV-Z]{26}$`)

// ValidPrincipalID reports whether s is a well-formed canonical principal id.
func ValidPrincipalID(s string) bool { return principalIDPattern.MatchString(s) }

// ParseAdminPrincipals reads ADMIN_PRINCIPALS: comma-separated principal ids.
// A malformed entry is an error, never skipped: a typo must stop the boot
// rather than silently leave someone out of (or in) the admin set.
func ParseAdminPrincipals(raw string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if !ValidPrincipalID(id) {
			return nil, fmt.Errorf("ADMIN_PRINCIPALS: %q is not a principal id (prn_ followed by 26 Crockford base32 characters)", id)
		}
		out[id] = true
	}
	return out, nil
}

// PrincipalMembershipSource is the principal-keyed tenant membership
// principal mode reads (gitops.Reader, adapted in cmd/api). An error means
// nothing could be read; unreadable lists the tenants that could not be,
// which may or may not include the principal.
type PrincipalMembershipSource interface {
	PrincipalTenants(principalID string) (namespaces, unreadable []string, err error)
}

// ErrPrincipalAuthzUnavailable: a human caller's tenants could not be
// decided, because its principal was not resolved or its membership could
// not be read. The request is refused with 503, never served with no
// tenants: "could not read" is not "member of nothing".
var ErrPrincipalAuthzUnavailable = errors.New("tenant membership could not be determined")

// PrincipalAuthz decides tenants and platform admin by principal.
type PrincipalAuthz struct {
	Members PrincipalMembershipSource
	Admins  map[string]bool
}

// Apply rewrites u's authorization for principal mode. It runs after the
// caller's principal is attached.
//
//   - The static service principal and the dev caller stay platform admins
//     (NewServiceUser, AUTH_REQUIRED=false).
//   - Any other non-human caller (surface, agent, CI, writers, a federated
//     machine identity) keeps no groups: principal mode reads no provider
//     group for anyone. A caller with no recognisable identity at all is
//     refused, not served as one.
//   - A human gets ADMIN_PRINCIPALS for admin and its GitOps membership for
//     tenants. A platform admin whose membership cannot be read is still
//     served, since admin does not depend on it; anyone else is refused
//     with ErrPrincipalAuthzUnavailable.
func (p *PrincipalAuthz) Apply(u *User) error {
	if u == nil {
		return nil
	}
	u.principalAuthz = true
	if u.service || u.dev {
		u.platformAdmin = true
		return nil
	}
	u.Groups = nil
	id, ok := u.Identity()
	if !ok {
		// Not a proven non-human: a caller whose identity has no
		// recognised shape (a Dex token with no sub) cannot be decided.
		return fmt.Errorf("%w: %q has no recordable identity", ErrPrincipalAuthzUnavailable, u.ID)
	}
	if id.Kind != KindHuman {
		return nil
	}
	prn := u.principalID
	if prn == "" {
		return fmt.Errorf("%w: principal of %q was not resolved", ErrPrincipalAuthzUnavailable, u.ID)
	}
	// A relayed or delegated caller is never an admin, whoever it acts
	// for: NewRelayedUser and NewDelegatedUser strip "admins" for the same
	// reason, and a delegated run must not approve its own actions.
	u.platformAdmin = p.Admins[prn] && u.actingPrincipal == ""
	if p.Members == nil {
		if u.platformAdmin {
			return nil
		}
		return fmt.Errorf("%w: no membership source", ErrPrincipalAuthzUnavailable)
	}
	namespaces, unreadable, err := p.Members.PrincipalTenants(prn)
	switch {
	case (err != nil || len(unreadable) > 0) && u.platformAdmin:
		// Served without tenant groups: a partial list would not be the
		// membership, and admin does not need it.
		return nil
	case err != nil:
		return fmt.Errorf("%w: %v", ErrPrincipalAuthzUnavailable, err)
	case len(unreadable) > 0:
		return fmt.Errorf("%w: tenants %v could not be read", ErrPrincipalAuthzUnavailable, unreadable)
	}
	// A tenant named "admins" grants nothing by membership: legacy and
	// shadow filter it the same way (tenantsOnly), and a platform admin
	// reaches it as admin. Granting it here would be a privilege change at
	// the switch that the shadow comparison, which drops "admins" from both
	// sides, could not report.
	u.Groups = tenantsOnly(namespaces)
	return nil
}

// NewFederatedUser builds a caller proven by a federated OIDC provider
// (MCTL_OIDC_PROVIDERS), with no groups. Exported for tests, like
// NewServiceUser; only the middleware mints one from a verified token.
func NewFederatedUser(provider, issuer, subject, display, kind string) *User {
	return &User{ID: display, oidcProviderName: provider, oidcIssuer: issuer, oidcSubject: subject, oidcKind: kind}
}

// HasRole reports whether u holds a platform role binding's role. "admins"
// is platform admin, decided by IsAdmin; any other role is a group name.
// In principal mode a tenant named "admins" therefore never matches the
// admins role, and in legacy mode the two readings agree.
func (u *User) HasRole(role string) bool {
	if u == nil {
		return false
	}
	if role == "admins" {
		return u.IsAdmin()
	}
	for _, g := range u.Groups {
		if g == role {
			return true
		}
	}
	return false
}
