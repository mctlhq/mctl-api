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

package operations

import "strings"

// Role is the minimum standing a caller needs to run an operation
// (mctl-api#478). The three tenant roles are the ones a tenant's
// members[].role carries in platform-gitops/tenants/<t>/values.yaml and the
// ones the portal knows (owner | developer | viewer); the other two are not
// tenant roles and never appear in a values file.
type Role string

const (
	// RoleViewer is the read-only tenant role. No write operation accepts
	// it; it exists so that "viewer" is a known role that ranks below every
	// write, rather than an unknown string.
	RoleViewer Role = "viewer"
	// RoleDeveloper may run the ordinary, recoverable writes: deploy,
	// rollback, previews, adding a domain.
	RoleDeveloper Role = "developer"
	// RoleOwner is required for anything destructive or irreversible, and
	// for every RiskHigh operation.
	RoleOwner Role = "owner"
	// RoleAdmin marks an operation only a platform admin may run. It is not
	// a tenant role: no members[].role value satisfies it.
	RoleAdmin Role = "admin"
	// RoleAuthenticated marks the one operation that needs no tenant at all,
	// create-tenant: the caller is making the tenant, so there is no
	// membership to hold a role in. The generic gate refuses it for every
	// other operation.
	RoleAuthenticated Role = "authenticated"
)

// tenantRoleRank orders the tenant roles. A role absent from it (empty,
// misspelled, or one this version does not know) ranks 0, below every
// minimum: an unknown role is never treated as a sufficient one.
var tenantRoleRank = map[Role]int{
	RoleViewer:    1,
	RoleDeveloper: 2,
	RoleOwner:     3,
}

// ParseTenantRole reads a members[].role value. It answers false for
// anything that is not one of the three tenant roles. Case is ignored, as
// the existing owner checks ignored it; nothing else is normalized.
func ParseTenantRole(s string) (Role, bool) {
	r := Role(strings.ToLower(s))
	if _, ok := tenantRoleRank[r]; !ok {
		return "", false
	}
	return r, true
}

// IsTenantRole reports whether r is a role a tenant member can hold.
func (r Role) IsTenantRole() bool {
	_, ok := tenantRoleRank[r]
	return ok
}

// Valid reports whether r is a minimum role an operation may declare.
func (r Role) Valid() bool {
	return r.IsTenantRole() || r == RoleAdmin || r == RoleAuthenticated
}

// Satisfies reports whether a member holding r meets the tenant minimum
// min. It is false whenever either side is not a tenant role, so neither an
// unknown held role nor a non-tenant minimum (admin, authenticated, the
// zero value) can be satisfied through tenant membership.
func (r Role) Satisfies(min Role) bool {
	have, ok := tenantRoleRank[r]
	need, okMin := tenantRoleRank[min]
	return ok && okMin && have >= need
}

// LeastTenantRole returns the least privileged of the given members[].role
// values, and false when there are none or any of them is not a tenant
// role. A login listed twice in one tenant with different roles is thereby
// held to the lower one, and to nothing if either entry is unreadable.
func LeastTenantRole(values []string) (Role, bool) {
	var least Role
	for _, v := range values {
		r, ok := ParseTenantRole(v)
		if !ok {
			return "", false
		}
		if least == "" || tenantRoleRank[r] < tenantRoleRank[least] {
			least = r
		}
	}
	return least, least != ""
}

// EffectiveTenantRole decides the one role a member holds from the roles
// each members list gives them (gitops.Reader.MemberRoles): the tenant-level
// list and, for a multi-team tenant, the list of the team in question.
//
// Inside a list, entries for one login contradict each other, so a list
// counts as its least privileged entry (LeastTenantRole). Across lists the
// grants add up, so the member holds the greatest of them: a tenant-wide
// owner is not lowered by also being a viewer of one team. It answers false
// when no list names the member, and when any list that does carries an
// entry that is not a tenant role, whichever list would otherwise have won:
// an unreadable entry is never outvoted.
func EffectiveTenantRole(scopes [][]string) (Role, bool) {
	var best Role
	for _, scope := range scopes {
		r, ok := LeastTenantRole(scope)
		if !ok {
			return "", false
		}
		if tenantRoleRank[r] > tenantRoleRank[best] {
			best = r
		}
	}
	return best, best != ""
}
