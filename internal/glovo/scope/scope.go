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

// Package scope resolves the tenant scope of a Glovo resource request. The
// resolver takes the authenticated user and nothing else: no header, query
// parameter, body field or tool argument can name a tenant, owner, namespace
// or task queue. The team comes only from the server-held grant the human
// created at consent, re-checked against live membership and the per-principal
// pilot allowlist on every request.
package scope

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Scope is the resolved caller scope.
type Scope struct {
	PrincipalID string
	Tenant      string
	Role        string
	GrantID     string
}

// GrantChecker loads a grant and matches it to the caller. ErrGrantInvalid is
// a refusal; any other error is a store failure.
type GrantChecker interface {
	Check(ctx context.Context, grantID, principalID, clientID, resource string) (teamgrant.Grant, error)
}

// MembershipReader is the principal-keyed membership (gitops.Reader).
type MembershipReader interface {
	TryNamespacesForPrincipal(principalID string) (gitops.PrincipalMembership, bool, error)
	MemberRolesForPrincipal(tenant, principalID string) ([][]string, error)
}

// AllowlistReader is the per-(tenant, principal) pilot allowlist.
type AllowlistReader interface {
	IsAllowlisted(ctx context.Context, tenant, principalID string) (bool, error)
}

// NonSelectable parses a comma-separated GLOVO_NON_SELECTABLE_TENANTS.
func NonSelectable(csv string) map[string]bool {
	out := map[string]bool{}
	for _, v := range strings.Split(csv, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out[v] = true
		}
	}
	return out
}

// Eligibility implements auth.TeamEligibility: live principal-mode
// membership intersected with the allowlist, minus the non-selectable
// tenants. Admin status is never consulted.
type Eligibility struct {
	Membership    MembershipReader
	Allowlist     AllowlistReader
	NonSelectable map[string]bool
}

var _ auth.TeamEligibility = (*Eligibility)(nil)

// role reads the principal's role on tenant: ok false is "read, not a member
// with a known role"; an error is "could not read".
func (e *Eligibility) role(tenant, principalID string) (operations.Role, bool, error) {
	roles, err := e.Membership.MemberRolesForPrincipal(tenant, principalID)
	if err != nil {
		return "", false, err
	}
	if len(roles) == 0 {
		return "", false, nil
	}
	r, known := operations.EffectiveTenantRole(roles)
	return r, known, nil
}

// Has implements auth.TeamEligibility.
func (e *Eligibility) Has(ctx context.Context, principalID, tenant string) (bool, error) {
	if e.NonSelectable[tenant] {
		return false, nil
	}
	_, ok, err := e.role(tenant, principalID)
	if err != nil || !ok {
		return false, err
	}
	return e.Allowlist.IsAllowlisted(ctx, tenant, principalID)
}

// Eligible implements auth.TeamEligibility. A tenant that could not be read
// makes the whole answer an error: a failure never shrinks the list.
func (e *Eligibility) Eligible(ctx context.Context, principalID string) ([]string, error) {
	m, observed, err := e.Membership.TryNamespacesForPrincipal(principalID)
	if err != nil {
		return nil, err
	}
	if !observed {
		return nil, errors.New("membership not observed")
	}
	if len(m.Unreadable) > 0 {
		return nil, fmt.Errorf("membership of %d tenant(s) could not be read", len(m.Unreadable))
	}
	var out []string
	for _, tenant := range m.Namespaces {
		ok, err := e.Has(ctx, principalID, tenant)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, tenant)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Resolver resolves the scope of a Glovo request. Its one entry point has no
// parameter other than the context and the authenticated user.
type Resolver struct {
	Grants   GrantChecker
	Elig     *Eligibility
	Resource string
	// Ready is the kill switch and readiness check (OAuthServer.GlovoReady).
	// Nil or false answers not_ready before anything else is read.
	Ready func() bool
}

func refuse(c glovo.Code) *glovo.Error { return glovo.Refuse(c) }

// Resolve implements steps 1-7 of the scope contract. A failing read is
// unavailable (503), never a refusal code.
func (r *Resolver) Resolve(ctx context.Context, u *auth.User) (Scope, *glovo.Error) {
	if r == nil || r.Grants == nil || r.Elig == nil || r.Elig.Membership == nil || r.Elig.Allowlist == nil || r.Resource == "" || r.Ready == nil || !r.Ready() {
		return Scope{}, refuse(glovo.CodeNotReady)
	}
	// 1. A human principal with a Glovo-only audience: not an agent run,
	// service, CI job, support token or relayed surface identity.
	if err := (glovo.Gate{Open: true}).Authorize(u); err != nil {
		var ge *glovo.Error
		if errors.As(err, &ge) {
			return Scope{}, ge
		}
		return Scope{}, refuse(glovo.CodeNotAuthorized)
	}
	prn := u.PrincipalID()
	// 2. The signed claims name a grant.
	grantID, tenant, ok := u.TeamGrant()
	if !ok {
		return Scope{}, refuse(glovo.CodeAmbiguousTenant)
	}
	// 3. The server-held grant matches the token.
	g, err := r.Grants.Check(ctx, grantID, prn, u.OAuthClientID(), r.Resource)
	if errors.Is(err, teamgrant.ErrGrantInvalid) {
		return Scope{}, refuse(glovo.CodeAmbiguousTenant)
	}
	if err != nil {
		return Scope{}, refuse(glovo.CodeUnavailable)
	}
	if g.Tenant != tenant {
		return Scope{}, refuse(glovo.CodeAmbiguousTenant)
	}
	// 4. System-only tenants, and anything that is not a team, are not
	// selectable. There is no personal scope in M1.
	if r.Elig.NonSelectable[g.Tenant] {
		return Scope{}, refuse(glovo.CodeScopeUnsupported)
	}
	// 5. Live membership; admin status is not consulted.
	role, member, err := r.Elig.role(g.Tenant, prn)
	if err != nil {
		return Scope{}, refuse(glovo.CodeUnavailable)
	}
	if !member {
		return Scope{}, refuse(glovo.CodeNoTenant)
	}
	// 6. Per-principal pilot allowlist.
	listed, err := r.Elig.Allowlist.IsAllowlisted(ctx, g.Tenant, prn)
	if err != nil {
		return Scope{}, refuse(glovo.CodeUnavailable)
	}
	if !listed {
		return Scope{}, refuse(glovo.CodeNotInPilot)
	}
	// 7.
	return Scope{PrincipalID: prn, Tenant: g.Tenant, Role: string(role), GrantID: g.ID}, nil
}
