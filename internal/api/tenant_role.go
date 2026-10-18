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
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Minimum roles for the writes decided in mctl-api#489. Each is the only
// place its minimum is declared.
const (
	// workItemWriteRole: every work-item write a person or surface makes
	// (create, transition, intent, execution, surface-ref). viewer passes none.
	workItemWriteRole = operations.RoleDeveloper
	// workItemExecutionRole: asking the platform to run work (resume and
	// execution requests).
	workItemExecutionRole = operations.RoleDeveloper
	// reposSyncRole: POST /repos/sync. The portal plugin must match it.
	reposSyncRole = operations.RoleDeveloper
)

// Tenant role gate (mctl-api#478).
//
// Tenant membership says a caller may see a tenant; it does not say what
// they may do to it. Every tenant-scoped write therefore also asks for a
// minimum role, and the role is read here, at the moment of the decision,
// from the same members list in the gitops checkout that granted the
// membership.
//
// The role is deliberately not carried in a token. Groups reach a caller by
// several routes (a GitHub token, an mctl-issued JWT minted after the GitHub
// or the ZITADEL sign-in, a surface relay, an agent delegation), some of
// them snapshots taken at sign-in. Reading the role per request gives all of
// them the same answer, makes a token issued before this change behave like
// one issued after it, and lets a role that was taken away stop working
// within the checkout's refresh interval instead of at token expiry.
//
// In principal mode (TENANT_AUTHZ_MODE=principal, the current mode) the role
// is read by the caller's prn_ principal from members[].principalId, so a
// GitHub, ZITADEL or other OIDC human is decided alike and non-human callers
// hold no tenant role.
//
// In legacy and shadow mode (rollback modes) the lookup is keyed on a GitHub
// login that authentication proved, because members[].userId is a GitHub
// login. A caller whose identity is something else (a Dex or other OIDC
// token, whose name can equal a member's login without being that person) has
// no role there and is refused: unknown is never owner.

// roleRefusal describes why a caller may not perform a tenant write. Its
// zero value means the caller may proceed.
type roleRefusal struct {
	status      int    // HTTP status; 0 when allowed
	message     string // what the caller is told
	auditStatus string // "denied" for a decision, "error" when no decision could be made
	detail      string // audit and log detail; never sent to the caller
}

func (d roleRefusal) refused() bool { return d.status != 0 }

// checkTenantRole decides whether user may perform, on tenant, a write that
// needs min. The caller has already established that user has access to
// tenant. Platform admins pass every minimum, as they pass
// HasTenantAccess.
//
// Every way of not knowing the role is a refusal, and the ones where the
// role could not be read are 503 rather than 403: "we could not check" is
// kept apart from "you are not allowed", and neither is a pass.
func (h *Handlers) checkTenantRole(user *auth.User, tenant string, min operations.Role, what string) roleRefusal {
	if h.opts.TenantAuthzMode == TenantAuthzPrincipal {
		return h.checkTenantRoleByPrincipal(user, tenant, min, what)
	}
	d := h.checkTenantRoleByLogin(user, tenant, min, what)
	if h.opts.TenantAuthzMode == TenantAuthzShadow {
		h.shadowTenantRole(user, tenant, min, d)
	}
	return d
}

// checkTenantRoleByLogin is the login-keyed decision, the one that
// authorizes in legacy and shadow mode (mctl-api#377).
func (h *Handlers) checkTenantRoleByLogin(user *auth.User, tenant string, min operations.Role, what string) roleRefusal {
	if d, decided := roleGate(user, min, what); decided {
		return d
	}
	login, proven := user.GitHubLogin()
	if !proven {
		return roleRefusal{
			status: http.StatusForbidden,
			message: fmt.Sprintf("%s requires role %q on tenant %q; your sign-in does not carry a tenant role. Sign in with your platform (GitHub-linked) account.",
				what, min, tenant),
			auditStatus: "denied",
			detail:      fmt.Sprintf("user %q has no GitHub-proven login, so no tenant role on %q; %q required", user.ID, tenant, min),
		}
	}
	var read func() ([][]string, error)
	if h.opts.GitReader != nil {
		read = func() ([][]string, error) { return h.opts.GitReader.MemberRoles(tenant, login) }
	}
	return decideWrittenRole(login, "gitops reader", tenant, min, what, read)
}

// checkTenantRoleByPrincipal is the principal-keyed decision of principal
// mode: the role GitOps writes for the caller's principal, read with no
// login at all. A human without a resolved principal is 503 (the
// middleware already refuses one; this is the second line), a non-human
// caller holds no tenant role.
func (h *Handlers) checkTenantRoleByPrincipal(user *auth.User, tenant string, min operations.Role, what string) roleRefusal {
	if d, decided := roleGate(user, min, what); decided {
		return d
	}
	id, ok := user.Identity()
	if !ok || id.Kind != auth.KindHuman {
		return roleRefusal{
			status:      http.StatusForbidden,
			message:     fmt.Sprintf("%s requires role %q on tenant %q; your sign-in does not carry a tenant role", what, min, tenant),
			auditStatus: "denied",
			detail:      fmt.Sprintf("caller %q is not a human principal, so no tenant role on %q; %q required", user.ID, tenant, min),
		}
	}
	prn := user.PrincipalID()
	if prn == "" {
		return roleRefusal{
			status:      http.StatusServiceUnavailable,
			message:     fmt.Sprintf("cannot verify your role on tenant %q right now; try again later", tenant),
			auditStatus: "error",
			detail:      fmt.Sprintf("role of %q on %q not read: principal not resolved", user.ID, tenant),
		}
	}
	var read func() ([][]string, error)
	if h.opts.PrincipalMembership != nil {
		read = func() ([][]string, error) { return h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, prn) }
	}
	return decideWrittenRole(prn, "principal membership reader", tenant, min, what, read)
}

// roleGate is what every tenant-role decision settles before reading a
// role: an admin passes, an admin-only action refuses anyone else, and a
// minimum that is no tenant role refuses everyone.
func roleGate(user *auth.User, min operations.Role, what string) (roleRefusal, bool) {
	if user.IsAdmin() {
		return roleRefusal{}, true
	}
	if min == operations.RoleAdmin {
		return roleRefusal{
			status:      http.StatusForbidden,
			message:     what + " requires a platform admin",
			auditStatus: "denied",
			detail:      fmt.Sprintf("user %q is not a platform admin; %s is admin-only", user.ID, what),
		}, true
	}
	if !min.IsTenantRole() {
		// A tenant write with no tenant minimum is a registry or handler
		// bug. Refusing it is the only safe reading of "nobody decided".
		return roleRefusal{
			status:      http.StatusInternalServerError,
			message:     what + " has no minimum role configured; refusing to run it",
			auditStatus: "error",
			detail:      fmt.Sprintf("minimum role %q of %s is not a tenant role", min, what),
		}, true
	}
	return roleRefusal{}, false
}

// decideWrittenRole decides min on tenant from the roles read for who (a
// login or a principal id). A nil read means reader, the option that would
// have answered, is not configured.
func decideWrittenRole(who, reader, tenant string, min operations.Role, what string, read func() ([][]string, error)) roleRefusal {
	unavailable := roleRefusal{
		status:      http.StatusServiceUnavailable,
		message:     fmt.Sprintf("cannot verify your role on tenant %q right now; try again later", tenant),
		auditStatus: "error",
	}
	if read == nil {
		unavailable.detail = fmt.Sprintf("role of %q on %q not read: %s not configured", who, tenant, reader)
		return unavailable
	}
	written, err := read()
	if err != nil {
		// The error can carry checkout paths; it goes to the log and the
		// audit entry, not to the caller.
		unavailable.detail = fmt.Sprintf("role of %q on %q not read: %v", who, tenant, err)
		return unavailable
	}
	if len(written) == 0 {
		// The caller's groups say member, the checkout says not: a session
		// that outlived the membership. Not a member is not a role.
		return roleRefusal{
			status:      http.StatusForbidden,
			message:     fmt.Sprintf("%s requires role %q on tenant %q; you are not listed as a member of it", what, min, tenant),
			auditStatus: "denied",
			detail:      fmt.Sprintf("user %q is not in the members of tenant %q; %q required", who, tenant, min),
		}
	}
	role, known := operations.EffectiveTenantRole(written)
	if !known {
		return roleRefusal{
			status:      http.StatusForbidden,
			message:     fmt.Sprintf("%s requires role %q on tenant %q; your role there is missing or not recognized", what, min, tenant),
			auditStatus: "denied",
			detail:      fmt.Sprintf("user %q has unrecognized role(s) %q on tenant %q; %q required", who, written, tenant, min),
		}
	}
	if !role.Satisfies(min) {
		return roleRefusal{
			status:      http.StatusForbidden,
			message:     fmt.Sprintf("%s requires role %q on tenant %q; your role is %q", what, min, tenant, role),
			auditStatus: "denied",
			detail:      fmt.Sprintf("user %q has role %q on tenant %q; %q required", who, role, tenant, min),
		}
	}
	return roleRefusal{}
}

// requireTenantRole runs checkTenantRole and, on a refusal, records it in
// the audit log, writes the response, and answers false. operation names
// the audit entry; what is how the response describes the action.
func (h *Handlers) requireTenantRole(w http.ResponseWriter, r *http.Request, user *auth.User, tenant string, min operations.Role, operation string, risk operations.RiskLevel) bool {
	d := h.checkTenantRole(user, tenant, min, "operation \""+operation+"\"")
	if !d.refused() {
		return true
	}
	h.auditRoleRefusal(r, user, tenant, operation, risk, d)
	writeError(w, d.status, d.message)
	return false
}

// operationMinRole is the registry's minimum role for the named operation,
// for a handler that performs that operation without going through the
// generic execute path. The registry is the single place a minimum is
// declared; fallback is used only where no registry is wired (tests, a
// local run), and is never used to override a registry entry, even one
// whose MinRole is unset: that reaches the gate as it is and is refused.
func (h *Handlers) operationMinRole(name string, fallback operations.Role) operations.Role {
	if h.opts.Registry == nil {
		return fallback
	}
	op, ok := h.opts.Registry.Get(name)
	if !ok {
		return fallback
	}
	return op.MinRole
}

// auditRoleRefusal logs and audits a refused tenant-role decision. It is
// shared by requireTenantRole and requireWorkItemRole.
func (h *Handlers) auditRoleRefusal(r *http.Request, user *auth.User, tenant, operation string, risk operations.RiskLevel, d roleRefusal) {
	if d.auditStatus == "error" {
		slog.Error("tenant role check could not be completed", "operation", operation, "tenant", tenant, "user", user.ID, "detail", d.detail)
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  operation,
		Parameters: map[string]string{"tenant": tenant},
		Status:     d.auditStatus,
		RiskLevel:  string(risk),
		Message:    d.detail,
	})
}
