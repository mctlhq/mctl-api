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

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/wire"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// requireGlovoTenantOwner is the strict owner check of the installation
// routes. It reads the principal-mode role through MemberRolesForPrincipal and
// admits only the tenant role owner. It never consults roleGate, so
// user.IsAdmin() adds nothing: a platform admin who is not a tenant owner is
// refused, and an owner who is also an admin is judged by the owner role
// alone. Agents, services, relayed and surface identities and Glovo-audience
// tokens are refused.
func (h *Handlers) requireGlovoTenantOwner(w http.ResponseWriter, r *http.Request, route, tenant string) (glovo.Actor, bool) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		glovo.WriteUnauthenticated(w, "")
		return glovo.Actor{}, false
	}
	deny := func(c glovo.Code) (glovo.Actor, bool) {
		_ = glovoRefuse(w, route, glovo.Refuse(c), "tenant", tenant)
		return glovo.Actor{}, false
	}
	id, human := user.Identity()
	_, relayed := user.RelaySurface()
	_, surface := user.Surface()
	if !human || id.Kind != auth.KindHuman || user.IsAgent() || user.IsService() || relayed || surface ||
		user.IsGlovoAudience() || user.IsGlovoWorker() || user.IsGlovoFacade() {
		return deny(glovo.CodeNotAuthorized)
	}
	prn := user.PrincipalID()
	if prn == "" || !auth.ValidPrincipalID(prn) {
		return deny(glovo.CodeNotAuthorized)
	}
	if h.opts.TenantAuthzMode != TenantAuthzPrincipal || h.opts.PrincipalMembership == nil {
		return deny(glovo.CodeNotReady)
	}
	roles, err := h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, prn)
	if err != nil {
		_ = glovoRefuse(w, route, err, "tenant", tenant)
		return glovo.Actor{}, false
	}
	role, known := operations.EffectiveTenantRole(roles)
	if !known || role != operations.RoleOwner {
		return deny(glovo.CodeNotAuthorized)
	}
	return glovo.Actor{PrincipalID: prn, Kind: glovo.ActorOwner}, true
}

func glovoInstallation(tenant string, i *glovo.Install) wire.Installation {
	return wire.Installation{
		Schema: wire.SchemaInstallation, Tenant: tenant, InstallationID: i.InstallID,
		InstallRevision: i.InstallRevision, State: string(i.State),
	}
}

// GlovoInstallationPut handles PUT /api/v1/glovo/tenants/{tenant}/installation.
// With no install it creates one at revision 1 (201). With an install it
// reinstalls: the revision rises by one and every live connection of the
// tenant bound to an older revision is revoked in the same transaction (200).
func (h *Handlers) GlovoInstallationPut(w http.ResponseWriter, r *http.Request) {
	const route = "installation_put"
	tenant := chi.URLParam(r, "tenant")
	actor, ok := h.requireGlovoTenantOwner(w, r, route, tenant)
	if !ok {
		return
	}
	var body wire.InstallationRequest
	if e := wire.Decode(w, r, &body, wire.SchemaInstallationReq, true); e != nil {
		_ = glovoRefuse(w, route, e)
		return
	}
	store := h.glovoRoutes().Store
	cur, err := store.InstallRow(r.Context(), tenant)
	if err != nil {
		_ = glovoRefuse(w, route, err)
		return
	}
	if cur == nil {
		inst, err := store.Install(r.Context(), tenant, actor)
		if err != nil {
			_ = glovoRefuse(w, route, err, "tenant", tenant)
			return
		}
		writeJSON(w, http.StatusCreated, glovoInstallation(tenant, inst))
		return
	}
	expected := cur.InstallRevision
	if body.InstallRevision != nil {
		expected = *body.InstallRevision
	}
	inst, _, err := store.Reinstall(r.Context(), tenant, actor, expected)
	if err != nil {
		ge := glovoRefuse(w, route, err, "tenant", tenant)
		h.glovoAuditRefusal(r.Context(), ge, tenant, "install", cur.InstallID, actor)
		return
	}
	writeJSON(w, http.StatusOK, glovoInstallation(tenant, inst))
}

// GlovoInstallationDelete handles DELETE /api/v1/glovo/tenants/{tenant}/installation:
// the tenant is uninstalled and every live connection of it is revoked in the
// same transaction.
func (h *Handlers) GlovoInstallationDelete(w http.ResponseWriter, r *http.Request) {
	const route = "installation_delete"
	tenant := chi.URLParam(r, "tenant")
	actor, ok := h.requireGlovoTenantOwner(w, r, route, tenant)
	if !ok {
		return
	}
	store := h.glovoRoutes().Store
	cur, err := store.InstallRow(r.Context(), tenant)
	if err != nil {
		_ = glovoRefuse(w, route, err)
		return
	}
	if cur == nil || cur.State != glovo.InstallInstalled {
		_ = glovoRefuse(w, route, glovo.Refuse(glovo.CodeNoInstall), "tenant", tenant)
		return
	}
	inst, _, err := store.RevokeInstall(r.Context(), tenant, actor, "owner_requested", cur.InstallRevision)
	if err != nil {
		ge := glovoRefuse(w, route, err, "tenant", tenant)
		h.glovoAuditRefusal(r.Context(), ge, tenant, "install", cur.InstallID, actor)
		return
	}
	writeJSON(w, http.StatusOK, glovoInstallation(tenant, inst))
}
