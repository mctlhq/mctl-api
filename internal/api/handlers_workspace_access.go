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
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

var workspaceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,49}$`)

// WorkspaceAccess is a read-only observation for the portal's readiness check.
// It grants nothing and never changes the production authorization mode.
type WorkspaceAccess struct {
	Version        int                    `json:"version"`
	Tenant         string                 `json:"tenant"`
	PrincipalID    string                 `json:"principalId"`
	Role           string                 `json:"role"`
	ObservedAt     string                 `json:"observedAt"`
	Infrastructure string                 `json:"infrastructure"`
	Environments   []WorkspaceEnvironment `json:"environments"`
	Portal         string                 `json:"portal"`
	MCP            string                 `json:"mcp"`
}

type WorkspaceEnvironment struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Status    string `json:"status"`
}

// ObserveWorkspaceAccess accepts only the portal service, naming a canonical
// principal in its actor header. The portal authorizes its browser caller
// separately; this service-to-service observation is not a relay credential.
func (h *Handlers) ObserveWorkspaceAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u := auth.UserFromContext(r.Context())
	if u == nil {
		writeError(w, 401, "authentication required")
		return
	}
	if surface, ok := u.Surface(); !ok || surface != surfaceid.SurfacePortal {
		writeErrorCode(w, 403, sidCodePortalOnly, "only the portal may observe workspace access", nil)
		return
	}
	pid, principalActor := strings.CutPrefix(r.Header.Get(SurfaceActorHeader), "principal:")
	tenant := chi.URLParam(r, "tenant")
	if !principalActor || !auth.ValidPrincipalID(pid) || !workspaceName.MatchString(tenant) {
		writeErrorCode(w, 400, sidCodeInvalid, "a canonical principal actor and workspace name are required", nil)
		return
	}
	unavailable := func(err error) {
		slog.Warn("workspace access observation failed", "tenant", tenant, "error", err)
		writeErrorCode(w, 503, "workspace_access_unknown", "workspace access could not be verified; retry later", nil)
	}
	checker, ok := h.opts.Principals.(auth.PrincipalChecker)
	if !ok || h.opts.PrincipalMembership == nil || h.opts.ArgoCD == nil || h.opts.QuotaReader == nil {
		unavailable(errors.New("readiness sources not configured"))
		return
	}
	if err := checker.CheckPrincipal(r.Context(), pid); err != nil {
		if errors.Is(err, auth.ErrPrincipalDisabled) || errors.Is(err, auth.ErrIdentityRefused) {
			writeErrorCode(w, 403, "workspace_access_refused", "the principal may not access this workspace", nil)
			return
		}
		unavailable(err)
		return
	}
	members, read, err := h.opts.PrincipalMembership.TryNamespacesForPrincipal(pid)
	if err != nil || !read || len(members.Unreadable) != 0 {
		unavailable(errors.New("principal membership snapshot unavailable or incomplete"))
		return
	}
	if !slices.Contains(members.Namespaces, tenant) {
		writeErrorCode(w, 403, "workspace_access_refused", "the principal is not a member of this workspace", nil)
		return
	}
	written, err := h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, pid)
	if err != nil {
		unavailable(err)
		return
	}
	role, known := operations.EffectiveTenantRole(written)
	if !known || !role.IsTenantRole() {
		unavailable(errors.New("principal role missing or invalid"))
		return
	}
	app, err := h.opts.ArgoCD.GetAppStatus("tenant-" + tenant)
	if err != nil {
		unavailable(err)
		return
	}
	if app == nil || app.Name != "tenant-"+tenant || app.Health == "" || app.SyncStatus == "" {
		unavailable(errors.New("tenant application observation malformed"))
		return
	}
	if !slices.Contains([]string{"Healthy", "Degraded", "Progressing", "Missing", "Suspended"}, app.Health) || !slices.Contains([]string{"Synced", "OutOfSync"}, app.SyncStatus) {
		unavailable(errors.New("tenant application state unknown"))
		return
	}
	result := WorkspaceAccess{Version: 1, Tenant: tenant, PrincipalID: pid, Role: string(role), Infrastructure: "pending", Portal: "blocked", MCP: "blocked"}
	for _, env := range []WorkspaceEnvironment{{Name: "production", Namespace: tenant}, {Name: "preview", Namespace: tenant + "-preview"}} {
		_, hard, err := h.opts.QuotaReader.GetNamespaceUsage(r.Context(), env.Namespace)
		if err != nil {
			unavailable(err)
			return
		}
		env.Status = "pending"
		if hard["requests.cpu"] != "" && hard["limits.cpu"] != "" && hard["requests.memory"] != "" && hard["limits.memory"] != "" && hard["pods"] != "" {
			env.Status = "ready"
		}
		result.Environments = append(result.Environments, env)
	}
	if app.Health == "Healthy" && app.SyncStatus == "Synced" && slices.IndexFunc(result.Environments, func(e WorkspaceEnvironment) bool { return e.Status != "ready" }) == -1 {
		result.Infrastructure = "ready"
	}
	if h.opts.SurfaceZitadel != nil && h.opts.SurfaceZitadel.SigninClientID != "" && h.opts.SurfaceZitadel.CustomersOrgID != "" {
		result.Portal = "configured"
	}
	// Matching membership is not MCP access while shadow/legacy authorizes by
	// login. This mirrors customerSigninPrincipal's launch guard.
	if h.principalMode() && h.opts.PrincipalAuthz != nil && h.opts.PrincipalAuthz.Members != nil && h.opts.OAuthServer != nil && (h.opts.OAuthUpstream == OAuthUpstreamZitadel || h.opts.OAuthUpstream == OAuthUpstreamBoth) && h.opts.OAuthZitadel != nil && h.opts.OAuthZitadel.Issuer != "" && h.opts.OAuthZitadel.ClientID != "" && h.opts.OAuthZitadel.CustomersOrgID != "" {
		namespaces, unreadable, err := h.opts.PrincipalAuthz.Members.PrincipalTenants(pid)
		if err != nil || len(unreadable) != 0 {
			unavailable(errors.New("MCP authorization unavailable"))
			return
		}
		if slices.Contains(namespaces, tenant) {
			result.MCP = "available"
		}
	}
	result.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, result)
}
