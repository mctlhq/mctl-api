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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

func (h *Handlers) Whoami(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	groups := uniquePreserveOrder(user.Groups)

	// Build list of accessible Argo Workflow namespaces.
	var namespaces []string
	for _, g := range groups {
		if g == "admins" {
			continue
		}
		namespaces = append(namespaces, g)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         user.ID,
		"groups":     groups,
		"isAdmin":    user.IsAdmin(),
		"namespaces": namespaces,
	})
}

func uniquePreserveOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// Logout acknowledges a logout request. Since access tokens are stateless JWTs,
// they cannot be actively invalidated — they expire naturally within 1 hour.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "logged out",
		"note":    "Stateless JWT tokens expire naturally within 1 hour. Discard the token on the client side.",
	})
}

func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil || !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "listing all tenants requires admin access")
		return
	}
	tenants, err := h.opts.GitReader.ListTenants()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenants: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": tenants,
		"count": len(tenants),
	})
}

func (h *Handlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	name := chi.URLParam(r, "name")
	if !user.IsAdmin() && !user.HasTenantAccess(name) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	tenant, err := h.opts.GitReader.GetTenant(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+name)
		return
	}
	services, _ := h.opts.GitReader.ListServices(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":   tenant,
		"services": services,
	})
}

func (h *Handlers) ListServices(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	teamFilter := r.URL.Query().Get("team")
	all, err := h.opts.GitReader.ListServices(teamFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list services: "+err.Error())
		return
	}

	var services []interface{}
	for _, svc := range all {
		if !user.IsAdmin() && !user.HasTenantAccess(svc.Team) {
			continue
		}
		services = append(services, svc)
	}
	if services == nil {
		services = []interface{}{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": services,
		"count": len(services),
	})
}

func (h *Handlers) GetService(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	svc, err := h.opts.GitReader.GetService(team, app)
	if err != nil {
		writeError(w, http.StatusNotFound, "service not found: "+team+"/"+app)
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

func (h *Handlers) GetServiceStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	svc, _ := h.opts.GitReader.GetService(team, app)

	// ArgoCD app naming convention: {team}-{app} (or preview-{team}-{app})
	argoAppName := team + "-" + app
	status, err := h.opts.ArgoCD.GetAppStatus(argoAppName)
	if err != nil {
		if errors.Is(err, argocd.ErrUnauthenticated) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"argocd":  nil,
				"service": svc,
				"error":   "ArgoCD token invalid or expired — update ARGOCD_TOKEN in Vault at platform/mctl-api/argocd-token",
			})
			return
		}
		// 403 or 404 — try preview app name
		status, err = h.opts.ArgoCD.GetAppStatus("preview-" + argoAppName)
		if err != nil {
			if errors.Is(err, argocd.ErrUnauthenticated) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"argocd":  nil,
					"service": svc,
					"error":   "ArgoCD token invalid or expired — update ARGOCD_TOKEN in Vault at platform/mctl-api/argocd-token",
				})
				return
			}
			// App not found in ArgoCD — return service info without ArgoCD status
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"argocd":  nil,
				"service": svc,
				"note":    "ArgoCD application not found: " + argoAppName + " (service may not be deployed yet or uses a different naming convention)",
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"argocd":  status,
		"service": svc,
	})
}

func (h *Handlers) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	teamFilter := r.URL.Query().Get("team")

	// Get workflows from audit log, filtered by team access.
	entries := h.opts.AuditLog.List(50)
	var items []map[string]interface{}
	for i := range entries {
		e := &entries[i]
		if e.WorkflowName == "" {
			continue
		}
		team := auditEntryTenant(e)
		if !user.IsAdmin() && team != "" && !user.HasTenantAccess(team) {
			continue
		}
		if teamFilter != "" && team != teamFilter {
			continue
		}
		items = append(items, map[string]interface{}{
			"workflowName": e.WorkflowName,
			"operation":    e.Operation,
			"status":       e.Status,
			"team":         team,
			"user":         e.UserID,
			"timestamp":    e.Timestamp,
		})
	}
	if items == nil {
		items = []map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}

func (h *Handlers) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Check audit log for a record of this workflow to determine the namespace and team.
	entry := h.opts.AuditLog.GetByWorkflow(name)
	if entry == nil {
		writeError(w, http.StatusNotFound, "workflow record not found in audit log")
		return
	}

	// Enforce team namespace access.
	team := auditEntryTenant(entry)
	if !user.IsAdmin() && team != "" && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied: workflow belongs to team "+team)
		return
	}

	// Route status lookups to the same namespace where the workflow was
	// submitted. We prefer the Registry → WorkflowTemplate mapping because the
	// audit entry records the op name, which can differ from the template
	// (e.g. op "delete-tenant" uses template "delete-tenant-safe").
	namespace := team
	if op, ok := h.opts.Registry.Get(entry.Operation); ok {
		namespace = operations.WorkflowNamespace(op.WorkflowTemplate, team)
	} else {
		// Audit stored a template name directly (legacy) — route on that.
		namespace = operations.WorkflowNamespace(entry.Operation, team)
	}

	// Fetch live status from Kubernetes.
	wf, err := h.opts.Executor.GetWorkflowStatus(r.Context(), namespace, name)
	if err != nil {
		// Fallback to audit log only if live fetch fails.
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow":  name,
			"audit":     entry,
			"namespace": namespace,
			"note":      "Live status unavailable: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow":  name,
		"audit":     entry,
		"namespace": namespace,
		"live":      wf,
	})
}

func (h *Handlers) ListPreviews(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := r.URL.Query().Get("team")
	service := r.URL.Query().Get("service")

	if team == "" {
		writeError(w, http.StatusBadRequest, "team query parameter is required")
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Preview ArgoCD apps follow the naming convention: preview-{team}-{service}-{id}
	// List all apps in the team's project and filter for preview prefix.
	apps, err := h.opts.ArgoCD.ListApps(team)
	if err != nil {
		if errors.Is(err, argocd.ErrUnauthenticated) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
				"error": "ArgoCD token invalid or expired — update ARGOCD_TOKEN in Vault at platform/mctl-api/argocd-token",
			})
			return
		}
		if errors.Is(err, argocd.ErrForbidden) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
				"note":  "ArgoCD access denied for project: " + team,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"items": []interface{}{},
			"count": 0,
			"note":  "ArgoCD query failed: " + err.Error(),
		})
		return
	}

	prefix := "preview-" + team + "-"
	if service != "" {
		prefix = "preview-" + team + "-" + service + "-"
	}

	var previews []argocd.AppStatus
	for i := range apps {
		if strings.HasPrefix(apps[i].Name, prefix) {
			previews = append(previews, apps[i])
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": previews,
		"count": len(previews),
		"team":  team,
	})
}

func (h *Handlers) GetResourceUsage(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tenant := chi.URLParam(r, "tenant")
	if !user.IsAdmin() && !user.HasTenantAccess(tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	t, err := h.opts.GitReader.GetTenant(tenant)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+tenant)
		return
	}

	resp := map[string]interface{}{
		"tenant":    tenant,
		"allocated": t.Quotas,
		"used":      map[string]string{},
	}

	if h.opts.QuotaReader != nil {
		used, _, quotaErr := h.opts.QuotaReader.GetNamespaceUsage(r.Context(), tenant)
		if quotaErr == nil && used != nil {
			resp["used"] = used
		} else if quotaErr != nil {
			resp["note"] = "quota fetch error: " + quotaErr.Error()
		}
	} else {
		resp["note"] = "Live usage metrics require in-cluster deployment"
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) GetServiceLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}

	since := time.Hour
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			since = d
		}
	}

	resp := map[string]interface{}{
		"team": team,
		"app":  app,
	}

	if h.opts.LogQuerier == nil {
		resp["lines"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Log querying requires in-cluster deployment with Loki (set LOKI_URL)"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	logLines, err := h.opts.LogQuerier.QueryRange(r.Context(), team, app, lines, since)
	if err != nil {
		resp["lines"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Loki query error: " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp["lines"] = logLines
	resp["count"] = len(logLines)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) ListAudit(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	entries := h.opts.AuditLog.List(50)
	var items []interface{}
	for i := range entries {
		team := auditEntryTenant(&entries[i])
		if !user.IsAdmin() && team != "" && !user.HasTenantAccess(team) {
			continue
		}
		items = append(items, entries[i])
	}
	if items == nil {
		items = []interface{}{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}

func (h *Handlers) ListOperations(w http.ResponseWriter, r *http.Request) {
	ops := h.opts.Registry.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": ops,
		"count": len(ops),
	})
}

func (h *Handlers) GetOperation(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	op, ok := h.opts.Registry.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "operation not found: "+name)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

// auditEntryTenant extracts the tenant/team from an audit entry's parameters.
func auditEntryTenant(entry *audit.Entry) string {
	if entry == nil || entry.Parameters == nil {
		return ""
	}
	for _, key := range []string{"tenant_name", "team_name"} {
		if v, ok := entry.Parameters[key]; ok && v != "" {
			return v
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
