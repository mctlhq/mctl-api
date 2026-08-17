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
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/mctlhq/mctl-api/internal/argoarchive"
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

	// Accessible Argo Workflow namespaces. "admins" used to be filtered out
	// here on the theory that it names a role rather than a tenant, but the
	// admins namespace does exist — it is a real tenant in
	// platform-gitops/tenants/admins and it runs mctl-agents-worker and the
	// mctl-api workflows. Hiding it made whoami under-report where an admin
	// can actually submit work.
	//
	// This field is informational: nothing authorizes against it. Access
	// checks read user.Groups directly (auth.User.IsAdmin, HasTenantAccess),
	// and the "one team per user" rule for create-tenant is enforced
	// separately by filterNonAdmin in handlers_write.go.
	namespaces := groups

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

// ListAgentRuns returns recent mctl-agents-* operations from the audit log.
// Admin-only — same gate as the corresponding MCP triggers.
// Mirrors ListWorkflows but filters to operation names starting with
// "mctl-agents-" and enriches each item with mode / service from the
// recorded parameters so the caller doesn't need to look them up.
func (h *Handlers) ListAgentRuns(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "admin group membership required")
		return
	}

	// Operator-initiated runs from the audit log. Don't cap here —
	// merge with cron-driven runs first, then sort+truncate so the
	// response shows the actual most-recent activity.
	entries := h.opts.AuditLog.List(50)
	items := []map[string]interface{}{}
	for i := range entries {
		e := &entries[i]
		if !strings.HasPrefix(e.Operation, "mctl-agents-") {
			continue
		}
		mode, service := "", ""
		if e.Parameters != nil {
			mode = e.Parameters["mode"]
			service = e.Parameters["service"]
		}
		items = append(items, map[string]interface{}{
			"workflowName": e.WorkflowName,
			"operation":    e.Operation,
			"mode":         mode,
			"service":      service,
			"status":       e.Status,
			"user":         e.UserID,
			// Format timestamp as RFC3339 string so the merge-sort
			// comparator (string compare) sees uniform types — cron
			// items already arrive as Z-suffixed RFC3339 strings.
			// audit.Entry.Timestamp is a time.Time, so without this
			// the type assertion in the comparator falls through to
			// "" and operator entries always sort last.
			"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
			"riskLevel": e.RiskLevel,
			"message":   e.Message,
			"source":    "operator",
		})
	}

	// Cron-driven runs from Argo Workflow API. The audit log only
	// records operator triggers (REST POST → Append), so without
	// this the response misses every scheduled mctl-agents-daily /
	// mctl-agents-shepherd firing. Limit to 14d so the merge stays
	// bounded; degrade gracefully on lookup errors instead of
	// failing the whole response — the operator panel still wants
	// audit-log data even if the cluster API is briefly unreachable.
	since := time.Now().Add(-14 * 24 * time.Hour)
	cronItems, err := h.opts.Executor.ListCronAgentRuns(r.Context(), cronWorkflowNamespace, "mctl-agents-", since)
	if err != nil {
		slog.Warn("ListCronAgentRuns failed; returning audit-only view",
			"error", err)
	} else {
		items = append(items, cronItems...)
	}

	// Sort by timestamp descending (newest first), then cap at 10.
	sort.SliceStable(items, func(i, j int) bool {
		ti, _ := items[i]["timestamp"].(string)
		tj, _ := items[j]["timestamp"].(string)
		// RFC3339 is lexicographically sortable when both values
		// have identical fractional-second precision; the audit
		// log and Argo both emit Zulu-suffixed RFC3339 without
		// fractional seconds, so direct string compare is safe.
		return ti > tj
	})
	if len(items) > 10 {
		items = items[:10]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
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

// cronWorkflowNamespace is where every mctl-agents-* CronWorkflow spawns its
// child Workflows, regardless of which service-agent it targets. It is not
// derived from operations.WorkflowNamespace because cron runs are created by
// Argo's CronWorkflow controller directly, bypassing Submit() entirely.
const cronWorkflowNamespace = "argo-workflows"

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
		// The audit log only records operator-initiated submissions
		// (mctl-api REST POST -> AuditLog.Append); every cron-driven run
		// (mctl-agents-issue-poll, -implement, -run, -shepherd, ...) is
		// spawned directly by Argo's CronWorkflow controller and never
		// appears here. Rather than 404 those outright, fall back to a
		// live k8s lookup in the namespace ListAgentRuns already assumes
		// all mctl-agents cron runs live in. Admin-only: without an audit
		// entry we cannot verify team ownership, mirroring the gate
		// GetWorkflowLogs uses for the same situation.
		if !user.IsAdmin() {
			writeError(w, http.StatusNotFound, "workflow record not found in audit log")
			return
		}
		wf, err := h.opts.Executor.GetWorkflowStatus(r.Context(), cronWorkflowNamespace, name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "workflow record not found in audit log, and no live workflow found in namespace "+cronWorkflowNamespace)
				return
			}
			// A non-NotFound error here means the live lookup itself failed
			// (RBAC denied, API server unreachable, timeout) — the workflow
			// may well exist. Collapsing this into the same 404 as a genuine
			// absence reads as "no such workflow" during an incident, when
			// the real story is "the cluster couldn't be asked." Log the
			// detail server-side rather than pasting it into the response.
			slog.Warn("live workflow lookup failed for cron fallback",
				"workflow", name, "namespace", cronWorkflowNamespace, "error", err)
			writeError(w, http.StatusBadGateway, "workflow record not found in audit log, and live lookup in namespace "+cronWorkflowNamespace+" failed (cluster-side error, workflow may still exist)")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow":  name,
			"namespace": cronWorkflowNamespace,
			"live":      wf,
			"note":      "No audit log entry — this is expected for cron-driven runs, which Argo's CronWorkflow controller spawns directly. Status fetched live from Kubernetes.",
		})
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
	var namespace string
	if op, ok := h.opts.Registry.Get(entry.Operation); ok {
		namespace = operations.WorkflowNamespace(op.WorkflowTemplate, team)
	} else {
		// Audit stored a template name directly (legacy) — route on that.
		namespace = operations.WorkflowNamespace(entry.Operation, team)
	}

	// Mask sensitive parameter values before exposing the audit entry to
	// the client (see internal/audit/redact.go).
	redactedEntry := audit.RedactEntry(*entry)

	// Fetch live status from Kubernetes.
	wf, err := h.opts.Executor.GetWorkflowStatus(r.Context(), namespace, name)
	if err != nil {
		// Fallback to audit log only if live fetch fails. Distinguish a
		// genuine absence from a cluster-side failure (RBAC denied, API
		// server unreachable) so the note doesn't read as "gone" when the
		// real story is "couldn't check."
		var note string
		if apierrors.IsNotFound(err) {
			note = "Live status unavailable: " + err.Error()
		} else {
			note = "Live status unavailable (cluster-side error, not confirmed missing): " + err.Error()
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow":  name,
			"audit":     redactedEntry,
			"namespace": namespace,
			"note":      note,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow":  name,
		"audit":     redactedEntry,
		"namespace": namespace,
		"live":      wf,
	})
}

// maxLogBodiesPerRequest caps how many step logs one call will return in
// full, so a broad `step` filter cannot produce an unbounded response.
const maxLogBodiesPerRequest = 10

// GetWorkflowLogs returns Argo step logs for a workflow from the archive
// Argo uploads them to.
//
// Without `step` it lists the archived steps. That listing is itself
// diagnostic: a step missing from an otherwise-populated workflow never
// ran, which is how a pod stuck in Pending is identified.
func (h *Handlers) GetWorkflowLogs(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Ownership comes from the audit log, which only records
	// operator-initiated submissions. Anything without an identifiable
	// owning team is admin-only:
	//   - no audit entry at all — every cron-driven run (mctl-agents-*),
	//     mirroring the gate ListAgentRuns uses for cron visibility;
	//   - an entry with no team_name/tenant_name — by definition an
	//     AdminOnly platform-scoped operation (see operations.Registry).
	// This is deliberately stricter than GetWorkflow, which tolerates an
	// empty team: a step log exposes far more than a status phase does.
	if !user.IsAdmin() {
		team := auditEntryTenant(h.opts.AuditLog.GetByWorkflow(name))
		if team == "" {
			writeError(w, http.StatusForbidden, "admin group membership required: workflow has no owning team")
			return
		}
		if !user.HasTenantAccess(team) {
			writeError(w, http.StatusForbidden, "access denied: workflow belongs to team "+team)
			return
		}
	}

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}
	stepFilter := r.URL.Query().Get("step")

	resp := map[string]interface{}{"workflow": name}

	if h.opts.WorkflowLogArchive == nil {
		resp["steps"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Workflow log archive not configured (set ARGO_LOGS_R2_ENDPOINT, ARGO_LOGS_R2_BUCKET, ARGO_LOGS_R2_ACCESS_KEY, ARGO_LOGS_R2_SECRET_KEY)"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	steps, err := h.opts.WorkflowLogArchive.ListSteps(r.Context(), name)
	if err != nil {
		resp["steps"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Log archive error: " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if len(steps) == 0 {
		resp["steps"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "No archived step logs. The workflow name may be wrong, the run may have aged out of the archive's retention window, or no step produced output."
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if stepFilter == "" {
		resp["steps"] = steps
		resp["count"] = len(steps)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	matched := make([]argoarchive.StepLog, 0, len(steps))
	for _, s := range steps {
		if strings.Contains(s.Step, stepFilter) || strings.Contains(s.Pod, stepFilter) {
			matched = append(matched, s)
		}
	}
	if len(matched) == 0 {
		available := make([]string, 0, len(steps))
		for _, s := range steps {
			available = append(available, s.Step)
		}
		resp["logs"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "No step matched " + strconv.Quote(stepFilter) + ". Archived steps: " + strings.Join(available, ", ")
		writeJSON(w, http.StatusOK, resp)
		return
	}

	truncated := false
	if len(matched) > maxLogBodiesPerRequest {
		matched = matched[:maxLogBodiesPerRequest]
		truncated = true
	}

	// Fetched concurrently: each archive read can itself take up to the
	// client's own 30s timeout, and the route's auth middleware imposes a
	// 30s deadline on the whole request — serial reads of even a few
	// matched steps could exceed it.
	logs := make([]map[string]interface{}, len(matched))
	var wg sync.WaitGroup
	for i, s := range matched {
		wg.Add(1)
		go func(i int, s argoarchive.StepLog) {
			defer wg.Done()
			entry := map[string]interface{}{
				"step": s.Step,
				"pod":  s.Pod,
				"size": s.Size,
			}
			body, err := h.opts.WorkflowLogArchive.GetStep(r.Context(), s.Key, lines)
			if err != nil {
				entry["error"] = err.Error()
			} else {
				entry["lines"] = body
			}
			logs[i] = entry
		}(i, s)
	}
	wg.Wait()

	resp["logs"] = logs
	resp["count"] = len(logs)
	if truncated {
		resp["note"] = "Response truncated to the first " + strconv.Itoa(maxLogBodiesPerRequest) + " matching steps; narrow the step filter."
	}
	writeJSON(w, http.StatusOK, resp)
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
		// Redact at read-time so historical entries persisted before the
		// audit/redact module landed are also protected. See
		// internal/audit/redact.go for the heuristic.
		items = append(items, audit.RedactEntry(entries[i]))
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
