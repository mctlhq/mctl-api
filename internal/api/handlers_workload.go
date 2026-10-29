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
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/k8s"
)

// dnsLabelPattern is an RFC 1123 label, at most 63 characters.
var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

const (
	minEventWindow     = time.Minute
	maxEventWindow     = 24 * time.Hour
	defaultEventWindow = time.Hour

	// defaultEventRetention is the Kubernetes default apiserver --event-ttl.
	defaultEventRetention = time.Hour
)

// GetServicePods returns the allow-listed state of every pod of a service.
func (h *Handlers) GetServicePods(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")
	if !dnsLabelPattern.MatchString(team) || !dnsLabelPattern.MatchString(app) {
		writeError(w, http.StatusBadRequest, "team and app must be DNS labels")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.requireRegisteredTenant(w, team) {
		return
	}
	if !h.resolveWorkloadService(w, team, app) {
		return
	}
	if h.opts.WorkloadReader == nil {
		writeError(w, http.StatusServiceUnavailable, "pod listing unavailable: kubernetes client not configured")
		return
	}
	workload := team + "-" + app
	pods, err := h.opts.WorkloadReader.ListServicePods(r.Context(), team, workload)
	if err != nil {
		slog.Warn("listing pods failed", "team", team, "namespace", team, "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not list pods in "+team)
		return
	}
	if pods == nil {
		pods = []k8s.PodState{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":     pods,
		"count":     len(pods),
		"team":      team,
		"namespace": team,
		"service":   app,
	})
}

// ListNamespaceEvents returns recent Kubernetes events of a tenant namespace.
func (h *Handlers) ListNamespaceEvents(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	team := chi.URLParam(r, "team")
	if !dnsLabelPattern.MatchString(team) {
		writeError(w, http.StatusBadRequest, "team must be a DNS label")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.requireRegisteredTenant(w, team) {
		return
	}
	q := r.URL.Query()
	since := defaultEventWindow
	sinceText := q.Get("since")
	if sinceText != "" {
		d, err := time.ParseDuration(sinceText)
		if err != nil || d < minEventWindow || d > maxEventWindow {
			writeError(w, http.StatusBadRequest, "since must be a duration between 1m and 24h")
			return
		}
		since = d
	}
	query := k8s.EventQuery{Since: since, Limit: k8s.DefaultEventLimit}
	switch t := q.Get("type"); t {
	case "":
	case "Warning", "Normal":
		query.Type = t
	default:
		writeError(w, http.StatusBadRequest, "type must be Warning or Normal")
		return
	}
	if app := q.Get("app"); app != "" {
		if !dnsLabelPattern.MatchString(app) {
			writeError(w, http.StatusBadRequest, "app must be a DNS label")
			return
		}
		if !h.resolveWorkloadService(w, team, app) {
			return
		}
		query.Workload = team + "-" + app
	}
	if h.opts.WorkloadReader == nil {
		writeError(w, http.StatusServiceUnavailable, "event listing unavailable: kubernetes client not configured")
		return
	}
	events, truncated, err := h.opts.WorkloadReader.ListEvents(r.Context(), team, query)
	if err != nil {
		slog.Warn("listing events failed", "team", team, "namespace", team, "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not list events in "+team)
		return
	}
	if events == nil {
		events = []k8s.Event{}
	}
	retention := h.opts.EventRetention
	if retention <= 0 {
		retention = defaultEventRetention
	}
	covered := since
	if retention < covered {
		covered = retention
	}
	resp := map[string]interface{}{
		"items":             events,
		"count":             len(events),
		"team":              team,
		"namespace":         team,
		"since":             since.String(),
		"truncated":         truncated,
		"observed_since":    time.Now().UTC().Add(-covered).Format(time.RFC3339),
		"coverage_complete": since <= retention,
		"event_retention":   retention.String(),
	}
	if since > retention {
		resp["coverage_note"] = "the cluster keeps events for about " + retention.String() +
			"; events before observed_since are no longer held, so their absence is unknown"
	}
	writeJSON(w, http.StatusOK, resp)
}

// requireRegisteredTenant answers false, after writing the response, unless
// team names a registered tenant. {team} becomes the Kubernetes namespace, and
// HasTenantAccess is true for any name for admins and ReadAllTenants agent
// scopes, so without this check they could read kube-system or argocd. Only a
// definite absence is 404; a failed or missing lookup is 503, never a 404.
func (h *Handlers) requireRegisteredTenant(w http.ResponseWriter, team string) bool {
	if h.opts.GitReader == nil {
		writeError(w, http.StatusServiceUnavailable, "tenant lookup not configured")
		return false
	}
	exists, err := h.opts.GitReader.TenantExists(team)
	if err != nil {
		slog.Error("workload read: tenant lookup failed", "team", team, "error", err)
		writeError(w, http.StatusServiceUnavailable, "tenant lookup failed")
		return false
	}
	if !exists {
		writeError(w, http.StatusNotFound, "tenant not found: "+team)
		return false
	}
	return true
}

// resolveWorkloadService answers false, after writing the response, unless
// app is a known service of team. The gitops catalogue is checked first; only
// when it reports the service absent is the ArgoCD workload list consulted, so
// external and platform applications keep working. A lookup that could not be
// made is 503, never 404 and never an empty read.
func (h *Handlers) resolveWorkloadService(w http.ResponseWriter, team, app string) bool {
	status, msg := h.checkServiceExists(team, app)
	switch status {
	case 0:
		return true
	case http.StatusNotFound:
		// Not in the catalogue; fall through to ArgoCD.
	default:
		writeError(w, status, msg)
		return false
	}
	unconfirmed := "cannot confirm whether service \"" + app + "\" exists in workspace \"" + team + "\""
	if h.opts.ArgoCD == nil {
		writeError(w, http.StatusServiceUnavailable, unconfirmed+": argocd not configured")
		return false
	}
	workloads, err := h.opts.ArgoCD.ListWorkloads()
	if err != nil {
		slog.Warn("workload read: argocd workload list failed", "team", team, "service", app, "error", err)
		writeError(w, http.StatusServiceUnavailable, unconfirmed+" right now; try again later")
		return false
	}
	// An exact {team}-{app} name already excludes preview apps
	// (preview-{team}-...); a prefix check would reject every app of a
	// tenant whose own name starts with "preview-".
	name := team + "-" + app
	for i := range workloads {
		if workloads[i].Name == name && workloads[i].DestNamespace == team {
			return true
		}
	}
	writeError(w, http.StatusNotFound, "service not found: "+app+" (workspace \""+team+"\")")
	return false
}
