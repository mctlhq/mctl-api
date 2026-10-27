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

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

const (
	minEventWindow     = time.Minute
	maxEventWindow     = 24 * time.Hour
	defaultEventWindow = time.Hour
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":     events,
		"count":     len(events),
		"team":      team,
		"namespace": team,
		"since":     since.String(),
		"truncated": truncated,
	})
}
