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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// CreateIncident handles POST /api/v1/incidents.
func (h *Handlers) CreateIncident(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var a alerts.Alert
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if a.ID == "" || a.Source == "" || a.Type == "" || a.Tenant == "" || a.Summary == "" || a.Severity == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: id, source, type, tenant, summary, severity")
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(a.Tenant) {
		writeError(w, http.StatusForbidden, "access denied to tenant: "+a.Tenant)
		return
	}

	if a.Status == "" {
		a.Status = alerts.StatusOpen
	}

	// occurrence_count and last_seen_at are store-managed; ignore any
	// caller-supplied values so a POST can't seed or corrupt the dedup counter.
	a.OccurrenceCount = 0
	a.LastSeenAt = nil

	stored, err := h.opts.AlertStore.Create(r.Context(), &a)
	if err != nil {
		if errors.Is(err, alerts.ErrIDConflict) {
			writeError(w, http.StatusConflict, "incident id already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create incident: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, stored)
}

// ResolveIncidentByFingerprint handles POST /api/v1/incidents/resolve-by-fingerprint.
func (h *Handlers) ResolveIncidentByFingerprint(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Tenant      string `json:"tenant"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if body.Tenant == "" || body.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: tenant, fingerprint")
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(body.Tenant) {
		writeError(w, http.StatusForbidden, "access denied to tenant: "+body.Tenant)
		return
	}

	resolved, err := h.opts.AlertStore.ResolveByFingerprint(r.Context(), body.Tenant, body.Fingerprint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve incident: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"resolved": resolved})
}

// ListIncidents handles GET /api/v1/incidents.
func (h *Handlers) ListIncidents(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	q := r.URL.Query()
	f := alerts.ListFilter{
		Status:   q.Get("status"),
		Tenant:   q.Get("tenant"),
		Service:  q.Get("service"),
		Type:     q.Get("type"),
		Severity: q.Get("severity"),
	}

	// Non-admins requesting a specific tenant must have access to it.
	if !user.IsAdmin() && f.Tenant != "" && !user.HasTenantAccess(f.Tenant) {
		writeError(w, http.StatusForbidden, "access denied to tenant: "+f.Tenant)
		return
	}

	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}

	all, err := h.opts.AlertStore.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list incidents: "+err.Error())
		return
	}

	// Post-filter: non-admins see only their accessible tenants.
	var items []alerts.Alert
	for i := range all {
		if user.IsAdmin() || user.HasTenantAccess(all[i].Tenant) {
			items = append(items, all[i])
		}
	}
	if items == nil {
		items = []alerts.Alert{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}

// GetIncident handles GET /api/v1/incidents/{id}.
func (h *Handlers) GetIncident(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")
	a, err := h.opts.AlertStore.GetByPrefix(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found: "+id)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(a.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	writeJSON(w, http.StatusOK, a)
}

// UpdateIncident handles PATCH /api/v1/incidents/{id}.
func (h *Handlers) UpdateIncident(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")
	existing, err := h.opts.AlertStore.GetByPrefix(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found: "+id)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	var patch struct {
		Status      *string `json:"status"`
		Analysis    *string `json:"analysis"`
		ProposedFix *string `json:"proposed_fix"`
		PRURL       *string `json:"pr_url"`
		PRNumber    *int    `json:"pr_number"`
		Confidence  *string `json:"confidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if patch.Status != nil {
		existing.Status = *patch.Status
	}
	if patch.Analysis != nil {
		existing.Analysis = *patch.Analysis
	}
	if patch.ProposedFix != nil {
		existing.ProposedFix = *patch.ProposedFix
	}
	if patch.PRURL != nil {
		existing.PRURL = *patch.PRURL
	}
	if patch.PRNumber != nil {
		existing.PRNumber = *patch.PRNumber
	}
	if patch.Confidence != nil {
		existing.Confidence = *patch.Confidence
	}

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update incident: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

// AcknowledgeIncident handles POST /api/v1/incidents/{id}/ack.
func (h *Handlers) AcknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")
	existing, err := h.opts.AlertStore.GetByPrefix(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found: "+id)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	userID := user.ID

	now := time.Now().UTC()
	existing.AcknowledgedBy = userID
	existing.AcknowledgedAt = &now
	existing.Status = alerts.StatusAcknowledged

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to acknowledge incident: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

// ResolveIncident handles POST /api/v1/incidents/{id}/resolve.
func (h *Handlers) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")
	existing, err := h.opts.AlertStore.GetByPrefix(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found: "+id)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	now := time.Now().UTC()
	existing.Status = alerts.StatusResolved
	existing.ResolvedAt = &now
	if body.Reason != "" {
		existing.Analysis = existing.Analysis + "\n\nResolution: " + body.Reason
	}

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve incident: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

// IncidentSummary handles GET /api/v1/incidents/summary.
func (h *Handlers) IncidentSummary(w http.ResponseWriter, r *http.Request) {
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Admins get the global summary; non-admins get a summary scoped to their tenants.
	if user.IsAdmin() {
		sum, err := h.opts.AlertStore.Summary(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get summary: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, sum)
		return
	}

	all, err := h.opts.AlertStore.List(r.Context(), alerts.ListFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get summary: "+err.Error())
		return
	}

	sum := &alerts.Summary{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}
	for i := range all {
		if !user.HasTenantAccess(all[i].Tenant) {
			continue
		}
		if all[i].Status == alerts.StatusResolved || all[i].Status == "suppressed" {
			continue
		}
		sum.ByStatus[all[i].Status]++
		sum.BySeverity[all[i].Severity]++
		sum.ByType[all[i].Type]++
		sum.Total++
	}

	writeJSON(w, http.StatusOK, sum)
}
