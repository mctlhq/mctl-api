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
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// incidentWriteRole is the tenant role needed to create or change an
// incident. Incidents are operational records, so the bar is the ordinary
// write role: a developer may acknowledge and resolve them, a read-only
// member may not (mctl-api#478).
const incidentWriteRole = operations.RoleDeveloper

// incidentChange is what a successful incident mutation records in the audit
// log: the exact incident and the status move, never the free text (analysis,
// resolution reason) the caller sent.
type incidentChange struct {
	ID, Tenant, Service    string
	PreviousStatus, Status string
}

// auditIncidentChange writes the success row for an incident mutation.
// requireTenantRole audits only refusals, so without this a change made by an
// allowed caller left no trace of who made it. The operation names match the
// refusal rows ("incident-update", "incident-ack", "incident-resolve"), and
// logAudit fills in the caller's principal and, for an agent run token, its
// execution id.
func (h *Handlers) auditIncidentChange(r *http.Request, user *auth.User, op string, c incidentChange, extra map[string]string) {
	params := map[string]string{
		"incident_id": c.ID,
		"tenant":      c.Tenant,
		"status":      c.Status,
		"actor":       principalOf(user),
	}
	if c.Service != "" {
		params["service"] = c.Service
	}
	if c.PreviousStatus != "" {
		params["previous_status"] = c.PreviousStatus
	}
	for k, v := range extra {
		params[k] = v
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     "succeeded",
		RiskLevel:  string(operations.RiskLow),
	})
}

// CreateIncident handles POST /api/v1/incidents.
func (h *Handlers) CreateIncident(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// The trace fields shadow Alert's so a wrong JSON type for them is
	// ignored instead of failing the whole request.
	var body struct {
		alerts.Alert
		TraceID          json.RawMessage `json:"trace_id"`
		WorkflowName     json.RawMessage `json:"workflow_name"`
		TraceSource      json.RawMessage `json:"trace_source"`
		TraceUnavailable json.RawMessage `json:"trace_unavailable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	a := body.Alert
	a.TraceID = validIncidentTraceID(body.TraceID)
	a.WorkflowName = validIncidentWorkflowName(body.WorkflowName)
	// Argo producers send no workflow_name, only a summary link. Store the
	// name from it so a dedup hit, which keeps the first occurrence's
	// summary, still records the newest run and derivation follows it.
	if a.WorkflowName == "" && a.Source == incidentSourceArgo {
		a.WorkflowName = workflowNameFromSummary(a.Summary)
	}

	if a.ID == "" || a.Source == "" || a.Type == "" || a.Tenant == "" || a.Summary == "" || a.Severity == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: id, source, type, tenant, summary, severity")
		return
	}

	producer := user.IsSupportIncidentProducer()
	if producer {
		if !h.confineSupportIncident(w, r, user, &a) {
			return
		}
	} else {
		if !user.IsAdmin() && !user.HasTenantAccess(a.Tenant) {
			writeError(w, http.StatusForbidden, "access denied to tenant: "+a.Tenant)
			return
		}
		if !h.requireTenantRole(w, r, user, a.Tenant, incidentWriteRole, "incident-create", operations.RiskLow) {
			return
		}
	}

	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
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

	if producer {
		h.respondToSupportProducer(w, r, user, &a, stored)
		return
	}

	labelStoredTrace(stored, traceNotDerived)
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
	if !h.requireTenantRole(w, r, user, body.Tenant, incidentWriteRole, "incident-resolve", operations.RiskLow) {
		return
	}

	ids, err := h.opts.AlertStore.ResolveByFingerprint(r.Context(), body.Tenant, body.Fingerprint, principalOf(user))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve incident: "+err.Error())
		return
	}
	for _, id := range ids {
		h.auditIncidentChange(r, user, "incident-resolve", incidentChange{
			ID: id, Tenant: body.Tenant, Status: alerts.StatusResolved,
		}, map[string]string{"fingerprint": body.Fingerprint})
	}

	writeJSON(w, http.StatusOK, map[string]bool{"resolved": len(ids) > 0})
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
	// The list does not run the audit derivation; mark the absence so it is
	// never read as "this incident has no trace".
	for i := range items {
		labelStoredTrace(&items[i], traceNotDerivedOnList)
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
		writeIncidentLookupError(w, id, err)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(a.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	var lookup workflowAuditLookup
	if h.opts.AuditLog != nil {
		lookup = h.opts.AuditLog
	}
	deriveIncidentTrace(r.Context(), a, lookup, func(e *audit.Entry) bool {
		return canReadAuditEntry(user, e)
	})

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
		writeIncidentLookupError(w, id, err)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.requireTenantRole(w, r, user, existing.Tenant, incidentWriteRole, "incident-update", operations.RiskLow) {
		return
	}

	var patch struct {
		Status      *string         `json:"status"`
		Analysis    *string         `json:"analysis"`
		ProposedFix *string         `json:"proposed_fix"`
		PRURL       *string         `json:"pr_url"`
		PRNumber    *int            `json:"pr_number"`
		Confidence  *string         `json:"confidence"`
		TraceID     json.RawMessage `json:"trace_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	previousStatus := existing.Status
	if patch.Status != nil {
		existing.Status = *patch.Status
	}
	// A PATCH that resolves is a resolve: it records who and when, the same
	// as POST .../resolve, so the resolver is never lost by taking this path.
	if existing.Status == alerts.StatusResolved && previousStatus != alerts.StatusResolved {
		now := time.Now().UTC()
		existing.ResolvedAt = &now
		existing.ResolvedBy = principalOf(user)
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

	if id := validIncidentTraceID(patch.TraceID); id != "" {
		existing.TraceID = id
	}

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update incident: "+err.Error())
		return
	}
	h.auditIncidentChange(r, user, "incident-update", incidentChange{
		ID: existing.ID, Tenant: existing.Tenant, Service: existing.Service,
		PreviousStatus: previousStatus, Status: existing.Status,
	}, nil)

	labelStoredTrace(existing, traceNotDerived)
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
		writeIncidentLookupError(w, id, err)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.requireTenantRole(w, r, user, existing.Tenant, incidentWriteRole, "incident-ack", operations.RiskLow) {
		return
	}

	userID := user.ID
	previousStatus := existing.Status

	now := time.Now().UTC()
	existing.AcknowledgedBy = userID
	existing.AcknowledgedAt = &now
	existing.Status = alerts.StatusAcknowledged

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to acknowledge incident: "+err.Error())
		return
	}
	h.auditIncidentChange(r, user, "incident-ack", incidentChange{
		ID: existing.ID, Tenant: existing.Tenant, Service: existing.Service,
		PreviousStatus: previousStatus, Status: existing.Status,
	}, nil)

	labelStoredTrace(existing, traceNotDerived)
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
		writeIncidentLookupError(w, id, err)
		return
	}

	if !user.IsAdmin() && !user.HasTenantAccess(existing.Tenant) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.requireTenantRole(w, r, user, existing.Tenant, incidentWriteRole, "incident-resolve", operations.RiskLow) {
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	previousStatus := existing.Status
	if previousStatus == alerts.StatusResolved {
		// Already resolved: the first resolver and time stand. A repeat
		// with nothing to add changes nothing and records nothing; one
		// with a reason only appends it, and is audited as that.
		if body.Reason == "" {
			labelStoredTrace(existing, traceNotDerived)
			writeJSON(w, http.StatusOK, existing)
			return
		}
	} else {
		now := time.Now().UTC()
		existing.Status = alerts.StatusResolved
		existing.ResolvedAt = &now
		existing.ResolvedBy = principalOf(user)
	}
	if body.Reason != "" {
		existing.Analysis = existing.Analysis + "\n\nResolution: " + body.Reason
	}

	if err := h.opts.AlertStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve incident: "+err.Error())
		return
	}
	h.auditIncidentChange(r, user, "incident-resolve", incidentChange{
		ID: existing.ID, Tenant: existing.Tenant, Service: existing.Service,
		PreviousStatus: previousStatus, Status: existing.Status,
	}, nil)

	labelStoredTrace(existing, traceNotDerived)
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

// writeIncidentLookupError maps an AlertStore.GetByPrefix error to a stable
// HTTP status. A failed lookup never reaches Update.
func writeIncidentLookupError(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, alerts.ErrPrefixTooShort):
		writeError(w, http.StatusBadRequest, fmt.Sprintf("incident id prefix must be at least %d characters", alerts.MinPrefixLen))
	case errors.Is(err, alerts.ErrNotFound):
		writeError(w, http.StatusNotFound, "incident not found: "+id)
	case errors.Is(err, alerts.ErrAmbiguousPrefix):
		writeError(w, http.StatusConflict, "incident id prefix is ambiguous; use a longer prefix or the full id")
	default:
		slog.Error("incident lookup failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to look up incident")
	}
}
