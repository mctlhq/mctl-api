package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Support incident producer (mctl-api#830): the single-capability principal
// mctl-support files incidents with, and the admin aggregation over them.

const (
	supportIncidentProducerRoute = "/api/v1/incidents"

	codeSupportProducerRouteNotAllowed = "support_incident_producer_route_not_allowed"
	codeSupportSourceNotAllowed        = "support_incident_source_not_allowed"
	codeSupportTypeNotAllowed          = "support_incident_type_not_allowed"
)

// supportIncidentProducerGate confines the support-incident-producer
// principal to POST /api/v1/incidents. It runs before any handler, so it
// also covers /mcp and every other route.
func supportIncidentProducerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsSupportIncidentProducer() &&
			(r.Method != http.MethodPost || r.URL.Path != supportIncidentProducerRoute) {
			writeErrorCode(w, http.StatusForbidden, codeSupportProducerRouteNotAllowed,
				"the support incident producer may only call POST "+supportIncidentProducerRoute, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// confineSupportIncident applies the producer's field rules to a decoded
// incident, writing the refusal itself and returning false when it refuses.
// On success the triage fields are cleared and the status forced to open.
func (h *Handlers) confineSupportIncident(w http.ResponseWriter, r *http.Request, user *auth.User, a *alerts.Alert) bool {
	deny := func(code, msg string) bool {
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: "incident-create",
			Parameters: map[string]string{
				"tenant": a.Tenant,
				"source": a.Source,
				"type":   a.Type,
				"code":   code,
				"actor":  user.ID,
			},
			Status:    "denied",
			RiskLevel: string(operations.RiskLow),
			Message:   msg,
		})
		writeErrorCode(w, http.StatusForbidden, code, msg, nil)
		return false
	}
	if a.Source != alerts.SourceSupport {
		return deny(codeSupportSourceNotAllowed, "the support incident producer may only file source="+alerts.SourceSupport+" incidents")
	}
	if !alerts.SupportTypes[a.Type] {
		return deny(codeSupportTypeNotAllowed, "incident type not allowed for the support incident producer")
	}
	if !strings.HasPrefix(a.Fingerprint, alerts.SupportFingerprintPrefix) {
		writeError(w, http.StatusBadRequest, "fingerprint must start with "+alerts.SupportFingerprintPrefix)
		return false
	}
	a.Status = alerts.StatusOpen
	a.Analysis = ""
	a.ProposedFix = ""
	a.PRURL = ""
	a.PRNumber = 0
	a.Confidence = ""
	a.AcknowledgedBy = ""
	a.AcknowledgedAt = nil
	a.ResolvedAt = nil
	a.ResolvedBy = ""
	return true
}

// auditSupportIncidentCreated writes the one audit row of a producer create
// or dedup hit. Summary and evidence text are never recorded.
func (h *Handlers) auditSupportIncidentCreated(r *http.Request, user *auth.User, requested, stored *alerts.Alert) {
	h.logAudit(r, audit.Entry{
		UserID:    user.ID,
		Operation: "incident-create",
		Parameters: map[string]string{
			"incident_id":  stored.ID,
			"requested_id": requested.ID,
			"tenant":       requested.Tenant,
			"source":       requested.Source,
			"type":         requested.Type,
			"fingerprint":  requested.Fingerprint,
			"deduplicated": strconv.FormatBool(stored.ID != requested.ID),
			"actor":        user.ID,
		},
		Status:    "succeeded",
		RiskLevel: string(operations.RiskLow),
	})
}

// SupportIncidentAggregation handles GET /api/v1/incidents/support/aggregation:
// open support incidents grouped by (fingerprint, type) across tenants.
// Admin only.
func (h *Handlers) SupportIncidentAggregation(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	if h.opts.AlertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "alert store not configured")
		return
	}
	rows, err := h.opts.AlertStore.SupportAggregation(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to aggregate support incidents: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "count": len(rows)})
}
