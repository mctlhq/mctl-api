package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
)

const codeDeploymentNotFound = "deployment_not_found"

// GetDeployment answers GET /api/v1/deploy/deployments/{id}: the record of
// one applied plan (mctl-api#1047), by its own id (dep_...) or by the plan's
// (dpl_...). A caller who is neither a member of the record's tenant nor an
// admin gets the same 404 as an unknown id. Fields not yet observed are
// absent and health reads unknown: the record never claims what it did not
// see.
func (h *Handlers) GetDeployment(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.deployment.read")
	defer a.write()

	id := chi.URLParam(r, "id")
	a.params["id"] = truncate256(id)
	if h.opts.DeployRecords == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_record_store_unavailable", "the deployment record store is not available")
		return
	}
	notFound := func() {
		a.set("denied", "denied:"+codeDeploymentNotFound)
		writeErrorCode(w, http.StatusNotFound, codeDeploymentNotFound, "no such deployment", nil)
	}
	var rec *deployplan.Record
	var err error
	switch {
	case strings.HasPrefix(id, deployplan.RecordIDPrefix):
		rec, err = h.opts.DeployRecords.GetRecord(r.Context(), id)
	case strings.HasPrefix(id, deployplan.IDPrefix):
		rec, err = h.opts.DeployRecords.RecordForPlan(r.Context(), id)
	default:
		notFound()
		return
	}
	switch {
	case errors.Is(err, deployplan.ErrRecordNotFound):
		notFound()
		return
	case err != nil:
		slog.Error("deployment: reading the record", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_record_store_unavailable", "the deployment record store is not available")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(rec.Tenant) {
		notFound()
		return
	}
	a.params["tenant"], a.params["service"], a.params["deployment_id"] = rec.Tenant, rec.Service, rec.ID
	a.set("succeeded", "succeeded")
	writeJSON(w, http.StatusOK, rec)
}
