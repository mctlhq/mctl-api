package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Governed rollback (mctl-api#1049): POST /api/v1/deploy/rollback plans the
// restoration of production to the state of one earlier production
// DeployRecord. Like a promotion it writes one deploy_plans row and nothing
// else; the plan is approved and applied by the deploy approval and apply
// routes, an owner's grant bound to the plan digest. The commit and digest
// come from the record, never from the request.

const (
	codeRollbackInvalidInput  = "rollback_invalid_input"
	codeRollbackValuesUnusage = "rollback_values_unusable"
	// codeRollbackRequiresGrant is the answer of the ungoverned
	// rollback-revision route for a production deployment.
	codeRollbackRequiresGrant = "rollback_requires_grant"
)

// DeployRollback answers POST /api/v1/deploy/rollback.
func (h *Handlers) DeployRollback(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.rollback")
	defer a.write()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, deployPlanMaxBody))
	if err != nil {
		a.refuse(w, http.StatusBadRequest, codeRollbackInvalidInput, "the request body cannot be read or is too large")
		return
	}
	var req promoteRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || jsonHasTrailingData(dec) || req.DeploymentID == "" {
		// A commit or digest in the body lands here: none is accepted.
		a.refuse(w, http.StatusBadRequest, codeRollbackInvalidInput,
			"the body must be a JSON object with deployment_id and optionally ttl_seconds; the commit and digest come from the deployment's record")
		return
	}
	ttl := deployplan.DefaultTTL
	if req.TTLSeconds != nil {
		if *req.TTLSeconds < int64(deployplan.MinTTL/time.Second) || *req.TTLSeconds > int64(deployplan.MaxTTL/time.Second) {
			a.refuse(w, http.StatusBadRequest, codeRollbackInvalidInput, "ttl_seconds must be between 60 and 86400")
			return
		}
		ttl = time.Duration(*req.TTLSeconds) * time.Second
	}
	a.params["deployment_id"] = truncate256(req.DeploymentID)
	if h.opts.DeployPlans == nil || h.opts.DeployRecords == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan or deployment record store is not available")
		return
	}
	notFound := func() {
		a.set("denied", "denied:"+codeRollbackDeploymentNotFound)
		writeErrorCode(w, http.StatusNotFound, codeRollbackDeploymentNotFound, "no such deployment", nil)
	}
	if !strings.HasPrefix(req.DeploymentID, deployplan.RecordIDPrefix) {
		notFound()
		return
	}
	rec, err := h.opts.DeployRecords.GetRecord(r.Context(), req.DeploymentID)
	switch {
	case errors.Is(err, deployplan.ErrRecordNotFound):
		notFound()
		return
	case err != nil:
		slog.Error("deploy rollback: reading the record", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the deployment record store is not available")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(rec.Tenant) {
		notFound()
		return
	}
	tenant, service := rec.Tenant, rec.Service
	a.params["tenant"], a.params["service"] = tenant, service
	if !h.requireTenantRole(w, r, user, tenant, h.operationMinRole(rollbackRevisionOp, operations.RoleDeveloper), "deploy.rollback", operations.RiskMedium) {
		a.skip = true
		return
	}
	if !h.promoteTenantEnabled(tenant) {
		a.refuse(w, http.StatusForbidden, codePromoteTenantDisabled,
			"production rollback is not enabled for this workspace yet")
		return
	}
	// Only a production deployment is a production rollback target: a
	// preview's commit is not a state production ever had.
	if rec.Environment != deployplan.EnvironmentProduction {
		a.refuse(w, http.StatusConflict, codeRollbackDeploymentNotUsable, "this deployment cannot be rolled back to: it is not a production deployment")
		return
	}
	if why := rollbackRecordUnusable(rec, tenant, service); why != "" {
		a.refuse(w, http.StatusConflict, codeRollbackDeploymentNotUsable, "this deployment cannot be rolled back to: "+why)
		return
	}

	if h.opts.DeployGitops == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}
	base, _, exists, baseSHA, err := h.opts.DeployGitops.ServiceValuesAt(tenant, service)
	switch {
	case err != nil:
		slog.Error("deploy rollback: reading service values", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	case !exists:
		a.refuse(w, http.StatusConflict, codeRollbackValuesUnusage, "the service has no production values in gitops")
		return
	case !deployRevRe.MatchString(baseSHA):
		slog.Error("deploy rollback: gitops revision is not a commit SHA")
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}
	current, err := deployplan.ParseValuesForCheck(base)
	if err != nil {
		slog.Error("deploy rollback: values unparseable", "tenant", tenant, "service", service, "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_values_unparseable", "the service's values.yaml cannot be parsed")
		return
	}
	beforeYAML, err := deployplan.RenderYAML(deployplan.Redact(current))
	if err != nil {
		slog.Error("deploy rollback: render", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}

	intent := deployplan.NewRollbackIntent(rec)
	canonical, err := intent.Canonical()
	if err != nil {
		slog.Error("deploy rollback: intent", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	valuesAfter := deployplan.RollbackValuesAfter(intent)
	host := deployplan.ProductionHost(current)
	approval := deployplan.RequiredApproval(deployplan.EnvironmentProduction, deployplan.ActionRollback)
	digest := deployplan.Digest(deployplan.DigestInput{
		Tenant: tenant, Service: service, Environment: deployplan.EnvironmentProduction,
		IntentCanonical: canonical, Revision: rec.Revision, GitopsBaseSHA: baseSHA,
		Action: deployplan.ActionRollback, PreviewID: "", ValuesAfter: valuesAfter, Host: host,
	})
	a.params["digest"] = digest

	now := h.deployPlanNow()
	surface := "rest"
	if r.Header.Get(deployPlanSurfaceHeader) == "mcp" {
		surface = "mcp"
	}
	createdBy := user.PrincipalID()
	if createdBy == "" {
		createdBy = user.ID
	}
	plan := &deployplan.Plan{
		ID: deployplan.NewID(), Digest: digest, SchemaVersion: deployplan.SchemaVersion,
		Tenant: tenant, Service: service, Environment: deployplan.EnvironmentProduction,
		Intent: []byte(canonical), IntentCanonical: canonical, Revision: rec.Revision, GitopsBaseSHA: baseSHA,
		Action: deployplan.ActionRollback, PreviewID: "",
		ValuesBeforeSHA256: deployplan.SHA256Hex(beforeYAML), ValuesAfter: valuesAfter,
		Diff: "values.yaml is restored from git as it was at commit " + intent.TargetCommit + "; the file is not rendered here", Host: host,
		RequiresApproval: approval.Required, RequiredRole: approval.Role, ApprovalReason: approval.Reason,
		CreatedBy: createdBy, Surface: surface,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	stored, replayed, err := h.opts.DeployPlans.Insert(r.Context(), plan)
	if err != nil {
		slog.Error("deploy rollback: storing", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return
	}
	a.params["plan_id"] = stored.ID
	status := http.StatusCreated
	if replayed {
		a.set("succeeded", "replayed")
		status = http.StatusOK
	} else {
		a.set("succeeded", "succeeded")
	}
	writeJSON(w, status, newPlanResponse(stored, now, replayed))
}
