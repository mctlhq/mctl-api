package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Promote (mctl-api#1049): POST /api/v1/deploy/promote plans the promotion
// of one verified preview to production. It writes one deploy_plans row and
// nothing else. The plan is then approved and applied by the same routes as
// a preview plan (POST /deploy/plans/{id}/approval, POST /deploy/apply): an
// owner's grant bound to the plan digest, which binds the preview's record,
// image tag and digest. The digest is read from the record here; no request
// field names it.

const (
	promoteDeploymentOp = "promote-deployment"

	codePromoteInvalidInput   = "promote_invalid_input"
	codePromoteNotFound       = "promote_deployment_not_found"
	codePromoteNotUsable      = "promote_deployment_not_usable"
	codePromoteTenantDisabled = "promote_tenant_not_enabled"
	codePromoteValuesUnusable = "promote_values_unusable"
)

type promoteRequest struct {
	DeploymentID string `json:"deployment_id"`
	TTLSeconds   *int64 `json:"ttl_seconds"`
}

// promoteTenantEnabled reports whether tenant may promote. Until the MCP
// gateway exists only the listed tenants may (mctl-api#1049); an empty list
// enables nobody, so an unconfigured server cannot promote.
func (h *Handlers) promoteTenantEnabled(tenant string) bool {
	return slices.Contains(h.opts.PromoteTenants, tenant)
}

// DeployPromote answers POST /api/v1/deploy/promote.
func (h *Handlers) DeployPromote(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.promote")
	defer a.write()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, deployPlanMaxBody))
	if err != nil {
		a.refuse(w, http.StatusBadRequest, codePromoteInvalidInput, "the request body cannot be read or is too large")
		return
	}
	var req promoteRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || jsonHasTrailingData(dec) || req.DeploymentID == "" {
		// A digest, tag or revision in the body lands here: none is accepted.
		a.refuse(w, http.StatusBadRequest, codePromoteInvalidInput,
			"the body must be a JSON object with deployment_id and optionally ttl_seconds; the image comes from the preview's record")
		return
	}
	ttl := deployplan.DefaultTTL
	if req.TTLSeconds != nil {
		if *req.TTLSeconds < int64(deployplan.MinTTL/time.Second) || *req.TTLSeconds > int64(deployplan.MaxTTL/time.Second) {
			a.refuse(w, http.StatusBadRequest, codePromoteInvalidInput, "ttl_seconds must be between 60 and 86400")
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
		a.set("denied", "denied:"+codePromoteNotFound)
		writeErrorCode(w, http.StatusNotFound, codePromoteNotFound, "no such deployment", nil)
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
		slog.Error("deploy promote: reading the record", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the deployment record store is not available")
		return
	}
	// A record of a tenant the caller is not in answers like an unknown id.
	if !user.IsAdmin() && !user.HasTenantAccess(rec.Tenant) {
		notFound()
		return
	}
	tenant, service := rec.Tenant, rec.Service
	a.params["tenant"], a.params["service"] = tenant, service
	if !h.requireTenantRole(w, r, user, tenant, h.operationMinRole(promoteDeploymentOp, operations.RoleDeveloper), "deploy.promote", operations.RiskMedium) {
		a.skip = true
		return
	}
	if !h.promoteTenantEnabled(tenant) {
		a.refuse(w, http.StatusForbidden, codePromoteTenantDisabled,
			"promotion to production is not enabled for this workspace yet")
		return
	}
	if why := deployplan.PromoteSourceUnusable(rec); why != "" {
		a.refuse(w, http.StatusConflict, codePromoteNotUsable, "this deployment cannot be promoted: "+why)
		return
	}

	if h.opts.DeployGitops == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}
	base, _, exists, baseSHA, err := h.opts.DeployGitops.ServiceValuesAt(tenant, service)
	switch {
	case err != nil:
		slog.Error("deploy promote: reading service values", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	case !exists:
		// Production values must exist: a promotion pins an image in them,
		// it does not create a service.
		a.refuse(w, http.StatusConflict, codePromoteValuesUnusable, "the service has no production values in gitops")
		return
	case !deployRevRe.MatchString(baseSHA):
		slog.Error("deploy promote: gitops revision is not a commit SHA")
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}

	intent := deployplan.NewPromoteIntent(rec)
	canonical, err := intent.Canonical()
	if err != nil {
		slog.Error("deploy promote: intent", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	before, after, err := deployplan.CompilePromote(base, intent)
	switch {
	case errors.Is(err, deployplan.ErrValuesUnparseable):
		slog.Error("deploy promote: values unparseable", "tenant", tenant, "service", service, "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_values_unparseable", "the service's values.yaml cannot be parsed")
		return
	case errors.Is(err, deployplan.ErrPromoteValues):
		a.refuse(w, http.StatusUnprocessableEntity, codePromoteValuesUnusable, truncate256(err.Error()))
		return
	case err != nil:
		slog.Error("deploy promote: compile", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	beforeYAML, err1 := deployplan.RenderYAML(deployplan.Redact(before))
	afterYAML, err2 := deployplan.RenderYAML(deployplan.Redact(after))
	if err1 != nil || err2 != nil {
		slog.Error("deploy promote: render", "before", err1, "after", err2)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	host := deployplan.ProductionHost(after)
	approval := deployplan.RequiredApproval(deployplan.EnvironmentProduction, deployplan.ActionPromote)
	digest := deployplan.Digest(deployplan.DigestInput{
		Tenant: tenant, Service: service, Environment: deployplan.EnvironmentProduction,
		IntentCanonical: canonical, Revision: rec.Revision, GitopsBaseSHA: baseSHA,
		Action: deployplan.ActionPromote, PreviewID: "", ValuesAfter: afterYAML, Host: host,
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
		Action: deployplan.ActionPromote, PreviewID: "",
		ValuesBeforeSHA256: deployplan.SHA256Hex(beforeYAML), ValuesAfter: afterYAML,
		Diff: deployplan.UnifiedDiff(beforeYAML, afterYAML), Host: host,
		RequiresApproval: approval.Required, RequiredRole: approval.Role, ApprovalReason: approval.Reason,
		CreatedBy: createdBy, Surface: surface,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	stored, replayed, err := h.opts.DeployPlans.Insert(r.Context(), plan)
	if err != nil {
		slog.Error("deploy promote: storing", "error", err)
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
