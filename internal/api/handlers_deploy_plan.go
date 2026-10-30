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

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployanalyze"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const (
	deployPlanMaxBody = 256 << 10
	// deployPlanSurfaceHeader lets the MCP tools label their rows. It is a
	// label only and decides nothing.
	deployPlanSurfaceHeader = "X-Mctl-Surface"
)

type deployPlanRequest struct {
	Intent         json.RawMessage `json:"intent"`
	IdempotencyKey string          `json:"idempotency_key"`
	TTLSeconds     *int64          `json:"ttl_seconds"`
}

// deployPlanResponse is a stored plan plus what is computed on read.
type deployPlanResponse struct {
	*deployplan.Plan
	Intent   json.RawMessage     `json:"intent"`
	Expired  bool                `json:"expired"`
	Approval deployplan.Approval `json:"approval"`
	Replayed bool                `json:"replayed,omitempty"`
}

func (h *Handlers) deployPlanNow() time.Time {
	if h.opts.Clock != nil {
		return h.opts.Clock().UTC()
	}
	return time.Now().UTC()
}

func newPlanResponse(p *deployplan.Plan, now time.Time, replayed bool) deployPlanResponse {
	return deployPlanResponse{
		Plan: p, Intent: json.RawMessage(p.IntentCanonical),
		Expired: p.Expired(now), Approval: p.Approval(), Replayed: replayed,
	}
}

func (h *Handlers) newDeployPlanAudit(r *http.Request, user *auth.User, op string) *deployAudit {
	return &deployAudit{h: h, r: r, user: user, op: op, params: map[string]string{}, status: "error", msg: "error:unknown"}
}

// peekRevision reads spec.source.revision without validating anything else,
// so a ref gets its own error code before the schema's generic one.
func peekRevision(raw json.RawMessage) (string, bool) {
	var p struct {
		Spec struct {
			Source struct {
				Revision any `json:"revision"`
			} `json:"source"`
		} `json:"spec"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return "", false
	}
	rev, ok := p.Spec.Source.Revision.(string)
	return rev, ok
}

// DeployPlan answers POST /api/v1/deploy/plan: a server-computed, immutable
// preview plan for a DeployIntent. It writes one deploy_plans row and
// nothing else: no gitops write, no workflow, no cluster change.
func (h *Handlers) DeployPlan(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.plan")
	defer a.write()

	// 2. The envelope.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, deployPlanMaxBody))
	if err != nil {
		a.refuse(w, http.StatusBadRequest, "deploy_plan_invalid_input", "the request body cannot be read or is larger than 256 KiB")
		return
	}
	var req deployPlanRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || len(req.Intent) == 0 || dec.More() {
		a.refuse(w, http.StatusBadRequest, "deploy_plan_invalid_input",
			"the body must be a JSON object with intent, and optionally idempotency_key and ttl_seconds")
		return
	}
	ttl := deployplan.DefaultTTL
	if req.TTLSeconds != nil {
		d := time.Duration(*req.TTLSeconds) * time.Second
		if *req.TTLSeconds < int64(deployplan.MinTTL/time.Second) || *req.TTLSeconds > int64(deployplan.MaxTTL/time.Second) {
			a.refuse(w, http.StatusBadRequest, "deploy_plan_invalid_input", "ttl_seconds must be between 60 and 86400")
			return
		}
		ttl = d
	}
	if len(req.IdempotencyKey) > 200 {
		a.refuse(w, http.StatusBadRequest, "deploy_plan_invalid_input", "idempotency_key is at most 200 characters")
		return
	}

	// 3. Revision shape, then the schema.
	if rev, ok := peekRevision(req.Intent); ok && !deployRevRe.MatchString(rev) {
		a.refuse(w, http.StatusUnprocessableEntity, "deploy_revision_not_a_sha",
			"spec.source.revision must be a full 40-character lowercase hex commit SHA; a branch or tag is never resolved")
		return
	}
	intent, canonical, err := deployplan.ParseIntent(req.Intent)
	if err != nil {
		a.refuse(w, http.StatusUnprocessableEntity, "deploy_intent_invalid", truncate256(err.Error()))
		return
	}
	tenant, service := intent.Metadata.Tenant, intent.Metadata.Service
	repo, rev := intent.Spec.Source.Repository, intent.Spec.Source.Revision
	a.params["tenant"], a.params["service"] = tenant, service
	a.params["repository"], a.params["revision"] = truncate256(repo), rev

	// 4. Production is reached only through promote.
	if intent.Spec.Environment != deployplan.EnvironmentPreview {
		a.refuse(w, http.StatusUnprocessableEntity, "prod_requires_promote",
			"production is reached only through promote; a plan describes a preview")
		return
	}

	// 5. Authorization.
	if !h.requireTenantRole(w, r, user, tenant, h.operationMinRole("deploy-service", operations.RoleDeveloper), "deploy.plan", operations.RiskLow) {
		a.skip = true
		return
	}

	// 6. Repository binding.
	if _, refusal := h.deployRepoBound(r.Context(), tenant, repo); refusal != nil {
		a.refuse(w, refusal.status, refusal.code, refusal.message)
		return
	}

	// 7. The revision exists in the repository.
	if h.opts.DeployContentReader == nil {
		a.refuse(w, http.StatusBadGateway, "deploy_github_unavailable", "the repository cannot be read right now")
		return
	}
	switch err := h.opts.DeployContentReader.Commit(r.Context(), repo, rev); {
	case errors.Is(err, deployanalyze.ErrRevisionUnreadable):
		a.refuse(w, http.StatusUnprocessableEntity, "deploy_revision_unreadable", "the revision cannot be read from the repository")
		return
	case errors.Is(err, deployanalyze.ErrGitHubMalformed):
		slog.Error("deploy plan: malformed github answer", "error", err)
		a.refuse(w, http.StatusBadGateway, "deploy_github_malformed", "GitHub returned an unusable answer")
		return
	case err != nil:
		slog.Error("deploy plan: github unavailable", "error", err)
		a.refuse(w, http.StatusBadGateway, "deploy_github_unavailable", "the repository cannot be read right now")
		return
	}

	// 8. The service in gitops: one read of values, annotation and revision.
	if h.opts.DeployGitops == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}
	base, sourceRepo, exists, baseSHA, err := h.opts.DeployGitops.ServiceValuesAt(tenant, service)
	if err != nil {
		slog.Error("deploy plan: reading service values", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}
	if !exists {
		a.refuse(w, http.StatusUnprocessableEntity, "onboard_requires_preview_onboard",
			"the service does not exist in gitops yet; first onboard is not planned here")
		return
	}
	if !strings.EqualFold(sourceRepo, repo) {
		a.refuse(w, http.StatusForbidden, "deploy_service_not_bound", "the service is not built from this repository")
		return
	}
	if !deployRevRe.MatchString(baseSHA) {
		slog.Error("deploy plan: gitops revision is not a commit SHA")
		a.refuse(w, http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now")
		return
	}

	// 9. Compile.
	if h.opts.PlatformDomain == "" {
		slog.Error("deploy plan: PlatformDomain is not configured")
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	previewID := deployplan.PreviewID(tenant, service, rev, baseSHA)
	host := deployplan.Host(service, previewID, h.opts.PlatformDomain)
	before, after, err := deployplan.CompilePreview(base, intent, previewID, host)
	switch {
	case errors.Is(err, deployplan.ErrValuesUnparseable):
		slog.Error("deploy plan: base values unparseable", "tenant", tenant, "service", service, "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_values_unparseable", "the service's values.yaml cannot be parsed")
		return
	case errors.Is(err, deployplan.ErrPreviewValuesRefused):
		a.refuse(w, http.StatusUnprocessableEntity, "deploy_preview_values_refused", truncate256(err.Error()))
		return
	case err != nil:
		slog.Error("deploy plan: compile", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}

	// 10. Redact, render, diff, digest.
	beforeYAML, err1 := deployplan.RenderYAML(deployplan.Redact(before))
	afterYAML, err2 := deployplan.RenderYAML(deployplan.Redact(after))
	if err1 != nil || err2 != nil {
		slog.Error("deploy plan: render", "before", err1, "after", err2)
		a.refuse(w, http.StatusInternalServerError, "deploy_plan_failed", "the plan could not be computed")
		return
	}
	approval := deployplan.RequiredApproval(intent.Spec.Environment, deployplan.ActionUpdate)
	digest := deployplan.Digest(deployplan.DigestInput{
		Tenant: tenant, Service: service, Environment: intent.Spec.Environment,
		IntentCanonical: string(canonical), Revision: rev, GitopsBaseSHA: baseSHA,
		Action: deployplan.ActionUpdate, PreviewID: previewID, ValuesAfter: afterYAML, Host: host,
	})
	a.params["digest"] = digest

	// 11. Store.
	if h.opts.DeployPlans == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return
	}
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
		Tenant: tenant, Service: service, Environment: intent.Spec.Environment,
		Intent: canonical, IntentCanonical: string(canonical), Revision: rev, GitopsBaseSHA: baseSHA,
		Action: deployplan.ActionUpdate, PreviewID: previewID,
		ValuesBeforeSHA256: deployplan.SHA256Hex(beforeYAML), ValuesAfter: afterYAML,
		Diff: deployplan.UnifiedDiff(beforeYAML, afterYAML), Host: host,
		RequiresApproval: approval.Required, RequiredRole: approval.Role, ApprovalReason: approval.Reason,
		CreatedBy: createdBy, Surface: surface, IdempotencyKey: req.IdempotencyKey,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	stored, replayed, err := h.opts.DeployPlans.Insert(r.Context(), plan)
	var conflict *deployplan.IdempotencyConflictError
	switch {
	case errors.As(err, &conflict):
		a.set("denied", "denied:deploy_plan_idempotency_conflict")
		writeErrorCode(w, http.StatusConflict, "deploy_plan_idempotency_conflict",
			"this idempotency_key was used for a different plan", map[string]interface{}{"plan_id": conflict.PlanID})
		return
	case err != nil:
		slog.Error("deploy plan: storing", "error", err)
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

// GetDeployPlan answers GET /api/v1/deploy/plans/{id}. A caller who is
// neither a member of the plan's tenant nor an admin gets the same 404 as an
// unknown id, so ids do not leak existence.
func (h *Handlers) GetDeployPlan(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.plan.read")
	defer a.write()

	id := chi.URLParam(r, "id")
	a.params["plan_id"] = truncate256(id)
	if h.opts.DeployPlans == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return
	}
	notFound := func() {
		a.set("denied", "denied:deploy_plan_not_found")
		writeErrorCode(w, http.StatusNotFound, "deploy_plan_not_found", "no such deploy plan", nil)
	}
	if !strings.HasPrefix(id, deployplan.IDPrefix) {
		notFound()
		return
	}
	p, err := h.opts.DeployPlans.Get(r.Context(), id)
	switch {
	case errors.Is(err, deployplan.ErrNotFound):
		notFound()
		return
	case err != nil:
		slog.Error("deploy plan: reading", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(p.Tenant) {
		notFound()
		return
	}
	a.params["tenant"], a.params["service"], a.params["digest"] = p.Tenant, p.Service, p.Digest
	a.set("succeeded", "succeeded")
	writeJSON(w, http.StatusOK, newPlanResponse(p, h.deployPlanNow(), false))
}
