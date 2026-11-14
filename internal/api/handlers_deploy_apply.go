package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Deploy grants (mctl-api#1026, mctlhq/.github#254 item 4).
//
// An apply is authorized by a human grant held by the server, never by a
// client-supplied confirm:
//
//  1. POST /api/v1/deploy/plans/{id}/approval opens a pending deploy.apply
//     aar_ for a stored plan. Any developer of the plan's tenant may ask,
//     an agent session included. The intent is built here from the stored
//     plan (plan id, digest, tenant/service, policy); the body carries
//     nothing.
//  2. A live owner of the tenant decides it on the fresh sign-in page
//     (workitems.DecideDeployApproval). No bearer route decides this kind:
//     an MCP session carries its person's own principal, so only a fresh
//     interactive sign-in tells the person from their agent.
//  3. POST /api/v1/deploy/apply spends the grant once, for exactly the
//     approved plan, right before preview-deploy is submitted with the
//     plan's preview id and gitops commit.
//
// Faithful or refused: preview-deploy renders the service's gitops values
// at the plan's commit with the plan's image and preview id, not the
// intent's runtime changes (that is epic item 9). A plan whose intent
// changes the values, or builds from a context other than the repository
// root, is refused rather than applied approximately.

const (
	deployApplyMaxBody = 16 << 10

	codeDeployApplyInvalidInput    = "deploy_apply_invalid_input"
	codeDeployApplyGrantRequired   = "deploy_apply_grant_required"
	codeDeployApplyNotReproducible = "deploy_apply_not_reproducible"
	codeDeployApplyUnavailable     = "deploy_apply_unavailable"
	codeDeployPlanExpired          = "deploy_plan_expired"
	codeDeployPlanNotFound         = "deploy_plan_not_found"

	// previewDeployOp is the operation an apply submits.
	previewDeployOp = "preview-deploy"
)

// deployServerSetParams are preview-deploy inputs only the apply route sets,
// from the approved plan. A request body naming one is refused on the
// generic execute path.
var deployServerSetParams = []string{"preview_id", "gitops_ref"}

// deployApplyIntent is what a deploy.apply grant binds, built from the
// stored plan alone.
func deployApplyIntent(p *deployplan.Plan) workitems.ActionIntent {
	return workitems.ActionIntent{
		ExecutionID:   p.ID,
		ActionKind:    workitems.ActionKindDeployApply,
		Target:        p.Tenant + "/" + p.Service,
		ArgsDigest:    p.Digest,
		PolicyRuleID:  workitems.DeployApplyPolicyRuleID,
		PolicyVersion: workitems.DeployApplyPolicyVersion,
		ArtifactHash:  p.Digest,
	}
}

// loadCallerPlan reads the plan named by id for user. A plan of a tenant the
// caller is not a member of answers like an unknown one.
func (h *Handlers) loadCallerPlan(w http.ResponseWriter, user *auth.User, a *deployAudit, id string) (*deployplan.Plan, bool) {
	a.params["plan_id"] = truncate256(id)
	if h.opts.DeployPlans == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return nil, false
	}
	notFound := func() (*deployplan.Plan, bool) {
		a.set("denied", "denied:"+codeDeployPlanNotFound)
		writeErrorCode(w, http.StatusNotFound, codeDeployPlanNotFound, "no such deploy plan", nil)
		return nil, false
	}
	if !strings.HasPrefix(id, deployplan.IDPrefix) {
		return notFound()
	}
	p, err := h.opts.DeployPlans.Get(a.r.Context(), id)
	switch {
	case errors.Is(err, deployplan.ErrNotFound):
		return notFound()
	case err != nil:
		slog.Error("deploy apply: reading plan", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_plan_store_unavailable", "the plan store is not available")
		return nil, false
	}
	if !user.IsAdmin() && !user.HasTenantAccess(p.Tenant) {
		return notFound()
	}
	a.params["tenant"], a.params["service"], a.params["digest"] = p.Tenant, p.Service, p.Digest
	return p, true
}

// planApplicable refuses a plan that cannot be applied as it was approved:
// expired, stored with a digest that no longer matches its fields, or not
// reproducible by preview-deploy. It returns the parsed intent.
func (h *Handlers) planApplicable(w http.ResponseWriter, a *deployAudit, p *deployplan.Plan) (deployplan.Intent, bool) {
	if p.Expired(h.deployPlanNow()) {
		a.refuse(w, http.StatusConflict, codeDeployPlanExpired, "the plan has expired; plan again")
		return deployplan.Intent{}, false
	}
	// The row is immutable and its digest binds every field an apply uses;
	// a mismatch means the stored row is not what was planned.
	if deployplan.Digest(deployplan.DigestInput{
		Tenant: p.Tenant, Service: p.Service, Environment: p.Environment,
		IntentCanonical: p.IntentCanonical, Revision: p.Revision, GitopsBaseSHA: p.GitopsBaseSHA,
		Action: p.Action, PreviewID: p.PreviewID, ValuesAfter: p.ValuesAfter, Host: p.Host,
	}) != p.Digest {
		slog.Error("deploy apply: stored plan does not match its digest", "plan", p.ID)
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan does not match its digest")
		return deployplan.Intent{}, false
	}
	intent, _, err := deployplan.ParseIntent([]byte(p.IntentCanonical))
	if err != nil {
		slog.Error("deploy apply: stored intent does not parse", "plan", p.ID, "error", err)
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan's intent cannot be read")
		return deployplan.Intent{}, false
	}
	switch {
	case p.Environment != deployplan.EnvironmentPreview || p.Action != deployplan.ActionUpdate:
		a.refuse(w, http.StatusUnprocessableEntity, codeDeployApplyNotReproducible, "only a preview update plan can be applied")
		return deployplan.Intent{}, false
	case p.IntentChangesValues == nil || *p.IntentChangesValues:
		a.refuse(w, http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
			"the intent changes the service's values (runtime, env, resources or secrets), and preview-deploy renders the gitops values; apply it after preview-from-intent lands, or change the values in gitops")
		return deployplan.Intent{}, false
	case intent.Spec.Source.Context != "." && intent.Spec.Source.Context != "":
		a.refuse(w, http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
			"the preview build supports only the repository root as build context")
		return deployplan.Intent{}, false
	}
	return intent, true
}

// RequestDeployApproval answers POST /api/v1/deploy/plans/{id}/approval: the
// pending deploy.apply grant request for a plan, created once per plan and
// requester (200 with the stored one on a repeat). It grants nothing.
func (h *Handlers) RequestDeployApproval(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.approval.request")
	defer a.write()
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, deployApplyMaxBody)); err != nil {
		a.refuse(w, http.StatusBadRequest, codeDeployApplyInvalidInput, "the request body is too large")
		return
	}
	if h.opts.WorkItems == nil {
		a.refuse(w, http.StatusServiceUnavailable, codeDeployApplyUnavailable, "approvals are not configured")
		return
	}
	p, ok := h.loadCallerPlan(w, user, a, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	if !h.requireTenantRole(w, r, user, p.Tenant, h.operationMinRole(previewDeployOp, operations.RoleDeveloper), "deploy.approval.request", operations.RiskLow) {
		a.skip = true
		return
	}
	if _, ok := h.planApplicable(w, a, p); !ok {
		return
	}
	actor, subject := actorAndSubject(user)
	in := workitems.ActionApprovalInput{
		ActionIntent:           deployApplyIntent(p),
		RequestedBy:            principalOf(user),
		RequestedByPrincipalID: user.PrincipalID(),
		ViaPrincipalID:         user.ViaPrincipalID(),
		ActorKind:              actor.Kind,
		ActorName:              actor.Name,
		AgentRunID:             user.AgentRunID(),
		IdempotencyKey:         workitems.DeployIdempotencyKey(p.ID),
		ExpiresAt:              p.ExpiresAt,
		RiskLevel:              string(operations.RiskMedium),
		IntentSource:           "deploy_plan:" + p.ID,
	}
	if subject != nil {
		in.SubjectPrincipalID, in.SubjectKind = subject.PrincipalID, subject.Kind
	}
	pol := h.approvalPolicies()[workitems.DeployApplyPolicyRuleID]
	in.SideEffect, in.PolicyDecision = pol.SideEffect, pol.Decision
	in.PolicyReasons = append([]string(nil), pol.Reasons...)
	approval, created, err := h.opts.WorkItems.CreateDeployApproval(r.Context(), in)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			a.set("denied", "denied:"+code)
		} else {
			slog.Error("deploy approval: create", "plan", p.ID, "error", err)
			a.set("error", "error:create_failed")
		}
		writeActionApprovalError(w, err)
		return
	}
	a.params["approval_id"] = approval.ID
	if created {
		h.auditActionApproval(r, user, "action_approval.create", approval, operations.RiskLow, nil)
		a.set("succeeded", "succeeded")
	} else {
		a.set("succeeded", "replayed")
	}
	writeJSON(w, createdStatus(created), map[string]any{
		"schema_version":   workitems.ActionApprovalSchemaVersion,
		"plan_id":          p.ID,
		"approval":         approval,
		"decision_context": h.decisionContext(approval),
		"decided_by":       "a live owner of tenant " + p.Tenant + ", signed in fresh on the decide page; a bearer token cannot decide it",
	})
}

type deployApplyRequest struct {
	PlanID     string `json:"plan_id"`
	ApprovalID string `json:"approval_id"`
}

// DeployApply answers POST /api/v1/deploy/apply: spend the deploy.apply grant
// for a plan once and submit preview-deploy exactly as planned. Every
// refusal happens before the grant is spent; a failed submit after the spend
// has still spent it, and the caller asks for a new one.
func (h *Handlers) DeployApply(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployPlanAudit(r, user, "deploy.apply")
	defer a.write()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, deployApplyMaxBody))
	if err != nil {
		a.refuse(w, http.StatusBadRequest, codeDeployApplyInvalidInput, "the request body cannot be read or is too large")
		return
	}
	var req deployApplyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() || req.PlanID == "" {
		// confirm lands here too: it authorizes nothing and is not accepted.
		a.refuse(w, http.StatusBadRequest, codeDeployApplyInvalidInput,
			"the body must be a JSON object with plan_id and approval_id and nothing else; an apply is authorized by an owner's grant, not by confirm")
		return
	}
	if req.ApprovalID == "" {
		a.refuse(w, http.StatusForbidden, codeDeployApplyGrantRequired,
			"an apply needs a deploy.apply grant decided by an owner of the tenant; request one with POST /api/v1/deploy/plans/{id}/approval")
		return
	}
	a.params["approval_id"] = truncate256(req.ApprovalID)
	if h.opts.WorkItems == nil || h.opts.Registry == nil || h.opts.Executor == nil {
		a.refuse(w, http.StatusServiceUnavailable, codeDeployApplyUnavailable, "apply is not configured")
		return
	}
	p, ok := h.loadCallerPlan(w, user, a, req.PlanID)
	if !ok {
		return
	}
	if !h.requireTenantRole(w, r, user, p.Tenant, h.operationMinRole(previewDeployOp, operations.RoleDeveloper), "deploy.apply", operations.RiskMedium) {
		a.skip = true
		return
	}
	intent, ok := h.planApplicable(w, a, p)
	if !ok {
		return
	}

	// The grant: this kind, this plan's intent, still approved.
	grant, err := h.opts.WorkItems.ActionApproval(r.Context(), req.ApprovalID)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", req.ApprovalID, code)
			a.set("denied", "denied:"+code)
		} else {
			slog.Error("deploy apply: reading grant", "approval", req.ApprovalID, "error", err)
			a.set("error", "error:grant_unreadable")
		}
		writeActionApprovalError(w, err)
		return
	}
	intentHash := workitems.IntentHash(deployApplyIntent(p))
	if grant.ActionKind != workitems.ActionKindDeployApply || grant.IntentHash != intentHash {
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", grant.ID, aarCodeIntentMismatch)
		a.set("denied", "denied:"+aarCodeIntentMismatch)
		writeErrorCode(w, http.StatusConflict, aarCodeIntentMismatch,
			"approval "+grant.ID+" was not granted for this plan", nil)
		return
	}
	if err := workitems.ConsumeStateRefusal(grant); err != nil {
		code := actionApprovalRefusalCode(err)
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", grant.ID, code)
		a.set("denied", "denied:"+code)
		writeActionApprovalError(w, err)
		return
	}
	if grant.AuthorityBasis != workitems.DeployAuthorityBasis {
		// Only DecideDeployApproval approves this kind, and it records the
		// basis; anything else was not decided by a fresh-signed-in owner.
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", grant.ID, aarCodeAuthorityRevoked)
		a.set("denied", "denied:"+aarCodeAuthorityRevoked)
		writeActionApprovalError(w, fmt.Errorf("%w: %s was not decided by a tenant owner", governance.ErrAuthorityRevoked, grant.ID))
		return
	}

	// The submission, built from the plan alone and validated before the
	// grant is spent.
	op, ok := h.opts.Registry.Get(previewDeployOp)
	if !ok {
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the preview-deploy operation is not registered")
		return
	}
	input := h.opts.Registry.ApplyDefaults(op, map[string]string{
		"team_name":       p.Tenant,
		"component_name":  p.Service,
		"image_tag":       "rev-" + p.Revision,
		"git_ref":         p.Revision,
		"dockerfile_repo": intent.Spec.Source.Repository,
		"dockerfile_path": intent.Spec.Source.Dockerfile,
		"preview_id":      p.PreviewID,
		"gitops_ref":      p.GitopsBaseSHA,
	})
	if errs := h.opts.Registry.ValidateInput(op, input); len(errs) > 0 {
		slog.Error("deploy apply: plan-built input does not validate", "plan", p.ID, "errors", strings.Join(errs, "; "))
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the plan cannot be turned into a valid preview-deploy")
		return
	}
	if err := h.checkBuildInputs(r.Context(), op, input, user, p.Tenant, false); err != nil {
		status, msg := http.StatusForbidden, err.Error()
		if !errors.Is(err, errBuildRepoRefused) {
			slog.Error("deploy apply: build input check could not be made", "plan", p.ID, "error", err)
			status, msg = http.StatusServiceUnavailable, errBuildCheckUnavailable.Error()
		}
		a.refuse(w, status, "deploy_apply_build_refused", msg)
		return
	}

	// Revalidate the decider's ownership, then spend, then submit. Ownership
	// lives in the gitops checkout, not in the ledger, so it cannot be read
	// inside the spend's compare-and-set: a demotion landing between the two
	// reads still lets this one apply through, the same window the generic
	// action approvals have. The grant is single-use and bound to one plan,
	// so the window admits at most the apply the owner already approved.
	reval, ok := h.revalidateDeployGrant(w, r, user, grant, p.Tenant)
	if !ok {
		a.set("denied", "denied:revalidation")
		return
	}
	spent, err := h.opts.WorkItems.ConsumeDeployApproval(r.Context(), grant.ID, intentHash)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", grant.ID, code)
			a.set("denied", "denied:"+code)
		} else {
			slog.Error("deploy apply: consume failed", "approval", grant.ID, "error", err)
			a.set("error", "error:consume_failed")
		}
		writeActionApprovalError(w, err)
		return
	}
	h.auditActionApproval(r, user, "action_approval.consume", spent, operations.RiskMedium,
		map[string]string{"revalidation": reval.Revalidation, "plan_id": p.ID})

	auditParams := redactSecrets(op, input)
	auditParams["plan_id"], auditParams["plan_digest"] = p.ID, p.Digest
	auditParams["grant_ref"], auditParams["subject_principal_id"] = spent.ID, spent.DecidedByPrincipalID
	submitCtx, executionEnded, prepared := h.prepareSubmitExecution(w, r, user, op, p.Tenant, input)
	if !prepared {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: previewDeployOp, Parameters: auditParams, Status: "failed",
			RiskLevel: string(op.RiskLevel), Message: "could not create the run's execution; nothing was submitted"})
		a.set("error", "error:execution_not_prepared")
		return
	}
	result, err := h.opts.Executor.Submit(submitCtx, op, input, user.ID, p.Tenant)
	note := executionEnded(result, err)
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: previewDeployOp, Parameters: auditParams, Status: "failed",
			RiskLevel: string(op.RiskLevel), Message: "submit failed: " + err.Error()})
		a.set("error", "error:submit_failed")
		writeErrorCode(w, http.StatusBadGateway, codeDeployApplyUnavailable,
			"the grant was spent but preview-deploy could not be submitted; request a new grant"+note, nil)
		return
	}
	h.logAudit(r, audit.Entry{UserID: user.ID, Operation: previewDeployOp, Parameters: auditParams,
		WorkflowName: result.WorkflowName, Status: "submitted", RiskLevel: string(op.RiskLevel)})
	a.params["workflow"] = result.WorkflowName
	a.set("succeeded", "submitted")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"plan_id":     p.ID,
		"approval_id": spent.ID,
		"preview_id":  p.PreviewID,
		"preview_url": "https://" + p.Host,
		"workflow":    result,
	})
}

// deployOwnerCheck answers whether principalID is a live owner of tenant:
// nil, or an error wrapping governance.ErrAuthorityRevoked (not an owner) or
// governance.ErrAuthorityUnavailable (the membership could not be read). An
// admin gets no pass. Ownership is read by principal, so outside principal
// authz mode it is unavailable: a deploy grant then cannot be decided or
// spent.
func (h *Handlers) deployOwnerCheck(tenant, principalID string) error {
	var read func() ([][]string, error)
	if h.opts.TenantAuthzMode == TenantAuthzPrincipal && h.opts.PrincipalMembership != nil {
		read = func() ([][]string, error) {
			return h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, principalID)
		}
	}
	ref := decideWrittenRole(principalID, "principal membership reader", tenant, operations.RoleOwner, "deciding a deploy grant", read)
	switch {
	case !ref.refused():
		return nil
	case ref.status == http.StatusForbidden:
		return fmt.Errorf("%w: %s", governance.ErrAuthorityRevoked, ref.detail)
	default:
		return fmt.Errorf("%w: %s", governance.ErrAuthorityUnavailable, ref.detail)
	}
}

// revalidateDeployGrant is revalidateApproval for a deploy grant: freshness,
// context, policy, and the decider still a live owner of the plan's tenant.
func (h *Handlers) revalidateDeployGrant(w http.ResponseWriter, r *http.Request, user *auth.User, a *workitems.ActionApprovalRequest, tenant string) (governance.Result, bool) {
	res, err := governance.Revalidate(r.Context(), a, governance.LiveAuthority{
		PrincipalMode: h.principalMode(),
		Mode:          string(h.opts.TenantAuthzMode),
		Admins:        h.opts.AdminPrincipals,
		Checker:       h.opts.Principals,
		Policies:      h.approvalPolicies(),
		StrictPolicy:  h.opts.RequireRegisteredPolicy,
		Registry:      h.opts.Registry,
		Now:           h.approvalNow(),
		TenantOwner: func(_ context.Context, prn string) error {
			return h.deployOwnerCheck(tenant, prn)
		},
	})
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", a.ID, code,
				map[string]string{"policy_status": res.PolicyStatus})
		}
		writeActionApprovalError(w, err)
		return res, false
	}
	return res, true
}
