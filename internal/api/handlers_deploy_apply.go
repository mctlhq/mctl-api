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
	"time"

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
	codeDeployPlanAlreadyApplied   = "deploy_plan_already_applied"
	codeDeployPlanExpired          = "deploy_plan_expired"
	codeDeployPlanNotFound         = "deploy_plan_not_found"

	// previewDeployOp is the operation an apply submits.
	previewDeployOp = "preview-deploy"
)

// deployServerSetParams are preview-deploy inputs only the apply route sets,
// from the approved plan. A request body naming one is refused on the
// generic execute path.
var deployServerSetParams = []string{"preview_id", "gitops_ref", "compiled_values", "values_sha256"}

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

// planRefusal is why a stored plan cannot be applied as it was planned.
type planRefusal struct {
	status    int
	code, msg string
}

// planApplicableCheck refuses a plan that cannot be applied as it was
// approved: expired, stored with a digest that no longer matches its
// fields, or not reproducible by preview-deploy. It returns the parsed
// intent. The apply route and the decide page ask the same question, so the
// page never offers to approve what the apply would refuse.
func planApplicableCheck(p *deployplan.Plan, now time.Time, imageOrg string) (deployplan.Intent, *planRefusal) {
	if p.Expired(now) {
		return deployplan.Intent{}, &planRefusal{http.StatusConflict, codeDeployPlanExpired, "the plan has expired; plan again"}
	}
	// The row is immutable and its digest binds every field an apply uses;
	// a mismatch means the stored row is not what was planned.
	if deployplan.Digest(deployplan.DigestInput{
		Tenant: p.Tenant, Service: p.Service, Environment: p.Environment,
		IntentCanonical: p.IntentCanonical, Revision: p.Revision, GitopsBaseSHA: p.GitopsBaseSHA,
		Action: p.Action, PreviewID: p.PreviewID, ValuesAfter: p.ValuesAfter, Host: p.Host,
	}) != p.Digest {
		slog.Error("deploy apply: stored plan does not match its digest", "plan", p.ID)
		return deployplan.Intent{}, &planRefusal{http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan does not match its digest"}
	}
	if p.Environment == deployplan.EnvironmentProduction && p.Action == deployplan.ActionPromote {
		// A promotion has no deploy intent: its own intent names the
		// preview record, tag and digest the plan's values were built from.
		if _, err := deployplan.ParsePromoteIntent(p.IntentCanonical); err != nil {
			slog.Error("deploy apply: stored promote intent does not parse", "plan", p.ID, "error", err)
			return deployplan.Intent{}, &planRefusal{http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan's intent cannot be read"}
		}
		return deployplan.Intent{}, nil
	}
	intent, _, err := deployplan.ParseIntent([]byte(p.IntentCanonical))
	if err != nil {
		slog.Error("deploy apply: stored intent does not parse", "plan", p.ID, "error", err)
		return deployplan.Intent{}, &planRefusal{http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan's intent cannot be read"}
	}
	switch {
	case p.Environment != deployplan.EnvironmentPreview || (p.Action != deployplan.ActionUpdate && p.Action != deployplan.ActionOnboard):
		return deployplan.Intent{}, &planRefusal{http.StatusUnprocessableEntity, codeDeployApplyNotReproducible, "only a preview update or onboard plan can be applied"}
	case p.Action == deployplan.ActionUpdate && (p.IntentChangesValues == nil || *p.IntentChangesValues):
		return deployplan.Intent{}, &planRefusal{http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
			"the intent changes the service's values (runtime, env, resources or secrets), and preview-deploy renders the gitops values; change the values in gitops first"}
	case intent.Spec.Source.Context != "." && intent.Spec.Source.Context != "":
		return deployplan.Intent{}, &planRefusal{http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
			"the preview build supports only the repository root as build context"}
	}
	if p.Action == deployplan.ActionOnboard {
		// The approval page asks this too, so it never offers a grant the
		// apply would refuse because the compiler or the image organization
		// changed since the plan was made.
		if _, _, err := deployplan.OnboardValuesForPlan(p, intent, imageOrg); err != nil {
			return deployplan.Intent{}, &planRefusal{http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
				"the plan's values cannot be reproduced; plan again"}
		}
	}
	return intent, nil
}

// planApplicable is checkPlan answered and audited.
func (h *Handlers) planApplicable(w http.ResponseWriter, a *deployAudit, p *deployplan.Plan) (deployplan.Intent, bool) {
	intent, ref := h.checkPlan(p)
	if ref != nil {
		a.refuse(w, ref.status, ref.code, ref.msg)
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
	out := map[string]any{
		"schema_version":   workitems.ActionApprovalSchemaVersion,
		"plan_id":          p.ID,
		"approval":         approval,
		"decision_context": h.decisionContext(approval),
		"decided_by":       "a live owner of tenant " + p.Tenant + ", signed in fresh on the decide page; a bearer token cannot decide it",
	}
	// The link carries no secret and grants nothing; without the page
	// mounted there is nowhere to decide, and saying so beats a dead link.
	if h.deployApproval != nil {
		out["decide_url"] = h.deployApproval.decideURL(approval.ID)
	} else {
		out["decide_unavailable"] = "the deploy approval page is not enabled on this server, so this grant cannot be decided yet"
	}
	writeJSON(w, createdStatus(created), out)
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
	if h.opts.WorkItems == nil || h.opts.Registry == nil || h.opts.Executor == nil || h.opts.DeployRecords == nil {
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
	promote := p.Action == deployplan.ActionPromote
	opName := previewDeployOp
	if promote {
		opName = promoteDeploymentOp
		if !h.promoteTenantEnabled(p.Tenant) {
			a.refuse(w, http.StatusForbidden, codePromoteTenantDisabled, "promotion to production is not enabled for this workspace yet")
			return
		}
	}
	op, ok := h.opts.Registry.Get(opName)
	if !ok {
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the "+opName+" operation is not registered")
		return
	}
	var input map[string]string
	if promote {
		// Tag and digest come from the approved plan alone.
		pi, err := deployplan.ParsePromoteIntent(p.IntentCanonical)
		if err != nil {
			a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the stored plan's intent cannot be read")
			return
		}
		input = h.opts.Registry.ApplyDefaults(op, map[string]string{
			"team_name": p.Tenant, "component_name": p.Service,
			"image_tag": pi.ImageTag, "image_digest": pi.ImageDigest,
		})
	} else {
		input = h.opts.Registry.ApplyDefaults(op, map[string]string{
			"team_name":       p.Tenant,
			"component_name":  p.Service,
			"image_tag":       "rev-" + p.Revision,
			"git_ref":         p.Revision,
			"dockerfile_repo": intent.Spec.Source.Repository,
			"dockerfile_path": intent.Spec.Source.Dockerfile,
			"preview_id":      p.PreviewID,
			"gitops_ref":      p.GitopsBaseSHA,
		})
	}
	if p.Action == deployplan.ActionOnboard {
		// The values come from the approved plan, never from the caller:
		// rebuilt from its intent and held to the redacted rendering the
		// plan's digest binds.
		b64, sha, err := deployplan.OnboardValuesForPlan(p, intent, h.opts.PlatformImageOrg)
		if err != nil {
			slog.Error("deploy apply: onboard values", "plan", p.ID, "error", err)
			a.refuse(w, http.StatusUnprocessableEntity, codeDeployApplyNotReproducible,
				"the plan's values cannot be reproduced; plan again")
			return
		}
		input["compiled_values"], input["values_sha256"] = b64, sha
	}
	if errs := h.opts.Registry.ValidateInput(op, input); len(errs) > 0 {
		slog.Error("deploy apply: plan-built input does not validate", "plan", p.ID, "errors", strings.Join(errs, "; "))
		a.refuse(w, http.StatusInternalServerError, codeDeployApplyUnavailable, "the plan cannot be turned into a valid preview-deploy")
		return
	}
	if promote {
		// Nothing is built or cloned from a caller-influenced repository.
	} else if err := h.checkBuildInputs(r.Context(), op, input, user, p.Tenant, false); err != nil {
		status, msg := http.StatusForbidden, err.Error()
		if !errors.Is(err, errBuildRepoRefused) {
			slog.Error("deploy apply: build input check could not be made", "plan", p.ID, "error", err)
			status, msg = http.StatusServiceUnavailable, errBuildCheckUnavailable.Error()
		}
		a.refuse(w, status, "deploy_apply_build_refused", msg)
		return
	}

	// A plan applies once (mctl-api#1047): grants are per requester, so a
	// second holder must be refused before spending theirs. A record store
	// that cannot be read is not "not applied".
	switch _, err := h.opts.DeployRecords.RecordForPlan(r.Context(), p.ID); {
	case err == nil:
		a.refuse(w, http.StatusConflict, codeDeployPlanAlreadyApplied, "this plan was already applied; create a new plan to deploy again")
		return
	case !errors.Is(err, deployplan.ErrRecordNotFound):
		slog.Error("deploy apply: reading the deployment record", "plan", p.ID, "error", err)
		a.refuse(w, http.StatusServiceUnavailable, codeDeployApplyUnavailable, "the deployment record store is not available; the grant was not spent")
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
	// The compiled values hold real Vault paths the plan stores redacted;
	// values_sha256 already identifies them.
	if v, ok := auditParams["compiled_values"]; ok {
		auditParams["compiled_values"] = fmt.Sprintf("[%d characters, see values_sha256]", len(v))
	}
	auditParams["plan_id"], auditParams["plan_digest"] = p.ID, p.Digest
	auditParams["grant_ref"], auditParams["subject_principal_id"] = spent.ID, spent.DecidedByPrincipalID
	// preview-deploy does not require an execution today
	// (operations.RequiresExecution), so this returns the request context and
	// a no-op; TestDeployApply_PreviewDeployNeedsNoExecution trips if that
	// changes, since the branches below then need tests that reach them.
	submitCtx, executionEnded, prepared := h.prepareSubmitExecution(w, r, user, op, p.Tenant, input)
	if !prepared {
		// Nothing recorded yet, so the plan stays appliable with a new grant.
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: opName, Parameters: auditParams, Status: "failed",
			RiskLevel: string(op.RiskLevel), Message: "could not create the run's execution; nothing was submitted"})
		a.set("error", "error:execution_not_prepared")
		return
	}
	// The workflow's name is fixed before the submit and kept in the record,
	// so an ambiguous submit can be resolved later by looking it up.
	requestID, preset := operations.WorkflowRequestIDFrom(submitCtx)
	if !preset {
		requestID = operations.NewWorkflowRequestID()
		submitCtx = operations.WithWorkflowRequestID(submitCtx, requestID)
	}

	// The deployment record, before anything is submitted: an apply that
	// cannot be recorded does not run (mctl-api#1047). The grant is spent
	// either way, as for a failed submit.
	appliedBy := user.PrincipalID()
	if appliedBy == "" {
		appliedBy = user.ID
	}
	rec, err := h.opts.DeployRecords.InsertRecord(r.Context(), deployplan.NewRecord(p, spent.ID,
		spent.DecidedByPrincipalID, appliedBy, operations.WorkflowNameFor(op, requestID), h.deployPlanNow()))
	if err != nil {
		executionEnded(nil, operations.NotCreated(err))
	}
	if errors.Is(err, deployplan.ErrRecordExists) {
		// Another apply of this plan won the race after the check above.
		a.set("denied", "denied:"+codeDeployPlanAlreadyApplied)
		writeErrorCode(w, http.StatusConflict, codeDeployPlanAlreadyApplied,
			"this plan was applied concurrently; nothing was submitted for this grant, and the plan cannot be applied again", nil)
		return
	}
	if err != nil {
		slog.Error("deploy apply: recording the deployment", "plan", p.ID, "approval", spent.ID, "error", err)
		a.set("error", "error:record_failed")
		writeErrorCode(w, http.StatusServiceUnavailable, codeDeployApplyUnavailable,
			"the grant was spent but the deployment could not be recorded, so nothing was submitted; create a new plan and request a grant for it", nil)
		return
	}
	a.params["deployment_id"] = rec.ID

	result, err := h.opts.Executor.Submit(submitCtx, op, input, user.ID, p.Tenant)
	note := executionEnded(result, err)
	h.recordSubmission(r.Context(), rec.ID, result, err)
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: opName, Parameters: auditParams, Status: "failed",
			RiskLevel: string(op.RiskLevel), Message: "submit failed: " + err.Error()})
		a.set("error", "error:submit_failed")
		writeErrorCode(w, http.StatusBadGateway, codeDeployApplyUnavailable,
			"the grant was spent but preview-deploy could not be submitted, and this plan cannot be applied again; create a new plan and request a grant for it"+note, nil)
		return
	}
	h.logAudit(r, audit.Entry{UserID: user.ID, Operation: opName, Parameters: auditParams,
		WorkflowName: result.WorkflowName, Status: "submitted", RiskLevel: string(op.RiskLevel)})
	a.params["workflow"] = result.WorkflowName
	a.set("succeeded", "submitted")
	resp := map[string]any{
		"deployment_id": rec.ID,
		"plan_id":       p.ID,
		"approval_id":   spent.ID,
		"workflow":      result,
	}
	if promote {
		resp["environment"] = p.Environment
	} else {
		resp["preview_id"], resp["preview_url"] = p.PreviewID, "https://"+p.Host
	}
	writeJSON(w, http.StatusAccepted, resp)
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

// recordSubmission writes the submit's outcome into the deployment record,
// only when the outcome is certain: submitted with a workflow name, or
// failed before any Workflow was created. An ambiguous failure (the create
// may have been accepted) leaves the record in submitting, which reads as
// "outcome not recorded", never as success or failure; the status moves
// only once, so a guess could not be corrected later. A failure to write
// cannot undo the side effect either; it is logged for the operator.
func (h *Handlers) recordSubmission(reqCtx context.Context, id string, result *operations.SubmitResult, submitErr error) {
	var status, workflow string
	switch {
	case submitErr == nil && result != nil && result.WorkflowName != "":
		status, workflow = deployplan.RecordSubmitted, result.WorkflowName
	case submitErr != nil && operations.IsNotCreated(submitErr):
		status = deployplan.RecordSubmitFailed
	default:
		slog.Warn("deploy apply: submit outcome is ambiguous; the record stays in submitting",
			"deployment", id, "error", submitErr)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), 10*time.Second)
	defer cancel()
	if _, err := h.opts.DeployRecords.SetRecordSubmission(ctx, id, status, workflow); err != nil {
		slog.Error("deploy apply: recording the submission outcome; the record stays in submitting",
			"deployment", id, "status", status, "error", err)
	}
}

// checkPlan is planApplicableCheck plus what needs the handlers' state. For a
// promotion that is the tenant allowlist and production itself: the owner
// approved a before/after diff computed against one production state, so a
// plan whose production values have moved since (another promotion, a
// changed repository) is refused, never applied over the newer state.
func (h *Handlers) checkPlan(p *deployplan.Plan) (deployplan.Intent, *planRefusal) {
	intent, ref := planApplicableCheck(p, h.deployPlanNow(), h.opts.PlatformImageOrg)
	if ref != nil || p.Action != deployplan.ActionPromote {
		return intent, ref
	}
	if !h.promoteTenantEnabled(p.Tenant) {
		return intent, &planRefusal{http.StatusForbidden, codePromoteTenantDisabled, "promotion to production is not enabled for this workspace yet"}
	}
	if h.opts.DeployGitops == nil {
		return intent, &planRefusal{http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now"}
	}
	base, _, exists, _, err := h.opts.DeployGitops.ServiceValuesAt(p.Tenant, p.Service)
	if err != nil {
		slog.Error("deploy apply: reading production values", "plan", p.ID, "error", err)
		return intent, &planRefusal{http.StatusServiceUnavailable, "deploy_gitops_unavailable", "the gitops checkout cannot be read right now"}
	}
	stale := &planRefusal{http.StatusConflict, codeDeployApplyNotReproducible,
		"production's values changed since this plan was made (another promotion or a gitops change); plan again"}
	if !exists {
		return intent, stale
	}
	cur, err := deployplan.ParseValuesForCheck(base)
	if err != nil {
		return intent, stale
	}
	curYAML, err := deployplan.RenderYAML(deployplan.Redact(cur))
	if err != nil || deployplan.SHA256Hex(curYAML) != p.ValuesBeforeSHA256 {
		return intent, stale
	}
	return intent, nil
}
