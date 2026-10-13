package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Grant-authorized mctl-agents-approve (mctl-api#571 R5-R8).
//
// An agent run that presents X-MCTL-On-Behalf-Of: aar_... on
// POST /operations/mctl-agents-approve/execute reaches ExecuteOperation as
// the human who decided that approval (agentPrincipalGate resolved and
// bound it to the run's we_). Such a subject is never an admin, so the
// operation's admin gate would refuse it; the grant replaces that gate for
// this one operation. Its only authority is a decision a human admin made
// under isHumanAdmin, for this execution, this kind and this target, and
// it is spent once (ConsumeActionApproval) before anything is submitted.
//
// The target is not the requester's to choose: the agent run names it when
// it creates the aar_, but the human approves a DevLoop by its workflow id,
// so the target must belong to that DevLoop. bindApprovalGrant checks it
// against the execution's engine_ref through the same <service>/<slug> ->
// workflow id mapping the shepherd uses
// (temporalclient.WorkflowIDForProposalRef). That mapping keeps only the
// slug's issue-<n>- prefix, so this binds the service and the issue, not
// the slug: the exact slug is pinned by the intent hash, which the server
// computed from the row when the run created the aar_, and it is recorded
// in the decision and consume audit (target).

// devLoopApprovalPolicyRule and devLoopApprovalPolicyVersion are what a
// DevLoop approval grant is created under (R1).
const (
	devLoopApprovalPolicyRule    = "dev-loop.human-approval"
	devLoopApprovalPolicyVersion = "v1"
)

// approvalSpend is a loaded aar_ waiting to be bound to the request's
// target and consumed right before the operation is submitted.
type approvalSpend struct {
	approval   *workitems.ActionApprovalRequest
	intentHash string
}

// prepareApprovalGrant loads the aar_ named by the request's delegation
// grant and records its decider as the approver, before the input is
// validated, so the recorded value passes the same checks as every other
// approver (R8). It refuses (and has answered) when ok is false.
func (h *Handlers) prepareApprovalGrant(w http.ResponseWriter, r *http.Request, user *auth.User, input map[string]string, ref string) (*approvalSpend, bool) {
	refuse := func(status int, code, msg string) (*approvalSpend, bool) {
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", ref, code)
		writeErrorCode(w, status, code, msg, nil)
		return nil, false
	}
	// R8: the approver is the grant's decider. A body naming one is
	// refused, not overwritten.
	if _, named := input["approver"]; named {
		return refuse(http.StatusBadRequest, wiCodeActorNotAccepted,
			`approver is not an input on a grant-authorized approval: it is taken from the approval's decider`)
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "work items are not configured", nil)
		return nil, false
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), ref)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", ref, code)
		} else {
			slog.Error("approval grant: action approval could not be read", "approval", ref, "error", err)
		}
		writeActionApprovalError(w, err)
		return nil, false
	}
	// A grant for another action is refused here, before the input is
	// validated or anything else is read, not only by the intent CAS at
	// spend time: it never authorized this operation.
	if a.ActionKind != devLoopApprovalKind {
		return refuse(http.StatusConflict, aarCodeIntentMismatch,
			"approval "+ref+" was not granted for "+devLoopApprovalKind)
	}
	approver, ok := approverName(a.DecidedBy)
	if !ok {
		// The gate already refuses an undecided aar_ (no subject), and a
		// decision is only ever made by a human admin; refused rather than
		// recording nobody.
		return refuse(http.StatusConflict, aarCodeNotApproved, "approval "+ref+" has no human decider")
	}
	input["approver"] = approver
	return &approvalSpend{approval: a}, true
}

// approverName is the recorded approver for a decider: the name without its
// principalOf namespace, as the human and relay paths record it (a bare
// login, or the IdP display name). Only human namespaces qualify.
func approverName(decidedBy string) (string, bool) {
	for _, ns := range []string{"github:", "oidc:"} {
		if name, ok := strings.CutPrefix(decidedBy, ns); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// bindApprovalGrant runs on the defaulted, validated input. It refuses a
// target whose service and issue are not the approval's own DevLoop's, then
// computes the intent the request asks for, which ConsumeActionApproval
// compares with the one the human approved.
//
// The intent is rebuilt from what the request asks for -- this action kind,
// this <service>/<slug> target, the DevLoop policy -- around the approval's
// own execution, work item, args digest and artifact hash. The operation
// takes no argument besides service and slug (approver is refused above),
// so the stored args digest is the requester's own digest of those and is
// carried as is. A target, kind or policy the approval was not granted for
// therefore yields a different hash, and the CAS refuses it (409
// approval_intent_mismatch) without spending the approval.
func (h *Handlers) bindApprovalGrant(w http.ResponseWriter, r *http.Request, user *auth.User, s *approvalSpend, input map[string]string) bool {
	a := s.approval
	target := input["service"] + "/" + input["slug"]
	refuse := func(msg string) bool {
		h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", a.ID, aarCodeIntentMismatch)
		writeErrorCode(w, http.StatusConflict, aarCodeIntentMismatch, msg, nil)
		return false
	}
	workflowID, err := temporalclient.WorkflowIDForProposalRef(target)
	if err != nil {
		return refuse("target " + target + " names no DevLoop")
	}
	exec, err := h.opts.WorkItems.ExecutionByID(r.Context(), a.ExecutionID)
	switch {
	case errors.Is(err, workitems.ErrNotFound):
		return refuse("the approval's execution " + a.ExecutionID + " does not exist")
	case err != nil:
		slog.Error("approval grant: execution could not be read", "approval", a.ID, "execution", a.ExecutionID, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable, "could not read the approval's execution", nil)
		return false
	}
	// engine_ref is the workflow id, or <workflow_id>#<request_id> for a
	// run dispatched from an execution request (D3).
	run, _, _ := strings.Cut(exec.EngineRef, "#")
	if exec.Engine != workitems.EngineTemporal || run != workflowID {
		return refuse("target " + target + " does not belong to the DevLoop this approval was decided for")
	}
	s.intentHash = workitems.IntentHash(workitems.ActionIntent{
		ExecutionID:   a.ExecutionID,
		ActionKind:    devLoopApprovalKind,
		Target:        target,
		ArgsDigest:    a.ArgsDigest,
		PolicyRuleID:  devLoopApprovalPolicyRule,
		PolicyVersion: devLoopApprovalPolicyVersion,
		ArtifactHash:  a.ArtifactHash,
		WorkItemID:    a.WorkItemID,
	})
	return true
}

// spendApprovalGrant consumes the prepared aar_: approved, same intent, not
// expired, not consumed -- one atomic compare-and-set. The consumed row is
// returned; its decider is the recorded approver. A submit that fails after
// this has still spent the approval: single use is the point, and the run
// asks for a new one.
func (h *Handlers) spendApprovalGrant(w http.ResponseWriter, r *http.Request, user *auth.User, s *approvalSpend) (*workitems.ActionApprovalRequest, bool) {
	a, err := h.opts.WorkItems.ConsumeActionApproval(r.Context(), s.approval.ID, s.intentHash)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", s.approval.ID, code)
		} else if !errors.Is(err, workitems.ErrNotFound) {
			slog.Error("approval grant: consume failed", "approval", s.approval.ID, "error", err)
		}
		writeActionApprovalError(w, err)
		return nil, false
	}
	h.auditActionApproval(r, user, "action_approval.consume", a, operations.RiskMedium)
	if a.DecidedBy != s.approval.DecidedBy {
		// A decision is final, so this cannot happen; if it did, the
		// approver already recorded in the input would not be the one who
		// decided what was just spent.
		slog.Error("approval grant: decider changed between load and consume", "approval", a.ID)
		writeErrorCode(w, http.StatusConflict, aarCodeNotApproved, "the approval's decider changed; ask for a new approval", nil)
		return nil, false
	}
	return a, true
}

// approvalGrantAuditParams records who acted and for whom on a
// grant-authorized submit: the agent run as actor, the decider as subject,
// and the grant spent.
func approvalGrantAuditParams(params map[string]string, user *auth.User, a *workitems.ActionApprovalRequest) {
	agent, _ := user.DelegatingAgent()
	params["actor_kind"] = string(auth.KindAgent)
	params["actor_name"] = agent
	params["agent_run_id"] = user.AgentRunID()
	params["execution_id"] = a.ExecutionID
	params["subject_principal_id"] = a.DecidedByPrincipalID
	params["grant_ref"] = a.ID
}
