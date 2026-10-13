package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
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

// devLoopApprovalPolicyRule and devLoopApprovalPolicyVersion are what a
// DevLoop approval grant is created under (R1).
const (
	devLoopApprovalPolicyRule    = "dev-loop.human-approval"
	devLoopApprovalPolicyVersion = "v1"
)

// approvalSpend is a loaded, checked aar_ waiting to be consumed right
// before the operation is submitted.
type approvalSpend struct {
	approval   *workitems.ActionApprovalRequest
	intentHash string
}

// prepareApprovalGrant loads the aar_ named by the request's delegation
// grant and computes the intent the request asks for, without spending it. It refuses
// (and has answered) when ok is false.
//
// The intent is rebuilt from what the request asks for -- this action kind,
// this <service>/<slug> target, the DevLoop policy -- around the approval's
// own execution, work item, args digest and artifact hash. The operation
// takes no argument besides service and slug (approver is refused below),
// so the stored args digest is the requester's own digest of those and is
// carried as is. A target, kind or policy the approval was not granted for
// therefore yields a different hash, and ConsumeActionApproval's CAS
// refuses it (409 approval_intent_mismatch) without spending the approval.
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
	intent := workitems.ActionIntent{
		ExecutionID:   a.ExecutionID,
		ActionKind:    devLoopApprovalKind,
		Target:        input["service"] + "/" + input["slug"],
		ArgsDigest:    a.ArgsDigest,
		PolicyRuleID:  devLoopApprovalPolicyRule,
		PolicyVersion: devLoopApprovalPolicyVersion,
		ArtifactHash:  a.ArtifactHash,
		WorkItemID:    a.WorkItemID,
	}
	return &approvalSpend{approval: a, intentHash: workitems.IntentHash(intent)}, true
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
