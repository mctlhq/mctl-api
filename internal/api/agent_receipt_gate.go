package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The action approval store side of the MCP agent receipt gate
// (mctl-api#723, internal/mcp/agent_receipt_gate.go). It reuses the action
// approval model of mctl-api#366 as it is: a receipt is an aar_ request the
// caller itself requested and consumed, and spending it is the existing
// consumed -> executed compare-and-set.

var _ mcp.AgentReceiptVerifier = (*Handlers)(nil)

// agentReceiptGateOperation labels the gate's audit rows.
const agentReceiptGateOperation = "agent-receipt-gate"

// VerifyAgentReceipt implements mcp.AgentReceiptVerifier.
func (h *Handlers) VerifyAgentReceipt(ctx context.Context, user *auth.User, c mcp.ReceiptCheck) string {
	if h.opts.WorkItems == nil {
		return mcp.ReceiptCodeUnverifiable
	}
	caller := principalOf(user)
	a, err := h.opts.WorkItems.ActionApproval(ctx, c.Ref)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return mcp.ReceiptCodeNotFound
	case err != nil:
		slog.Warn("agent receipt gate: receipt unreadable", "tool", c.Tool, "approval_id", c.Ref, "error", err)
		return mcp.ReceiptCodeUnverifiable
	}
	// Another principal's request reads as absent, as on the REST routes.
	if a.RequestedBy != caller {
		return mcp.ReceiptCodeNotFound
	}
	if a.ActionKind != mcp.ReceiptActionKindPrefix+c.Tool {
		return mcp.ReceiptCodeOperationMismatch
	}
	if a.Target != mcp.ReceiptTarget {
		return mcp.ReceiptCodeTargetMismatch
	}
	switch a.State {
	case workitems.ApprovalConsumed:
	case workitems.ApprovalExecuted:
		return mcp.ReceiptCodeAlreadyExecuted
	default:
		return mcp.ReceiptCodeNotConsumed
	}
	if c.ArtifactHash == "" || a.ArtifactHash == "" || a.ArtifactHash != c.ArtifactHash {
		return mcp.ReceiptCodeArtifactMismatch
	}
	if !c.Redeem {
		return ""
	}
	_, err = h.opts.WorkItems.MarkActionApprovalExecuted(ctx, c.Ref, mcp.ReceiptTarget, c.ArtifactHash, caller)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, workitems.ErrApprovalExecuted):
		return mcp.ReceiptCodeAlreadyExecuted
	case errors.Is(err, workitems.ErrApprovalNotConsumed), errors.Is(err, workitems.ErrApprovalDenied):
		return mcp.ReceiptCodeNotConsumed
	case errors.Is(err, workitems.ErrApprovalTargetMismatch):
		return mcp.ReceiptCodeArtifactMismatch
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return mcp.ReceiptCodeNotFound
	default:
		slog.Warn("agent receipt gate: spend failed", "tool", c.Tool, "approval_id", c.Ref, "error", err)
		return mcp.ReceiptCodeUnverifiable
	}
}

// AuditAgentReceipt implements mcp.AgentReceiptVerifier: one row per
// governed call from mctl-agent. Status is "succeeded" for a call a receipt
// authorized, "denied" for one enforce refused, and "observed" for one
// observe let through without a valid receipt.
func (h *Handlers) AuditAgentReceipt(ctx context.Context, user *auth.User, o mcp.ReceiptOutcome) {
	status, msg := "succeeded", "governed agent call carried a valid receipt"
	switch {
	case o.Refused:
		status, msg = "denied", "governed agent call refused: "+o.Code
	case o.Code != "":
		status, msg = "observed", "governed agent call without a valid receipt (observe mode): "+o.Code
	}
	params := map[string]string{
		"tool":           o.Tool,
		"mode":           string(o.Mode),
		"policy_version": mcp.AgentReceiptGatePolicyVersion,
	}
	if o.Code != "" {
		params["code"] = o.Code
	}
	if o.Ref != "" {
		params["approval_id"] = o.Ref
	}
	h.logAuditCtx(ctx, audit.Entry{
		UserID:     user.ID,
		Operation:  agentReceiptGateOperation,
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
		Message:    msg,
		Parameters: params,
	})
}
