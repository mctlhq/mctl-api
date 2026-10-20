package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

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

// agentReceiptGateTotal counts the gate's decisions next to its audit rows,
// because an audit write is best-effort: a row that failed to land must
// still show up somewhere. code is "valid" for a receipt that authorized the
// call, and one of the known refusal codes otherwise.
var agentReceiptGateTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mcp_agent_receipt_gate_total",
	Help: "Governed MCP calls from mctl-agent seen by the receipt gate (mctl-api#723), by mode and receipt code.",
}, []string{"mode", "code"})

func init() { prometheus.MustRegister(agentReceiptGateTotal) }

// receiptCodeLabels bounds the counter's code label to the codes the gate
// defines; anything else counts as "other".
var receiptCodeLabels = map[string]struct{}{
	mcp.ReceiptCodeMissing: {}, mcp.ReceiptCodeMalformed: {}, mcp.ReceiptCodeNotFound: {},
	mcp.ReceiptCodeOperationMismatch: {}, mcp.ReceiptCodeTargetMismatch: {}, mcp.ReceiptCodeNotConsumed: {},
	mcp.ReceiptCodeAlreadyExecuted: {}, mcp.ReceiptCodeArtifactMismatch: {}, mcp.ReceiptCodeUnverifiable: {},
}

// receiptModeLabel bounds the counter's mode label the same way: the boot
// check admits only these modes today, but AuditAgentReceipt is exported, so
// the label set must not depend on every caller having run that check.
func receiptModeLabel(mode mcp.AgentReceiptGateMode) string {
	switch mode {
	case mcp.AgentReceiptGateOff, mcp.AgentReceiptGateObserve, mcp.AgentReceiptGateEnforce:
		return string(mode)
	}
	return "other"
}

func receiptCodeLabel(code string) string {
	if code == "" {
		return "valid"
	}
	if _, ok := receiptCodeLabels[code]; ok {
		return code
	}
	return "other"
}

// VerifyAgentReceipt implements mcp.AgentReceiptVerifier.
func (h *Handlers) VerifyAgentReceipt(ctx context.Context, user *auth.User, c mcp.ReceiptCheck) string {
	// The gate keeps nil out today, but this method must not rely on another
	// package's guard: a nil caller here would panic outside recoverToolPanic.
	if user == nil || h.opts.WorkItems == nil {
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
	code := spendErrorCode(err)
	if code == mcp.ReceiptCodeUnverifiable {
		slog.Warn("agent receipt gate: spend failed", "tool", c.Tool, "approval_id", c.Ref, "error", err)
	}
	return code
}

// spendErrorCode maps a MarkActionApprovalExecuted refusal to a receipt
// code. These fire only when the request changed between the read above and
// the compare-and-set (another call spent it, say).
func spendErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, workitems.ErrApprovalExecuted):
		return mcp.ReceiptCodeAlreadyExecuted
	case errors.Is(err, workitems.ErrApprovalNotConsumed), errors.Is(err, workitems.ErrApprovalDenied):
		return mcp.ReceiptCodeNotConsumed
	case errors.Is(err, workitems.ErrApprovalTargetMismatch):
		// The store raises this one error for a target OR an artifact hash
		// mismatch (MarkActionApprovalExecuted). The target was compared
		// above and cannot change after creation, so only the hash can
		// differ here: this is an artifact mismatch, not a target one.
		return mcp.ReceiptCodeArtifactMismatch
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return mcp.ReceiptCodeNotFound
	default:
		return mcp.ReceiptCodeUnverifiable
	}
}

// AuditAgentReceipt implements mcp.AgentReceiptVerifier: one row per
// governed call from mctl-agent. Status is "succeeded" for a call a receipt
// authorized, "denied" for one enforce refused, and "observed" for one
// observe let through without a valid receipt.
func (h *Handlers) AuditAgentReceipt(ctx context.Context, user *auth.User, o mcp.ReceiptOutcome) {
	agentReceiptGateTotal.WithLabelValues(receiptModeLabel(o.Mode), receiptCodeLabel(o.Code)).Inc()
	userID := ""
	if user != nil {
		userID = user.ID
	}
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
	if o.Malformed != "" {
		params["malformed"] = o.Malformed
	}
	h.logAuditCtx(ctx, audit.Entry{
		UserID:     userID,
		Operation:  agentReceiptGateOperation,
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
		Message:    msg,
		Parameters: params,
	})
}
