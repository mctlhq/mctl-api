package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Agent receipt gate (mctl-api#723).
//
// mctl-agents' policy checkpoint runs inside the agent process, so this
// server cannot tell whether a governed tool call from the mctl-agent
// service principal passed through it. For the tools that checkpoint marks
// REQUIRE_APPROVAL, the gate asks for evidence that it did: the id of an
// action approval (aar_…) that was approved by someone else, consumed by
// mctl-agent for exactly this tool, and not yet spent on another call.
//
//   - The receipt travels as two reserved tool arguments, which are removed
//     from every call before any handler sees them, whatever the mode.
//   - Observe audits each governed call and changes nothing. A presented
//     receipt is checked read-only there and is not spent.
//   - Enforce refuses a governed call without a valid receipt. A valid one
//     is reserved before the handler runs (consumed -> in_flight, one
//     compare-and-set, so two concurrent calls cannot both pass), marked
//     executed when the handler succeeded, and released back to consumed
//     when it failed, so a failed call does not burn the human approval
//     (mctl-api#772). One receipt authorizes one successful call.
//   - A receipt is refused once its consumed_at is older than the
//     configured age bound or its decision's fresh_until has passed
//     (mctl-api#773): mctl-agents consumes it immediately before the call,
//     so an old one is a crashed run or a replay.
//   - A receipt that could not be checked is its own code, never "valid"
//     and never "missing".
//   - Gated: the direct mctl-agent service principal, and every agent run
//     token acting directly (mctlhq/mctl-agents#717 S4). An agent's receipt
//     must also be bound to the execution its token is bound to: an agent
//     requests and consumes approvals only for its own execution, and a
//     receipt of another execution, or a token bound to none, is not found.
//     Human principals and relayed requests are not gated.
//     No run scope admits a governed tool yet, so a scoped run is refused
//     by its scope before this gate (TestAgentScopesAdmitNoGovernedTool);
//     this gate is what then holds a scope that is widened to one. An
//     unscoped run token skips the scope check, and is now held here too.
//
// v1 binds an approval to the principal, the tool and one successful use. It
// does not bind the call's arguments: the server does not recompute the
// arguments digest, and the artifact hash is the one the agent recorded.
// "Failed" is the handler's own verdict (a Go error or an isError result),
// so a handler that reports failure after a partial side effect gets its
// receipt back; a call whose request was cancelled or timed out has an
// unknown outcome and spends it. A reservation whose settle cannot be written stays
// in_flight and is never usable again: fail closed. Only the hosted
// endpoint is gated; cmd/mcp's stdio server is not.

// AgentReceiptGateMode is the parsed MCTL_AGENT_RECEIPT_GATE.
type AgentReceiptGateMode string

const (
	AgentReceiptGateOff     AgentReceiptGateMode = "off"
	AgentReceiptGateObserve AgentReceiptGateMode = "observe"
	AgentReceiptGateEnforce AgentReceiptGateMode = "enforce"
)

// ParseAgentReceiptGateMode reads MCTL_AGENT_RECEIPT_GATE. Empty is off. Any
// other value is refused: a mistyped mode must stop the boot, not fall back
// to one the operator did not ask for.
func ParseAgentReceiptGateMode(raw string) (AgentReceiptGateMode, error) {
	switch m := AgentReceiptGateMode(strings.TrimSpace(raw)); m {
	case "", AgentReceiptGateOff:
		return AgentReceiptGateOff, nil
	case AgentReceiptGateObserve, AgentReceiptGateEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("MCTL_AGENT_RECEIPT_GATE %q is not one of off, observe, enforce", raw)
	}
}

// AgentReceiptGatePolicyVersion names the governed tool set below. Changing
// the set changes the version.
const AgentReceiptGatePolicyVersion = "mctl-api/agent-receipt-gate/v2"

// The reserved tool arguments that carry a receipt.
const (
	ArgActionApprovalRef          = "action_approval_ref"
	ArgActionApprovalArtifactHash = "action_approval_artifact_hash"
)

// The intent mctl-agents' checkpoint binds an mctl MCP tool call to
// (orchestrator/action_approvals.py intent_for): action_kind is
// "mcp.tool.call:mcp__mctl__<tool>" and target is the server alias.
const (
	ReceiptActionKindPrefix = "mcp.tool.call:mcp__mctl__"
	ReceiptTarget           = "mctl"
)

// Refusal codes, one per reason.
const (
	ReceiptCodeMissing           = "agent_receipt_missing"
	ReceiptCodeMalformed         = "agent_receipt_malformed"
	ReceiptCodeNotFound          = "agent_receipt_not_found"
	ReceiptCodeOperationMismatch = "agent_receipt_operation_mismatch"
	ReceiptCodeTargetMismatch    = "agent_receipt_target_mismatch"
	ReceiptCodeNotConsumed       = "agent_receipt_not_consumed"
	ReceiptCodeAlreadyExecuted   = "agent_receipt_already_executed"
	ReceiptCodeArtifactMismatch  = "agent_receipt_artifact_mismatch"
	ReceiptCodeUnverifiable      = "agent_receipt_unverifiable"
	// ReceiptCodeInFlight: the receipt is reserved by another call that is
	// still running (mctl-api#772).
	ReceiptCodeInFlight = "agent_receipt_in_flight"
	// ReceiptCodeStale: the receipt was consumed longer ago than the age
	// bound, or its decision is past fresh_until (mctl-api#773).
	ReceiptCodeStale = "agent_receipt_stale"
)

// DefaultAgentReceiptMaxAge is the receipt age bound when
// MCTL_AGENT_RECEIPT_MAX_AGE is unset (mctl-api#773).
const DefaultAgentReceiptMaxAge = 5 * time.Minute

// MaxAgentReceiptMaxAge caps the configurable bound: a receipt is consumed
// seconds before its call, and a bound of hours would make the check
// meaningless.
const MaxAgentReceiptMaxAge = time.Hour

// ParseAgentReceiptMaxAge reads MCTL_AGENT_RECEIPT_MAX_AGE, a Go duration.
// Empty is DefaultAgentReceiptMaxAge. A value that does not parse, is not
// positive, or exceeds MaxAgentReceiptMaxAge is refused: a mistyped bound
// must stop the boot, not silently widen or close the gate.
func ParseAgentReceiptMaxAge(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultAgentReceiptMaxAge, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("MCTL_AGENT_RECEIPT_MAX_AGE %q is not a duration: %w", raw, err)
	}
	if d <= 0 || d > MaxAgentReceiptMaxAge {
		return 0, fmt.Errorf("MCTL_AGENT_RECEIPT_MAX_AGE %s must be positive and at most %s", d, MaxAgentReceiptMaxAge)
	}
	return d, nil
}

// governedAgentTools is the explicit set of tools that need a receipt from
// mctl-agent: the tools mctl-agents' BUILTIN_POLICY gates with
// REQUIRE_APPROVAL (rule mctl-mcp-default-approval), that is every tool
// except the read verbs (get_, list_, read_, search_, describe_), whoami,
// incident_summary, resolve_agent, resolve_incident and
// acknowledge_incident. The gate must not require a receipt the agent never
// asks for, so it follows the agent's names, not this server's annotations.
// Every registered tool is in this set or in ungovernedAgentTools; a test
// fails on a tool in neither.
var governedAgentTools = toolSet(
	"mctl_abandon_dev_loop",
	// Creates a support task and spends the tenant's model budget.
	"mctl_ask_support",
	// Read-only, but not a read verb, so mctl-agents' policy asks for approval.
	"mctl_deploy_analyze",
	// Stores an immutable plan row; not a read verb.
	"mctl_deploy_plan",
	"mctl_add_custom_domain",
	"mctl_approve_dev_loop",
	"mctl_bind_agent_release",
	"mctl_cancel_customer_deletion",
	"mctl_create_agent",
	"mctl_create_preview",
	"mctl_create_tenant",
	"mctl_decide_signup_request",
	"mctl_delete_preview",
	"mctl_delete_tenant",
	"mctl_deploy_service",
	"mctl_deprecate_platform_skill",
	"mctl_disable_tenant_skill",
	"mctl_enable_tenant_skill",
	"mctl_erpact_create_site",
	"mctl_erpact_list_sites",
	"mctl_erpact_site_status",
	"mctl_fence_lifecycle_claim",
	"mctl_grant_repo_access",
	"mctl_inspect_lifecycle_conflict",
	"mctl_plan_epic_wave",
	"mctl_promote_agent",
	"mctl_provision_database",
	"mctl_publish_agent_definition_version",
	"mctl_publish_agent_profile_version",
	"mctl_publish_agent_version",
	"mctl_publish_platform_skill",
	"mctl_remove_custom_domain",
	"mctl_request_lifecycle_handoff",
	"mctl_request_lifecycle_reconcile",
	"mctl_request_work_item_execution",
	"mctl_create_work_item",
	"mctl_append_work_item_intent",
	"mctl_retire_service",
	"mctl_retry_lifecycle_handoff",
	"mctl_rollback_agent",
	"mctl_rollback_agent_binding",
	"mctl_rollback_service",
	"mctl_scale_service",
	"mctl_set_agent_version_lifecycle",
	"mctl_signup_capacity",
	"mctl_start_epic_wave",
	"mctl_sync_repos",
	"mctl_trigger_agents_run",
	"mctl_trigger_approve",
	"mctl_trigger_implementer",
	"mctl_trigger_incident_responder",
	"mctl_trigger_issue",
	"mctl_trigger_mentor_only",
	"mctl_trigger_portal_server_auth_apply",
	"mctl_trigger_reconcile",
	"mctl_trigger_shepherd",
	"mctl_trigger_single_service",
	"mctl_verify_domain",
)

// ungovernedAgentTools are the tools mctl-agents allows without an
// approval: reads, plus the two incident mutations agents make by design.
var ungovernedAgentTools = toolSet(
	"mctl_whoami",
	"mctl_incident_summary",
	"mctl_resolve_agent",
	"mctl_resolve_incident",
	"mctl_acknowledge_incident",
)

func toolSet(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

// Shape limits for a presented receipt. Its fields come from the one
// principal the gate distrusts and an MCP argument is bounded only by the
// request body, so a malformed value is refused before it reaches the store
// read or an audit row. An approval id is "aar_" and 32 hex digits
// (workitems.CreateActionApproval); the hash limit is the store's
// MaxApprovalFieldBytes.
const (
	receiptRefPrefix    = "aar_"
	maxReceiptRefBytes  = 64
	maxReceiptHashBytes = 512
)

// WellFormedReceipt reports whether ref and artifactHash have a receipt's
// shape: an "aar_" id of letters and digits, and a printable ASCII hash.
func WellFormedReceipt(ref, artifactHash string) bool {
	if len(ref) > maxReceiptRefBytes || !strings.HasPrefix(ref, receiptRefPrefix) || len(ref) == len(receiptRefPrefix) {
		return false
	}
	for _, r := range ref[len(receiptRefPrefix):] {
		if !isASCIIAlnum(r) {
			return false
		}
	}
	if len(artifactHash) > maxReceiptHashBytes {
		return false
	}
	for _, r := range artifactHash {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// maxMalformedEchoChars bounds how much of a malformed ref an audit row
// shows.
const maxMalformedEchoChars = 8

// DescribeMalformedReceipt is a bounded, printable account of a receipt
// WellFormedReceipt refused, for the audit row: whether the ref has the
// "aar_" prefix, both lengths, and at most the first eight letters or
// digits after the prefix. It never echoes anything else, so a broken
// injection can be told from a probe without storing what the caller sent.
func DescribeMalformedReceipt(ref, artifactHash string) string {
	prefixed := strings.HasPrefix(ref, receiptRefPrefix)
	tail := ref
	if prefixed {
		tail = ref[len(receiptRefPrefix):]
	}
	var head strings.Builder
	for _, r := range tail {
		if head.Len() == maxMalformedEchoChars || !isASCIIAlnum(r) {
			break
		}
		head.WriteRune(r)
	}
	return fmt.Sprintf("prefix=%t ref_len=%d head=%q hash_len=%d", prefixed, len(ref), head.String(), len(artifactHash))
}

func isASCIIAlnum(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
}

// isAgentReadTool mirrors the agent's read-verb rule for the ungoverned side.
func isAgentReadTool(name string) bool {
	for _, verb := range []string{"get_", "list_", "read_", "search_", "describe_"} {
		if strings.HasPrefix(name, "mctl_"+verb) {
			return true
		}
	}
	return false
}

// ReceiptCheck is one receipt presented for one call.
type ReceiptCheck struct {
	Tool         string
	Ref          string
	ArtifactHash string
	// Redeem reserves the receipt for this call (enforce); the caller then
	// settles it with SettleAgentReceipt. Without it the check is read-only.
	Redeem bool
}

// ReceiptOutcome is what the gate decided for one governed call.
type ReceiptOutcome struct {
	Tool string
	Ref  string
	// Code is "" when the receipt authorized the call.
	Code    string
	Mode    AgentReceiptGateMode
	Refused bool
	// Malformed is DescribeMalformedReceipt's account when Code is
	// ReceiptCodeMalformed, and empty otherwise.
	Malformed string
}

// AgentReceiptVerifier checks receipts against the action approval store
// and records each decision. The in-process HTTP server implements it.
type AgentReceiptVerifier interface {
	// VerifyAgentReceipt answers "" when the receipt authorizes the call,
	// otherwise one of the ReceiptCode* values. A receipt it could not read
	// is ReceiptCodeUnverifiable.
	VerifyAgentReceipt(ctx context.Context, user *auth.User, check ReceiptCheck) string
	// SettleAgentReceipt ends the reservation a redeeming check that
	// answered "" made: executed when the call succeeded, back to consumed
	// when it did not. An error leaves the receipt reserved, which no later
	// call can use.
	SettleAgentReceipt(ctx context.Context, user *auth.User, check ReceiptCheck, succeeded bool) error
	AuditAgentReceipt(ctx context.Context, user *auth.User, outcome ReceiptOutcome)
}

// settleTimeout bounds the settle write. It runs on a context detached from
// the request's cancellation: a client that hung up after the side effect
// must not leave the receipt reserved.
const settleTimeout = 10 * time.Second

// callSucceeded decides how a reserved receipt is settled: true spends it,
// false releases it for a retry. It is the handler's own verdict, except
// when the request was cancelled or ran past its deadline while the handler
// ran: the handler then usually reports an error even when the REST call
// behind it already applied the side effect, so the outcome is unknown and
// the receipt is spent, never handed back for a replay.
func callSucceeded(ctx context.Context, res *mcplib.CallToolResult, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	return err == nil && res != nil && !res.IsError
}

type agentReceiptGate struct {
	mode     AgentReceiptGateMode
	verifier AgentReceiptVerifier
}

// SetAgentReceiptGate wires the gate. Off, or a nil verifier, disables it;
// the reserved arguments are still removed from every call.
func (s *Server) SetAgentReceiptGate(v AgentReceiptVerifier, mode AgentReceiptGateMode) {
	if v == nil || mode == "" || mode == AgentReceiptGateOff {
		s.receiptGate.Store(nil)
		return
	}
	s.receiptGate.Store(&agentReceiptGate{mode: mode, verifier: v})
}

// isAgentServicePrincipal is the mctl-agent service principal acting for
// itself, not relayed for anyone.
func isAgentServicePrincipal(u *auth.User) bool {
	if u == nil || !u.IsService() || u.ID != auth.ServiceUserID {
		return false
	}
	_, relayed := u.RelaySurface()
	return !relayed
}

// isReceiptGatedPrincipal is a caller the gate holds: the mctl-agent
// service principal or an agent run token, either acting directly.
func isReceiptGatedPrincipal(u *auth.User) bool {
	if isAgentServicePrincipal(u) {
		return true
	}
	if u == nil || !u.IsAgent() {
		return false
	}
	_, relayed := u.RelaySurface()
	return !relayed
}

// gatedCallerLabel names a gated caller in a refusal: "mctl-agent" for the
// service principal, as before, and the agent run otherwise.
func gatedCallerLabel(u *auth.User) string {
	if name, ok := u.AgentName(); ok {
		return "agent run " + name
	}
	return "mctl-agent"
}

// takeReceiptArgs removes the reserved arguments from req and returns them.
func takeReceiptArgs(req mcplib.CallToolRequest) (ref, artifactHash string, out mcplib.CallToolRequest) {
	args := req.GetArguments()
	_, hasRef := args[ArgActionApprovalRef]
	_, hasHash := args[ArgActionApprovalArtifactHash]
	if !hasRef && !hasHash {
		return "", "", req
	}
	ref, _ = args[ArgActionApprovalRef].(string)
	artifactHash, _ = args[ArgActionApprovalArtifactHash].(string)
	rest := make(map[string]any, len(args))
	for k, v := range args {
		if k != ArgActionApprovalRef && k != ArgActionApprovalArtifactHash {
			rest[k] = v
		}
	}
	req.Params.Arguments = rest
	// Handlers read the map; the raw bytes would still carry the receipt.
	req.Params.RawArguments = nil
	return strings.TrimSpace(ref), strings.TrimSpace(artifactHash), req
}

// agentReceiptMiddleware applies the gate to tools/call.
func (s *Server) agentReceiptMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ref, artifactHash, req := takeReceiptArgs(req)
		gate := s.receiptGate.Load()
		if gate == nil {
			return next(ctx, req)
		}
		tool := req.Params.Name
		if _, governed := governedAgentTools[tool]; !governed {
			return next(ctx, req)
		}
		user := auth.UserFromContext(ctx)
		if !isReceiptGatedPrincipal(user) {
			return next(ctx, req)
		}
		enforce := gate.mode == AgentReceiptGateEnforce
		code, malformed := ReceiptCodeMissing, ""
		switch {
		case ref == "":
		case !WellFormedReceipt(ref, artifactHash):
			// Neither field is stored or audited as sent: either may be
			// huge. Only the bounded description is.
			code, malformed, ref = ReceiptCodeMalformed, DescribeMalformedReceipt(ref, artifactHash), ""
		default:
			code = gate.verifier.VerifyAgentReceipt(ctx, user, ReceiptCheck{
				Tool: tool, Ref: ref, ArtifactHash: artifactHash, Redeem: enforce,
			})
		}
		refused := enforce && code != ""
		gate.verifier.AuditAgentReceipt(ctx, user, ReceiptOutcome{
			Tool: tool, Ref: ref, Code: code, Mode: gate.mode, Refused: refused, Malformed: malformed,
		})
		if refused {
			return mcplib.NewToolResultError(fmt.Sprintf(
				"%s: %s from %s needs a consumed action approval for this call (%s)",
				code, tool, gatedCallerLabel(user), AgentReceiptGatePolicyVersion)), nil
		}
		if !enforce || code != "" {
			return next(ctx, req)
		}
		// Enforce with a reserved receipt: settle it however the handler
		// ends. recoverToolPanic sits inside this middleware, so a panic
		// arrives here as an error.
		check := ReceiptCheck{Tool: tool, Ref: ref, ArtifactHash: artifactHash, Redeem: true}
		res, err := next(ctx, req)
		succeeded := callSucceeded(ctx, res, err)
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
		defer cancel()
		if serr := gate.verifier.SettleAgentReceipt(settleCtx, user, check, succeeded); serr != nil {
			slog.Error("agent receipt gate: settle failed; the receipt stays reserved and cannot be used again",
				"tool", tool, "approval_id", ref, "succeeded", succeeded, "error", serr)
		}
		return res, err
	}
}
