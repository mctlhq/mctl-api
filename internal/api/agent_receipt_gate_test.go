package api

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const receiptTool = "mctl_deploy_service"

// receiptInput is the intent mctl-agents' checkpoint records for one mctl MCP
// tool call, requested by the mctl-agent service principal.
func (env *workItemsEnv) receiptInput(key, tool string) workitems.ActionApprovalInput {
	return workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID:   env.tenant + "-receipt",
			ActionKind:    mcp.ReceiptActionKindPrefix + tool,
			Target:        mcp.ReceiptTarget,
			ArgsDigest:    "sha256:args",
			PolicyRuleID:  "mctl-mcp-default-approval",
			PolicyVersion: "v1",
			ArtifactHash:  "sha256:action",
		},
		RequestedBy:    principalOf(auth.NewServiceUser()),
		IdempotencyKey: env.tenant + "-" + key,
		ExpiresAt:      time.Now().Add(time.Hour),
	}
}

// receipt creates an approval and walks it to state: "requested",
// "approved" or "consumed".
func (env *workItemsEnv) receipt(in workitems.ActionApprovalInput, state string) string {
	env.t.Helper()
	ctx := context.Background()
	store := env.h.opts.WorkItems
	a, _, err := store.CreateActionApproval(ctx, in)
	if err != nil {
		env.t.Fatalf("create: %v", err)
	}
	if state == "requested" {
		return a.ID
	}
	if _, err := store.DecideActionApproval(ctx, workitems.ActionDecisionInput{
		ID: a.ID, DecidedBy: "github:owner", Decision: workitems.DecisionApprove,
	}); err != nil {
		env.t.Fatalf("approve: %v", err)
	}
	if state == "approved" {
		return a.ID
	}
	if _, err := store.ConsumeActionApproval(ctx, a.ID, workitems.IntentHash(in.ActionIntent)); err != nil {
		env.t.Fatalf("consume: %v", err)
	}
	return a.ID
}

func (env *workItemsEnv) verify(tool, ref, hash string, redeem bool) string {
	return env.h.VerifyAgentReceipt(context.Background(), auth.NewServiceUser(), mcp.ReceiptCheck{
		Tool: tool, Ref: ref, ArtifactHash: hash, Redeem: redeem,
	})
}

func (env *workItemsEnv) state(ref string) string {
	env.t.Helper()
	a, err := env.h.opts.WorkItems.ActionApproval(context.Background(), ref)
	if err != nil {
		env.t.Fatalf("read %s: %v", ref, err)
	}
	return a.State
}

func TestVerifyAgentReceipt_SpendsOnceForItsOwnTool(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("ok", receiptTool), "consumed")
	if code := env.verify(receiptTool, ref, "sha256:action", true); code != "" {
		t.Fatalf("valid receipt refused: %s", code)
	}
	if got := env.state(ref); got != workitems.ApprovalExecuted {
		t.Fatalf("state after spend = %s, want executed", got)
	}
	if code := env.verify(receiptTool, ref, "sha256:action", true); code != mcp.ReceiptCodeAlreadyExecuted {
		t.Fatalf("reuse = %q, want %s", code, mcp.ReceiptCodeAlreadyExecuted)
	}
}

func TestVerifyAgentReceipt_ObserveDoesNotSpend(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("observe", receiptTool), "consumed")
	if code := env.verify(receiptTool, ref, "sha256:action", false); code != "" {
		t.Fatalf("valid receipt refused: %s", code)
	}
	if got := env.state(ref); got != workitems.ApprovalConsumed {
		t.Fatalf("observe changed state to %s", got)
	}
}

// Each refusal is checked read-only too, so the store's own compare-and-set
// in the redeem path cannot hide a missing check in the verifier.
func TestVerifyAgentReceipt_Refusals(t *testing.T) {
	env := newWorkItemsEnv(t)
	consumed := env.receipt(env.receiptInput("refuse", receiptTool), "consumed")
	otherTarget := env.receiptInput("target", receiptTool)
	otherTarget.Target = "github"
	otherRequester := env.receiptInput("requester", receiptTool)
	otherRequester.RequestedBy = "github:alice"
	noHash := env.receiptInput("nohash", receiptTool)
	noHash.ArtifactHash = ""

	cases := []struct {
		name, tool, ref, hash, want string
	}{
		{"unknown id", receiptTool, "aar_does_not_exist", "sha256:action", mcp.ReceiptCodeNotFound},
		{"other tool", "mctl_scale_service", consumed, "sha256:action", mcp.ReceiptCodeOperationMismatch},
		{"artifact mismatch", receiptTool, consumed, "sha256:other", mcp.ReceiptCodeArtifactMismatch},
		{"artifact missing", receiptTool, consumed, "", mcp.ReceiptCodeArtifactMismatch},
		{"other target", receiptTool, env.receipt(otherTarget, "consumed"), "sha256:action", mcp.ReceiptCodeTargetMismatch},
		{"other requester", receiptTool, env.receipt(otherRequester, "consumed"), "sha256:action", mcp.ReceiptCodeNotFound},
		{"approved, not consumed", receiptTool, env.receipt(env.receiptInput("approved", receiptTool), "approved"), "sha256:action", mcp.ReceiptCodeNotConsumed},
		{"never decided", receiptTool, env.receipt(env.receiptInput("requested", receiptTool), "requested"), "sha256:action", mcp.ReceiptCodeNotConsumed},
		{"stored hash empty", receiptTool, env.receipt(noHash, "consumed"), "", mcp.ReceiptCodeArtifactMismatch},
	}
	for _, c := range cases {
		for _, redeem := range []bool{false, true} {
			if got := env.verify(c.tool, c.ref, c.hash, redeem); got != c.want {
				t.Errorf("%s (redeem=%v) = %q, want %q", c.name, redeem, got, c.want)
			}
		}
	}
	if got := env.state(consumed); got != workitems.ApprovalConsumed {
		t.Fatalf("a refused check spent the receipt: %s", got)
	}
}

func TestVerifyAgentReceipt_NoStoreIsUnverifiable(t *testing.T) {
	h := &Handlers{}
	got := h.VerifyAgentReceipt(context.Background(), auth.NewServiceUser(), mcp.ReceiptCheck{Tool: receiptTool, Ref: "aar_1", ArtifactHash: "x"})
	if got != mcp.ReceiptCodeUnverifiable {
		t.Fatalf("got %q, want %s", got, mcp.ReceiptCodeUnverifiable)
	}
}

func TestVerifyAgentReceipt_UnreadableStoreIsUnverifiable(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("closed", receiptTool), "consumed")
	store, err := workitems.NewStore(context.Background(), env.connStr)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	h := &Handlers{opts: Options{WorkItems: store}}
	got := h.VerifyAgentReceipt(context.Background(), auth.NewServiceUser(), mcp.ReceiptCheck{Tool: receiptTool, Ref: ref, ArtifactHash: "sha256:action"})
	if got != mcp.ReceiptCodeUnverifiable {
		t.Fatalf("closed store = %q, want %s", got, mcp.ReceiptCodeUnverifiable)
	}
}

func TestAuditAgentReceipt_Statuses(t *testing.T) {
	env := newWorkItemsEnv(t)
	for _, c := range []struct {
		o    mcp.ReceiptOutcome
		want string
	}{
		{mcp.ReceiptOutcome{Tool: receiptTool, Ref: "aar_1", Mode: mcp.AgentReceiptGateEnforce}, "succeeded"},
		{mcp.ReceiptOutcome{Tool: receiptTool, Code: mcp.ReceiptCodeMissing, Mode: mcp.AgentReceiptGateEnforce, Refused: true}, "denied"},
		{mcp.ReceiptOutcome{Tool: receiptTool, Code: mcp.ReceiptCodeMissing, Mode: mcp.AgentReceiptGateObserve}, "observed"},
	} {
		env.h.AuditAgentReceipt(context.Background(), auth.NewServiceUser(), c.o)
		got := env.audit.List(1)
		if len(got) != 1 || got[0].Operation != agentReceiptGateOperation || got[0].Status != c.want ||
			got[0].Parameters["tool"] != receiptTool || got[0].Parameters["code"] != c.o.Code ||
			got[0].Parameters["policy_version"] != mcp.AgentReceiptGatePolicyVersion {
			t.Errorf("%+v: audit = %+v", c.o, got)
		}
	}
}
