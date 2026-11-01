package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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

func (env *workItemsEnv) settle(tool, ref string, succeeded bool) error {
	return env.h.SettleAgentReceipt(context.Background(), auth.NewServiceUser(), mcp.ReceiptCheck{
		Tool: tool, Ref: ref, ArtifactHash: "sha256:action", Redeem: true,
	}, succeeded)
}

// mctl-api#772: a redeeming check reserves the receipt; a concurrent call
// sees it in flight; a failed call releases it for a retry; a successful
// one spends it for good.
func TestVerifyAgentReceipt_SpendsOnceForItsOwnTool(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("ok", receiptTool), "consumed")
	if code := env.verify(receiptTool, ref, "sha256:action", true); code != "" {
		t.Fatalf("valid receipt refused: %s", code)
	}
	if got := env.state(ref); got != workitems.ApprovalInFlight {
		t.Fatalf("state after reserve = %s, want in_flight", got)
	}
	for _, redeem := range []bool{false, true} {
		if code := env.verify(receiptTool, ref, "sha256:action", redeem); code != mcp.ReceiptCodeInFlight {
			t.Fatalf("concurrent call (redeem=%v) = %q, want %s", redeem, code, mcp.ReceiptCodeInFlight)
		}
	}
	if err := env.settle(receiptTool, ref, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := env.state(ref); got != workitems.ApprovalConsumed {
		t.Fatalf("state after a failed call = %s, want consumed", got)
	}
	if code := env.verify(receiptTool, ref, "sha256:action", true); code != "" {
		t.Fatalf("retry after a failed call refused: %s", code)
	}
	if err := env.settle(receiptTool, ref, true); err != nil {
		t.Fatalf("settle success: %v", err)
	}
	if got := env.state(ref); got != workitems.ApprovalExecuted {
		t.Fatalf("state after a successful call = %s, want executed", got)
	}
	if code := env.verify(receiptTool, ref, "sha256:action", true); code != mcp.ReceiptCodeAlreadyExecuted {
		t.Fatalf("reuse = %q, want %s", code, mcp.ReceiptCodeAlreadyExecuted)
	}
	if err := env.settle(receiptTool, ref, false); err == nil {
		t.Fatal("an executed receipt was released")
	}
}

// mctl-api#773: a consumed receipt older than the configured bound is
// refused as stale, read-only and redeeming, and is left consumed.
func TestVerifyAgentReceipt_RefusesAStaleReceipt(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("stale", receiptTool), "consumed")
	env.h.opts.AgentReceiptMaxAge = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	for _, redeem := range []bool{false, true} {
		if code := env.verify(receiptTool, ref, "sha256:action", redeem); code != mcp.ReceiptCodeStale {
			t.Fatalf("old receipt (redeem=%v) = %q, want %s", redeem, code, mcp.ReceiptCodeStale)
		}
	}
	if got := env.state(ref); got != workitems.ApprovalConsumed {
		t.Fatalf("a stale refusal changed the state to %s", got)
	}
	env.h.opts.AgentReceiptMaxAge = time.Hour
	if code := env.verify(receiptTool, ref, "sha256:action", false); code != "" {
		t.Fatalf("the same receipt under a wide bound = %q", code)
	}
	env.h.opts.AgentReceiptMaxAge = 0
	if got := env.h.receiptMaxAge(); got != mcp.DefaultAgentReceiptMaxAge {
		t.Fatalf("unset bound = %s, want the default", got)
	}
}

// The approval's fresh_until bounds the receipt too, inside the age bound.
func TestVerifyAgentReceipt_RefusesAReceiptPastFreshUntil(t *testing.T) {
	env := newWorkItemsEnv(t)
	ctx := context.Background()
	store := env.h.opts.WorkItems
	in := env.receiptInput("fresh-until", receiptTool)
	a, _, err := store.CreateActionApproval(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecideActionApproval(ctx, workitems.ActionDecisionInput{
		ID: a.ID, DecidedBy: "github:owner", Decision: workitems.DecisionApprove, FreshFor: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeActionApproval(ctx, a.ID, workitems.IntentHash(in.ActionIntent)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if code := env.verify(receiptTool, a.ID, "sha256:action", true); code != mcp.ReceiptCodeStale {
		t.Fatalf("receipt past fresh_until = %q, want %s", code, mcp.ReceiptCodeStale)
	}
	if got := env.state(a.ID); got != workitems.ApprovalConsumed {
		t.Fatalf("state = %s, want consumed", got)
	}
}

// The gate's shape check runs before the verifier: the ids the store mints
// must pass it, or enforce would refuse every real receipt as malformed.
func TestVerifyAgentReceipt_StoreIDsAreWellFormed(t *testing.T) {
	env := newWorkItemsEnv(t)
	for i := range 3 {
		ref := env.receipt(env.receiptInput(fmt.Sprintf("shape-%d", i), receiptTool), "requested")
		if !mcp.WellFormedReceipt(ref, "sha256:action") {
			t.Fatalf("store id %q fails the gate's shape check", ref)
		}
	}
}

func TestSpendErrorCode(t *testing.T) {
	for err, want := range map[error]string{
		nil:                                 "",
		workitems.ErrApprovalExecuted:       mcp.ReceiptCodeAlreadyExecuted,
		workitems.ErrApprovalInFlight:       mcp.ReceiptCodeInFlight,
		workitems.ErrApprovalReceiptStale:   mcp.ReceiptCodeStale,
		workitems.ErrApprovalNotConsumed:    mcp.ReceiptCodeNotConsumed,
		workitems.ErrApprovalDenied:         mcp.ReceiptCodeNotConsumed,
		workitems.ErrApprovalTargetMismatch: mcp.ReceiptCodeArtifactMismatch,
		workitems.ErrApprovalNotFound:       mcp.ReceiptCodeNotFound,
		errors.New("connection reset"):      mcp.ReceiptCodeUnverifiable,
	} {
		wrapped := err
		if err != nil {
			wrapped = fmt.Errorf("workitems: aar_x: %w", err)
		}
		if got := spendErrorCode(wrapped); got != want {
			t.Errorf("spendErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestAgentReceiptVerifier_NilUser(t *testing.T) {
	env := newWorkItemsEnv(t)
	if got := env.h.VerifyAgentReceipt(context.Background(), nil, mcp.ReceiptCheck{Tool: receiptTool, Ref: "aar_1", ArtifactHash: "x"}); got != mcp.ReceiptCodeUnverifiable {
		t.Fatalf("nil user = %q", got)
	}
	env.h.AuditAgentReceipt(context.Background(), nil, mcp.ReceiptOutcome{Tool: receiptTool, Code: mcp.ReceiptCodeMissing})
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
		{"unknown id", receiptTool, "aar_00000000000000000000000000000000", "sha256:action", mcp.ReceiptCodeNotFound},
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
		{mcp.ReceiptOutcome{Tool: receiptTool, Code: mcp.ReceiptCodeMalformed, Mode: mcp.AgentReceiptGateObserve,
			Malformed: `prefix=true ref_len=9 head="ab" hash_len=8`}, "observed"},
	} {
		env.h.AuditAgentReceipt(context.Background(), auth.NewServiceUser(), c.o)
		got := env.audit.List(1)
		if len(got) != 1 || got[0].Operation != agentReceiptGateOperation || got[0].Status != c.want ||
			got[0].Parameters["tool"] != receiptTool || got[0].Parameters["code"] != c.o.Code ||
			got[0].Parameters["policy_version"] != mcp.AgentReceiptGatePolicyVersion ||
			got[0].Parameters["malformed"] != c.o.Malformed {
			t.Errorf("%+v: audit = %+v", c.o, got)
		}
	}
}

// The counter is bumped before the best-effort audit write, so it counts a
// decision even with no audit log at all. Its code label is bounded.
func TestAuditAgentReceipt_Counter(t *testing.T) {
	h := &Handlers{}
	for _, c := range []struct {
		code, label string
	}{
		{"", "valid"},
		{mcp.ReceiptCodeMalformed, mcp.ReceiptCodeMalformed},
		{mcp.ReceiptCodeUnverifiable, mcp.ReceiptCodeUnverifiable},
		{"something_new", "other"},
	} {
		m := agentReceiptGateTotal.WithLabelValues(string(mcp.AgentReceiptGateObserve), c.label)
		before := testutil.ToFloat64(m)
		h.AuditAgentReceipt(context.Background(), auth.NewServiceUser(),
			mcp.ReceiptOutcome{Tool: receiptTool, Code: c.code, Mode: mcp.AgentReceiptGateObserve})
		if n := testutil.ToFloat64(m) - before; n != 1 {
			t.Errorf("code %q: label %q moved by %v", c.code, c.label, n)
		}
	}
}

// The mode label is bounded like the code label: an unvalidated mode counts
// as "other" rather than adding a series per distinct value.
func TestAuditAgentReceipt_CounterModeLabel(t *testing.T) {
	h := &Handlers{}
	for _, c := range []struct {
		mode  mcp.AgentReceiptGateMode
		label string
	}{
		{mcp.AgentReceiptGateOff, "off"},
		{mcp.AgentReceiptGateObserve, "observe"},
		{mcp.AgentReceiptGateEnforce, "enforce"},
		{"", "other"},
		{"Enforce", "other"},
		{"something_new", "other"},
	} {
		m := agentReceiptGateTotal.WithLabelValues(c.label, "valid")
		before := testutil.ToFloat64(m)
		h.AuditAgentReceipt(context.Background(), auth.NewServiceUser(),
			mcp.ReceiptOutcome{Tool: receiptTool, Mode: c.mode})
		if n := testutil.ToFloat64(m) - before; n != 1 {
			t.Errorf("mode %q: label %q moved by %v", c.mode, c.label, n)
		}
	}
}

// mctl-api#772: concurrent governed calls presenting one receipt, through
// the verifier and the real store: exactly one is authorized, the rest are
// refused as in flight.
func TestVerifyAgentReceipt_ConcurrentCallsAuthorizeOne(t *testing.T) {
	env := newWorkItemsEnv(t)
	ref := env.receipt(env.receiptInput("race", receiptTool), "consumed")
	const racers = 8
	codes := make([]string, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = env.verify(receiptTool, ref, "sha256:action", true)
		}()
	}
	close(start)
	wg.Wait()
	won := 0
	for _, c := range codes {
		switch c {
		case "":
			won++
		case mcp.ReceiptCodeInFlight:
		default:
			t.Fatalf("loser code %q", c)
		}
	}
	if won != 1 {
		t.Fatalf("%d calls authorized, want exactly 1 (%v)", won, codes)
	}
}

// An agent run's receipt is its own execution's (mctlhq/mctl-agents#717
// S4): every run of one agent shares a principal, so a receipt another run
// consumed reads as absent, and so does any receipt to a token bound to no
// execution. The run's own receipt is spent like the service's.
func TestVerifyAgentReceipt_AgentReceiptIsItsExecutions(t *testing.T) {
	env := newWorkItemsEnv(t)
	run := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: env.tenant + "-receipt", RunID: "art_a"})
	in := env.receiptInput("agent", receiptTool)
	in.RequestedBy = principalOf(run)
	ref := env.receipt(in, "consumed")
	check := mcp.ReceiptCheck{Tool: receiptTool, Ref: ref, ArtifactHash: "sha256:action", Redeem: true}

	for name, u := range map[string]*auth.User{
		"another run":      auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: env.tenant + "-other", RunID: "art_b"}),
		"an unbound token": auth.NewAgentUser("implementer", auth.AgentRun{RunID: "art_c"}),
		"the service":      auth.NewServiceUser(),
	} {
		if got := env.h.VerifyAgentReceipt(context.Background(), u, check); got != mcp.ReceiptCodeNotFound {
			t.Errorf("%s: %q, want %q", name, got, mcp.ReceiptCodeNotFound)
		}
	}
	if s := env.state(ref); s != workitems.ApprovalConsumed {
		t.Fatalf("after refusals: %s", s)
	}
	if got := env.h.VerifyAgentReceipt(context.Background(), run, check); got != "" {
		t.Fatalf("own receipt: %q", got)
	}
	if err := env.h.SettleAgentReceipt(context.Background(), run, check, true); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if s := env.state(ref); s != workitems.ApprovalExecuted {
		t.Fatalf("after settle: %s", s)
	}
}
