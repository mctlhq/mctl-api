package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctlhq/mctl-gitops#1980: an implementer run without an execution exchanges
// its ServiceAccount token for one pinned to the newest human-decided grant
// of the one proposal it was submitted for.

const pinTarget = "mctl-api/issue-571-x"

// pinExchangeEnv is the exchange env with the fake binder answering a
// grant-pinned implementer run for pinTarget.
func pinExchangeEnv(t *testing.T) (*workItemsEnv, *fakeBinder) {
	e, b, _ := exchangeEnv(t)
	e.h.opts.Registry = operations.NewRegistry()
	e.h.opts.TemporalClient = &fakeDevLoopClient{}
	b.binding.Agent = "implementer"
	b.binding.Scope = auth.AgentScopeImplementGrant
	b.binding.ExecutionID = ""
	b.binding.GrantTarget = pinTarget
	b.binding.Template = "mctl-agents-implement"
	return e, b
}

// spentGrant takes a DevLoop grant through a human decision and the worker's
// spend, and returns its id.
func (e *workItemsEnv) spentGrant(suffix string) string {
	e.t.Helper()
	dl := e.startDevLoopRun(suffix)
	id := e.requestDevLoopGrant(dl.execID, e.tenant+"-"+suffix)
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusOK {
		e.t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	row := e.approvalRow(id)
	if res := e.consume(id, row["intent_hash"].(string)); res.code != http.StatusOK {
		e.t.Fatalf("consume = %d %s", res.code, res.raw)
	}
	return id
}

func pinnedRun(grant string) *auth.User {
	return auth.NewAgentUser("implementer", auth.AgentRun{
		Agent: "implementer", RunID: "art_pinned", Scope: auth.AgentScopeImplementGrant, GrantID: grant,
	})
}

func TestExchangeAgentRunToken_PinsTheProposalsNewestGrant(t *testing.T) {
	e, _ := pinExchangeEnv(t)
	e.spentGrant("older")
	newest := e.spentGrant("newer")

	res := e.exchange("sa-token", map[string]any{"grant_id": "aar_named_by_the_pod", "scope": auth.AgentScopeImplement})
	if res.code != http.StatusCreated {
		t.Fatalf("exchange = %d %s", res.code, res.raw)
	}
	if res.body["grant_id"] != newest || res.body["execution_id"] != "" || res.body["scope"] != auth.AgentScopeImplementGrant {
		t.Fatalf("exchanged = %v, want grant %s", res.body, newest)
	}
	run, err := e.h.opts.WorkItems.ResolveAgentRunToken(context.Background(), res.body["token"].(string))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if run.GrantID != newest || run.ExecutionID != "" || run.WorkItemID != "" {
		t.Fatalf("resolved = %+v", run)
	}
	found := false
	for _, entry := range e.audit.List(1000) {
		if entry.Operation == "agent_run_token.exchange" && entry.Parameters["grant_id"] == newest {
			found = true
		}
	}
	if !found {
		t.Error("the exchange audit row does not name the pinned grant")
	}
}

// Refusals and unknowns: nothing spent, or a newest grant that fails a check,
// is a refusal, and an older good one is not a fallback. A store that cannot
// answer is 503.
func TestExchangeAgentRunToken_PinIssuesNothingWithoutAGrant(t *testing.T) {
	t.Run("nothing decided", func(t *testing.T) {
		e, _ := pinExchangeEnv(t)
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusForbidden || code(res) != artCodeGrantNotFound {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
	t.Run("decided but not spent", func(t *testing.T) {
		e, _ := pinExchangeEnv(t)
		dl := e.startDevLoopRun("unspent")
		id := e.requestDevLoopGrant(dl.execID, e.tenant+"-unspent")
		if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusOK {
			t.Fatalf("approve = %d %s", res.code, res.raw)
		}
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusForbidden || code(res) != artCodeGrantNotFound {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
	t.Run("another proposal's grant", func(t *testing.T) {
		e, b := pinExchangeEnv(t)
		e.spentGrant("other")
		b.binding.GrantTarget = "mctl-api/issue-572-y"
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusForbidden || code(res) != artCodeGrantNotFound {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
	t.Run("newest has no human decider", func(t *testing.T) {
		e, _ := pinExchangeEnv(t)
		e.spentGrant("good-older")
		store := e.h.opts.WorkItems
		dl := e.startDevLoopRun("service-decided")
		id := e.requestDevLoopGrant(dl.execID, e.tenant+"-service-decided")
		row := e.approvalRow(id)
		ctx := context.Background()
		if _, err := store.DecideActionApproval(ctx, workitems.ActionDecisionInput{ID: id, DecidedBy: "service:another", Decision: "approve"}); err != nil {
			t.Fatalf("decide: %v", err)
		}
		if _, err := store.ConsumeActionApproval(ctx, id, row["intent_hash"].(string)); err != nil {
			t.Fatalf("consume: %v", err)
		}
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusForbidden || code(res) != artCodeGrantUnusable {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
	t.Run("newest binds no content", func(t *testing.T) {
		e, _ := pinExchangeEnv(t)
		e.spentGrant("good-older")
		store, ctx := e.h.opts.WorkItems, context.Background()
		a, _, err := store.CreateActionApproval(ctx, workitems.ActionApprovalInput{
			ActionIntent: workitems.ActionIntent{
				ExecutionID: e.tenant + "-exec", ActionKind: devLoopApprovalKind, Target: pinTarget,
				ArgsDigest: "sha256:args", PolicyRuleID: "dev-loop.human-approval", PolicyVersion: "v1",
			},
			RequestedBy: principalOf(auth.NewServiceUser()), IdempotencyKey: e.tenant + "-no-digest", ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.DecideActionApproval(ctx, workitems.ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: "approve"}); err != nil {
			t.Fatalf("decide: %v", err)
		}
		if _, err := store.ConsumeActionApproval(ctx, a.ID, a.IntentHash); err != nil {
			t.Fatalf("consume: %v", err)
		}
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusForbidden || code(res) != artCodeGrantUnusable {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
	t.Run("store unreadable", func(t *testing.T) {
		e, _ := pinExchangeEnv(t)
		e.spentGrant("before-close")
		closed, err := workitems.NewStore(context.Background(), e.connStr)
		if err != nil {
			t.Fatal(err)
		}
		closed.Close()
		e.h.opts.WorkItems = closed
		res := e.exchange("sa-token", nil)
		if res.code != http.StatusServiceUnavailable || code(res) != artCodeExchangeUnavailable {
			t.Fatalf("exchange = %d %s", res.code, res.raw)
		}
	})
}

// No caller names a pin: the direct mint cannot issue the scope, a body field
// is not decoded, and a pin on any other scope is refused.
func TestMintAgentRunToken_CannotAskForAPin(t *testing.T) {
	e, _ := pinExchangeEnv(t)
	id := e.spentGrant("mint")
	dl := e.startDevLoopRun("mint-exec")
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/agent-run-tokens", map[string]any{
		"agent": "implementer", "scope": auth.AgentScopeImplementGrant, "execution_id": dl.execID,
	})
	if res.code != http.StatusBadRequest || code(res) != artCodeGrantRequired {
		t.Fatalf("direct mint = %d %s", res.code, res.raw)
	}
	res = e.do(auth.NewServiceUser(), "POST", "/api/v1/agent-run-tokens", map[string]any{
		"agent": "implementer", "scope": auth.AgentScopeImplementGrant, "execution_id": dl.execID, "grant_id": id,
	})
	if res.code != http.StatusBadRequest {
		t.Fatalf("direct mint naming a grant = %d %s", res.code, res.raw)
	}
	if _, ok := res.body["token"]; ok {
		t.Fatal("a direct mint naming a grant returned a token")
	}
	iss := agentRunIssuer{UserID: "k8s:x", Actor: "k8s:x", Exchange: true}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/agent-run-tokens/exchange", nil)
	e.h.issueAgentRunToken(rec, req, iss, agentRunTokenBody{
		Agent: "implementer", Scope: auth.AgentScopeImplement, WithoutExecution: true, GrantID: id,
	}, time.Hour, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pin on another scope = %d %s", rec.Code, rec.Body.String())
	}
}

// What the pin is for: that one grant, read and marked executed once, and no
// other approval; nothing requested, spent, decided or listed. Through the
// scope gate and the handlers together.
func TestPinnedRun_ReachesItsGrantOnly(t *testing.T) {
	e, _ := pinExchangeEnv(t)
	gated := chi.NewRouter()
	gated.Use(e.h.agentScopeGate)
	gated.Mount("/", e.router)
	e.router = gated

	id := e.spentGrant("pinned")
	other := e.spentGrant("not-pinned")
	row := e.approvalRow(id)
	run := pinnedRun(id)
	target, _ := row["target"].(string)
	body := executeBody(target, testContentDigest)

	if res := e.do(run, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusOK {
		t.Fatalf("read pinned = %d %s", res.code, res.raw)
	}
	if res := e.do(run, "GET", "/api/v1/action-approvals/"+other, nil); res.code != http.StatusNotFound {
		t.Fatalf("read other = %d %s", res.code, res.raw)
	}
	if res := e.markExecuted(run, other, body); res.code != http.StatusNotFound {
		t.Fatalf("execute other = %d %s", res.code, res.raw)
	}
	if st := e.approvalRow(other)["state"]; st != "consumed" {
		t.Fatalf("other grant state = %v", st)
	}
	for name, res := range map[string]wiResponse{
		"create":   e.do(run, "POST", "/api/v1/action-approvals", e.devLoopGrantBody(e.tenant+"-exec", e.tenant+"-pin-create")),
		"list":     e.do(run, "GET", "/api/v1/action-approvals", nil),
		"consume":  e.do(run, "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": row["intent_hash"]}),
		"decision": e.do(run, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": "approve"}),
	} {
		if res.code != http.StatusForbidden {
			t.Errorf("%s = %d %s, want 403", name, res.code, res.raw)
		}
	}
	if res := e.markExecuted(run, id, executeBody("mctl-api/issue-572-y", testContentDigest)); res.code == http.StatusOK {
		t.Fatalf("execute for another target = %d %s", res.code, res.raw)
	}
	if res := e.markExecuted(run, id, body); res.code != http.StatusOK {
		t.Fatalf("execute pinned = %d %s", res.code, res.raw)
	}
	found := false
	for _, entry := range e.audit.List(1000) {
		p := entry.Parameters
		if entry.Operation == "action_approval.execute" && p["approval_id"] == id {
			found = p["actor"] == "agent:implementer" && p["pinned_grant_id"] == id && p["agent_run_id"] == "art_pinned"
		}
	}
	if !found {
		t.Error("the execute audit row does not name the pinned run")
	}
	if res := e.markExecuted(run, id, body); res.code != http.StatusConflict || code(res) != aarCodeExecuted {
		t.Fatalf("second execute = %d %s", res.code, res.raw)
	}
	// A finished grant still answers: an earlier attempt's retry reads it.
	if res := e.do(run, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusOK {
		t.Fatalf("read executed = %d %s", res.code, res.raw)
	}
}

// The pin is the only thing the predicate honours: an implement token that
// happens to carry a grant id, an empty pin, and a pin on an approval that is
// not the control worker's DevLoop grant reach nothing.
func TestPinnedRun_PredicateIsTheScopeAndTheGrant(t *testing.T) {
	e, _ := pinExchangeEnv(t)
	id := e.spentGrant("predicate")

	wrongScope := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", Scope: auth.AgentScopeImplement, GrantID: id})
	unscoped := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", GrantID: id})
	for name, u := range map[string]*auth.User{"implement scope": wrongScope, "unscoped": unscoped, "empty pin": pinnedRun("")} {
		if res := e.do(u, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusForbidden {
			t.Errorf("%s read = %d %s, want 403", name, res.code, res.raw)
		}
		if res := e.markExecuted(u, id, executeBody(pinTarget, testContentDigest)); res.code != http.StatusForbidden {
			t.Errorf("%s execute = %d %s, want 403", name, res.code, res.raw)
		}
	}

	notTheWorkers, _, err := e.h.opts.WorkItems.CreateActionApproval(context.Background(), workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID: e.tenant + "-exec", ActionKind: devLoopApprovalKind, Target: pinTarget,
			ArgsDigest: "sha256:args", PolicyRuleID: "dev-loop.human-approval", PolicyVersion: "v1", ArtifactHash: testContentDigest,
		},
		RequestedBy: "service:someone-else", IdempotencyKey: e.tenant + "-not-the-workers", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := e.do(pinnedRun(notTheWorkers.ID), "GET", "/api/v1/action-approvals/"+notTheWorkers.ID, nil); res.code != http.StatusNotFound {
		t.Errorf("pin on another requester's grant = %d %s, want 404", res.code, res.raw)
	}
	wrongKind := e.approvedForExecute(e.tenant + "-pin-kind")
	if res := e.do(pinnedRun(wrongKind["id"].(string)), "GET", "/api/v1/action-approvals/"+wrongKind["id"].(string), nil); res.code != http.StatusNotFound {
		t.Errorf("pin on another kind = %d %s, want 404", res.code, res.raw)
	}
}
