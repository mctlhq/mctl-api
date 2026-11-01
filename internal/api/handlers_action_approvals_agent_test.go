package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Execution-bound agent approvals (mctlhq/mctl-agents#717 S4): an agent run
// token requests, reads, consumes and marks executed only approvals of the
// execution it is bound to, and reads and marks executed (never consumes)
// that execution's DevLoop grant.

// agentTestWorkItem is the work item the test runs are bound to. Requests
// that name it are cleaned up by their execution id, like the rest.
const agentTestWorkItem = "wi_agent-test"

// agentTestScope is a defined scope. The handlers need a scoped token; which
// scopes reach the approval routes is the scope gate's route list, which
// these handler-level tests do not run.
const agentTestScope = auth.AgentScopeInvestigate

func (e *workItemsEnv) agentRun(execID, runID string) *auth.User {
	return auth.NewAgentUser("implementer", auth.AgentRun{
		Agent: "implementer", ExecutionID: execID, WorkItemID: agentTestWorkItem, RunID: runID, Scope: agentTestScope,
	})
}

// agentApprovalBody is approvalBody bound to executeArtifactHash, so the
// request can later be marked executed.
func (e *workItemsEnv) agentApprovalBody(key string) map[string]any {
	b := e.approvalBody(key)
	b["artifact_hash"] = executeArtifactHash
	return b
}

func TestAgentApprovals_ARunRequestsSpendsAndMarksItsOwnExecutionsApproval(t *testing.T) {
	e := newWorkItemsEnv(t)
	run := e.agentRun(e.tenant+"-exec", "art_run_a")

	res := e.do(run, "POST", "/api/v1/action-approvals", e.agentApprovalBody("k-agent-own"))
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	a := res.body["approval"].(map[string]any)
	id := a["id"].(string)
	if a["requested_by"] != "agent:implementer" || a["agent_run_id"] != "art_run_a" || a["execution_id"] != e.tenant+"-exec" {
		t.Fatalf("recorded requester = %v run = %v execution = %v", a["requested_by"], a["agent_run_id"], a["execution_id"])
	}
	if res := e.do(run, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusOK {
		t.Fatalf("own read = %d %s", res.code, res.raw)
	}
	res = e.do(run, "GET", "/api/v1/action-approvals", nil)
	if list := res.body["approvals"].([]any); res.code != http.StatusOK || len(list) != 1 {
		t.Fatalf("own list = %d %s", res.code, res.raw)
	}

	// The agent cannot decide its own request: a human admin does.
	if res := e.decide(run, id, "approve"); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
		t.Fatalf("agent decide = %d %s", res.code, res.raw)
	}
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	res = e.do(run, "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": a["intent_hash"]})
	if res.code != http.StatusOK {
		t.Fatalf("own consume = %d %s", res.code, res.raw)
	}
	if res := e.markExecuted(run, id, executeBody(a["target"].(string), executeArtifactHash)); res.code != http.StatusOK {
		t.Fatalf("own execute = %d %s", res.code, res.raw)
	}
	if row := e.approvalRow(id); row["state"] != "executed" {
		t.Fatalf("state = %v", row["state"])
	}
}

func TestAgentApprovals_ARunRequestsOnlyForItsOwnExecution(t *testing.T) {
	e := newWorkItemsEnv(t)
	run := e.agentRun(e.tenant+"-exec", "art_run_a")
	otherExec := e.agentApprovalBody("k-agent-other-exec")
	otherExec["execution_id"] = e.tenant + "-exec-other"
	otherItem := e.agentApprovalBody("k-agent-other-item")
	otherItem["work_item_id"] = "wi_agent-test-other"
	devLoop := e.devLoopGrantBody(e.tenant+"-exec", "k-agent-devloop")
	for name, c := range map[string]struct {
		user *auth.User
		body map[string]any
	}{
		"another execution":       {run, otherExec},
		"another work item":       {run, otherItem},
		"the DevLoop gate":        {run, devLoop},
		"a token with no binding": {auth.NewAgentUser("implementer", auth.AgentRun{RunID: "art_unbound", Scope: agentTestScope}), e.agentApprovalBody("k-agent-unbound")},
		// The agent scope gate passes an unscoped token through unchecked,
		// so the handlers refuse it themselves.
		"an unscoped token": {auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: e.tenant + "-exec", RunID: "art_unscoped"}), e.agentApprovalBody("k-agent-unscoped")},
	} {
		res := e.do(c.user, "POST", "/api/v1/action-approvals", c.body)
		if res.code != http.StatusForbidden || code(res) != aarCodeRequesterForbidden {
			t.Errorf("%s: create = %d %s", name, res.code, res.raw)
		}
	}
	if n := e.auditRefusals("action_approval.create_refused", "", aarCodeRequesterForbidden); n < 5 {
		t.Errorf("refusals audited = %d, want 5", n)
	}
	// Its own work item is accepted.
	item := e.open(auth.NewServiceUser(), nil)["id"].(string)
	bound := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: e.tenant + "-exec", WorkItemID: item, RunID: "art_run_a", Scope: agentTestScope})
	own := e.agentApprovalBody("k-agent-own-item")
	own["work_item_id"] = item
	if res := e.do(bound, "POST", "/api/v1/action-approvals", own); res.code != http.StatusCreated {
		t.Fatalf("own work item = %d %s", res.code, res.raw)
	}
}

// All runs of one agent share its principal: the execution is what tells
// one run's approval from another's.
func TestAgentApprovals_AnotherRunOfTheSameAgentSeesNothing(t *testing.T) {
	e := newWorkItemsEnv(t)
	run := e.agentRun(e.tenant+"-exec", "art_run_a")
	other := e.agentRun(e.tenant+"-exec-other", "art_run_b")
	res := e.do(run, "POST", "/api/v1/action-approvals", e.agentApprovalBody("k-agent-iso"))
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	a := res.body["approval"].(map[string]any)
	id := a["id"].(string)
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	for name, res := range map[string]wiResponse{
		"read":    e.do(other, "GET", "/api/v1/action-approvals/"+id, nil),
		"consume": e.do(other, "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": a["intent_hash"]}),
		"execute": e.markExecuted(other, id, executeBody(a["target"].(string), executeArtifactHash)),
	} {
		if res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
			t.Errorf("other run %s = %d %s", name, res.code, res.raw)
		}
	}
	res = e.do(other, "GET", "/api/v1/action-approvals", nil)
	if list := res.body["approvals"].([]any); res.code != http.StatusOK || len(list) != 0 {
		t.Errorf("other run list = %d %s", res.code, res.raw)
	}
	res = e.do(other, "GET", "/api/v1/action-approvals?execution_id="+e.tenant+"-exec", nil)
	if res.code != http.StatusForbidden || code(res) != aarCodeReaderForbidden {
		t.Errorf("other run list of another execution = %d %s", res.code, res.raw)
	}
	if row := e.approvalRow(id); row["state"] != "approved" {
		t.Fatalf("after refusals = %v", row["state"])
	}
}

// A request the service made for the run's execution is not the run's:
// the one exception is the execution's DevLoop grant.
func TestAgentApprovals_TheServicesRequestsAreNotTheRuns(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.consumedApproval("k-agent-svc")
	id := a["id"].(string)
	run := e.agentRun(a["execution_id"].(string), "art_run_a")
	for name, res := range map[string]wiResponse{
		"read":    e.do(run, "GET", "/api/v1/action-approvals/"+id, nil),
		"execute": e.markExecuted(run, id, executeBody(a["target"].(string), executeArtifactHash)),
	} {
		if res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
			t.Errorf("%s = %d %s", name, res.code, res.raw)
		}
	}
	if row := e.approvalRow(id); row["state"] != "consumed" {
		t.Fatalf("state = %v", row["state"])
	}
}

// The DevLoop grant the control worker requested for an execution is read
// and marked executed by that execution's run, never consumed by it, and is
// invisible to every other run.
func TestAgentApprovals_ARunMarksItsExecutionsDevLoopGrant(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	dl := e.startDevLoopRun("agent-grant")
	id := e.requestDevLoopGrant(dl.execID, "k-agent-grant")
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	grant := e.approvalRow(id)
	run := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: dl.execID, WorkItemID: dl.itemID, RunID: "art_impl", Scope: agentTestScope})
	other := e.agentRun(e.tenant+"-exec-other", "art_other")

	if res := e.do(run, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusOK {
		t.Fatalf("run reads its grant = %d %s", res.code, res.raw)
	}
	if res := e.do(other, "GET", "/api/v1/action-approvals/"+id, nil); res.code != http.StatusNotFound {
		t.Fatalf("other run reads the grant = %d %s", res.code, res.raw)
	}
	res := e.do(run, "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": grant["intent_hash"]})
	if res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("run consumes the grant = %d %s", res.code, res.raw)
	}
	if row := e.approvalRow(id); row["state"] != "approved" {
		t.Fatalf("after the run's consume = %v", row["state"])
	}
	// The worker spends it (here: its requester, the service).
	if res := e.consume(id, grant["intent_hash"].(string)); res.code != http.StatusOK {
		t.Fatalf("service consume = %d %s", res.code, res.raw)
	}
	body := executeBody(grant["target"].(string), testContentDigest)
	if res := e.markExecuted(other, id, body); res.code != http.StatusNotFound {
		t.Fatalf("other run executes the grant = %d %s", res.code, res.raw)
	}
	if res := e.markExecuted(run, id, body); res.code != http.StatusOK {
		t.Fatalf("run executes its grant = %d %s", res.code, res.raw)
	}
	if row := e.approvalRow(id); row["state"] != "executed" {
		t.Fatalf("state = %v", row["state"])
	}
	found := false
	for _, entry := range e.audit.List(1000) {
		p := entry.Parameters
		if entry.Operation == "action_approval.execute" && p["approval_id"] == id {
			found = p["actor"] == "agent:implementer" && p["bound_execution_id"] == dl.execID && p["agent_run_id"] == "art_impl"
		}
	}
	if !found {
		t.Fatal("the execute audit row does not name the agent run as executor")
	}
	if res := e.markExecuted(run, id, body); res.code != http.StatusConflict || code(res) != aarCodeExecuted {
		t.Fatalf("second execute = %d %s", res.code, res.raw)
	}
}

// Every run of one agent shares its principal, so idempotency keys collide
// across executions: the conflict must not name the other run's request.
func TestAgentApprovals_AKeyConflictDoesNotNameAnotherRunsRequest(t *testing.T) {
	e := newWorkItemsEnv(t)
	run := e.agentRun(e.tenant+"-exec", "art_run_a")
	other := e.agentRun(e.tenant+"-exec-other", "art_run_b")
	res := e.do(run, "POST", "/api/v1/action-approvals", e.agentApprovalBody("k-agent-shared"))
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	id := res.body["approval"].(map[string]any)["id"].(string)
	b := e.agentApprovalBody("k-agent-shared")
	b["execution_id"] = e.tenant + "-exec-other"
	res = e.do(other, "POST", "/api/v1/action-approvals", b)
	if res.code != http.StatusConflict || code(res) != aarCodeIdempotencyConflict {
		t.Fatalf("conflict = %d %s", res.code, res.raw)
	}
	if strings.Contains(res.raw, id) || strings.Contains(res.raw, "sha256:") {
		t.Fatalf("conflict names the other request: %s", res.raw)
	}
}

// A mctl-agents-approve request the run may see is the control worker's
// grant: one any other principal made for the execution is not it.
func TestAgentApprovals_OnlyTheServicesGrantIsTheRuns(t *testing.T) {
	e := newWorkItemsEnv(t)
	run := e.agentRun(e.tenant+"-exec", "art_run_a")
	in := workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID: e.tenant + "-exec", ActionKind: devLoopApprovalKind, Target: "mctl-api/issue-1-x",
			ArgsDigest: "sha256:args", PolicyRuleID: "dev-loop.human-approval", PolicyVersion: "v1",
			ArtifactHash: testContentDigest,
		},
		RequestedBy:    "service:someone-else",
		IdempotencyKey: e.tenant + "-k-not-the-worker",
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	a, _, err := e.h.opts.WorkItems.CreateActionApproval(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res := e.do(run, "GET", "/api/v1/action-approvals/"+a.ID, nil); res.code != http.StatusNotFound {
		t.Fatalf("run reads another principal's gate = %d %s", res.code, res.raw)
	}
}
