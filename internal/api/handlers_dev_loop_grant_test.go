package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#571 slice 2: a DevLoop's human approval is the decision of an
// aar_ bound to the run's we_, resolved from the workflow id through the
// execution's (engine, engine_ref). These run against Postgres like the rest
// of the work-items handler tests.

// devLoopRun is one DevLoop as the worker sets it up: a work item, a running
// temporal execution under the workflow id, and that execution's id.
type devLoopRun struct {
	workflowID, itemID, execID string
}

func (e *workItemsEnv) startDevLoopRun(suffix string) devLoopRun {
	e.t.Helper()
	svc := auth.NewServiceUser()
	item := e.open(svc, nil)
	run := devLoopRun{workflowID: e.tenant + "-dev-loop-" + suffix, itemID: item["id"].(string)}
	run.execID = e.attachExecution(svc, run.itemID, run.workflowID, "Running")
	e.forgetApprovalsOf(run.execID)
	return run
}

// forgetApprovalsOf deletes the approvals of a we_ at cleanup: the env's own
// cleanup deletes by the tenant prefix, which a we_ id does not carry.
func (e *workItemsEnv) forgetApprovalsOf(execID string) {
	e.t.Cleanup(func() {
		pool, err := pgxpool.New(context.Background(), e.connStr)
		if err == nil {
			_, _ = pool.Exec(context.Background(), `DELETE FROM action_approval_requests WHERE execution_id=$1`, execID)
			pool.Close()
		}
	})
}

// testContentDigest is the proposal content digest a DevLoop grant binds
// (mctl-agents#681).
const testContentDigest = "sha256:5d7c0d221b7ca6ff07f9cbe5a05dc78a252bdceeede030599304ed449c485a81"

func (e *workItemsEnv) devLoopGrantBody(execID, key string) map[string]any {
	return map[string]any{
		"execution_id":    execID,
		"action_kind":     devLoopApprovalKind,
		"target":          "mctl-api/issue-571-x",
		"args_digest":     "sha256:args",
		"policy_rule_id":  "dev-loop.human-approval",
		"policy_version":  "v1",
		"artifact_hash":   testContentDigest,
		"idempotency_key": key,
		"expires_at":      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func (e *workItemsEnv) requestDevLoopGrant(execID, key string) string {
	e.t.Helper()
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", e.devLoopGrantBody(execID, key))
	if res.code != http.StatusCreated {
		e.t.Fatalf("create dev-loop grant = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)["id"].(string)
}

func (e *workItemsEnv) approveDevLoop(u *auth.User, workflowID, body string) wiResponse {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/"+workflowID+"/approve", strings.NewReader(body))
	req = withChiParam(req, "workflow_id", workflowID)
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	e.h.ApproveDevLoopWorkflow(rec, req)
	out := wiResponse{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func (e *workItemsEnv) approvalState(id string) map[string]any {
	e.t.Helper()
	res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if res.code != http.StatusOK {
		e.t.Fatalf("get approval = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

func newDevLoopGrantEnv(t *testing.T) (*workItemsEnv, *fakeDevLoopClient) {
	e := newWorkItemsEnv(t)
	fake := &fakeDevLoopClient{}
	e.h.opts.TemporalClient = fake
	// The registry production wires: it sets the grant's risk level, which
	// an approve requires (mctl-api#700).
	e.h.opts.Registry = operations.NewRegistry()
	return e, fake
}

// R3: the approve call decides the run's pending grant as the caller and
// signals its id, never a free-text approver; a retry after the decision
// re-sends the same grant instead of deciding again or falling back.
func TestDevLoopApprove_DecidesTheBoundGrant(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("a")
	id := e.requestDevLoopGrant(run.execID, "gate-1")
	// A newer pending approval of another kind on the same execution is not
	// the DevLoop's gate and must stay untouched.
	merge := e.approvalBody("k-merge")
	merge["execution_id"] = run.execID
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", merge)
	if res.code != http.StatusCreated {
		t.Fatalf("create merge approval = %d %s", res.code, res.raw)
	}
	mergeID := res.body["approval"].(map[string]any)["id"].(string)

	res = e.approveDevLoop(rootAdmin, run.workflowID, `{"reason":"looks right"}`)
	if res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if fake.lastApprovedWorkflow != run.workflowID {
		t.Fatalf("signalled %q, want %q", fake.lastApprovedWorkflow, run.workflowID)
	}
	if got := fake.lastApprovePayload; got["approval_ref"] != id || got["reason"] != "looks right" || got["approver"] != "" {
		t.Fatalf("payload = %v, want approval_ref %s and no approver", got, id)
	}
	a := e.approvalState(id)
	if a["state"] != workitems.ApprovalApproved || a["decided_by"] != "github:root" {
		t.Fatalf("grant after approve = %v", a)
	}
	if n := e.auditOps("action_approval.decision", id); n != 1 {
		t.Fatalf("decision audited %d times, want 1", n)
	}
	if m := e.approvalState(mergeID); m["state"] != workitems.ApprovalPending {
		t.Fatalf("the other kind's approval moved to %v", m["state"])
	}

	fake.lastApprovePayload = nil
	if res := e.approveDevLoop(rootAdmin, run.workflowID, ""); res.code != http.StatusOK {
		t.Fatalf("retry = %d %s", res.code, res.raw)
	}
	if fake.lastApprovePayload["approval_ref"] != id {
		t.Fatalf("retry payload = %v, want the same grant", fake.lastApprovePayload)
	}
	if n := e.auditOps("action_approval.decision", id); n != 1 {
		t.Fatalf("retry decided again: %d decisions", n)
	}
}

// R4: the service principal carries the admins group and may read and start
// DevLoops, but approving is the human act.
func TestDevLoopApprove_ServicePrincipalCannotApprove(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("svc")
	id := e.requestDevLoopGrant(run.execID, "gate-1")

	if res := e.approveDevLoop(auth.NewServiceUser(), run.workflowID, ""); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
		t.Fatalf("service approve = %d %s, want 403 %s", res.code, res.raw, aarCodeDeciderForbidden)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("a refused approval signalled %v", fake.lastApprovePayload)
	}
	if a := e.approvalState(id); a["state"] != workitems.ApprovalPending {
		t.Fatalf("a refused approval moved the grant to %v", a["state"])
	}
	denied := 0
	for _, entry := range e.audit.List(1000) {
		if entry.Operation == "dev-loop-approve" && entry.Status == "denied" && entry.WorkflowName == run.workflowID &&
			strings.HasPrefix(entry.Message, aarCodeDeciderForbidden) {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("the refusal was audited %d times, want 1", denied)
	}
	// Nor through the legacy payload, where no grant's self-decision rule
	// would catch it.
	if res := e.approveDevLoop(auth.NewServiceUser(), e.tenant+"-unattached", ""); res.code != http.StatusForbidden {
		t.Fatalf("service legacy approve = %d %s, want 403", res.code, res.raw)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("a refused legacy approval signalled %v", fake.lastApprovePayload)
	}
}

// Without a grant to decide, the legacy payload is what it was while the
// flag is on, and a typed 409 once it is off -- whether the workflow has no
// we_ at all or its we_ has no pending grant.
func TestDevLoopApprove_NoGrantFollowsTheLegacyFlag(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("legacy")
	for name, wf := range map[string]string{"no pending grant": run.workflowID, "no execution": e.tenant + "-unattached"} {
		e.h.opts.LegacyApproverDisabled = false
		fake.lastApprovePayload = nil
		if res := e.approveDevLoop(rootAdmin, wf, ""); res.code != http.StatusOK {
			t.Fatalf("%s, flag on: %d %s", name, res.code, res.raw)
		}
		if got := fake.lastApprovePayload; got["approver"] != "root" || got["approval_ref"] != "" {
			t.Fatalf("%s, flag on: payload %v, want the legacy approver", name, got)
		}

		e.h.opts.LegacyApproverDisabled = true
		fake.lastApprovePayload = nil
		res := e.approveDevLoop(rootAdmin, wf, "")
		if res.code != http.StatusConflict || code(res) != devLoopCodeGrantMissing {
			t.Fatalf("%s, flag off: %d %s, want 409 %s", name, res.code, res.raw, devLoopCodeGrantMissing)
		}
		if fake.lastApprovePayload != nil {
			t.Fatalf("%s, flag off: signalled %v", name, fake.lastApprovePayload)
		}
	}
}

// A grant that was denied, spent or let expire is a recorded outcome, not
// an absent gate: approving over it is refused with its state's code even
// while the legacy flag is on, and nothing is signalled.
func TestDevLoopApprove_ClosedGrantIsNeverLegacy(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	decide := func(id, decision string) {
		t.Helper()
		if res := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": decision}); res.code != http.StatusOK {
			t.Fatalf("decide %s = %d %s", decision, res.code, res.raw)
		}
	}
	for _, tc := range []struct {
		name, code string
		close      func(id string)
	}{
		{"denied", aarCodeDenied, func(id string) { decide(id, workitems.DecisionDeny) }},
		{"consumed", aarCodeConsumed, func(id string) {
			decide(id, workitems.DecisionApprove)
			hash := e.approvalState(id)["intent_hash"]
			if res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": hash}); res.code != http.StatusOK {
				t.Fatalf("consume = %d %s", res.code, res.raw)
			}
		}},
		{"expired", aarCodeExpired, func(id string) {
			pool, err := pgxpool.New(context.Background(), e.connStr)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			if _, err := pool.Exec(context.Background(),
				`UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		for _, off := range []bool{false, true} {
			e.h.opts.LegacyApproverDisabled = off
			name := fmt.Sprintf("%s-flag-off-%v", tc.name, off)
			run := e.startDevLoopRun("closed-" + name)
			id := e.requestDevLoopGrant(run.execID, "gate-"+name)
			tc.close(id)
			fake.lastApprovePayload = nil
			res := e.approveDevLoop(rootAdmin, run.workflowID, "")
			if res.code != http.StatusConflict || code(res) != tc.code {
				t.Errorf("%s grant: approve = %d %s, want 409 %s", name, res.code, res.raw, tc.code)
			}
			if fake.lastApprovePayload != nil {
				t.Errorf("%s grant: signalled %v", name, fake.lastApprovePayload)
			}
		}
	}
}

// The newest grant decides: an older grant that is still live does not
// outrank a newer recorded denial.
func TestDevLoopApprove_NewestGrantDecides(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	e.h.opts.LegacyApproverDisabled = false
	for _, older := range []string{workitems.ApprovalApproved, workitems.ApprovalPending} {
		run := e.startDevLoopRun("newest-" + older)
		first := e.requestDevLoopGrant(run.execID, "gate-old-"+older)
		if older == workitems.ApprovalApproved {
			if res := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+first+"/decision", map[string]any{"decision": workitems.DecisionApprove}); res.code != http.StatusOK {
				t.Fatalf("approve older = %d %s", res.code, res.raw)
			}
		}
		second := e.requestDevLoopGrant(run.execID, "gate-new-"+older)
		if res := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+second+"/decision", map[string]any{"decision": workitems.DecisionDeny}); res.code != http.StatusOK {
			t.Fatalf("deny newer = %d %s", res.code, res.raw)
		}
		fake.lastApprovePayload = nil
		res := e.approveDevLoop(rootAdmin, run.workflowID, "")
		if res.code != http.StatusConflict || code(res) != aarCodeDenied {
			t.Errorf("older %s under a newer denial: approve = %d %s, want 409 %s", older, res.code, res.raw, aarCodeDenied)
		}
		if fake.lastApprovePayload != nil {
			t.Errorf("older %s under a newer denial: signalled %v", older, fake.lastApprovePayload)
		}
		if st := e.approvalState(first)["state"]; st != older {
			t.Errorf("the older grant moved to %v", st)
		}
	}
}

// The same workflow id under two work items names no single execution: the
// approval stops rather than picking one.
func TestDevLoopApprove_AmbiguousExecutionIsRefused(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("dup")
	other := e.open(auth.NewServiceUser(), nil)
	e.attachExecution(auth.NewServiceUser(), other["id"].(string), run.workflowID, "Running")
	e.requestDevLoopGrant(run.execID, "gate-1")

	res := e.approveDevLoop(rootAdmin, run.workflowID, "")
	if res.code != http.StatusConflict || code(res) != devLoopCodeExecutionAmbiguous {
		t.Fatalf("ambiguous = %d %s, want 409 %s", res.code, res.raw, devLoopCodeExecutionAmbiguous)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("an ambiguous approval signalled %v", fake.lastApprovePayload)
	}
}

// A store that cannot be read is not "no grant": even with the legacy
// payload allowed, the approval answers 503 and signals nothing.
func TestDevLoopApprove_UnreadableStoreIs503NotLegacy(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	broken, err := workitems.NewStore(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	e.h.opts.WorkItems = broken

	res := e.approveDevLoop(rootAdmin, e.tenant+"-any", "")
	if res.code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable store = %d %s, want 503", res.code, res.raw)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("an unreadable store fell back to signalling %v", fake.lastApprovePayload)
	}
}

// R2: a DevLoop grant names an existing, unfinished we_; other action kinds
// are not affected.
func TestActionApprovals_DevLoopGrantNeedsAnOpenExecution(t *testing.T) {
	e := newWorkItemsEnv(t)
	svc := auth.NewServiceUser()
	item := e.open(svc, nil)
	done := e.attachExecution(svc, item["id"].(string), e.tenant+"-finished", "Succeeded")
	e.forgetApprovalsOf(done)

	for name, tc := range map[string]struct {
		execID string
		status int
		code   string
	}{
		"workflow id":  {e.tenant + "-dev-loop-x", http.StatusBadRequest, aarCodeExecutionInvalid},
		"unknown we_":  {workitems.ExecutionIDPrefix + "00000000-0000-0000-0000-000000000000", http.StatusBadRequest, aarCodeExecutionInvalid},
		"finished run": {done, http.StatusConflict, aarCodeExecutionNotOpen},
	} {
		res := e.do(svc, "POST", "/api/v1/action-approvals", e.devLoopGrantBody(tc.execID, "k-"+name))
		if res.code != tc.status || code(res) != tc.code {
			t.Errorf("%s: %d %s, want %d %s", name, res.code, res.raw, tc.status, tc.code)
		}
	}
	other := e.approvalBody("k-other-kind")
	other["execution_id"] = e.tenant + "-free-form"
	if res := e.do(svc, "POST", "/api/v1/action-approvals", other); res.code != http.StatusCreated {
		t.Fatalf("another kind with a free-form execution id = %d %s", res.code, res.raw)
	}
}

// A run dispatched from an execution request holds its we_ under
// "<workflow_id>#<request_id>" (mctl-agents#461), and finished executions
// are history: the approval finds the run's one open we_ either way, and a
// workflow id that merely shares a prefix is another run.
func TestDevLoopApprove_FindsTheDispatchedOpenExecution(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	svc := auth.NewServiceUser()
	wf := e.tenant + "-dev-loop-57"

	old := e.open(svc, nil)
	e.attachExecution(svc, old["id"].(string), wf, "Succeeded")
	sibling := e.open(svc, nil)
	siblingExec := e.attachExecution(svc, sibling["id"].(string), wf+"1#xr_other", "Running")
	e.forgetApprovalsOf(siblingExec)
	e.requestDevLoopGrant(siblingExec, "gate-sibling")

	item := e.open(svc, nil)
	execID := e.attachExecution(svc, item["id"].(string), wf+"#xr_1", "Running")
	e.forgetApprovalsOf(execID)
	id := e.requestDevLoopGrant(execID, "gate-1")

	res := e.approveDevLoop(rootAdmin, wf, "")
	if res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if got := fake.lastApprovePayload["approval_ref"]; got != id {
		t.Fatalf("approval_ref = %q, want the dispatched run's grant %s", got, id)
	}
}
