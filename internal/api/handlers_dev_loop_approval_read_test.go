package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#936: the binding values of a parked DevLoop are readable by
// workflow id, without leaving MCP for a local REST client.

func (e *workItemsEnv) readDevLoopApproval(u *auth.User, workflowID string) wiResponse {
	e.t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/"+workflowID+"/approval", nil)
	req = withChiParam(req, "workflow_id", workflowID)
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	e.h.GetDevLoopApproval(rec, req)
	out := wiResponse{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

// The read names the grant, its digests and its expiry, and those exact
// values are what a bound approve accepts: read and approve agree on which
// grant decides. Reading decides nothing.
func TestDevLoopApprovalRead_ValuesBindAnApprove(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("read")
	id := e.requestDevLoopGrant(run.execID, "gate-1")

	res := e.readDevLoopApproval(rootAdmin, run.workflowID)
	if res.code != http.StatusOK {
		t.Fatalf("read = %d %s", res.code, res.raw)
	}
	if res.body["workflow_id"] != run.workflowID {
		t.Fatalf("workflow_id = %v", res.body["workflow_id"])
	}
	approval := res.body["approval"].(map[string]any)
	dc := res.body["decision_context"].(map[string]any)
	if approval["id"] != id || approval["state"] != workitems.ApprovalPending ||
		approval["artifact_hash"] != testContentDigest || approval["expires_at"] == nil || dc["context_digest"] == "" {
		t.Fatalf("read body = %s", res.raw)
	}
	if st := e.approvalState(id)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("a read moved the grant to %v", st)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("a read signalled %v", fake.lastApprovePayload)
	}

	bind := map[string]any{"approval_ref": approval["id"], "context_digest": dc["context_digest"], "content_digest": approval["artifact_hash"]}
	if a := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(bind)); a.code != http.StatusOK {
		t.Fatalf("approve with the read's values = %d %s", a.code, a.raw)
	}
	if fake.lastApprovePayload["approval_ref"] != id {
		t.Fatalf("payload = %v", fake.lastApprovePayload)
	}
}

// A superseded grant is never offered: only the newest can be decided.
func TestDevLoopApprovalRead_NewestGrantIsTheOneRead(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("newest")
	e.requestDevLoopGrant(run.execID, "gate-1")
	newest := e.requestDevLoopGrant(run.execID, "gate-2")

	res := e.readDevLoopApproval(rootAdmin, run.workflowID)
	if res.code != http.StatusOK || res.body["approval"].(map[string]any)["id"] != newest {
		t.Fatalf("read = %d %s, want newest %s", res.code, res.raw, newest)
	}
}

// Absence is reported only when the store proved it, under a typed code.
func TestDevLoopApprovalRead_ProvenAbsenceIsTyped404(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("nogrant")
	for name, wf := range map[string]string{"no execution": e.tenant + "-none", "no grant": run.workflowID} {
		res := e.readDevLoopApproval(rootAdmin, wf)
		if res.code != http.StatusNotFound || code(res) != devLoopCodeGrantMissing {
			t.Errorf("%s = %d %s, want 404 %s", name, res.code, res.raw, devLoopCodeGrantMissing)
		}
	}
}

// A failed read is an error and never "no grant".
func TestDevLoopApprovalRead_UnreadableStoreIs503(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	broken, err := workitems.NewStore(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	e.h.opts.WorkItems = broken

	res := e.readDevLoopApproval(rootAdmin, e.tenant+"-any")
	if res.code != http.StatusServiceUnavailable || code(res) != wiCodeUnavailable {
		t.Fatalf("unreadable store = %d %s, want 503 %s", res.code, res.raw, wiCodeUnavailable)
	}
}

func TestDevLoopApprovalRead_UnconfiguredStoreIs503(t *testing.T) {
	h := &Handlers{}
	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/wf/approval", nil)
	req = withChiParam(req, "workflow_id", "wf")
	req = req.WithContext(auth.WithUser(req.Context(), rootAdmin))
	rec := httptest.NewRecorder()
	h.GetDevLoopApproval(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store = %d %s, want 503", rec.Code, rec.Body.String())
	}
}

func TestDevLoopApprovalRead_AmbiguousExecutionIs409(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("dup")
	other := e.open(auth.NewServiceUser(), nil)
	e.attachExecution(auth.NewServiceUser(), other["id"].(string), run.workflowID, "Running")
	e.requestDevLoopGrant(run.execID, "gate-1")

	res := e.readDevLoopApproval(rootAdmin, run.workflowID)
	if res.code != http.StatusConflict || code(res) != devLoopCodeExecutionAmbiguous {
		t.Fatalf("ambiguous = %d %s, want 409 %s", res.code, res.raw, devLoopCodeExecutionAmbiguous)
	}
}

// Admin sees all, the requesting service its own, everyone else 403 before
// the store is asked anything, so the answer cannot reveal a run exists.
func TestDevLoopApprovalRead_Access(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("access")
	e.requestDevLoopGrant(run.execID, "gate-1")

	if res := e.readDevLoopApproval(auth.NewServiceUser(), run.workflowID); res.code != http.StatusOK {
		t.Fatalf("requesting service = %d %s, want 200", res.code, res.raw)
	}
	refused := map[string]*auth.User{
		"non-admin person": auth.NewGitHubUser("someone", []string{"devs"}),
		"bound agent run":  auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: run.execID, WorkItemID: run.itemID}),
	}
	for name, u := range refused {
		for _, wf := range []string{run.workflowID, e.tenant + "-none"} {
			res := e.readDevLoopApproval(u, wf)
			if res.code != http.StatusForbidden || code(res) != aarCodeReaderForbidden {
				t.Errorf("%s on %s = %d %s, want 403 %s", name, wf, res.code, res.raw, aarCodeReaderForbidden)
			}
		}
	}
}

// The requester sees only its own: a grant another principal requested for
// the run is refused to the service and still readable by an admin.
func TestDevLoopApprovalRead_ServiceSeesOnlyItsOwnGrant(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("other")
	_, _, err := e.h.opts.WorkItems.CreateActionApproval(context.Background(), workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID: run.execID, ActionKind: devLoopApprovalKind, Target: "mctl-api/issue-1-x",
			ArgsDigest: "sha256:args", PolicyRuleID: "dev-loop.human-approval", PolicyVersion: "v1",
			ArtifactHash: testContentDigest,
		},
		RequestedBy:    "service:someone-else",
		IdempotencyKey: e.tenant + "-k-other",
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res := e.readDevLoopApproval(auth.NewServiceUser(), run.workflowID); res.code != http.StatusForbidden || code(res) != aarCodeReaderForbidden {
		t.Fatalf("service on another's grant = %d %s, want 403", res.code, res.raw)
	}
	if res := e.readDevLoopApproval(rootAdmin, run.workflowID); res.code != http.StatusOK {
		t.Fatalf("admin = %d %s, want 200", res.code, res.raw)
	}
}

// The route reaches its handler, which answers for the missing store where an
// unrouted path would be a 404, and only through the API's authentication.
func TestDevLoopApprovalRead_RouteIsWiredBehindAuth(t *testing.T) {
	authenticated := false
	router := NewRouter(Options{AuthMiddleware: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authenticated = true
			next.ServeHTTP(w, r)
		})
	}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/dev-loop/wf/approval", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !authenticated {
		t.Fatalf("GET = %d %s, authenticated = %v; want the handler's 503 behind auth", rec.Code, rec.Body.String(), authenticated)
	}
}

// mctl_get_dev_loop_approval treats this literal as proven absence. Renaming
// the code would turn every real absence into "unknown" without any error.
func TestDevLoopApprovalRead_AbsenceCodeIsTheToolContract(t *testing.T) {
	if devLoopCodeGrantMissing != "approval_grant_missing" {
		t.Fatalf("devLoopCodeGrantMissing = %q; update mctl_get_dev_loop_approval too", devLoopCodeGrantMissing)
	}
}
