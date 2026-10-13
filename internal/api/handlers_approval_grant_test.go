package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/delegation"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// mctl-api#571 slice 3 (R5-R8, A1-A4): an agent run exercises a human's
// DevLoop approval through X-MCTL-On-Behalf-Of: aar_... on
// POST /operations/mctl-agents-approve/execute. These go through the real
// delegation gate, the real StoreResolver and Postgres; only the workflow
// executor is a fake, so "nothing submitted" is observable.

const grantApprovePath = "/api/v1/operations/mctl-agents-approve/execute"

type grantEnv struct {
	*workItemsEnv
	exec   *fakeDomainExecutor
	router chi.Router
	// decider is the human admin who decides, with a resolved principal.
	decider *auth.User
}

func newGrantEnv(t *testing.T) *grantEnv {
	e, _ := newDevLoopGrantEnv(t)
	exec := &fakeDomainExecutor{}
	e.h.opts.Executor = exec
	e.h.opts.Registry = operations.NewRegistry()
	e.h.opts.Principals = loginPrincipals{}
	e.h.opts.Delegation = delegation.NewStoreResolver(e.h.opts.WorkItems, nil)
	r := chi.NewRouter()
	r.With(e.h.agentPrincipalGate).Post("/api/v1/operations/{name}/execute", e.h.ExecuteOperation)
	decider := auth.NewGitHubUser("root", []string{"admins"})
	if err := auth.AttachPrincipal(context.Background(), loginPrincipals{}, decider); err != nil {
		t.Fatal(err)
	}
	return &grantEnv{workItemsEnv: e, exec: exec, router: r, decider: decider}
}

// grantedRun is a DevLoop run with a pending approval grant for
// mctl-api/issue-571-x, and the agent run bound to it.
type grantedRun struct {
	devLoopRun
	approval string
	agent    *auth.User
}

func (g *grantEnv) grantedRun(suffix string) grantedRun {
	g.t.Helper()
	run := g.startDevLoopRun(suffix)
	return grantedRun{
		devLoopRun: run,
		approval:   g.requestDevLoopGrant(run.execID, "k-"+suffix),
		agent:      g.runAgent(run.execID),
	}
}

// runAgent mints a real run token for execID through the mint route and
// authenticates it the way the auth middleware does
// (ResolveAgentRunToken), so the run's binding is the server's, not one
// the test made up.
func (g *grantEnv) runAgent(execID string) *auth.User {
	g.t.Helper()
	res := g.do(auth.NewServiceUser(), "POST", "/api/v1/agent-run-tokens", map[string]any{"agent": "implementer", "execution_id": execID})
	if res.code != http.StatusCreated {
		g.t.Fatalf("mint run token = %d %s", res.code, res.raw)
	}
	run, err := g.h.opts.WorkItems.ResolveAgentRunToken(context.Background(), res.body["token"].(string))
	if err != nil {
		g.t.Fatalf("resolve run token: %v", err)
	}
	return auth.NewAgentUser("implementer", *run)
}

func (g *grantEnv) decide(id, decision string) {
	g.t.Helper()
	res := g.do(g.decider, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": decision})
	if res.code != http.StatusOK {
		g.t.Fatalf("decide %s = %d %s", decision, res.code, res.raw)
	}
}

func (g *grantEnv) execute(u *auth.User, ref string, body map[string]string) wiResponse {
	g.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		g.t.Fatal(err)
	}
	req := httptest.NewRequest("POST", grantApprovePath, bytes.NewReader(raw))
	if ref != "" {
		req.Header.Set(OnBehalfOfHeader, ref)
	}
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	out := wiResponse{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func approveInput(slug string) map[string]string {
	return map[string]string{"service": "mctl-api", "slug": slug}
}

func (g *grantEnv) submitted() int { return len(g.exec.submitted) }

func (g *grantEnv) expire(id string) {
	g.t.Helper()
	pool, err := pgxpool.New(context.Background(), g.connStr)
	if err != nil {
		g.t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(),
		`UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id=$1`, id); err != nil {
		g.t.Fatal(err)
	}
}

// A1 + A2 (second use): the decided grant is exercised once, as the human
// who decided it, through the agent run; the approval is spent; the same
// grant presented again submits nothing.
func TestApprovalGrant_BoundGrantApprovesOnceAsTheDecider(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("a1")
	g.decide(run.approval, "approve")

	res := g.execute(run.agent, run.approval, approveInput("issue-571-x"))
	if res.code != http.StatusAccepted {
		t.Fatalf("grant-authorized approve = %d %s", res.code, res.raw)
	}
	if g.submitted() != 1 {
		t.Fatalf("submitted %d workflows, want 1", g.submitted())
	}
	params := g.exec.submitted[0]
	if params["approver"] != "github:root" || params["service"] != "mctl-api" || params["slug"] != "issue-571-x" {
		t.Errorf("submitted params = %v, want approver github:root for mctl-api/issue-571-x", params)
	}
	if st := g.approvalState(run.approval)["state"]; st != "consumed" {
		t.Errorf("approval state = %v, want consumed", st)
	}
	var found bool
	for _, entry := range g.audit.List(200) {
		if entry.Operation != devLoopApprovalKind || entry.Status != "submitted" {
			continue
		}
		found = true
		p := entry.Parameters
		if p["actor_kind"] != string(auth.KindAgent) || p["actor_name"] != "implementer" ||
			p["subject_principal_id"] != "prn_root" || p["grant_ref"] != run.approval || p["execution_id"] != run.execID {
			t.Errorf("submit audit params = %v", p)
		}
		if entry.UserID != "root" || entry.PrincipalID != "prn_root" {
			t.Errorf("submit audit names %q (%q), want the decider", entry.UserID, entry.PrincipalID)
		}
	}
	if !found {
		t.Error("no submitted audit entry for the grant-authorized approve")
	}
	if n := g.auditOps("action_approval.consume", run.approval); n != 1 {
		t.Errorf("consume audited %d times, want 1", n)
	}

	again := g.execute(run.agent, run.approval, approveInput("issue-571-x"))
	if again.code < 400 || g.submitted() != 1 {
		t.Errorf("second use = %d %s, submitted %d; want a refusal and nothing more submitted", again.code, again.raw, g.submitted())
	}
}

// A2: the same grant presented by another execution's run is not bound to
// it. A run token's work item is its execution's (the mint derives it), and
// a work item has one open execution at a time, so another execution is
// another run, whatever its work item.
func TestApprovalGrant_OtherExecutionIsNotBound(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("a2")
	other := g.startDevLoopRun("a2-other")
	g.decide(run.approval, "approve")

	res := g.execute(g.runAgent(other.execID), run.approval, approveInput("issue-571-x"))
	if res.code != http.StatusForbidden || res.body["code"] != delegationCodeNotBound {
		t.Errorf("other execution = %d %s, want 403 %s", res.code, res.raw, delegationCodeNotBound)
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}
}

// A3: anything that is not an aar_ of this run is refused before the
// handler -- a workflow id, a we_, an unknown aar_.
func TestApprovalGrant_ArbitraryRefsAreRefused(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("a3")
	g.decide(run.approval, "approve")
	for _, ref := range []string{run.workflowID, run.execID, "aar_00000000000000000000000000", "42"} {
		res := g.execute(run.agent, ref, approveInput("issue-571-x"))
		if res.code != http.StatusForbidden {
			t.Errorf("ref %q = %d %s, want 403", ref, res.code, res.raw)
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
}

// R6: a target, or an action kind, the human did not approve is refused
// and leaves the approval unspent.
func TestApprovalGrant_WrongTargetOrKindIsRefused(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("tgt")
	g.decide(run.approval, "approve")

	res := g.execute(run.agent, run.approval, approveInput("issue-999-other"))
	if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
		t.Errorf("wrong slug = %d %s, want 409 %s", res.code, res.raw, aarCodeIntentMismatch)
	}
	res = g.execute(run.agent, run.approval, map[string]string{"service": "mctl-web", "slug": "issue-571-x"})
	if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
		t.Errorf("wrong service = %d %s, want 409 %s", res.code, res.raw, aarCodeIntentMismatch)
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}

	// Same run, same target, another action kind: decided by the same
	// human, still not an approval of mctl-agents-approve.
	body := g.devLoopGrantBody(run.execID, "k-tgt-merge")
	body["action_kind"] = "merge"
	created := g.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", body)
	if created.code != http.StatusCreated {
		t.Fatalf("create merge approval = %d %s", created.code, created.raw)
	}
	merge := created.body["approval"].(map[string]any)["id"].(string)
	g.decide(merge, "approve")
	res = g.execute(run.agent, merge, approveInput("issue-571-x"))
	if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
		t.Errorf("other kind = %d %s, want 409 %s", res.code, res.raw, aarCodeIntentMismatch)
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
}

// A4: pending, denied and expired grants fail closed and submit nothing.
func TestApprovalGrant_UndecidedDeniedExpiredFailClosed(t *testing.T) {
	g := newGrantEnv(t)

	pending := g.grantedRun("pend")
	if res := g.execute(pending.agent, pending.approval, approveInput("issue-571-x")); res.code != http.StatusForbidden ||
		res.body["code"] != delegationCodeUnresolved {
		t.Errorf("pending = %d %s, want 403 %s", res.code, res.raw, delegationCodeUnresolved)
	}

	denied := g.grantedRun("deny")
	g.decide(denied.approval, "deny")
	if res := g.execute(denied.agent, denied.approval, approveInput("issue-571-x")); res.code != http.StatusForbidden ||
		res.body["code"] != delegationCodeNotBound {
		t.Errorf("denied = %d %s, want 403 %s", res.code, res.raw, delegationCodeNotBound)
	}

	expired := g.grantedRun("exp")
	g.decide(expired.approval, "approve")
	g.expire(expired.approval)
	if res := g.execute(expired.agent, expired.approval, approveInput("issue-571-x")); res.code != http.StatusForbidden ||
		res.body["code"] != delegationCodeNotBound {
		t.Errorf("expired = %d %s, want 403 %s", res.code, res.raw, delegationCodeNotBound)
	}

	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
}

// R8: the approver comes from the grant; a body naming one -- even the
// decider, even empty -- is refused and leaves the approval unspent.
func TestApprovalGrant_BodyApproverIsRefused(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("r8")
	g.decide(run.approval, "approve")
	for _, approver := range []string{"github:root", "someone-else", ""} {
		in := approveInput("issue-571-x")
		in["approver"] = approver
		res := g.execute(run.agent, run.approval, in)
		if res.code != http.StatusBadRequest || res.body["code"] != wiCodeActorNotAccepted {
			t.Errorf("approver %q = %d %s, want 400 %s", approver, res.code, res.raw, wiCodeActorNotAccepted)
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}
}

// R7: without an action_approval grant nothing changes -- an agent run
// with no grant, a delegated subject under another grant kind and a
// non-admin human are all refused by the admin gate, as before.
func TestApprovalGrant_EveryoneElseIsRefusedAsBefore(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("r7")
	g.decide(run.approval, "approve")

	if res := g.execute(run.agent, "", approveInput("issue-571-x")); res.code != http.StatusForbidden {
		t.Errorf("agent without a grant = %d %s, want 403", res.code, res.raw)
	}
	if res := g.execute(g.user("dev"), "", approveInput("issue-571-x")); res.code != http.StatusForbidden {
		t.Errorf("non-admin human = %d %s, want 403", res.code, res.raw)
	}

	// The gate only builds github: subjects today, so another grant kind
	// is put on the context directly: what ExecuteOperation must do with a
	// delegated subject whose grant is not an action approval.
	subject := auth.NewDelegatedUser("root", []string{"admins"}, run.agent)
	for _, kind := range []string{delegation.KindWorkItem, delegation.KindExecutionRequest, delegation.KindSurfaceLink} {
		raw, _ := json.Marshal(approveInput("issue-571-x"))
		req := httptest.NewRequest("POST", grantApprovePath, bytes.NewReader(raw))
		req = withChiParam(req, "name", devLoopApprovalKind)
		ctx := withDelegationGrant(auth.WithUser(req.Context(), subject), identityGrant{Kind: kind, Ref: run.approval})
		rec := httptest.NewRecorder()
		g.h.ExecuteOperation(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Errorf("delegated under %s = %d %s, want 403", kind, rec.Code, rec.Body.String())
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}

	// And a human admin acting directly still approves as before.
	if res := g.execute(g.decider, "", approveInput("issue-571-x")); res.code != http.StatusAccepted {
		t.Errorf("human admin = %d %s, want 202", res.code, res.raw)
	}
}

// R5: the allowlist gains exactly the approve operation route.
func TestDelegationAllowlist_OnlyTheApproveOperation(t *testing.T) {
	if !delegationAllowlisted(http.MethodPost, grantApprovePath) {
		t.Error("mctl-agents-approve is not delegable")
	}
	for _, path := range []string{
		"/api/v1/operations/deploy-service/execute",
		"/api/v1/operations/mctl-agents-approve/execute/x",
		"/api/v1/operations/mctl-agents-approve-x/execute",
		"/api/v1/agents/dev-loop/dev-loop-x/approve",
	} {
		if delegationAllowlisted(http.MethodPost, path) {
			t.Errorf("%s is delegable", path)
		}
	}
	if delegationAllowlisted(http.MethodGet, grantApprovePath) {
		t.Error("GET on the approve route is delegable")
	}
}
