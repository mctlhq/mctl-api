package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// grantedRun is a DevLoop run for a proposal of mctl-api, attached under the
// workflow id the real DevLoop has for it, with a pending approval grant
// for that proposal and the agent run bound to it.
type grantedRun struct {
	devLoopRun
	slug     string
	approval string
	agent    *auth.User
}

// grantIssues numbers the proposals of these tests: workflow ids are global,
// so each run gets an issue no other run (or earlier test process) uses.
var grantIssues atomic.Int64

func init() { grantIssues.Store(time.Now().UnixNano() % 1_000_000_000) }

func (g *grantEnv) grantedRun(suffix string) grantedRun {
	g.t.Helper()
	return g.grantedRunTargeting(suffix, "")
}

// grantedRunTargeting is grantedRun with the grant created for target
// instead of the run's own proposal ("" keeps it).
func (g *grantEnv) grantedRunTargeting(suffix, target string) grantedRun {
	g.t.Helper()
	n := grantIssues.Add(1)
	run := grantedRun{slug: fmt.Sprintf("issue-%d-x", n)}
	svc := auth.NewServiceUser()
	item := g.open(svc, nil)
	run.devLoopRun = devLoopRun{workflowID: fmt.Sprintf("dev-loop-mctlhq-mctl-api-%d", n), itemID: item["id"].(string)}
	run.execID = g.attachExecution(svc, run.itemID, run.workflowID, "Running")
	g.forgetApprovalsOf(run.execID)
	if target == "" {
		target = "mctl-api/" + run.slug
	}
	run.approval = g.createGrant(run.execID, "k-"+suffix, target, devLoopApprovalKind)
	run.agent = g.runAgent(run.execID)
	return run
}

func (g *grantEnv) createGrant(execID, key, target, kind string) string {
	g.t.Helper()
	body := g.devLoopGrantBody(execID, key)
	body["target"], body["action_kind"] = target, kind
	res := g.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", body)
	if res.code != http.StatusCreated {
		g.t.Fatalf("create grant = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)["id"].(string)
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

	res := g.execute(run.agent, run.approval, approveInput(run.slug))
	if res.code != http.StatusAccepted {
		t.Fatalf("grant-authorized approve = %d %s", res.code, res.raw)
	}
	if g.submitted() != 1 {
		t.Fatalf("submitted %d workflows, want 1", g.submitted())
	}
	params := g.exec.submitted[0]
	if params["approver"] != "root" || params["service"] != "mctl-api" || params["slug"] != run.slug {
		t.Errorf("submitted params = %v, want approver root for mctl-api/%s", params, run.slug)
	}
	// mctl-agents#681: the workflow is told the content the human decided.
	if params[expectedContentDigestParam] != testContentDigest {
		t.Errorf("submitted %s = %q, want the grant's artifact_hash %q", expectedContentDigestParam, params[expectedContentDigestParam], testContentDigest)
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
	// What the human authorized is answerable from the audit alone.
	for _, op := range []string{"action_approval.decision", "action_approval.consume"} {
		for _, entry := range g.audit.List(1000) {
			if entry.Operation == op && entry.Parameters["approval_id"] == run.approval && entry.Parameters["target"] != "mctl-api/"+run.slug {
				t.Errorf("%s audit target = %q, want mctl-api/%s", op, entry.Parameters["target"], run.slug)
			}
			if entry.Operation == op && entry.Parameters["approval_id"] == run.approval && entry.Parameters["artifact_hash"] != testContentDigest {
				t.Errorf("%s audit artifact_hash = %q, want %q", op, entry.Parameters["artifact_hash"], testContentDigest)
			}
		}
	}

	again := g.execute(run.agent, run.approval, approveInput(run.slug))
	if again.code < 400 || g.submitted() != 1 {
		t.Errorf("second use = %d %s, submitted %d; want a refusal and nothing more submitted", again.code, again.raw, g.submitted())
	}
}

// A6 (R9): a human admin with no GitHub identity -- a ZITADEL sign-in --
// decides the approval and the agent run exercises it end to end. The
// delegated subject is the decider's stored principal; nothing about it is
// read from a GitHub login.
func TestApprovalGrant_NonGitHubDeciderApprovesEndToEnd(t *testing.T) {
	g := newGrantEnv(t)
	zed := auth.NewFederatedUser("zitadel", "https://id.example.com", "z-sub", "zed@example.com", string(auth.KindHuman))
	zed.Groups = []string{"admins"}
	if err := auth.AttachPrincipal(context.Background(), loginPrincipals{}, zed); err != nil {
		t.Fatal(err)
	}
	if _, gh := zed.GitHubLogin(); gh {
		t.Fatal("the decider must have no GitHub login")
	}
	g.decider = zed
	run := g.grantedRun("a6")
	g.decide(run.approval, "approve")

	res := g.execute(run.agent, run.approval, approveInput(run.slug))
	if res.code != http.StatusAccepted {
		t.Fatalf("grant-authorized approve by a ZITADEL decider = %d %s", res.code, res.raw)
	}
	if g.submitted() != 1 {
		t.Fatalf("submitted %d workflows, want 1", g.submitted())
	}
	if got := g.exec.submitted[0]["approver"]; got != "zed@example.com" {
		t.Errorf("approver = %q, want zed@example.com", got)
	}
	var found bool
	for _, entry := range g.audit.List(200) {
		if entry.Operation != devLoopApprovalKind || entry.Status != "submitted" {
			continue
		}
		found = true
		if entry.UserID != "zed@example.com" || entry.PrincipalID != "prn_zed@example.com" ||
			entry.Parameters["subject_principal_id"] != "prn_zed@example.com" || entry.Parameters["actor_name"] != "implementer" {
			t.Errorf("submit audit = user %q principal %q params %v", entry.UserID, entry.PrincipalID, entry.Parameters)
		}
	}
	if !found {
		t.Error("no submitted audit entry")
	}
}

// R8: the decider recorded as approver is validated like every other
// approver before anything is spent. A decider name the operation's
// identity pattern refuses (an IdP display name with a newline, which
// would land in .status.yaml and a commit message) is a 400 and leaves the
// approval unspent.
func TestApprovalGrant_DeciderIsValidatedAsTheApprover(t *testing.T) {
	g := newGrantEnv(t)
	odd := auth.NewFederatedUser("zitadel", "https://id.example.com", "z-odd", "zed\napproved_by: someone-else", string(auth.KindHuman))
	odd.Groups = []string{"admins"}
	if err := auth.AttachPrincipal(context.Background(), loginPrincipals{}, odd); err != nil {
		t.Fatal(err)
	}
	g.decider = odd
	run := g.grantedRun("ctl")
	g.decide(run.approval, "approve")
	res := g.execute(run.agent, run.approval, approveInput(run.slug))
	if res.code != http.StatusBadRequest || !strings.Contains(res.raw, "validation failed") || !strings.Contains(res.raw, "approver") {
		t.Errorf("control character in the decider = %d %s, want 400 validation failed on approver", res.code, res.raw)
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
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

	res := g.execute(g.runAgent(other.execID), run.approval, approveInput(run.slug))
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
		res := g.execute(run.agent, ref, approveInput(run.slug))
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
	n := strings.TrimSuffix(strings.TrimPrefix(run.slug, "issue-"), "-x")

	for name, in := range map[string]map[string]string{
		// Another DevLoop's proposal: refused by the binding.
		"other issue":   approveInput("issue-1-x"),
		"other service": {"service": "mctl-web", "slug": run.slug},
		"no devloop":    approveInput("not-an-issue-slug"),
		// This DevLoop, another proposal than the one approved: the
		// binding passes and the intent CAS refuses it.
		"other slug": approveInput("issue-" + n + "-y"),
	} {
		res := g.execute(run.agent, run.approval, in)
		if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
			t.Errorf("%s = %d %s, want 409 %s", name, res.code, res.raw, aarCodeIntentMismatch)
		}
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}

	// Same run, same target, another action kind: decided by the same
	// human, still not an approval of mctl-agents-approve.
	merge := g.createGrant(run.execID, "k-tgt-merge", "mctl-api/"+run.slug, "merge")
	g.decide(merge, "approve")
	res := g.execute(run.agent, merge, approveInput(run.slug))
	if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
		t.Errorf("other kind = %d %s, want 409 %s", res.code, res.raw, aarCodeIntentMismatch)
	}
	// Refused before the input is validated: an invalid body still gets
	// the kind refusal, not a validation error.
	res = g.execute(run.agent, merge, map[string]string{"service": "mctl-api"})
	if res.code != http.StatusConflict || res.body["code"] != aarCodeIntentMismatch {
		t.Errorf("other kind, invalid body = %d %s, want 409 %s", res.code, res.raw, aarCodeIntentMismatch)
	}
	if st := g.approvalState(merge)["state"]; st != "approved" {
		t.Errorf("other-kind approval state = %v, want approved (unspent)", st)
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
}

// The requester names the target when it creates the grant, but the human
// approves a DevLoop, not a target. A grant created for another DevLoop's
// proposal and approved through this execution is refused at use, whoever
// decided it, and stays unspent: the target is bound to the execution's
// engine_ref server-side.
func TestApprovalGrant_TargetIsBoundToTheExecutionsDevLoop(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRunTargeting("bind", "mctl-web/issue-1-x")
	g.decide(run.approval, "approve")

	res := g.execute(run.agent, run.approval, approveInput("issue-1-x"))
	res2 := g.execute(run.agent, run.approval, map[string]string{"service": "mctl-web", "slug": "issue-1-x"})
	for _, r := range []wiResponse{res, res2} {
		if r.code != http.StatusConflict || r.body["code"] != aarCodeIntentMismatch {
			t.Errorf("foreign target = %d %s, want 409 %s", r.code, r.raw, aarCodeIntentMismatch)
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}
}

// A run dispatched from an execution request carries
// <workflow_id>#<request_id> as its engine_ref (D3); its own proposal binds.
func TestApprovalGrant_DispatchedRunBindsItsProposal(t *testing.T) {
	g := newGrantEnv(t)
	n := grantIssues.Add(1)
	slug := fmt.Sprintf("issue-%d-x", n)
	svc := auth.NewServiceUser()
	item := g.open(svc, nil)
	execID := g.attachExecution(svc, item["id"].(string), fmt.Sprintf("dev-loop-mctlhq-mctl-api-%d#xr_01TEST", n), "Running")
	g.forgetApprovalsOf(execID)
	approval := g.createGrant(execID, "k-disp", "mctl-api/"+slug, devLoopApprovalKind)
	g.decide(approval, "approve")
	if res := g.execute(g.runAgent(execID), approval, approveInput(slug)); res.code != http.StatusAccepted {
		t.Fatalf("dispatched run = %d %s, want 202", res.code, res.raw)
	}
}

// A4: pending, denied and expired grants fail closed and submit nothing.
func TestApprovalGrant_UndecidedDeniedExpiredFailClosed(t *testing.T) {
	g := newGrantEnv(t)

	pending := g.grantedRun("pend")
	if res := g.execute(pending.agent, pending.approval, approveInput(pending.slug)); res.code != http.StatusForbidden ||
		res.body["code"] != delegationCodeUnresolved {
		t.Errorf("pending = %d %s, want 403 %s", res.code, res.raw, delegationCodeUnresolved)
	}

	denied := g.grantedRun("deny")
	g.decide(denied.approval, "deny")
	if res := g.execute(denied.agent, denied.approval, approveInput(denied.slug)); res.code != http.StatusForbidden ||
		res.body["code"] != delegationCodeNotBound {
		t.Errorf("denied = %d %s, want 403 %s", res.code, res.raw, delegationCodeNotBound)
	}

	expired := g.grantedRun("exp")
	g.decide(expired.approval, "approve")
	g.expire(expired.approval)
	if res := g.execute(expired.agent, expired.approval, approveInput(expired.slug)); res.code != http.StatusForbidden ||
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
	for _, approver := range []string{"root", "github:root", "someone-else", ""} {
		in := approveInput(run.slug)
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

// mctl-agents#681: the content digest the workflow checks is the grant's;
// a body naming one -- the grant's own value, another, or empty -- is
// refused and leaves the approval unspent.
func TestApprovalGrant_BodyContentDigestIsRefused(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("681-body")
	g.decide(run.approval, "approve")
	for _, digest := range []string{testContentDigest, "sha256:" + strings.Repeat("b", 64), ""} {
		in := approveInput(run.slug)
		in[expectedContentDigestParam] = digest
		res := g.execute(run.agent, run.approval, in)
		if res.code != http.StatusBadRequest || res.body["code"] != wiCodeActorNotAccepted {
			t.Errorf("%s %q = %d %s, want 400 %s", expectedContentDigestParam, digest, res.code, res.raw, wiCodeActorNotAccepted)
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows", g.submitted())
	}
	if st := g.approvalState(run.approval)["state"]; st != "approved" {
		t.Errorf("approval state = %v, want approved (unspent)", st)
	}
}

// mctl-agents#681: a DevLoop grant that binds no proposal content -- none,
// or something that is not a content digest -- is refused before anything
// is spent or submitted, never exercised as an approval of whatever the
// slug holds at flip time.
func TestApprovalGrant_GrantWithoutContentDigestFailsClosed(t *testing.T) {
	g := newGrantEnv(t)
	for i, artifact := range []string{"", "sha256:args", "sha256:" + strings.Repeat("A", 64)} {
		n := grantIssues.Add(1)
		slug := fmt.Sprintf("issue-%d-x", n)
		svc := auth.NewServiceUser()
		item := g.open(svc, nil)
		execID := g.attachExecution(svc, item["id"].(string), fmt.Sprintf("dev-loop-mctlhq-mctl-api-%d", n), "Running")
		g.forgetApprovalsOf(execID)
		body := g.devLoopGrantBody(execID, fmt.Sprintf("k-681-unbound-%d", i))
		body["target"] = "mctl-api/" + slug
		if artifact == "" {
			delete(body, "artifact_hash")
		} else {
			body["artifact_hash"] = artifact
		}
		created := g.do(svc, "POST", "/api/v1/action-approvals", body)
		if created.code != http.StatusCreated {
			t.Fatalf("create grant (artifact %q) = %d %s", artifact, created.code, created.raw)
		}
		approval := created.body["approval"].(map[string]any)["id"].(string)
		g.decide(approval, "approve")

		res := g.execute(g.runAgent(execID), approval, approveInput(slug))
		if res.code != http.StatusConflict || res.body["code"] != aarCodeContentUnbound {
			t.Errorf("artifact %q = %d %s, want 409 %s", artifact, res.code, res.raw, aarCodeContentUnbound)
		}
		if st := g.approvalState(approval)["state"]; st != "approved" {
			t.Errorf("artifact %q: approval state = %v, want approved (unspent)", artifact, st)
		}
	}
	if g.submitted() != 0 {
		t.Fatalf("submitted %d workflows, want 0", g.submitted())
	}
}

// R7: without an action_approval grant nothing changes -- an agent run
// with no grant, a delegated subject under another grant kind and a
// non-admin human are all refused by the admin gate, as before.
func TestApprovalGrant_EveryoneElseIsRefusedAsBefore(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("r7")
	g.decide(run.approval, "approve")

	if res := g.execute(run.agent, "", approveInput(run.slug)); res.code != http.StatusForbidden {
		t.Errorf("agent without a grant = %d %s, want 403", res.code, res.raw)
	}
	if res := g.execute(g.user("dev"), "", approveInput(run.slug)); res.code != http.StatusForbidden {
		t.Errorf("non-admin human = %d %s, want 403", res.code, res.raw)
	}

	// Another grant kind is put on the context directly: what
	// ExecuteOperation must do with a delegated subject whose grant is not
	// an action approval, whichever route delivered it.
	subject := auth.NewDelegatedUser("root", []string{"admins"}, run.agent)
	for _, kind := range []string{delegation.KindWorkItem, delegation.KindExecutionRequest, delegation.KindSurfaceLink} {
		raw, _ := json.Marshal(approveInput(run.slug))
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
	if res := g.execute(g.decider, "", approveInput(run.slug)); res.code != http.StatusAccepted {
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
