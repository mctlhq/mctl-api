package api

// Human Input is information, never authorization (mctlhq/mctl-agents#198).
// These tests put both paths behind ONE Handlers: the work-items store that
// holds action approval receipts (aar_), and the human-input ledger and
// DevLoop client that carry answers to a waiting workflow, writing to the
// same audit log. Each test proves one direction of the separation: nothing
// on the human-input path can decide or spend a receipt, and nothing on the
// approval path can answer a human-input request.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// recordingLedger counts every write a handler makes to the human-input
// ledger, so a test can prove the approval path wrote nothing at all rather
// than only that one known row is absent.
type recordingLedger struct {
	*humaninput.MemoryLedger
	mu     sync.Mutex
	writes []string
}

func (l *recordingLedger) note(op, id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writes = append(l.writes, op+":"+id)
}

func (l *recordingLedger) Claim(ctx context.Context, d humaninput.Delivery) (*humaninput.Delivery, bool, error) {
	l.note("claim", d.RequestID)
	return l.MemoryLedger.Claim(ctx, d)
}

func (l *recordingLedger) NoteAttempt(ctx context.Context, requestID string) error {
	l.note("attempt", requestID)
	return l.MemoryLedger.NoteAttempt(ctx, requestID)
}

func (l *recordingLedger) Resolve(ctx context.Context, d humaninput.Delivery, state string) error {
	l.note("resolve:"+state, d.RequestID)
	return l.MemoryLedger.Resolve(ctx, d, state)
}

func (l *recordingLedger) writeLog() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.writes...)
}

// gateEnv is one Handlers serving both the action-approval routes (real
// Postgres work-items store) and the human-input routes (the sealed
// fixtures, a fake DevLoop client whose workflow WAITS on hiASCII, and a
// recording ledger), with a single audit log.
type gateEnv struct {
	*workItemsEnv
	tc     *fakeDevLoopClient
	ledger *recordingLedger
}

func newGateEnv(t *testing.T) *gateEnv {
	t.Helper()
	e := newWorkItemsEnv(t) // skips without TEST_DATABASE_URL
	hi, tc := newHumanInputHandlers(t)
	tc.onSignal = workflowAccepts
	ledger := &recordingLedger{MemoryLedger: humaninput.NewMemoryLedger()}
	e.h.opts.GitReader = hi.opts.GitReader
	e.h.opts.TemporalClient = tc
	e.h.opts.HumanInputLedger = ledger
	prev := humanInputConfirmInterval
	humanInputConfirmInterval = 0
	t.Cleanup(func() { humanInputConfirmInterval = prev })
	// The same paths the production router mounts them on.
	e.router.Get("/api/v1/human-input", e.h.ListHumanInputs)
	e.router.Get("/api/v1/human-input/{request_id}", e.h.GetHumanInput)
	e.router.Post("/api/v1/human-input/{request_id}/response", e.h.RespondHumanInput)
	return &gateEnv{workItemsEnv: e, tc: tc, ledger: ledger}
}

// requestApprovalOn opens a pending receipt on executionID. A receipt on the
// human-input fixture's own workflow (hiWF) is outside the env's tenant
// cleanup, so it is deleted by id.
func (g *gateEnv) requestApprovalOn(executionID, key string) (id, intentHash string) {
	g.t.Helper()
	b := g.approvalBody(g.tenant + "-" + key)
	b["execution_id"] = executionID
	res := g.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", b)
	if res.code != http.StatusCreated {
		g.t.Fatalf("create = %d %s", res.code, res.raw)
	}
	a := res.body["approval"].(map[string]any)
	id, intentHash = a["id"].(string), a["intent_hash"].(string)
	g.t.Cleanup(func() {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, g.connStr)
		if err != nil {
			g.t.Logf("cleanup: receipt %s left behind: %v", id, err)
			return
		}
		defer pool.Close()
		if _, err := pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE id=$1`, id); err != nil {
			g.t.Logf("cleanup: receipt %s left behind: %v", id, err)
		}
	})
	return id, intentHash
}

// receipt reads a receipt as an admin.
func (g *gateEnv) receipt(id string) map[string]any {
	g.t.Helper()
	res := g.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if res.code != http.StatusOK {
		g.t.Fatalf("read %s = %d %s", id, res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

// requireUntouched fails unless the receipt is exactly as created: pending,
// never decided, never spent.
func (g *gateEnv) requireUntouched(id, why string) {
	g.t.Helper()
	a := g.receipt(id)
	if a["state"] != workitems.ApprovalPending || a["decided_by"] != nil || a["decided_at"] != nil || a["consumed_at"] != nil || a["reason"] != nil {
		g.t.Fatalf("%s changed receipt %s: %v", why, id, a)
	}
}

func (g *gateEnv) respondHI(u *auth.User, id, body string) wiResponse {
	g.t.Helper()
	return g.do(u, "POST", "/api/v1/human-input/"+id+"/response", body)
}

// humanInputState reads the request as its respondent sees it.
func (g *gateEnv) humanInputState(id string) humanInputView {
	g.t.Helper()
	res := g.do(alice, "GET", "/api/v1/human-input/"+id, nil)
	var v humanInputView
	if res.code != http.StatusOK || json.Unmarshal([]byte(res.raw), &v) != nil {
		g.t.Fatalf("read %s = %d %s", id, res.code, res.raw)
	}
	return v
}

// approvalAudit counts action_approval.* entries for id.
func (g *gateEnv) approvalAudit(id string) map[string]int {
	out := map[string]int{}
	entries := g.audit.List(1000)
	for i := range entries {
		if strings.HasPrefix(entries[i].Operation, "action_approval.") && entries[i].Parameters["approval_id"] == id {
			out[entries[i].Operation+"/"+entries[i].Status]++
		}
	}
	return out
}

// adminAlice is the fixture's eligible respondent (github:alice) who is also
// a human admin acting directly: the one caller who may both answer the
// question and decide an approval.
var adminAlice = auth.NewGitHubUser("alice", []string{"admins"})

// An aar_ receipt cannot be reached through the human-input endpoint, and
// answering the real request on the receipt's own execution leaves the
// receipt exactly as it was.
func TestHumanInputNeverSatisfiesActionApproval_ResponseLeavesTheReceiptPending(t *testing.T) {
	g := newGateEnv(t)
	if !isHumanAdmin(adminAlice) {
		t.Fatal("fixture: adminAlice must be able to decide approvals")
	}
	id, hash := g.requestApprovalOn(hiWF, "same-exec")

	// The receipt's own id on the human-input endpoint, by every caller who
	// could decide or is eligible, with every body shape.
	for name, u := range map[string]*auth.User{"respondent": alice, "admin respondent": adminAlice, "admin": rootAdmin} {
		for _, body := range []string{
			answer(`"library A"`),
			answer(`"approve"`),
			`{"request_hash":"` + hash + `","value":"approve"}`,
			`{"request_hash":"` + hash + `","value":{"decision":"approve"}}`,
		} {
			if res := g.respondHI(u, id, body); res.code == http.StatusOK || res.code == http.StatusAccepted {
				t.Errorf("%s answering %s with %s = %d %s", name, id, body, res.code, res.raw)
			}
		}
	}
	g.requireUntouched(id, "a human-input response addressed to the receipt")
	if len(g.tc.humanInputSignals) != 0 || len(g.ledger.writeLog()) != 0 {
		t.Fatalf("an answer addressed to the receipt reached the workflow (%v) or the ledger (%v)", g.tc.humanInputSignals, g.ledger.writeLog())
	}

	// The real request, waiting on the same execution the receipt binds,
	// answered by an admin who could decide it: accepted as an answer.
	res := g.respondHI(adminAlice, hiASCII, answer(`"library A"`))
	if res.code != http.StatusOK || res.body["status"] != humaninput.DeliveryAccepted {
		t.Fatalf("answer = %d %s", res.code, res.raw)
	}
	if len(g.tc.humanInputSignals) != 1 {
		t.Fatalf("signals = %v, want the one answer", g.tc.humanInputSignals)
	}
	g.requireUntouched(id, "an accepted answer on the same execution")
	if n := g.approvalAudit(id); len(n) != 1 || n["action_approval.create/succeeded"] != 1 {
		t.Fatalf("approval audit after the answers = %v, want only the create", n)
	}
	if res := g.consume(id, hash); res.code != http.StatusConflict || code(res) != aarCodeNotApproved {
		t.Fatalf("consume after the answer = %d %s, want %s", res.code, res.raw, aarCodeNotApproved)
	}
	if res := g.do(rootAdmin, "GET", "/api/v1/action-approvals?state=approved&execution_id="+hiWF, nil); res.code != http.StatusOK {
		t.Fatalf("list = %d %s", res.code, res.raw)
	} else {
		for _, a := range res.body["approvals"].([]any) {
			if a.(map[string]any)["id"] == id {
				t.Fatalf("the receipt is listed as approved: %s", res.raw)
			}
		}
	}
}

// Answering is not deciding, even for an admin; only the decision endpoint,
// called by a human admin acting directly, decides, and only then can the
// receipt be spent.
func TestHumanInputNeverSatisfiesActionApproval_OnlyTheDecisionEndpointDecides(t *testing.T) {
	g := newGateEnv(t)
	id, hash := g.requestApprovalOn(hiWF, "admin-answer")

	if res := g.respondHI(adminAlice, hiASCII, answer(`"library A"`)); res.code != http.StatusOK {
		t.Fatalf("answer = %d %s", res.code, res.raw)
	}
	// A resubmission is the idempotent replay of the same answer: still
	// nothing on the receipt.
	if res := g.respondHI(adminAlice, hiASCII, answer(`"library A"`)); res.code != http.StatusOK {
		t.Fatalf("replay = %d %s", res.code, res.raw)
	}
	g.requireUntouched(id, "an admin's answer")
	if res := g.consume(id, hash); res.code != http.StatusConflict || code(res) != aarCodeNotApproved {
		t.Fatalf("consume after an admin's answer = %d %s", res.code, res.raw)
	}

	signals := len(g.tc.humanInputSignals)
	res := g.decide(adminAlice, id, "approve")
	if res.code != http.StatusOK || res.body["approval"].(map[string]any)["state"] != workitems.ApprovalApproved ||
		res.body["approval"].(map[string]any)["decided_by"] != "github:alice" {
		t.Fatalf("decide = %d %s", res.code, res.raw)
	}
	if res := g.consume(id, hash); res.code != http.StatusOK || res.body["approval"].(map[string]any)["state"] != workitems.ApprovalConsumed {
		t.Fatalf("consume after the decision = %d %s", res.code, res.raw)
	}
	if len(g.tc.humanInputSignals) != signals {
		t.Fatalf("deciding signalled the human-input workflow: %v", g.tc.humanInputSignals[signals:])
	}
}

// Deciding or spending a receipt answers no question: no human-input signal,
// no ledger write, no approve signal, and the request is still open for its
// respondent afterwards.
func TestActionApprovalNeverAnswersHumanInput(t *testing.T) {
	g := newGateEnv(t)
	approved, hash := g.requestApprovalOn(hiWF, "decide-approve")
	denied, _ := g.requestApprovalOn(hiWF, "decide-deny")

	if res := g.decide(rootAdmin, approved, "approve"); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if res := g.decide(adminAlice, denied, "deny"); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
	if res := g.consume(approved, hash); res.code != http.StatusOK {
		t.Fatalf("consume = %d %s", res.code, res.raw)
	}
	// The request's own id on the approval endpoints is not a receipt.
	for _, u := range []*auth.User{rootAdmin, adminAlice} {
		if res := g.decide(u, hiASCII, "approve"); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
			t.Fatalf("deciding %s = %d %s", hiASCII, res.code, res.raw)
		}
	}
	if res := g.consume(hiASCII, hiASCIIHash); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("consuming %s = %d %s", hiASCII, res.code, res.raw)
	}

	if len(g.tc.humanInputSignals) != 0 {
		t.Fatalf("the approval path signalled a human-input response: %v to %v", g.tc.humanInputSignals, g.tc.humanInputSignalTo)
	}
	if g.tc.lastApprovedWorkflow != "" || g.tc.lastApprovePayload != nil {
		t.Fatalf("the approval path signalled approve on %q", g.tc.lastApprovedWorkflow)
	}
	if w := g.ledger.writeLog(); len(w) != 0 {
		t.Fatalf("the approval path wrote the human-input ledger: %v", w)
	}
	if st := g.tc.humanInputStates[hiWF]; st.State != temporalclient.HumanInputWaitingForInput || st.RequestID != hiASCII || st.ResumeCount != 0 {
		t.Fatalf("workflow state = %+v, want still waiting on %s", st, hiASCII)
	}
	if v := g.humanInputState(hiASCII); v.State != HumanInputPending || !v.CanRespond {
		t.Fatalf("request after the decisions = %+v, want pending and answerable", v)
	}
	entries := g.audit.List(1000)
	for i := range entries {
		if e := &entries[i]; strings.HasPrefix(e.Operation, "human_input.") {
			t.Fatalf("the approval path audited a human-input event: %+v", e)
		}
	}

	// And the respondent can still answer it.
	if res := g.respondHI(alice, hiASCII, answer(`"library A"`)); res.code != http.StatusOK || res.body["status"] != humaninput.DeliveryAccepted {
		t.Fatalf("answer after the decisions = %d %s", res.code, res.raw)
	}
}

// The two paths write distinct operations to the shared audit log, and
// neither records the other's identifiers or outcome.
func TestHumanInputAndActionApprovalAuditDoNotCross(t *testing.T) {
	g := newGateEnv(t)
	id, hash := g.requestApprovalOn(hiWF, "audit")

	// Human input: a rejected answer, the receipt's id on the HI endpoint,
	// then an accepted answer.
	if res := g.respondHI(adminAlice, hiASCII, `{"request_hash":"sha256:00","value":"library A"}`); res.code != http.StatusConflict {
		t.Fatalf("stale answer = %d %s", res.code, res.raw)
	}
	g.respondHI(adminAlice, id, answer(`"library A"`))
	if res := g.respondHI(adminAlice, hiASCII, answer(`"library A"`)); res.code != http.StatusOK {
		t.Fatalf("answer = %d %s", res.code, res.raw)
	}
	// Approval: a refused decision on the request's id, then decide and
	// consume the receipt.
	g.decide(rootAdmin, hiASCII, "approve")
	if res := g.decide(adminAlice, id, "approve"); res.code != http.StatusOK {
		t.Fatalf("decide = %d %s", res.code, res.raw)
	}
	if res := g.consume(id, hash); res.code != http.StatusOK {
		t.Fatalf("consume = %d %s", res.code, res.raw)
	}

	// Keys that belong to exactly one of the two records.
	approvalOnly := []string{"approval_id", "intent_hash", "decided_by", "requested_by", "action_kind", "policy_rule_id"}
	humanInputOnly := []string{"request_id", "respondent", "surface", "proposal"}
	got := map[string]int{}
	entries := g.audit.List(1000)
	for i := range entries {
		e := &entries[i]
		got[e.Operation+"/"+e.Status]++
		switch {
		case strings.HasPrefix(e.Operation, "human_input."):
			if e.Parameters["request_id"] != hiASCII {
				t.Errorf("human-input entry about %q: %+v", e.Parameters["request_id"], e)
			}
			for _, k := range approvalOnly {
				if _, ok := e.Parameters[k]; ok {
					t.Errorf("human-input entry carries approval field %s: %+v", k, e)
				}
			}
			for k, v := range e.Parameters {
				if strings.HasPrefix(v, workitems.ActionApprovalIDPrefix) {
					t.Errorf("human-input entry names receipt %s in %s: %+v", v, k, e)
				}
			}
		case strings.HasPrefix(e.Operation, "action_approval."):
			for _, k := range humanInputOnly {
				if _, ok := e.Parameters[k]; ok {
					t.Errorf("approval entry carries human-input field %s: %+v", k, e)
				}
			}
			// The only approval entry about the request's id is the refusal.
			if e.Parameters["approval_id"] == hiASCII && (e.Operation != "action_approval.decision_refused" || e.Status != "failed") {
				t.Errorf("approval entry succeeded on %s: %+v", hiASCII, e)
			}
		default:
			t.Errorf("unexpected audit operation %q: %+v", e.Operation, e)
		}
	}
	want := map[string]int{
		"human_input.response_rejected/failed":    1,
		"human_input.signal_sent/submitted":       1,
		"human_input.response_accepted/succeeded": 1,
		"action_approval.create/succeeded":        1,
		"action_approval.decision_refused/failed": 1,
		"action_approval.decision/succeeded":      1,
		"action_approval.consume/succeeded":       1,
	}
	for op, n := range want {
		if got[op] != n {
			t.Errorf("%s audited %d times, want %d (all: %v)", op, got[op], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("audit operations = %v, want exactly %v", got, want)
	}
}

// The fixture itself: the env really is one Handlers with both paths wired,
// so a test above that passes is not passing against a stub.
func TestGateEnvWiresBothPaths(t *testing.T) {
	g := newGateEnv(t)
	if g.h.opts.WorkItems == nil || g.h.opts.HumanInputLedger == nil || g.h.opts.TemporalClient == nil || g.h.opts.GitReader == nil || g.h.opts.AuditLog != g.audit {
		t.Fatal("gate env is missing a dependency")
	}
	if v := g.humanInputState(hiASCII); v.State != HumanInputPending {
		t.Fatalf("fixture request = %+v", v)
	}
	id, _ := g.requestApprovalOn(hiWF, "wired")
	if g.receipt(id)["execution_id"] != hiWF {
		t.Fatal("receipt is not on the fixture's execution")
	}
}
