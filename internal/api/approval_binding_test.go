package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func TestParseApprovalBindingMode(t *testing.T) {
	for raw, want := range map[string]ApprovalBindingMode{
		"": ApprovalBindingObserve, "observe": ApprovalBindingObserve,
		"off": ApprovalBindingOff, "enforce": ApprovalBindingEnforce,
	} {
		got, err := ParseApprovalBindingMode(raw)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := ParseApprovalBindingMode("strict"); err == nil {
		t.Error("an unknown mode must be refused")
	}
}

func TestDecisionBinding_MissingFields(t *testing.T) {
	full := decisionBinding{ApprovalRef: "aar_1", ContextDigest: "sha256:a", ContentDigest: "sha256:b"}
	if m := full.missingFields(); len(m) != 0 {
		t.Fatalf("complete binding misses %v", m)
	}
	var nilB *decisionBinding
	if m := nilB.missingFields(); len(m) != 3 {
		t.Fatalf("nil binding misses %v", m)
	}
	for field, mut := range map[string]func(b *decisionBinding){
		"approval_ref":   func(b *decisionBinding) { b.ApprovalRef = "x_1" },
		"context_digest": func(b *decisionBinding) { b.ContextDigest = "" },
		"content_digest": func(b *decisionBinding) { b.ContentDigest = "a b" },
	} {
		b := full
		mut(&b)
		if m := b.missingFields(); len(m) != 1 || m[0] != field {
			t.Errorf("%s: missing = %v", field, m)
		}
	}
}

// boundDecision builds the binding a card shows for an approval.
func (e *workItemsEnv) bindingOf(id string) map[string]any {
	e.t.Helper()
	res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if res.code != http.StatusOK {
		e.t.Fatalf("get approval = %d %s", res.code, res.raw)
	}
	dc := res.body["decision_context"].(map[string]any)
	a := res.body["approval"].(map[string]any)
	return map[string]any{"approval_ref": id, "context_digest": dc["context_digest"], "content_digest": a["artifact_hash"]}
}

func (e *workItemsEnv) newPendingApproval(key string) string {
	e.t.Helper()
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", e.approvalBody(key))
	if res.code != http.StatusCreated {
		e.t.Fatalf("create = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)["id"].(string)
}

func (e *workItemsEnv) decideBound(u *auth.User, id string, binding any) wiResponse {
	body := map[string]any{"decision": workitems.DecisionApprove}
	if binding != nil {
		body["binding"] = binding
	}
	return e.do(u, "POST", "/api/v1/action-approvals/"+id+"/decision", body)
}

// T1, T2, T3, T7, T11.
func TestActionApprovalDecision_Binding(t *testing.T) {
	e := newWorkItemsEnv(t)
	id := e.newPendingApproval("b1")
	good := e.bindingOf(id)

	for name, mut := range map[string]func(map[string]any){
		"context_digest": func(b map[string]any) { b["context_digest"] = "sha256:other" },
		"content_digest": func(b map[string]any) { b["content_digest"] = "sha256:other" },
		"approval_ref":   func(b map[string]any) { b["approval_ref"] = "aar_other" },
	} {
		b := map[string]any{}
		for k, v := range good {
			b[k] = v
		}
		mut(b)
		res := e.decideBound(rootAdmin, id, b)
		if res.code != http.StatusConflict || code(res) != aarCodeContextChanged {
			t.Errorf("%s differs: %d %s, want 409 %s", name, res.code, res.raw, aarCodeContextChanged)
		}
		if st := e.approvalState(id)["state"]; st != workitems.ApprovalPending {
			t.Errorf("%s differs: grant is %v", name, st)
		}
	}

	if res := e.decideBound(rootAdmin, id, good); res.code != http.StatusOK {
		t.Fatalf("matching binding = %d %s", res.code, res.raw)
	}
	// T7: a duplicate returns the existing decision, with no second one.
	if res := e.decideBound(rootAdmin, id, good); res.code != http.StatusOK {
		t.Fatalf("duplicate = %d %s", res.code, res.raw)
	}
	if n := e.auditOps("action_approval.decision", id); n != 1 {
		t.Fatalf("decided %d times, want 1", n)
	}

	// T11: a denied grant with a stale binding answers the state code.
	id2 := e.newPendingApproval("b2")
	stale := e.bindingOf(id2)
	if res := e.decide(rootAdmin, id2, workitems.DecisionDeny); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
	stale["context_digest"] = "sha256:old"
	if res := e.decideBound(rootAdmin, id2, stale); res.code != http.StatusConflict || code(res) != aarCodeAlreadyDecided {
		t.Fatalf("denied + stale = %d %s, want 409 %s", res.code, res.raw, aarCodeAlreadyDecided)
	}
}

// T8 and T10.
func TestActionApprovalDecision_BindingModes(t *testing.T) {
	e := newWorkItemsEnv(t)
	for mode, wantCode := range map[ApprovalBindingMode]int{
		ApprovalBindingOff: http.StatusOK, ApprovalBindingObserve: http.StatusOK, ApprovalBindingEnforce: http.StatusUnprocessableEntity,
	} {
		e.h.opts.ApprovalBindingMode = mode
		id := e.newPendingApproval("m-" + string(mode))
		res := e.decideBound(rootAdmin, id, nil)
		if res.code != wantCode {
			t.Fatalf("%s without binding = %d %s, want %d", mode, res.code, res.raw, wantCode)
		}
		if mode == ApprovalBindingEnforce && code(res) != aarCodeBindingMissing {
			t.Fatalf("enforce code = %s", code(res))
		}
		absent := 0
		for _, en := range e.audit.List(1000) {
			if en.Operation == "approval.binding_absent" && en.Parameters["approval_id"] == id {
				absent++
			}
		}
		if (mode == ApprovalBindingObserve) != (absent == 1) || absent > 1 {
			t.Fatalf("%s: binding_absent audited %d times", mode, absent)
		}
		// T10: a partial binding is refused in every mode.
		partial := map[string]any{"approval_ref": id, "context_digest": "sha256:x"}
		if res := e.decideBound(rootAdmin, e.newPendingApproval("p-"+string(mode)), partial); res.code != http.StatusUnprocessableEntity || code(res) != aarCodeBindingMissing {
			t.Fatalf("%s partial = %d %s", mode, res.code, res.raw)
		}
	}
}

// T9.
func TestActionApprovalDecision_BindingDoesNotWidenAuthority(t *testing.T) {
	e := newWorkItemsEnv(t)
	id := e.newPendingApproval("auth")
	b := e.bindingOf(id)
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"service": auth.NewServiceUser(), "surface": surface,
		"relayed": auth.NewRelayedUser("root", []string{"admins", e.tenant}, surface),
	} {
		for _, bind := range []any{nil, b} {
			if res := e.decideBound(u, id, bind); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
				t.Errorf("%s: %d %s", name, res.code, res.raw)
			}
		}
	}
	if st := e.approvalState(id)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("grant is %v", st)
	}
}

func bindingJSON(m map[string]any) string {
	return `{"binding":{"approval_ref":"` + m["approval_ref"].(string) + `","context_digest":"` + m["context_digest"].(string) + `","content_digest":"` + m["content_digest"].(string) + `"}}`
}

// T4, T5.
func TestDevLoopApprove_Binding(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("bind")
	a := e.requestDevLoopGrant(run.execID, "gate-a")
	cardA := e.bindingOf(a)
	// The proposal is amended: grant A is superseded by B.
	b := e.requestDevLoopGrant(run.execID, "gate-b")
	res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(cardA))
	if res.code != http.StatusConflict || code(res) != aarCodeContextChanged {
		t.Fatalf("stale card = %d %s", res.code, res.raw)
	}
	d, _ := res.body["details"].(map[string]any)
	if d["current_approval_ref"] != b || d["reapproval_required"] != true {
		t.Fatalf("details = %v", d)
	}
	if st := e.approvalState(b)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("B moved to %v", st)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", fake.lastApprovePayload)
	}

	cardB := e.bindingOf(b)
	stale := map[string]any{"approval_ref": b, "context_digest": "sha256:old", "content_digest": cardB["content_digest"]}
	if res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(stale)); res.code != http.StatusConflict || code(res) != aarCodeContextChanged {
		t.Fatalf("stale digest = %d %s", res.code, res.raw)
	}
	if res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(cardB)); res.code != http.StatusOK {
		t.Fatalf("matching = %d %s", res.code, res.raw)
	}
	if fake.lastApprovePayload["approval_ref"] != b {
		t.Fatalf("payload = %v", fake.lastApprovePayload)
	}
	// Duplicate: one decision, same signal.
	fake.lastApprovePayload = nil
	if res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(cardB)); res.code != http.StatusOK || fake.lastApprovePayload["approval_ref"] != b {
		t.Fatalf("duplicate = %d %s", res.code, res.raw)
	}
	if n := e.auditOps("action_approval.decision", b); n != 1 {
		t.Fatalf("decided %d times", n)
	}
}

// T6 and enforce on the DevLoop route.
func TestDevLoopApprove_BindingModeAndUnreadableStore(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	e.h.opts.ApprovalBindingMode = ApprovalBindingEnforce
	run := e.startDevLoopRun("enf")
	e.requestDevLoopGrant(run.execID, "gate-1")
	res := e.approveDevLoop(rootAdmin, run.workflowID, "")
	if res.code != http.StatusUnprocessableEntity || code(res) != aarCodeBindingMissing {
		t.Fatalf("enforce unbound = %d %s", res.code, res.raw)
	}
	if res := e.approveDevLoop(rootAdmin, run.workflowID, `{"binding":{"approval_ref":"aar_x"}}`); res.code != http.StatusUnprocessableEntity {
		t.Fatalf("partial = %d %s", res.code, res.raw)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", fake.lastApprovePayload)
	}
}

// Review P2 on #902: a bound decision with no grant to match must never fall
// back to the unbound legacy approval, in any mode and with the legacy flag
// on: a made-up approval_ref would otherwise approve the workflow and satisfy
// enforce.
func TestDevLoopApprove_BoundDecisionNeverFallsBackToLegacy(t *testing.T) {
	made := bindingJSON(map[string]any{"approval_ref": "aar_madeup", "context_digest": "sha256:x", "content_digest": "sha256:y"})
	for _, mode := range []ApprovalBindingMode{ApprovalBindingOff, ApprovalBindingObserve, ApprovalBindingEnforce} {
		e, fake := newDevLoopGrantEnv(t)
		e.h.opts.ApprovalBindingMode = mode
		e.h.opts.LegacyApproverDisabled = false
		run := e.startDevLoopRun("nf-" + string(mode))
		for name, wf := range map[string]string{"no pending grant": run.workflowID, "no execution": e.tenant + "-unattached"} {
			fake.lastApprovePayload = nil
			res := e.approveDevLoop(rootAdmin, wf, made)
			if res.code != http.StatusConflict || code(res) != devLoopCodeGrantMissing {
				t.Fatalf("%s/%s: %d %s, want 409 %s", mode, name, res.code, res.raw, devLoopCodeGrantMissing)
			}
			if fake.lastApprovePayload != nil {
				t.Fatalf("%s/%s: signalled %v", mode, name, fake.lastApprovePayload)
			}
		}
	}
}

// Without a work-items store a bound decision cannot be checked, so it is a
// 503 and never the legacy approval.
func TestDevLoopApprove_BoundDecisionWithoutStore(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger(), GitReader: ownerEverywhere{}}}
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/wf/approve",
		strings.NewReader(bindingJSON(map[string]any{"approval_ref": "aar_x", "context_digest": "sha256:x", "content_digest": "sha256:y"})))
	req = withChiParam(req, "workflow_id", "wf")
	req = req.WithContext(auth.WithUser(req.Context(), rootAdmin))
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("bound, no store = %d %s", rec.Code, rec.Body.String())
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", fake.lastApprovePayload)
	}
}

// T6: an unreadable grant store is a 503 for a bound decision, not the legacy
// payload, and nothing is signalled.
func TestDevLoopApprove_BoundDecisionUnreadableStore(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("unread")
	id := e.requestDevLoopGrant(run.execID, "gate-u")
	card := bindingJSON(e.bindingOf(id))
	e.h.opts.WorkItems.Close()
	res := e.approveDevLoop(rootAdmin, run.workflowID, card)
	if res.code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable store = %d %s, want 503", res.code, res.raw)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", fake.lastApprovePayload)
	}
}

// An already approved newest grant is returned only to the binding it was
// decided under.
func TestDevLoopApprove_ApprovedGrantNeedsTheSameBinding(t *testing.T) {
	e, fake := newDevLoopGrantEnv(t)
	run := e.startDevLoopRun("appr")
	id := e.requestDevLoopGrant(run.execID, "gate-ap")
	card := e.bindingOf(id)
	if res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(card)); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	fake.lastApprovePayload = nil
	other := map[string]any{"approval_ref": id, "context_digest": "sha256:other", "content_digest": card["content_digest"]}
	res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(other))
	if res.code != http.StatusConflict || code(res) != aarCodeContextChanged {
		t.Fatalf("approved + other digest = %d %s", res.code, res.raw)
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", fake.lastApprovePayload)
	}
}

// Observe mode counts an unbound approve per route and audits it with the
// workflow id on the DevLoop route; bound requests count nothing.
func TestApprovalBinding_ObserveCountsUnboundOnly(t *testing.T) {
	e, _ := newDevLoopGrantEnv(t)
	e.h.opts.ApprovalBindingMode = ApprovalBindingObserve
	run := e.startDevLoopRun("obs")
	id := e.requestDevLoopGrant(run.execID, "gate-o")
	c := approvalBindingAbsentTotal.WithLabelValues(bindingRouteDevLoop)
	before := testutil.ToFloat64(c)
	if res := e.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(e.bindingOf(id))); res.code != http.StatusOK {
		t.Fatalf("bound = %d %s", res.code, res.raw)
	}
	if got := testutil.ToFloat64(c); got != before {
		t.Fatalf("a bound approve was counted: %v -> %v", before, got)
	}
	if res := e.approveDevLoop(rootAdmin, run.workflowID, ""); res.code != http.StatusOK {
		t.Fatalf("unbound = %d %s", res.code, res.raw)
	}
	if got := testutil.ToFloat64(c); got != before+1 {
		t.Fatalf("unbound approve counted %v, want %v", got, before+1)
	}
	found := false
	for _, en := range e.audit.List(1000) {
		if en.Operation == "approval.binding_absent" && en.Parameters["workflow_id"] == run.workflowID {
			found = true
		}
	}
	if !found {
		t.Fatal("no approval.binding_absent audit keyed by workflow_id")
	}
}
