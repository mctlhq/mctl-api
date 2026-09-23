package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.temporal.io/api/serviceerror"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

const hiASCIIHash = "sha256:377a93a48528eb1342dfd881f52cb48513c47762ddc4a451f71f8c5f7d34ae08"

// workflowAccepts stands in for the workflow draining its queue and
// accepting the answer: RUNNING, resume_count up.
func workflowAccepts(f *fakeDevLoopClient, wf string, _ map[string]any) {
	st := *f.humanInputStates[wf]
	st.State = temporalclient.HumanInputRunning
	st.ResumeCount++
	f.humanInputStates[wf] = &st
}

// workflowRefuses: still WAITING, rejected_count up.
func workflowRefuses(f *fakeDevLoopClient, wf string, _ map[string]any) {
	st := *f.humanInputStates[wf]
	st.RejectedCount++
	f.humanInputStates[wf] = &st
}

func newHumanInputResponseHandlers(t *testing.T) (*Handlers, *fakeDevLoopClient, *humaninput.MemoryLedger, *audit.Logger) {
	t.Helper()
	h, tc := newHumanInputHandlers(t)
	ledger := humaninput.NewMemoryLedger()
	log := audit.NewLogger()
	h.opts.HumanInputLedger = ledger
	h.opts.AuditLog = log
	prev := humanInputConfirmInterval
	humanInputConfirmInterval = 0
	t.Cleanup(func() { humanInputConfirmInterval = prev })
	return h, tc, ledger, log
}

type respondResult struct {
	code int
	res  humanInputResponseResult
	raw  string
}

func respond(t *testing.T, h *Handlers, u *auth.User, id, body string) respondResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/human-input/"+id+"/response", bytes.NewBufferString(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	if u != nil {
		req = asUser(req, u)
	}
	w := httptest.NewRecorder()
	h.RespondHumanInput(w, req)
	var res humanInputResponseResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	return respondResult{w.Code, res, w.Body.String()}
}

func answer(value string) string {
	return `{"request_hash":"` + hiASCIIHash + `","value":` + value + `,"surface":"portal"}`
}

func auditOps(log *audit.Logger) []string {
	var ops []string
	entries := log.List(100)
	for i := range entries {
		ops = append(ops, entries[i].Operation+"/"+entries[i].Status)
	}
	return ops
}

func TestRespondHumanInput_AuthorizedResponseIsDeliveredOnceAndAccepted(t *testing.T) {
	h, tc, ledger, log := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts

	got := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if got.code != http.StatusOK || got.res.Status != "accepted" || got.res.Respondent != "github:alice" {
		t.Fatalf("respond = %d %s", got.code, got.raw)
	}
	if len(tc.humanInputSignals) != 1 || tc.humanInputSignalTo[0] != hiWF+"@run-1" {
		t.Fatalf("signals = %v to %v, want exactly one to the sealed run", tc.humanInputSignals, tc.humanInputSignalTo)
	}
	doc := tc.humanInputSignals[0]
	want := map[string]any{
		"api_version": humaninput.APIVersion, "kind": humaninput.ResponseKind,
		"request_id": hiASCII, "request_hash": hiASCIIHash, "surface": "portal",
		"value": "library A", "received_at": "2026-09-23T12:00:00Z",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("signal[%s] = %v, want %v", k, doc[k], v)
		}
	}
	if resp, _ := doc["respondent"].(map[string]any); resp["actor_type"] != "github" || resp["actor_id"] != "alice" {
		t.Errorf("respondent = %v", doc["respondent"])
	}
	row, _ := ledger.Get(context.Background(), hiASCII)
	if row == nil || row.State != humaninput.DeliveryAccepted || row.Value != nil {
		t.Fatalf("ledger row = %+v, want accepted with the value cleared", row)
	}
	ops := strings.Join(auditOps(log), ",")
	if !strings.Contains(ops, "human_input.signal_sent/submitted") || !strings.Contains(ops, "human_input.response_accepted/succeeded") {
		t.Fatalf("audit = %s", ops)
	}
	entries := log.List(100)
	for i := range entries {
		e := &entries[i]
		if strings.Contains(e.Message, "library A") || strings.Contains(strings.Join(mapValues(e.Parameters), " "), "library A") {
			t.Fatalf("audit entry leaks the answer: %+v", e)
		}
	}
	// Clarification is not approval.
	if tc.lastApprovedWorkflow != "" || tc.lastApprovePayload != nil {
		t.Fatalf("a human-input response signalled approve on %q", tc.lastApprovedWorkflow)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestRespondHumanInput_OnlyEligibleHumansMayAnswer(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts
	for name, tt := range map[string]struct {
		u    *auth.User
		code int
	}{
		"anonymous":                   {nil, http.StatusUnauthorized},
		"not in actor_refs":           {bob, http.StatusNotFound},
		"admin but not in actor_refs": {admin, http.StatusForbidden},
		"service principal":           {auth.NewServiceUser(), http.StatusForbidden},
		"case-folded login":           {auth.NewGitHubUser("Alice", nil), http.StatusNotFound},
		// Same ID as alice but not proven by GitHub (e.g. a Dex username).
		"unverified alice":       {&auth.User{ID: "alice"}, http.StatusNotFound},
		"unverified admin alice": {&auth.User{ID: "alice", Groups: []string{"admins"}}, http.StatusForbidden},
	} {
		if got := respond(t, h, tt.u, hiASCII, answer(`"library A"`)); got.code != tt.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, tt.code)
		}
	}
	if len(tc.humanInputSignals) != 0 {
		t.Fatalf("an ineligible caller reached the workflow: %v", tc.humanInputSignals)
	}
}

func TestRespondHumanInput_RespondentCannotBeSupplied(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts
	for _, body := range []string{
		`{"request_hash":"` + hiASCIIHash + `","value":"library A","respondent":{"actor_type":"github","actor_id":"alice"}}`,
		`{"request_hash":"` + hiASCIIHash + `","value":"library A","respondent":"github:alice"}`,
		`{"request_hash":"` + hiASCIIHash + `","value":"library A","actor":"github:alice"}`,
	} {
		// bob tries to answer as alice; alice tries to name herself. Both
		// are refused: identity only ever comes from authentication.
		for _, u := range []*auth.User{bob, alice} {
			if got := respond(t, h, u, hiASCII, body); got.code != http.StatusBadRequest {
				t.Errorf("%s with %s: %d %s, want 400", u.ID, body, got.code, got.raw)
			}
		}
	}
	if len(tc.humanInputSignals) != 0 {
		t.Fatalf("signals = %v", tc.humanInputSignals)
	}
}

func TestRespondHumanInput_StaleOrClosedRequestsAreRejected(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T, tc *fakeDevLoopClient)
		body  string
		code  int
		state string
	}{
		"hash mismatch": {nil, `{"request_hash":"sha256:00","value":"library A"}`, http.StatusConflict, "superseded"},
		"expired": {func(t *testing.T, _ *fakeDevLoopClient) { withHumanInputClock(t, "2026-09-24T02:00:00Z") },
			answer(`"library A"`), http.StatusConflict, HumanInputExpired},
		"workflow moved on": {func(_ *testing.T, tc *fakeDevLoopClient) {
			tc.humanInputStates[hiWF] = &temporalclient.HumanInputState{State: temporalclient.HumanInputWaitingForInput, RequestID: "hir-ffffffffffffffff"}
		}, answer(`"library A"`), http.StatusConflict, HumanInputNotPending},
		"timed out": {func(_ *testing.T, tc *fakeDevLoopClient) {
			tc.humanInputStates[hiWF] = &temporalclient.HumanInputState{State: temporalclient.HumanInputTimedOut, RequestID: hiASCII}
		}, answer(`"library A"`), http.StatusConflict, HumanInputTimedOut},
		"workflow gone": {func(_ *testing.T, tc *fakeDevLoopClient) {
			tc.humanInputErr = serviceerror.NewNotFound("workflow not found")
		}, answer(`"library A"`), http.StatusConflict, HumanInputNotPending},
		// A closed execution still answers the query with its last state;
		// the signal is what fails.
		"execution closed while parked": {func(_ *testing.T, tc *fakeDevLoopClient) {
			tc.signalErr = serviceerror.NewNotFound("workflow execution already completed")
		}, answer(`"library A"`), http.StatusConflict, HumanInputNotPending},
		"not a declared option": {nil, answer(`"library C"`), http.StatusUnprocessableEntity, "invalid_value"},
		"wrong value type":      {nil, answer(`["library A"]`), http.StatusUnprocessableEntity, "invalid_value"},
		"null value":            {nil, answer(`null`), http.StatusUnprocessableEntity, "invalid_value"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			h, tc, ledger, log := newHumanInputResponseHandlers(t)
			tc.onSignal = workflowAccepts
			if tt.setup != nil {
				tt.setup(t, tc)
			}
			got := respond(t, h, alice, hiASCII, tt.body)
			if got.code != tt.code || got.res.Status != "rejected" || got.res.State != tt.state {
				t.Fatalf("respond = %d %s, want %d/%s", got.code, got.raw, tt.code, tt.state)
			}
			if len(tc.humanInputSignals) != 0 {
				t.Fatalf("signalled: %v", tc.humanInputSignals)
			}
			row, _ := ledger.Get(context.Background(), hiASCII)
			// Only a submission that got as far as the signal is recorded,
			// and then only as rejected with the answer cleared.
			if row != nil && (name != "execution closed while parked" || row.State != humaninput.DeliveryRejected || row.Value != nil) {
				t.Fatalf("ledger after rejection: %+v", row)
			}
			if ops := strings.Join(auditOps(log), ","); !strings.Contains(ops, "human_input.response_rejected/failed") {
				t.Fatalf("audit = %s", ops)
			}
		})
	}
}

func TestRespondHumanInput_FreeTextIsTyped(t *testing.T) {
	h, _, _, _ := newHumanInputResponseHandlers(t)
	// unicode_free_text asks alice for free text; blank is not an answer.
	body := `{"request_hash":"sha256:accc85063686b5e0","value":"   "}`
	raw := humanInputFixture(t, "unicode_free_text")
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	body = strings.Replace(body, "sha256:accc85063686b5e0", doc["request_hash"].(string), 1)
	if got := respond(t, h, alice, hiUnicode, body); got.code != http.StatusUnprocessableEntity {
		t.Fatalf("blank free text = %d %s", got.code, got.raw)
	}
}

func TestRespondHumanInput_DuplicateIsIdempotentAndConflictIsDeterministic(t *testing.T) {
	h, tc, _, log := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts

	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusOK {
		t.Fatalf("first = %d %s", got.code, got.raw)
	}
	again := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if again.code != http.StatusOK || again.res.Status != "accepted" {
		t.Fatalf("duplicate = %d %s, want the same accepted result", again.code, again.raw)
	}
	other := respond(t, h, alice, hiASCII, answer(`"library B"`))
	if other.code != http.StatusConflict || other.res.State != "answered" {
		t.Fatalf("conflicting = %d %s, want 409 answered", other.code, other.raw)
	}
	// An attempt to override a recorded answer is audited like any refusal.
	var overrides int
	entries := log.List(100)
	for i := range entries {
		if entries[i].Operation == "human_input.response_rejected" && strings.HasPrefix(entries[i].Message, "answered") {
			overrides++
		}
	}
	if overrides != 1 {
		t.Fatalf("override attempts audited %d times, want 1: %v", overrides, auditOps(log))
	}
	if len(tc.humanInputSignals) != 1 {
		t.Fatalf("%d signals, want exactly 1", len(tc.humanInputSignals))
	}
}

func TestRespondHumanInput_OutageKeepsTheAnswerRecoverable(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.signalErr = errors.New("temporal unavailable")

	first := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if first.code != http.StatusServiceUnavailable || first.res.Status != "pending_delivery" {
		t.Fatalf("during outage = %d %s", first.code, first.raw)
	}
	row, _ := ledger.Get(context.Background(), hiASCII)
	if row == nil || row.State != humaninput.DeliveryPending || string(row.Value) != `"library A"` {
		t.Fatalf("ledger = %+v, want the answer retained as pending_delivery", row)
	}

	// Recovery: ANY later submission pushes the recorded answer through
	// first. Here a different answer arrives; it must lose to the recorded
	// one, which is what reaches the workflow.
	withHumanInputClock(t, "2026-09-23T13:00:00Z")
	tc.signalErr = nil
	tc.onSignal = workflowAccepts
	second := respond(t, h, alice, hiASCII, answer(`"library B"`))
	if second.code != http.StatusConflict || second.res.State != "answered" {
		t.Fatalf("after recovery = %d %s", second.code, second.raw)
	}
	if len(tc.humanInputSignals) != 1 || tc.humanInputSignals[0]["value"] != "library A" ||
		tc.humanInputSignals[0]["received_at"] != "2026-09-23T12:00:00Z" {
		t.Fatalf("signals = %v, want the recorded answer with its original received_at", tc.humanInputSignals)
	}
	row, _ = ledger.Get(context.Background(), hiASCII)
	if row.State != humaninput.DeliveryAccepted {
		t.Fatalf("ledger = %+v", row)
	}
}

func TestRespondHumanInput_IdenticalRetryAfterOutageIsDelivered(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	tc.signalErr = errors.New("temporal unavailable")
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusServiceUnavailable {
		t.Fatalf("outage = %d", got.code)
	}
	tc.signalErr = nil
	tc.onSignal = workflowAccepts
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusOK || got.res.Status != "accepted" {
		t.Fatalf("retry = %d %s", got.code, got.raw)
	}
}

func TestRespondHumanInput_QueryOutageRecordsNothing(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.humanInputErr = errors.New("no worker")
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusServiceUnavailable {
		t.Fatalf("respond = %d %s", got.code, got.raw)
	}
	if row, _ := ledger.Get(context.Background(), hiASCII); row != nil || len(tc.humanInputSignals) != 0 {
		t.Fatalf("recorded %+v / signalled %v while pending could not be proven", row, tc.humanInputSignals)
	}
}

func TestRespondHumanInput_UnconfirmedDeliveryBlocksACompetingAnswer(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	// The workflow has not drained its queue yet.
	first := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if first.code != http.StatusAccepted || first.res.Status != "pending_delivery" {
		t.Fatalf("unconfirmed = %d %s", first.code, first.raw)
	}
	second := respond(t, h, alice, hiASCII, answer(`"library B"`))
	if second.code != http.StatusConflict || second.res.State != "answered" {
		t.Fatalf("competing = %d %s", second.code, second.raw)
	}
	for _, s := range tc.humanInputSignals {
		if s["value"] != "library A" {
			t.Fatalf("the competing answer reached the workflow: %v", tc.humanInputSignals)
		}
	}
}

func TestRespondHumanInput_WorkflowRefusalFreesTheRequest(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowRefuses
	got := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if got.code != http.StatusConflict || got.res.Status != "rejected" {
		t.Fatalf("refused = %d %s", got.code, got.raw)
	}
	if row, _ := ledger.Get(context.Background(), hiASCII); row.State != humaninput.DeliveryRejected || row.Value != nil {
		t.Fatalf("ledger = %+v", row)
	}
	tc.onSignal = workflowAccepts
	if got := respond(t, h, alice, hiASCII, answer(`"library B"`)); got.code != http.StatusOK {
		t.Fatalf("a corrected answer after a refusal = %d %s", got.code, got.raw)
	}
	if len(tc.humanInputSignals) != 2 {
		t.Fatalf("%d signals", len(tc.humanInputSignals))
	}
}

func TestRespondHumanInput_NotConfigured(t *testing.T) {
	h, _, _, _ := newHumanInputResponseHandlers(t)
	h.opts.HumanInputLedger = nil
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusServiceUnavailable {
		t.Fatalf("no ledger = %d", got.code)
	}
}

func TestRespondHumanInput_MalformedBodies(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts
	for _, body := range []string{
		`{"value":"library A"}`,
		`{"request_hash":"` + hiASCIIHash + `"}`,
		`{"request_hash":"` + hiASCIIHash + `","value":"library A","surface":"Tele gram"}`,
		answer(`"library A"`) + `{}`,
		`not json`,
	} {
		if got := respond(t, h, alice, hiASCII, body); got.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, got.code, got.raw)
		}
	}
	if got := respond(t, h, alice, "hir-XYZ", answer(`"library A"`)); got.code != http.StatusBadRequest {
		t.Errorf("bad id = %d", got.code)
	}
}

// A workflow in a later round already has non-zero counters. Neither may be
// read as this response's outcome: only a change after it was recorded is.
func TestRespondHumanInput_EarlierRoundsDoNotCountAsAnOutcome(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.humanInputStates[hiWF] = &temporalclient.HumanInputState{
		State: temporalclient.HumanInputWaitingForInput, RequestID: hiASCII, ResumeCount: 2, RejectedCount: 3,
	}
	got := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if got.code != http.StatusAccepted || got.res.Status != "pending_delivery" {
		t.Fatalf("respond = %d %s, want 202 pending_delivery (nothing changed yet)", got.code, got.raw)
	}
	if row, _ := ledger.Get(context.Background(), hiASCII); row.BaselineResumeCount != 2 || row.State != humaninput.DeliveryPending {
		t.Fatalf("ledger = %+v", row)
	}
	tc.onSignal = workflowAccepts
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusOK {
		t.Fatalf("after the workflow drains = %d %s", got.code, got.raw)
	}
}

// The audit row of an invalid value names the outcome only: the validation
// message lists the question's options.
func TestRespondHumanInput_InvalidValueAuditCarriesNoQuestionContent(t *testing.T) {
	h, _, _, log := newHumanInputResponseHandlers(t)
	got := respond(t, h, alice, hiASCII, answer(`"library C"`))
	if got.code != http.StatusUnprocessableEntity || !strings.Contains(got.res.Detail, "library A") {
		t.Fatalf("respond = %d %s (the caller still gets the reason)", got.code, got.raw)
	}
	entries := log.List(100)
	for i := range entries {
		if strings.Contains(entries[i].Message, "library") {
			t.Fatalf("audit leaks question options: %+v", entries[i])
		}
	}
}

// A client returning no state is an unanswered query: nothing is recorded.
func TestRespondHumanInput_NilStateIsNotPending(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.humanInputStates[hiWF] = nil
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusServiceUnavailable {
		t.Fatalf("respond = %d %s", got.code, got.raw)
	}
	if row, _ := ledger.Get(context.Background(), hiASCII); row != nil {
		t.Fatalf("recorded %+v", row)
	}
}

// An answer that could not be delivered before its request expired is not
// kept: the next submission (for any request) drops it.
func TestRespondHumanInput_UndeliverableAnswerIsNotRetained(t *testing.T) {
	h, tc, ledger, _ := newHumanInputResponseHandlers(t)
	tc.signalErr = errors.New("temporal unavailable")
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusServiceUnavailable {
		t.Fatalf("outage = %d", got.code)
	}
	withHumanInputClock(t, "2026-09-24T02:00:00Z")
	if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusConflict || got.res.State != HumanInputExpired {
		t.Fatalf("after expiry = %d %s", got.code, got.raw)
	}
	if row, _ := ledger.Get(context.Background(), hiASCII); row == nil || row.Value != nil {
		t.Fatalf("ledger after expiry = %+v, want the answer dropped", row)
	}
}

// The confirmation wait is bounded as a whole, not per query.
func TestRespondHumanInput_ConfirmationIsBounded(t *testing.T) {
	h, tc, _, _ := newHumanInputResponseHandlers(t)
	prevB, prevI := humanInputConfirmBudget, humanInputConfirmInterval
	humanInputConfirmBudget, humanInputConfirmInterval = 50*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { humanInputConfirmBudget, humanInputConfirmInterval = prevB, prevI })
	tc.onSignal = func(f *fakeDevLoopClient, _ string, _ map[string]any) { f.humanInputBlocks = true }
	start := time.Now()
	got := respond(t, h, alice, hiASCII, answer(`"library A"`))
	if got.code != http.StatusAccepted || got.res.Status != "pending_delivery" || time.Since(start) > time.Second {
		t.Fatalf("respond = %d %s after %s", got.code, got.raw, time.Since(start))
	}
}
