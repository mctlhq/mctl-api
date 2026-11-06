package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/api/serviceerror"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Owner actions against a real work-items store and grants (mctl-api#900).
// Test ids in the comments are the proposal's tasks.md ids. The env runs
// with the production settings: the legacy approver payload disabled and the
// binding mode observe, unless a test says otherwise.

type ownerActionEnv struct {
	*workItemsEnv
	fake *fakeDevLoopClient
}

func newOwnerActionEnv(t *testing.T) *ownerActionEnv {
	t.Helper()
	e, fake := newDevLoopGrantEnv(t)
	e.h.opts.LegacyApproverDisabled = true
	e.h.opts.ApprovalBindingMode = ApprovalBindingObserve
	e.router.Post("/api/v1/agents/dev-loop/{workflow_id}/owner-actions", e.h.RequestDevLoopOwnerAction)
	e.router.Get("/api/v1/agents/dev-loop/{workflow_id}/owner-actions", e.h.ListDevLoopOwnerActions)
	e.router.Get("/api/v1/agents/dev-loop/{workflow_id}/owner-actions/{id}", e.h.GetDevLoopOwnerAction)
	t.Cleanup(func() {
		pool, err := pgxpool.New(context.Background(), e.connStr)
		if err == nil {
			_, _ = pool.Exec(context.Background(), `DELETE FROM dev_loop_owner_actions WHERE workflow_id LIKE $1`, e.tenant+"%")
			pool.Close()
		}
	})
	fake.describeExec = &temporalclient.DevLoopExecution{Status: devLoopStatusRunning, RunID: "run-1"}
	return &ownerActionEnv{workItemsEnv: e, fake: fake}
}

func (o *ownerActionEnv) act(u *auth.User, workflowID string, body map[string]any) wiResponse {
	o.t.Helper()
	return o.do(u, "POST", "/api/v1/agents/dev-loop/"+workflowID+"/owner-actions", body)
}

func (o *ownerActionEnv) rows(workflowID string) []workitems.OwnerAction {
	o.t.Helper()
	list, err := o.h.opts.WorkItems.ListOwnerActions(context.Background(), workflowID, 0)
	if err != nil {
		o.t.Fatal(err)
	}
	return list
}

func (o *ownerActionEnv) row(id string) *workitems.OwnerAction {
	o.t.Helper()
	r, err := o.h.opts.WorkItems.GetOwnerAction(context.Background(), id)
	if err != nil {
		o.t.Fatal(err)
	}
	return r
}

// setGrantState puts a grant in a state no API path reaches directly in a
// test (in_flight, executed).
func (o *ownerActionEnv) setGrantState(id, state string) {
	o.t.Helper()
	pool, err := pgxpool.New(context.Background(), o.connStr)
	if err != nil {
		o.t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET state=$2 WHERE id=$1`, id, state); err != nil {
		o.t.Fatal(err)
	}
}

func (o *ownerActionEnv) decideGrant(id, decision string) {
	o.t.Helper()
	if res := o.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": decision}); res.code != http.StatusOK {
		o.t.Fatalf("decide %s = %d %s", decision, res.code, res.raw)
	}
}

func (o *ownerActionEnv) consumeGrant(id string) {
	o.t.Helper()
	o.decideGrant(id, workitems.DecisionApprove)
	hash := o.approvalState(id)["intent_hash"]
	if res := o.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": hash}); res.code != http.StatusOK {
		o.t.Fatalf("consume = %d %s", res.code, res.raw)
	}
}

func (o *ownerActionEnv) requireNoSignal(why string) {
	o.t.Helper()
	if o.fake.abandonCalls != 0 || o.fake.lastApprovePayload != nil || o.fake.startCalls != 0 || o.fake.restartCalls != 0 {
		o.t.Fatalf("%s: abandon=%d approve=%v start=%d restart=%d", why, o.fake.abandonCalls, o.fake.lastApprovePayload,
			o.fake.startCalls, o.fake.restartCalls)
	}
}

func (o *ownerActionEnv) requireGrantUntouched(id, why string) {
	o.t.Helper()
	a := o.approvalState(id)
	if a["state"] != workitems.ApprovalPending || a["decided_by"] != nil || a["decided_at"] != nil {
		o.t.Fatalf("%s changed grant %s: %v", why, id, a)
	}
	if n := o.auditOps("action_approval.decision", id); n != 0 {
		o.t.Fatalf("%s audited %d grant decisions", why, n)
	}
}

func key(n string) map[string]any { return map[string]any{"idempotency_key": n} }

func with(m map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

// T1: every caller that is not a direct human admin is refused before any
// lookup, on a run with a grant and on one without: no row, no Temporal
// call, the grant untouched.
func TestOwnerActionDB_T1_OnlyDirectHumanAdmins(t *testing.T) {
	o := newOwnerActionEnv(t)
	withGrant := o.startDevLoopRun("t1-grant")
	grant := o.requestDevLoopGrant(withGrant.execID, "gate-t1")
	preGrant := o.startDevLoopRun("t1-pre")
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"service principal": auth.NewServiceUser(),
		"surface":           surface,
		"relayed":           auth.NewRelayedUser("alice", []string{"admins"}, surface),
		"non-admin":         auth.NewGitHubUser("bob", []string{o.tenant}),
	} {
		for _, run := range []devLoopRun{withGrant, preGrant} {
			for _, action := range []string{"request_changes", "defer", "request_cancel"} {
				res := o.act(u, run.workflowID, with(key("k-"+name+action), "action", action))
				if res.code != http.StatusForbidden {
					t.Errorf("%s %s on %s = %d %s, want 403", name, action, run.workflowID, res.code, res.raw)
				}
				if u.IsAdmin() && code(res) != ownerActionCodeForbidden {
					t.Errorf("%s %s: code %q, want %s", name, action, code(res), ownerActionCodeForbidden)
				}
			}
		}
	}
	if n := len(o.rows(withGrant.workflowID)) + len(o.rows(preGrant.workflowID)); n != 0 {
		t.Fatalf("refused callers left %d rows", n)
	}
	if o.fake.describeExecCalls != 0 {
		t.Fatalf("refused callers reached Temporal: %d describes", o.fake.describeExecCalls)
	}
	o.requireNoSignal("refused callers")
	o.requireGrantUntouched(grant, "refused callers")
}

// T3 + T10: request_changes and defer on a pending grant record a row and
// decide nothing; a retry or a second request of the same kind on the grant
// returns that row; the same key with other content is a conflict.
func TestOwnerActionDB_T3_RequestChangesAndDeferDecideNothing(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("t3")
	grant := o.requestDevLoopGrant(run.execID, "gate-t3")
	binding := o.bindingOf(grant)

	ids := map[string]string{}
	for action, outcome := range map[string]string{"request_changes": ownerOutcomeChangesRequested, "defer": ownerOutcomeDeferred} {
		body := with(key("k-"+action), "action", action, "binding", binding, "reason_code", "scope.too_wide")
		res := o.act(rootAdmin, run.workflowID, body)
		if res.code != http.StatusOK {
			t.Fatalf("%s = %d %s", action, res.code, res.raw)
		}
		b := res.body
		if b["state"] != workitems.OwnerActionRecorded || b["outcome"] != outcome || b["approval_ref"] != grant ||
			b["execution_id"] != run.execID || b["replayed"] != false || b["run_id"] != nil {
			t.Fatalf("%s response = %v", action, b)
		}
		ids[action] = b["id"].(string)

		again := o.act(rootAdmin, run.workflowID, body)
		if again.code != http.StatusOK || again.body["id"] != ids[action] || again.body["replayed"] != true {
			t.Fatalf("%s retry = %d %s, want the same row replayed", action, again.code, again.raw)
		}
		other := o.act(auth.NewGitHubUser("carol", []string{"admins"}), run.workflowID, with(key("k2-"+action), "action", action))
		if other.code != http.StatusOK || other.body["id"] != ids[action] || other.body["replayed"] != true {
			t.Fatalf("second %s on the grant = %d %s, want the existing row replayed", action, other.code, other.raw)
		}
		conflict := o.act(rootAdmin, run.workflowID, with(body, "reason_code", "other.reason"))
		if conflict.code != http.StatusConflict || code(conflict) != ownerActionCodeIdempotencyConflict {
			t.Fatalf("%s key reuse = %d %s, want 409 %s", action, conflict.code, conflict.raw, ownerActionCodeIdempotencyConflict)
		}
	}
	if ids["request_changes"] == ids["defer"] {
		t.Fatal("request_changes and defer share a row")
	}
	if n := len(o.rows(run.workflowID)); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	if o.fake.describeExecCalls != 0 {
		t.Fatalf("request_changes/defer described the run %d times", o.fake.describeExecCalls)
	}
	o.requireNoSignal("request_changes/defer")
	o.requireGrantUntouched(grant, "request_changes/defer")
}

// T4 + T15(c): request_changes and defer need a pending grant: a decided or
// closed one answers its state's code, a missing one approval_grant_missing
// in observe and enforce alike. Nothing is recorded.
func TestOwnerActionDB_T4_GrantStateRefusals(t *testing.T) {
	o := newOwnerActionEnv(t)
	for _, tc := range []struct {
		name, code string
		close      func(id string)
	}{
		{"approved", aarCodeAlreadyDecided, func(id string) { o.decideGrant(id, workitems.DecisionApprove) }},
		{"denied", aarCodeDenied, func(id string) { o.decideGrant(id, workitems.DecisionDeny) }},
		{"consumed", aarCodeConsumed, o.consumeGrant},
		{"expired", aarCodeExpired, o.expire},
	} {
		run := o.startDevLoopRun("t4-" + tc.name)
		id := o.requestDevLoopGrant(run.execID, "gate-t4-"+tc.name)
		tc.close(id)
		for _, action := range []string{"request_changes", "defer"} {
			res := o.act(rootAdmin, run.workflowID, with(key("k-"+tc.name+action), "action", action))
			if res.code != http.StatusConflict || code(res) != tc.code {
				t.Errorf("%s on a %s grant = %d %s, want 409 %s", action, tc.name, res.code, res.raw, tc.code)
			}
		}
		if n := len(o.rows(run.workflowID)); n != 0 {
			t.Errorf("%s grant: %d rows recorded", tc.name, n)
		}
	}
	run := o.startDevLoopRun("t4-none")
	for _, mode := range []ApprovalBindingMode{ApprovalBindingObserve, ApprovalBindingEnforce} {
		o.h.opts.ApprovalBindingMode = mode
		for _, action := range []string{"request_changes", "defer"} {
			res := o.act(rootAdmin, run.workflowID, with(key("k-none-"+string(mode)+action), "action", action))
			if res.code != http.StatusConflict || code(res) != devLoopCodeGrantMissing {
				t.Errorf("%s with no grant (%s) = %d %s, want 409 %s", action, mode, res.code, res.raw, devLoopCodeGrantMissing)
			}
		}
	}
	if n := len(o.rows(run.workflowID)); n != 0 {
		t.Fatalf("no grant: %d rows recorded", n)
	}
	o.requireNoSignal("grant-state refusals")
}

// T5: a binding for a superseded grant, or with a digest that differs,
// answers approval_context_changed with the current grant; enforce mode
// without a binding answers approval_binding_missing for every action while
// a grant exists; observe mode audits the absence on the owner-action route.
// No refusal records or signals anything.
func TestOwnerActionDB_T5_StaleCardBinding(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("t5")
	older := o.requestDevLoopGrant(run.execID, "gate-t5-old")
	stale := o.bindingOf(older)
	newer := o.requestDevLoopGrant(run.execID, "gate-t5-new")
	current := o.bindingOf(newer)
	if stale["approval_ref"] == current["approval_ref"] {
		t.Fatal("fixture: the two grants share an id")
	}

	for _, action := range []string{"request_changes", "defer", "request_cancel"} {
		for name, b := range map[string]map[string]any{
			"older grant":    stale,
			"context digest": with(current, "context_digest", "sha256:other"),
			"content digest": with(current, "content_digest", "sha256:other"),
		} {
			res := o.act(rootAdmin, run.workflowID, with(key("k-"+action+name), "action", action, "binding", b))
			if res.code != http.StatusConflict || code(res) != aarCodeContextChanged {
				t.Errorf("%s, %s = %d %s, want 409 %s", action, name, res.code, res.raw, aarCodeContextChanged)
				continue
			}
			if d, _ := res.body["details"].(map[string]any); d["current_approval_ref"] != newer {
				t.Errorf("%s, %s: details = %v, want current_approval_ref %s", action, name, res.body["details"], newer)
			}
		}
	}

	o.h.opts.ApprovalBindingMode = ApprovalBindingEnforce
	for _, action := range []string{"request_changes", "defer", "request_cancel"} {
		res := o.act(rootAdmin, run.workflowID, with(key("k-enforce-"+action), "action", action))
		if res.code != http.StatusUnprocessableEntity || code(res) != aarCodeBindingMissing {
			t.Errorf("enforce, unbound %s = %d %s, want 422 %s", action, res.code, res.raw, aarCodeBindingMissing)
		}
	}
	if n := len(o.rows(run.workflowID)); n != 0 {
		t.Fatalf("binding refusals recorded %d rows", n)
	}
	o.requireNoSignal("binding refusals")

	// A bound request on the current grant passes in enforce mode.
	if res := o.act(rootAdmin, run.workflowID, with(key("k-bound"), "action", "defer", "binding", current)); res.code != http.StatusOK {
		t.Fatalf("enforce, bound defer = %d %s", res.code, res.raw)
	}

	o.h.opts.ApprovalBindingMode = ApprovalBindingObserve
	if res := o.act(rootAdmin, run.workflowID, with(key("k-observe"), "action", "request_changes")); res.code != http.StatusOK {
		t.Fatalf("observe, unbound request_changes = %d %s", res.code, res.raw)
	}
	absent := 0
	for _, entry := range o.audit.List(1000) {
		if entry.Operation == "approval.binding_absent" && entry.Parameters["route"] == bindingRouteDevLoopOwnerAction &&
			entry.Parameters["workflow_id"] == run.workflowID {
			absent++
		}
	}
	if absent == 0 {
		t.Fatal("observe mode did not audit approval.binding_absent on the owner-action route")
	}
}

// T6 + T10: a cancel on a running run with a pending grant signals abandon
// once, pinned to the described run, with ids and codes only; it reports
// cancellation_pending and leaves the grant pending. A retry, or another
// principal's cancel of the same run under another key, returns that row and
// signals nothing more.
func TestOwnerActionDB_T6_CancelWithPendingGrant(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("t6")
	grant := o.requestDevLoopGrant(run.execID, "gate-t6")
	body := with(key("k-t6"), "action", "request_cancel", "binding", o.bindingOf(grant), "reason_code", "owner.stop")

	res := o.act(rootAdmin, run.workflowID, body)
	if res.code != http.StatusOK {
		t.Fatalf("cancel = %d %s", res.code, res.raw)
	}
	b := res.body
	id, _ := b["id"].(string)
	if b["outcome"] != ownerOutcomeCancellationPending || b["state"] != workitems.OwnerActionSignalled ||
		b["run_id"] != "run-1" || b["approval_ref"] != grant || b["replayed"] != false {
		t.Fatalf("cancel response = %v", b)
	}
	if o.fake.abandonCalls != 1 || o.fake.lastAbandonRunID != "run-1" {
		t.Fatalf("signals = %d to %q, want 1 to run-1", o.fake.abandonCalls, o.fake.lastAbandonRunID)
	}
	p := o.fake.lastAbandonPayload
	if len(p) != 2 || p["reason"] != "owner_action:"+id+":owner.stop" || p["abandoned_by"] != rootAdmin.ID {
		t.Fatalf("signal payload = %v", p)
	}
	o.requireGrantUntouched(grant, "a cancel")

	if again := o.act(rootAdmin, run.workflowID, body); again.code != http.StatusOK || again.body["id"] != id || again.body["replayed"] != true {
		t.Fatalf("retry = %d %s", again.code, again.raw)
	}
	other := o.act(auth.NewGitHubUser("carol", []string{"admins"}), run.workflowID, with(key("k-t6-carol"), "action", "request_cancel"))
	if other.code != http.StatusOK || other.body["id"] != id || other.body["replayed"] != true {
		t.Fatalf("another cancel of the run = %d %s, want the existing row", other.code, other.raw)
	}
	if o.fake.abandonCalls != 1 {
		t.Fatalf("replays signalled again: %d signals", o.fake.abandonCalls)
	}
	if n := len(o.rows(run.workflowID)); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// T7: a delivered signal on a run whose grant is past pending may come too
// late: cancellation_effects_unknown, never pending.
func TestOwnerActionDB_T7_CancelAfterApprovalIsEffectsUnknown(t *testing.T) {
	o := newOwnerActionEnv(t)
	for _, tc := range []struct {
		state string
		set   func(id string)
	}{
		{workitems.ApprovalApproved, func(id string) { o.decideGrant(id, workitems.DecisionApprove) }},
		{workitems.ApprovalInFlight, func(id string) {
			o.decideGrant(id, workitems.DecisionApprove)
			o.setGrantState(id, workitems.ApprovalInFlight)
		}},
		{workitems.ApprovalConsumed, o.consumeGrant},
		{workitems.ApprovalExecuted, func(id string) {
			o.consumeGrant(id)
			o.setGrantState(id, workitems.ApprovalExecuted)
		}},
	} {
		run := o.startDevLoopRun("t7-" + tc.state)
		id := o.requestDevLoopGrant(run.execID, "gate-t7-"+tc.state)
		tc.set(id)
		if st := o.approvalState(id)["state"]; st != tc.state {
			t.Fatalf("fixture: grant is %v, want %s", st, tc.state)
		}
		res := o.act(rootAdmin, run.workflowID, with(key("k-t7-"+tc.state), "action", "request_cancel"))
		if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeEffectsUnknown || res.body["state"] != workitems.OwnerActionSignalled {
			t.Errorf("cancel with a %s grant = %d %s, want signalled %s", tc.state, res.code, res.raw, ownerOutcomeEffectsUnknown)
		}
		if st := o.approvalState(id)["state"]; st != tc.state {
			t.Errorf("the cancel moved the %s grant to %v", tc.state, st)
		}
	}
	if o.fake.abandonCalls != 4 {
		t.Fatalf("signals = %d, want 4", o.fake.abandonCalls)
	}
}

// T8: a run that already ended is read, never signalled: abandoned before
// implement is cancelled, after implement effects-unknown, ended otherwise
// already_finished, and an unreadable ending effects-unknown.
func TestOwnerActionDB_T8_CancelOnFinishedRuns(t *testing.T) {
	o := newOwnerActionEnv(t)
	for _, tc := range []struct {
		name, status, ended string
		implemented         bool
		endedErr            error
		want                string
	}{
		{"abandoned-early", devLoopStatusCompleted, temporalclient.AbandonedEndedPrefix + "owner", false, nil, ownerOutcomeCancelled},
		{"abandoned-late", devLoopStatusCompleted, temporalclient.AbandonedEndedPrefix + "owner", true, nil, ownerOutcomeEffectsUnknown},
		{"completed", devLoopStatusCompleted, "merged", true, nil, ownerOutcomeAlreadyDone},
		{"unreadable", devLoopStatusCompleted, "", false, errors.New("history unavailable"), ownerOutcomeEffectsUnknown},
		{"failed", "Failed", "", false, nil, ownerOutcomeAlreadyDone},
	} {
		run := o.startDevLoopRun("t8-" + tc.name)
		o.fake.describeExec = &temporalclient.DevLoopExecution{Status: tc.status, RunID: "run-" + tc.name}
		o.fake.ended, o.fake.implemented, o.fake.endedErr = tc.ended, tc.implemented, tc.endedErr
		res := o.act(rootAdmin, run.workflowID, with(key("k-t8-"+tc.name), "action", "request_cancel"))
		if res.code != http.StatusOK || res.body["outcome"] != tc.want || res.body["state"] != workitems.OwnerActionFinished ||
			res.body["run_id"] != "run-"+tc.name {
			t.Errorf("%s: %d %s, want finished %s", tc.name, res.code, res.raw, tc.want)
		}
	}
	o.requireNoSignal("finished runs")
}

// T9: the described run ends and a successor takes the workflow id before
// the signal lands: 409, the successor is not signalled, the row stays
// requested, and a replay answers for the stored run without signalling the
// successor.
func TestOwnerActionDB_T9_RunChangedBetweenDescribeAndSignal(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("t9")
	o.fake.onAbandon = func(f *fakeDevLoopClient) {
		f.abandonErr = serviceerror.NewNotFound("run-1 completed")
		f.describeExec = &temporalclient.DevLoopExecution{Status: devLoopStatusRunning, RunID: "run-2"}
		f.onAbandon = nil
	}
	body := with(key("k-t9"), "action", "request_cancel")
	res := o.act(rootAdmin, run.workflowID, body)
	if res.code != http.StatusConflict || code(res) != ownerActionCodeRunChanged {
		t.Fatalf("run changed = %d %s, want 409 %s", res.code, res.raw, ownerActionCodeRunChanged)
	}
	if o.fake.abandonCalls != 1 || o.fake.lastAbandonRunID != "run-1" {
		t.Fatalf("signals = %d, last to %q; want only the pinned attempt at run-1", o.fake.abandonCalls, o.fake.lastAbandonRunID)
	}
	rows := o.rows(run.workflowID)
	if len(rows) != 1 || rows[0].State != workitems.OwnerActionRequested || rows[0].Outcome != "" || rows[0].RunID != "run-1" {
		t.Fatalf("row after run change = %+v", rows)
	}

	o.fake.abandonErr = nil
	o.fake.ended = "merged"
	replay := o.act(rootAdmin, run.workflowID, body)
	if replay.code != http.StatusOK || replay.body["replayed"] != true || replay.body["run_id"] != "run-1" ||
		replay.body["state"] != workitems.OwnerActionFinished || replay.body["outcome"] != ownerOutcomeAlreadyDone {
		t.Fatalf("replay = %d %s, want run-1 finished %s", replay.code, replay.raw, ownerOutcomeAlreadyDone)
	}
	if o.fake.abandonCalls != 1 {
		t.Fatalf("the replay signalled the successor: %d signals, last to %q", o.fake.abandonCalls, o.fake.lastAbandonRunID)
	}
	if got := o.fake.endedReadRuns; len(got) != 1 || got[0] != "run-1" {
		t.Fatalf("ending read for %v, want run-1 only", got)
	}
}

// T11: a signal that fails in transport is 502, or 503 when Temporal is
// unavailable; the row stays requested and a replay with the same key
// retries exactly one signal to the stored run.
func TestOwnerActionDB_T11_TransportFailureThenReplay(t *testing.T) {
	o := newOwnerActionEnv(t)
	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"transport":   {errors.New("connection reset"), http.StatusBadGateway},
		"unavailable": {fmt.Errorf("signal: %w", temporalclient.ErrUnavailable), http.StatusServiceUnavailable},
	} {
		run := o.startDevLoopRun("t11-" + name)
		o.requestDevLoopGrant(run.execID, "gate-t11-"+name)
		o.fake.abandonCalls, o.fake.abandonErr = 0, tc.err
		body := with(key("k-t11-"+name), "action", "request_cancel")
		res := o.act(rootAdmin, run.workflowID, body)
		if res.code != tc.status {
			t.Fatalf("%s: %d %s, want %d", name, res.code, res.raw, tc.status)
		}
		rows := o.rows(run.workflowID)
		if len(rows) != 1 || rows[0].State != workitems.OwnerActionRequested || rows[0].Outcome != "" {
			t.Fatalf("%s: row after the failure = %+v", name, rows)
		}
		o.fake.abandonErr = nil
		replay := o.act(rootAdmin, run.workflowID, body)
		if replay.code != http.StatusOK || replay.body["id"] != rows[0].ID || replay.body["replayed"] != true ||
			replay.body["state"] != workitems.OwnerActionSignalled || replay.body["outcome"] != ownerOutcomeCancellationPending {
			t.Fatalf("%s: replay = %d %s", name, replay.code, replay.raw)
		}
		if o.fake.abandonCalls != 2 || o.fake.lastAbandonRunID != "run-1" {
			t.Fatalf("%s: signals = %d, last to %q; want the failure plus one retry to run-1", name, o.fake.abandonCalls, o.fake.lastAbandonRunID)
		}
	}
}

// T15 and the review's P2: a cancel before any grant exists is accepted
// without a binding in both modes and bound to the described run. It reports
// cancellation_pending only where the run is shown to be before implement:
// an open we_ was read and the legacy approver payload is disabled. With the
// legacy payload allowed, or no open execution to read a grant from, a
// missing grant proves nothing and the outcome is effects-unknown.
func TestOwnerActionDB_T15_PreGrantCancel(t *testing.T) {
	o := newOwnerActionEnv(t)
	for _, mode := range []ApprovalBindingMode{ApprovalBindingObserve, ApprovalBindingEnforce} {
		o.h.opts.ApprovalBindingMode = mode
		run := o.startDevLoopRun("t15-" + string(mode))
		o.fake.abandonCalls = 0
		res := o.act(rootAdmin, run.workflowID, with(key("k-t15-"+string(mode)), "action", "request_cancel", "expected_run_id", "run-1"))
		if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeCancellationPending || res.body["approval_ref"] != nil ||
			res.body["execution_id"] != run.execID {
			t.Fatalf("%s: pre-grant cancel = %d %s, want 200 %s", mode, res.code, res.raw, ownerOutcomeCancellationPending)
		}
		if o.fake.abandonCalls != 1 || o.fake.lastAbandonRunID != "run-1" {
			t.Fatalf("%s: signals = %d to %q", mode, o.fake.abandonCalls, o.fake.lastAbandonRunID)
		}
		if rows := o.rows(run.workflowID); len(rows) != 1 || rows[0].ApprovalRef != "" || rows[0].RunID != "run-1" {
			t.Fatalf("%s: rows = %+v", mode, rows)
		}
	}

	// expected_run_id naming another run: nothing recorded or signalled.
	o.h.opts.ApprovalBindingMode = ApprovalBindingEnforce
	run := o.startDevLoopRun("t15-moved")
	o.fake.abandonCalls = 0
	res := o.act(rootAdmin, run.workflowID, with(key("k-t15-moved"), "action", "request_cancel", "expected_run_id", "run-0"))
	if res.code != http.StatusConflict || code(res) != ownerActionCodeRunChanged {
		t.Fatalf("expected_run_id mismatch = %d %s, want 409 %s", res.code, res.raw, ownerActionCodeRunChanged)
	}
	if d, _ := res.body["details"].(map[string]any); d["current_run_id"] != "run-1" {
		t.Fatalf("details = %v", res.body["details"])
	}
	if n := len(o.rows(run.workflowID)); n != 0 || o.fake.abandonCalls != 0 {
		t.Fatalf("a mismatched card recorded %d rows and %d signals", n, o.fake.abandonCalls)
	}
	// A binding with no grant to bind to names a card that is not current.
	res = o.act(rootAdmin, run.workflowID, with(key("k-t15-bound"), "action", "request_cancel",
		"binding", map[string]any{"approval_ref": "aar_ghost", "context_digest": "sha256:a", "content_digest": "sha256:b"}))
	if res.code != http.StatusConflict || code(res) != devLoopCodeGrantMissing {
		t.Fatalf("bound pre-grant cancel = %d %s, want 409 %s", res.code, res.raw, devLoopCodeGrantMissing)
	}

	// The legacy payload may have approved a run with no grant at all.
	o.h.opts.LegacyApproverDisabled = false
	legacy := o.startDevLoopRun("t15-legacy")
	res = o.act(rootAdmin, legacy.workflowID, with(key("k-t15-legacy"), "action", "request_cancel"))
	if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeEffectsUnknown {
		t.Fatalf("no grant, legacy approver enabled = %d %s, want %s", res.code, res.raw, ownerOutcomeEffectsUnknown)
	}
	o.h.opts.LegacyApproverDisabled = true

	// No open execution (never attached, or closed): no grant could be read.
	unattached := o.tenant + "-dev-loop-unattached"
	res = o.act(rootAdmin, unattached, with(key("k-t15-unattached"), "action", "request_cancel"))
	if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeEffectsUnknown || res.body["execution_id"] != nil {
		t.Fatalf("no open execution = %d %s, want %s", res.code, res.raw, ownerOutcomeEffectsUnknown)
	}
}

// T12: reading a signalled cancel re-observes the run without signalling:
// a run that has since ended abandoned before implement is recorded
// cancelled; a run that could not be read keeps its stored outcome and says
// so; a running run whose grant was approved after the signal is no longer
// reported pending.
func TestOwnerActionDB_T12_GetReobserves(t *testing.T) {
	o := newOwnerActionEnv(t)
	get := func(wf, id string) wiResponse {
		t.Helper()
		return o.do(rootAdmin, "GET", "/api/v1/agents/dev-loop/"+wf+"/owner-actions/"+id, nil)
	}
	run := o.startDevLoopRun("t12")
	o.requestDevLoopGrant(run.execID, "gate-t12")
	res := o.act(rootAdmin, run.workflowID, with(key("k-t12"), "action", "request_cancel"))
	id, _ := res.body["id"].(string)
	if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeCancellationPending {
		t.Fatalf("cancel = %d %s", res.code, res.raw)
	}
	signals := o.fake.abandonCalls

	// Still running, observed: unchanged.
	if g := get(run.workflowID, id); g.code != http.StatusOK || g.body["outcome"] != ownerOutcomeCancellationPending || g.body["observed"] != true {
		t.Fatalf("running = %d %s", g.code, g.raw)
	}
	// Not observable: the stored outcome, flagged as not observed.
	o.fake.describeExecErr = errors.New("frontend down")
	if g := get(run.workflowID, id); g.code != http.StatusOK || g.body["observed"] != false || g.body["state"] != workitems.OwnerActionSignalled {
		t.Fatalf("unobservable = %d %s, want observed=false", g.code, g.raw)
	}
	o.fake.describeExecErr = nil
	// Ended abandoned before implement: recorded as cancelled.
	o.fake.describeExec = &temporalclient.DevLoopExecution{Status: devLoopStatusCompleted, RunID: "run-1"}
	o.fake.ended, o.fake.implemented = temporalclient.AbandonedEndedPrefix+"owner", false
	g := get(run.workflowID, id)
	if g.code != http.StatusOK || g.body["state"] != workitems.OwnerActionFinished || g.body["outcome"] != ownerOutcomeCancelled || g.body["observed"] != true {
		t.Fatalf("ended = %d %s, want finished %s", g.code, g.raw, ownerOutcomeCancelled)
	}
	if r := o.row(id); r.State != workitems.OwnerActionFinished || r.Outcome != ownerOutcomeCancelled {
		t.Fatalf("not persisted: %+v", r)
	}
	if o.fake.abandonCalls != signals || o.fake.startCalls != 0 || o.fake.restartCalls != 0 {
		t.Fatalf("GET signalled or started: abandon %d->%d, start %d, restart %d", signals, o.fake.abandonCalls, o.fake.startCalls, o.fake.restartCalls)
	}
	// Another workflow's path does not reach the row.
	if g := get(o.tenant+"-other", id); g.code != http.StatusNotFound || code(g) != ownerActionCodeNotFound {
		t.Fatalf("other workflow = %d %s, want 404", g.code, g.raw)
	}

	// A grant approved after the cancel was signalled: implement may run.
	run2 := o.startDevLoopRun("t12-approved-later")
	grant2 := o.requestDevLoopGrant(run2.execID, "gate-t12-2")
	o.fake.describeExec = &temporalclient.DevLoopExecution{Status: devLoopStatusRunning, RunID: "run-7"}
	res = o.act(rootAdmin, run2.workflowID, with(key("k-t12-2"), "action", "request_cancel"))
	id2, _ := res.body["id"].(string)
	if res.code != http.StatusOK || res.body["outcome"] != ownerOutcomeCancellationPending {
		t.Fatalf("cancel 2 = %d %s", res.code, res.raw)
	}
	o.decideGrant(grant2, workitems.DecisionApprove)
	g = get(run2.workflowID, id2)
	if g.code != http.StatusOK || g.body["state"] != workitems.OwnerActionSignalled || g.body["outcome"] != ownerOutcomeEffectsUnknown {
		t.Fatalf("approved after the signal = %d %s, want signalled %s", g.code, g.raw, ownerOutcomeEffectsUnknown)
	}
	if r := o.row(id2); r.Outcome != ownerOutcomeEffectsUnknown {
		t.Fatalf("not persisted: %+v", r)
	}
}

// The listing reads the store only, newest first, and bounds its size.
func TestOwnerActionDB_ListIsBounded(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("list")
	grant := o.requestDevLoopGrant(run.execID, "gate-list")
	for _, action := range []string{"request_changes", "defer"} {
		if res := o.act(rootAdmin, run.workflowID, with(key("k-list-"+action), "action", action)); res.code != http.StatusOK {
			t.Fatalf("%s = %d %s", action, res.code, res.raw)
		}
	}
	path := "/api/v1/agents/dev-loop/" + run.workflowID + "/owner-actions"
	res := o.do(rootAdmin, "GET", path, nil)
	if list, _ := res.body["owner_actions"].([]any); res.code != http.StatusOK || len(list) != 2 ||
		list[0].(map[string]any)["action"] != "defer" || list[0].(map[string]any)["approval_ref"] != grant {
		t.Fatalf("list = %d %s, want 2 rows newest first", res.code, res.raw)
	}
	if res := o.do(rootAdmin, "GET", path+"?limit=1", nil); len(res.body["owner_actions"].([]any)) != 1 {
		t.Fatalf("limit=1 = %s", res.raw)
	}
	for _, bad := range []string{"0", "-1", "501", "x"} {
		if res := o.do(rootAdmin, "GET", path+"?limit="+bad, nil); res.code != http.StatusBadRequest {
			t.Errorf("limit=%s = %d, want 400", bad, res.code)
		}
	}
	if o.fake.describeExecCalls != 0 {
		t.Fatal("the listing reached Temporal")
	}
}

// P3 (review of mctl-api#930): the idempotency key is the principal's across
// workflows, so reusing it on another workflow is a conflict, not a store
// failure.
func TestOwnerActionDB_KeyReuseAcrossWorkflowsIsAConflict(t *testing.T) {
	o := newOwnerActionEnv(t)
	a := o.startDevLoopRun("reuse-a")
	b := o.startDevLoopRun("reuse-b")
	if res := o.act(rootAdmin, a.workflowID, with(key("k-shared"), "action", "request_cancel")); res.code != http.StatusOK {
		t.Fatalf("first = %d %s", res.code, res.raw)
	}
	res := o.act(rootAdmin, b.workflowID, with(key("k-shared"), "action", "request_cancel"))
	if res.code != http.StatusConflict || code(res) != ownerActionCodeIdempotencyConflict {
		t.Fatalf("reuse on another workflow = %d %s, want 409 %s", res.code, res.raw, ownerActionCodeIdempotencyConflict)
	}
	if n := len(o.rows(b.workflowID)); n != 0 {
		t.Fatalf("workflow b rows = %d", n)
	}
}

// T13: responses and audit entries carry ids, codes and states only.
func TestOwnerActionDB_T13_ResponsesAndAuditHoldNoFreeText(t *testing.T) {
	o := newOwnerActionEnv(t)
	run := o.startDevLoopRun("t13")
	grant := o.requestDevLoopGrant(run.execID, "gate-t13")
	responseKeys := map[string]bool{
		"id": true, "workflow_id": true, "action": true, "state": true, "outcome": true, "replayed": true,
		"created_at": true, "updated_at": true, "run_id": true, "execution_id": true, "approval_ref": true, "reason_code": true,
	}
	auditKeys := map[string]bool{
		"owner_action_id": true, "action": true, "workflow_id": true, "run_id": true, "execution_id": true,
		"approval_ref": true, "reason_code": true, "outcome": true, "replayed": true, "reason": true,
	}
	for _, body := range []map[string]any{
		with(key("k-t13-d"), "action", "defer", "binding", o.bindingOf(grant), "reason_code", "later"),
		with(key("k-t13-c"), "action", "request_cancel", "reason_code", "owner.stop"),
		with(key("k-t13-x"), "action", "defer", "binding", with(o.bindingOf(grant), "context_digest", "sha256:x")),
	} {
		res := o.act(rootAdmin, run.workflowID, body)
		if res.code != http.StatusOK {
			continue
		}
		for k := range res.body {
			if !responseKeys[k] {
				t.Errorf("response key %q is not an id, code or state", k)
			}
		}
	}
	seen := 0
	for _, entry := range o.audit.List(1000) {
		if entry.Operation != "dev-loop-owner-action" || entry.WorkflowName != run.workflowID {
			continue
		}
		seen++
		for k, v := range entry.Parameters {
			if !auditKeys[k] {
				t.Errorf("audit parameter %q=%q is not an id, code or state", k, v)
			}
			if strings.ContainsAny(v, " \n") {
				t.Errorf("audit parameter %q=%q carries text", k, v)
			}
		}
	}
	if seen < 3 {
		t.Fatalf("audited %d owner actions, want at least 3", seen)
	}
}
