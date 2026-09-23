package api

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// Execution requests (mctl-api#368), through the real router and surface
// gate: SURFACE REQUESTS EXECUTION; SURFACE DOES NOT DECLARE EXECUTION
// IDENTITY.

func (e *sidEnv) relay(method, path string, body any, headers ...string) (int, map[string]any) {
	e.t.Helper()
	return e.do("telegram", method, path, body, append([]string{SurfaceActorHeader, "4242"}, headers...)...)
}

// relayedItem links alice to telegram 4242 and opens an item through the
// relay.
func (e *sidEnv) relayedItem() string {
	e.t.Helper()
	e.link("alice", "telegram", "4242")
	code, body := e.relayCreate("telegram", "4242", nil)
	if code != http.StatusCreated {
		e.t.Fatalf("relayed create = %d %v", code, body)
	}
	return body["work_item"].(map[string]any)["id"].(string)
}

func (e *sidEnv) claimRequest() (map[string]any, string) {
	e.t.Helper()
	code, body := e.do("service", "POST", "/api/v1/execution-requests/claim", map[string]any{"lease_seconds": 60})
	if code != http.StatusOK {
		e.t.Fatalf("claim = %d %v", code, body)
	}
	return body["execution_request"].(map[string]any), body["claim_token"].(string)
}

func TestExecutionRequests_SurfaceRequestsButNeverDeclaresIdentity(t *testing.T) {
	e := newSIDEnv(t)
	id := e.relayedItem()
	base := "/api/v1/work-items/" + id + "/execution-requests"
	start := map[string]any{"kind": "start", "expected_state_version": 1}

	// No relayed body may carry execution identity, whatever else it says.
	for _, field := range []string{"engine", "engine_ref", "execution_id"} {
		body := map[string]any{"kind": "start", "expected_state_version": 1, field: "temporal"}
		if code, res := e.relay("POST", base, body); code != http.StatusBadRequest || res["code"] != xrCodeIdentityNotAccepted {
			t.Errorf("relayed %s = %d %v", field, code, res)
		}
	}
	for _, body := range []map[string]any{
		{"kind": "start", "expected_state_version": 1, "requested_by": "github:bob"},
		{"kind": "start", "expected_state_version": 1, "actor": "github:bob"},
	} {
		if code, res := e.relay("POST", base, body); code != http.StatusBadRequest || res["code"] != "actor_not_accepted" {
			t.Errorf("relayed actor field %v = %d %v", body, code, res)
		}
	}
	if code, res := e.relay("POST", base, map[string]any{"kind": "start", "expected_state_version": 1, "surface": "portal"}); code != http.StatusBadRequest {
		t.Errorf("relayed request claiming portal = %d %v", code, res)
	}
	// The surface has no path that declares engine identity: /resume is
	// off its allowlist, as is attaching an execution.
	for _, path := range []string{"/api/v1/work-items/" + id + "/resume", "/api/v1/work-items/" + id + "/executions"} {
		if code, res := e.relay("POST", path, map[string]any{"expected_state_version": 1, "engine": "temporal", "engine_ref": "run-x"}); code != http.StatusForbidden || res["code"] != sidCodeRouteNotAllowed {
			t.Errorf("relayed POST %s = %d %v", path, code, res)
		}
	}
	// Nor the platform's side.
	for _, path := range []string{"/api/v1/execution-requests/claim", "/api/v1/execution-requests/xr_x/fulfil", "/api/v1/execution-requests/xr_x/reject"} {
		if code, res := e.relay("POST", path, map[string]any{}); code != http.StatusForbidden || res["code"] != sidCodeRouteNotAllowed {
			t.Errorf("relayed POST %s = %d %v", path, code, res)
		}
	}

	// A relayed request is the human's, carried by the surface.
	code, res := e.relay("POST", base, start, "Idempotency-Key", "tg-1")
	if code != http.StatusCreated {
		t.Fatalf("relayed request = %d %v", code, res)
	}
	x := res["execution_request"].(map[string]any)
	rid := x["id"].(string)
	if x["requested_by"] != "github:alice" || x["acting_principal"] != "surface:telegram" || x["surface"] != "telegram" ||
		x["state"] != "pending" || x["execution_id"] != nil || res["schema_version"] != "workitem/v1" {
		t.Fatalf("request = %v", x)
	}
	if code, res := e.relay("POST", base, start, "Idempotency-Key", "tg-1"); code != http.StatusOK || res["execution_request"].(map[string]any)["id"] != rid {
		t.Fatalf("replay = %d %v", code, res)
	}
	if code, res := e.relay("POST", base, map[string]any{"kind": "start", "expected_state_version": 1, "surface": "telegram"},
		"Idempotency-Key", "tg-1"); code != http.StatusConflict || res["code"] != wiCodeKeyReused {
		t.Fatalf("same key, other body = %d %v", code, res)
	}
	code, res = e.relay("POST", base, start)
	if details, _ := res["details"].(map[string]any); code != http.StatusConflict || res["code"] != xrCodeOpen || details["execution_request_id"] != rid {
		t.Fatalf("second open request = %d %v", code, res)
	}
	// The service principal never requests on a user's behalf.
	if code, res := e.do("service", "POST", base, start); code != http.StatusForbidden || res["code"] != xrCodeRequesterForbidden {
		t.Fatalf("service create = %d %v", code, res)
	}

	// Relayed reads.
	if code, res := e.relay("GET", base, nil); code != http.StatusOK || len(res["execution_requests"].([]any)) != 1 {
		t.Fatalf("relayed list = %d %v", code, res)
	}
	if code, res := e.relay("GET", base+"/"+rid, nil); code != http.StatusOK || res["execution_request"].(map[string]any)["id"] != rid {
		t.Fatalf("relayed get = %d %v", code, res)
	}
	if code, res := e.relay("GET", base+"/xr_missing", nil); code != http.StatusNotFound || res["code"] != xrCodeNotFound {
		t.Fatalf("relayed get of a missing request = %d %v", code, res)
	}
	// bob cannot see alice's item, nor its requests.
	if code, _ := e.do("bob", "GET", base, nil); code != http.StatusNotFound {
		t.Fatalf("bob list = %d", code)
	}

	// Only the platform claims, fulfils and rejects.
	for _, who := range []string{"alice", "root"} {
		if code, res := e.do(who, "POST", "/api/v1/execution-requests/claim", map[string]any{}); code != http.StatusForbidden || res["code"] != xrCodeClaimantForbidden {
			t.Errorf("%s claim = %d %v", who, code, res)
		}
	}
	if code, res := e.do("service", "POST", "/api/v1/execution-requests/claim", map[string]any{"lease_seconds": 1}); code != http.StatusBadRequest {
		t.Fatalf("claim with a 1s lease = %d %v", code, res)
	}
	claimed, token := e.claimRequest()
	if claimed["id"] != rid || claimed["state"] != "claimed" || claimed["claimed_by"] != "service:mctl-agent" || claimed["claim_token"] != nil {
		t.Fatalf("claimed = %v", claimed)
	}
	// The claim token is the claimant's alone: reads never carry it.
	if _, res := e.relay("GET", base+"/"+rid, nil); res["claim_token"] != nil || res["execution_request"].(map[string]any)["claim_token"] != nil {
		t.Fatalf("read carries the claim token: %v", res)
	}
	if code, _ := e.do("service", "POST", "/api/v1/execution-requests/claim", map[string]any{}); code != http.StatusNoContent {
		t.Fatalf("claim with nothing claimable = %d", code)
	}

	fulfilPath := "/api/v1/execution-requests/" + rid + "/fulfil"
	run := map[string]any{"claim_token": token, "engine": "temporal", "engine_ref": "dev-loop-1"}
	if code, res := e.do("service", "POST", fulfilPath, map[string]any{"claim_token": "xc_forged", "engine": "temporal", "engine_ref": "dev-loop-1"}); code != http.StatusConflict || res["code"] != xrCodeNotClaimed {
		t.Fatalf("fulfil with a forged token = %d %v", code, res)
	}
	code, res = e.do("service", "POST", fulfilPath, run)
	if code != http.StatusCreated {
		t.Fatalf("fulfil = %d %v", code, res)
	}
	exec := res["execution"].(map[string]any)
	if exec["phase"] != "Running" || exec["engine_ref"] != "dev-loop-1" || res["execution_request"].(map[string]any)["execution_id"] != exec["id"] {
		t.Fatalf("fulfilled = %v", res)
	}
	if code, res := e.do("service", "POST", fulfilPath, run); code != http.StatusOK || res["execution"].(map[string]any)["id"] != exec["id"] {
		t.Fatalf("re-fulfil = %d %v", code, res)
	}
	if code, res := e.do("service", "POST", fulfilPath, map[string]any{"claim_token": token, "engine": "temporal", "engine_ref": "dev-loop-2"}); code != http.StatusConflict || res["code"] != xrCodeClosed {
		t.Fatalf("fulfil with another run = %d %v", code, res)
	}
	if code, res := e.relay("GET", "/api/v1/work-items/"+id, nil); code != http.StatusOK || res["latest_execution"].(map[string]any)["id"] != exec["id"] {
		t.Fatalf("item after fulfil = %d %v", code, res)
	}

	// History and audit: the human requested, the surface carried, the
	// platform claimed and fulfilled.
	rows, err := e.pool.Query(context.Background(), `SELECT kind, actor_principal, acting_principal FROM work_item_events
		WHERE work_item_id=$1 AND kind LIKE 'execution%' ORDER BY seq`, id)
	if err != nil {
		t.Fatal(err)
	}
	var got [][3]string
	for rows.Next() {
		var ev [3]string
		if err := rows.Scan(&ev[0], &ev[1], &ev[2]); err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	rows.Close()
	want := [][3]string{
		{"execution_requested", "github:alice", "surface:telegram"},
		{"execution_request_claimed", "service:mctl-agent", ""},
		{"execution_attached", "service:mctl-agent", ""},
		{"execution_request_fulfilled", "service:mctl-agent", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("events = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %v, want %v", i, got[i], want[i])
		}
	}
	audited := map[string]bool{}
	for _, entry := range e.audit.List(200) {
		switch entry.Operation {
		case "work_item.execution_request":
			if entry.UserID != "alice" || entry.Parameters["actor"] != "github:alice" ||
				entry.Parameters["acting_principal"] != "surface:telegram" || entry.Parameters["execution_request_id"] != rid {
				t.Errorf("create audit = %s %v", entry.UserID, entry.Parameters)
			}
		case "work_item.execution_request_claimed", "work_item.execution_request_fulfilled":
			if entry.Parameters["actor"] != "service:mctl-agent" || entry.Parameters["requested_by"] != "github:alice" {
				t.Errorf("%s audit = %v", entry.Operation, entry.Parameters)
			}
		case "work_item.execution_request_fulfil_refused":
			if entry.Parameters["reason"] != xrCodeNotClaimed && entry.Parameters["reason"] != xrCodeClosed {
				t.Errorf("refusal audit = %v", entry.Parameters)
			}
		}
		audited[entry.Operation] = true
	}
	for _, op := range []string{"work_item.execution_request", "work_item.execution_request_claimed",
		"work_item.execution_request_fulfilled", "work_item.execution_request_fulfil_refused", "work_item.execution_request_refused"} {
		if !audited[op] {
			t.Errorf("no %s audit row", op)
		}
	}
}

func TestExecutionRequests_ResumeRejectAndLapsedClaim(t *testing.T) {
	e := newSIDEnv(t)
	id := e.relayedItem()
	base := "/api/v1/work-items/" + id + "/execution-requests"

	// A first run the platform attached directly, now finished.
	if code, res := e.do("service", "POST", "/api/v1/work-items/"+id+"/executions",
		map[string]any{"engine": "temporal", "engine_ref": "run-1", "phase": "Succeeded"}); code != http.StatusCreated {
		t.Fatalf("attach = %d %v", code, res)
	}
	_, view := e.relay("GET", "/api/v1/work-items/"+id, nil)
	first := view["latest_execution"].(map[string]any)["id"].(string)
	code, res := e.relay("POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": "try again"})
	if code != http.StatusCreated {
		t.Fatalf("intent = %d %v", code, res)
	}
	intentID := res["intent"].(map[string]any)["id"]

	// Refusals a surface can hit: stale version, foreign execution.
	if code, res := e.relay("POST", base, map[string]any{"kind": "resume", "expected_state_version": 9}); code != http.StatusConflict || res["code"] != wiCodeVersionConflict {
		t.Fatalf("stale version = %d %v", code, res)
	}
	if code, res := e.relay("POST", base, map[string]any{"kind": "resume", "expected_state_version": 1, "resumed_from_execution_id": "we_foreign"}); code != http.StatusNotFound || res["code"] != wiCodeExecutionNotFound {
		t.Fatalf("foreign resumed_from = %d %v", code, res)
	}
	if code, res := e.relay("POST", base, map[string]any{"kind": "resume", "expected_state_version": 1, "intent_id": 999999999}); code != http.StatusNotFound || res["code"] != xrCodeIntentNotFound {
		t.Fatalf("foreign intent = %d %v", code, res)
	}

	resume := map[string]any{"kind": "resume", "expected_state_version": 1, "resumed_from_execution_id": first, "intent_id": intentID}
	if code, res := e.relay("POST", base, resume, "Idempotency-Key", "tg-r1"); code != http.StatusCreated {
		t.Fatalf("resume request = %d %v", code, res)
	}
	x, stale := e.claimRequest()
	rid := x["id"].(string)
	// The lease lapses; the platform re-claims; the lapsed holder is fenced.
	if _, err := e.pool.Exec(context.Background(), `UPDATE work_item_execution_requests SET claim_expires_at=$2 WHERE id=$1`,
		rid, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	again, fresh := e.claimRequest()
	if again["id"] != rid || fresh == stale {
		t.Fatalf("re-claim = %v %s", again, fresh)
	}
	rejectPath := "/api/v1/execution-requests/" + rid + "/reject"
	if code, res := e.do("service", "POST", rejectPath, map[string]any{"claim_token": stale, "reason": "late"}); code != http.StatusConflict || res["code"] != xrCodeNotClaimed {
		t.Fatalf("lapsed holder reject = %d %v", code, res)
	}
	if code, res := e.do("service", "POST", "/api/v1/execution-requests/"+rid+"/fulfil",
		map[string]any{"claim_token": stale, "engine": "temporal", "engine_ref": "run-2"}); code != http.StatusConflict || res["code"] != xrCodeNotClaimed {
		t.Fatalf("lapsed holder fulfil = %d %v", code, res)
	}
	if code, res := e.do("service", "POST", rejectPath, map[string]any{"claim_token": fresh, "reason": "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"}); code != http.StatusBadRequest || res["code"] != wiCodeSecret {
		t.Fatalf("secret reason = %d %v", code, res)
	}
	code, res = e.do("service", "POST", rejectPath, map[string]any{"claim_token": fresh, "reason": "no capacity"})
	if code != http.StatusOK || res["execution_request"].(map[string]any)["state"] != "rejected" {
		t.Fatalf("reject = %d %v", code, res)
	}
	if _, res := e.relay("GET", base+"/"+rid, nil); res["execution_request"].(map[string]any)["reason"] != "no capacity" {
		t.Fatalf("rejected request = %v", res)
	}

	// Rejected is closed: a fresh request resumes the item.
	delete(resume, "intent_id")
	if code, res := e.relay("POST", base, resume, "Idempotency-Key", "tg-r2"); code != http.StatusCreated {
		t.Fatalf("second resume request = %d %v", code, res)
	}
	y, token := e.claimRequest()
	code, res = e.do("service", "POST", "/api/v1/execution-requests/"+y["id"].(string)+"/fulfil",
		map[string]any{"claim_token": token, "engine": "temporal", "engine_ref": "run-2"})
	if code != http.StatusCreated {
		t.Fatalf("fulfil resume = %d %v", code, res)
	}
	exec := res["execution"].(map[string]any)
	if exec["attempt"] != float64(2) || exec["resumed_from_execution_id"] != first || res["state_version"] != float64(2) {
		t.Fatalf("resumed = %v", res)
	}
	var execs int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM work_item_executions WHERE work_item_id=$1`, id).Scan(&execs); err != nil || execs != 2 {
		t.Fatalf("executions = %d %v", execs, err)
	}

	// A terminal item takes no request.
	if code, res := e.do("service", "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "archive", "expected_state_version": 2}); code != http.StatusOK {
		t.Fatalf("archive = %d %v", code, res)
	}
	if code, res := e.relay("POST", base, map[string]any{"kind": "resume", "expected_state_version": 3}); code != http.StatusConflict || res["code"] != wiCodeInvalidTransit {
		t.Fatalf("request on an archived item = %d %v", code, res)
	}
}
