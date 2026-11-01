package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// mctl-api#871 T6/T7: a redacted pinned intent is refused with a typed 409
// that names the intent by id only, at create and at fulfil; the claim says
// whether the pin is readable; executions carry their request's provenance.
func TestExecutionRequests_IntentUnavailable(t *testing.T) {
	e := newSIDEnv(t)
	id := e.relayedItem()
	base := "/api/v1/work-items/" + id + "/execution-requests"
	const secret = "deploy the thing at midnight"
	newIntent := func() any {
		code, res := e.relay("POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": secret})
		if code != http.StatusCreated {
			t.Fatalf("intent = %d %v", code, res)
		}
		return res["intent"].(map[string]any)["id"]
	}
	redact := func(intentID any) {
		if _, err := e.pool.Exec(context.Background(), `UPDATE work_item_intents SET text=NULL WHERE id=$1`, intentID); err != nil {
			t.Fatal(err)
		}
	}
	noText := func(what string, res map[string]any) {
		b, _ := json.Marshal(res)
		if strings.Contains(string(b), secret) {
			t.Fatalf("%s carries intent text: %s", what, b)
		}
	}

	// At create: 409 intent_unavailable, details {intent_id}, no text.
	gone := newIntent()
	redact(gone)
	code, res := e.relay("POST", base, map[string]any{"kind": "start", "expected_state_version": 1, "intent_id": gone})
	if code != http.StatusConflict || res["code"] != xrCodeIntentUnavailable {
		t.Fatalf("create with a redacted intent = %d %v", code, res)
	}
	if d, _ := res["details"].(map[string]any); d["intent_id"] != gone {
		t.Fatalf("details = %v, want intent_id %v", res["details"], gone)
	}
	noText("create refusal", res)
	var open int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM work_item_execution_requests WHERE work_item_id=$1`, id).Scan(&open); err != nil || open != 0 {
		t.Fatalf("requests after the refusal = %d %v", open, err)
	}

	// Readable at create, redacted before fulfil.
	pin := newIntent()
	if code, res := e.relay("POST", base, map[string]any{"kind": "start", "expected_state_version": 1, "intent_id": pin}); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, res)
	}
	code, claimed := e.do("service", "POST", "/api/v1/execution-requests/claim", map[string]any{"lease_seconds": 60})
	if code != http.StatusOK || claimed["intent_available"] != true {
		t.Fatalf("claim of a readable pin = %d %v", code, claimed)
	}
	if _, inRequest := claimed["execution_request"].(map[string]any)["intent_available"]; inRequest {
		t.Fatalf("intent_available leaked into the request: %v", claimed)
	}
	rid := claimed["execution_request"].(map[string]any)["id"].(string)
	token := claimed["claim_token"].(string)
	redact(pin)
	code, res = e.do("service", "POST", "/api/v1/execution-requests/"+rid+"/fulfil",
		map[string]any{"claim_token": token, "engine": "temporal", "engine_ref": "run-1"})
	if code != http.StatusConflict || res["code"] != xrCodeIntentUnavailable {
		t.Fatalf("fulfil after redaction = %d %v", code, res)
	}
	noText("fulfil refusal", res)
	if _, x := e.relay("GET", base+"/"+rid, nil); x["execution_request"].(map[string]any)["state"] != "claimed" {
		t.Fatalf("request after a refused fulfil = %v", x)
	}
	refused := false
	for _, entry := range e.audit.List(200) {
		if entry.Operation == "work_item.execution_request_fulfil_refused" && entry.Parameters["reason"] == xrCodeIntentUnavailable {
			refused = true
			b, _ := json.Marshal(entry.Parameters)
			if strings.Contains(string(b), secret) {
				t.Fatalf("audit carries intent text: %s", b)
			}
		}
	}
	if !refused {
		t.Fatal("no fulfil_refused audit row with reason intent_unavailable")
	}
	if code, res := e.do("service", "POST", "/api/v1/execution-requests/"+rid+"/reject",
		map[string]any{"claim_token": token, "reason": "intent_unavailable"}); code != http.StatusOK {
		t.Fatalf("reject = %d %v", code, res)
	}

	// A claim of a pin that is already redacted says false.
	late := newIntent()
	if code, res := e.relay("POST", base, map[string]any{"kind": "start", "expected_state_version": 1, "intent_id": late}); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, res)
	}
	redact(late)
	if code, claimed := e.do("service", "POST", "/api/v1/execution-requests/claim", map[string]any{"lease_seconds": 60}); code != http.StatusOK || claimed["intent_available"] != false {
		t.Fatalf("claim of a redacted pin = %d %v", code, claimed)
	}
}

// T13 through the API: the executions list and the work item's
// latest_execution carry the fulfilled request's provenance.
func TestExecutionRequests_ExecutionCarriesRequestProvenance(t *testing.T) {
	e := newSIDEnv(t)
	id := e.relayedItem()
	if code, res := e.relay("POST", "/api/v1/work-items/"+id+"/execution-requests", map[string]any{"kind": "start", "expected_state_version": 1}); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, res)
	}
	x, token := e.claimRequest()
	if code, res := e.do("service", "POST", "/api/v1/execution-requests/"+x["id"].(string)+"/fulfil",
		map[string]any{"claim_token": token, "engine": "temporal", "engine_ref": "run-1"}); code != http.StatusCreated {
		t.Fatalf("fulfil = %d %v", code, res)
	}
	_, view := e.relay("GET", "/api/v1/work-items/"+id, nil)
	latest := view["latest_execution"].(map[string]any)
	if latest["surface"] != "telegram" || latest["requested_by"] != "github:alice" || latest["acting_principal"] != "surface:telegram" {
		t.Fatalf("latest_execution = %v", latest)
	}
	_, list := e.relay("GET", "/api/v1/work-items/"+id+"/executions", nil)
	execs := list["executions"].([]any)
	if len(execs) != 1 || execs[0].(map[string]any)["requested_by"] != "github:alice" {
		t.Fatalf("executions = %v", list)
	}
}
