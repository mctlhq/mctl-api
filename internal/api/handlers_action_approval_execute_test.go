package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// The single-use execution mark: POST /api/v1/action-approvals/{id}/execute
// moves a consumed request to executed once, for its bound target and
// artifact, and only for the service that requested it.

var executeArtifactHash = "sha256:" + strings.Repeat("e", 64)

// consumedApproval is a request bound to executeArtifactHash, approved by a
// human admin and consumed by its requester.
func (e *workItemsEnv) consumedApproval(key string) map[string]any {
	e.t.Helper()
	a := e.approvedForExecute(key)
	res := e.consume(a["id"].(string), a["intent_hash"].(string))
	if res.code != http.StatusOK {
		e.t.Fatalf("consume = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

func (e *workItemsEnv) pendingForExecute(key string) map[string]any {
	e.t.Helper()
	body := e.approvalBody(key)
	body["artifact_hash"] = executeArtifactHash
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", body)
	if res.code != http.StatusCreated {
		e.t.Fatalf("create = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

func (e *workItemsEnv) approvedForExecute(key string) map[string]any {
	e.t.Helper()
	a := e.pendingForExecute(key)
	if res := e.decide(rootAdmin, a["id"].(string), "approve"); res.code != http.StatusOK {
		e.t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	return a
}

func executeBody(target, hash string) map[string]any {
	return map[string]any{"target": target, "artifact_hash": hash}
}

func (e *workItemsEnv) markExecuted(u *auth.User, id string, body any) wiResponse {
	e.t.Helper()
	return e.do(u, "POST", "/api/v1/action-approvals/"+id+"/execute", body)
}

func (e *workItemsEnv) approvalRow(id string) map[string]any {
	e.t.Helper()
	res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if res.code != http.StatusOK {
		e.t.Fatalf("read %s = %d %s", id, res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

func TestActionApprovals_ExecuteMarksAConsumedRequestOnce(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.consumedApproval("k-exec")
	id, target := a["id"].(string), a["target"].(string)

	res := e.markExecuted(auth.NewServiceUser(), id, executeBody(target, executeArtifactHash))
	if res.code != http.StatusOK {
		t.Fatalf("execute = %d %s", res.code, res.raw)
	}
	got := res.body["approval"].(map[string]any)
	if got["state"] != "executed" || got["executed_at"] == nil || got["consumed_at"] == nil {
		t.Fatalf("execute answered %s", res.raw)
	}
	if n := e.auditOps("action_approval.execute", id); n != 1 {
		t.Fatalf("execute audited %d times", n)
	}
	// GET and list serve the state and the timestamp.
	if row := e.approvalRow(id); row["state"] != "executed" || row["executed_at"] == nil {
		t.Fatalf("read = %v", row)
	}
	list := e.do(rootAdmin, "GET", "/api/v1/action-approvals?state=executed&execution_id="+e.tenant+"-exec", nil)
	if list.code != http.StatusOK {
		t.Fatalf("list = %d %s", list.code, list.raw)
	}
	if items := list.body["approvals"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != id || items[0].(map[string]any)["executed_at"] == nil {
		t.Fatalf("executed list = %s", list.raw)
	}

	again := e.markExecuted(auth.NewServiceUser(), id, executeBody(target, executeArtifactHash))
	if again.code != http.StatusConflict || code(again) != aarCodeExecuted {
		t.Fatalf("second execute = %d %s", again.code, again.raw)
	}
	if n := e.auditRefusals("action_approval.execute_refused", id, aarCodeExecuted); n != 1 {
		t.Fatalf("second execute audited %d times", n)
	}
	// Executed is final for consume too.
	if res := e.consume(id, a["intent_hash"].(string)); res.code != http.StatusConflict || code(res) != aarCodeConsumed {
		t.Fatalf("consume executed = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_ExecuteRefusalsAreTyped(t *testing.T) {
	e := newWorkItemsEnv(t)
	pending := e.pendingForExecute("k-pending")
	approved := e.approvedForExecute("k-approved")
	denied := e.pendingForExecute("k-denied")
	if res := e.decide(rootAdmin, denied["id"].(string), "deny"); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
	consumed := e.consumedApproval("k-consumed")
	target := consumed["target"].(string)
	otherHash := "sha256:" + strings.Repeat("f", 64)

	for _, tc := range []struct {
		name  string
		id    string
		body  map[string]any
		code  string
		state string
	}{
		{"pending", pending["id"].(string), executeBody(target, executeArtifactHash), aarCodeNotConsumed, "pending"},
		{"approved", approved["id"].(string), executeBody(target, executeArtifactHash), aarCodeNotConsumed, "approved"},
		{"denied", denied["id"].(string), executeBody(target, executeArtifactHash), aarCodeDenied, "denied"},
		{"wrong target", consumed["id"].(string), executeBody(target+"-other", executeArtifactHash), aarCodeTargetMismatch, "consumed"},
		{"wrong artifact", consumed["id"].(string), executeBody(target, otherHash), aarCodeTargetMismatch, "consumed"},
		{"non-digest artifact", consumed["id"].(string), executeBody(target, "sha256:diff"), aarCodeTargetMismatch, "consumed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := e.markExecuted(auth.NewServiceUser(), tc.id, tc.body)
			if res.code != http.StatusConflict || code(res) != tc.code {
				t.Fatalf("execute = %d %s, want 409 %s", res.code, res.raw, tc.code)
			}
			if n := e.auditRefusals("action_approval.execute_refused", tc.id, tc.code); n < 1 {
				t.Errorf("refusal not audited")
			}
			if row := e.approvalRow(tc.id); row["state"] != tc.state || row["executed_at"] != nil {
				t.Fatalf("after refusal = %v, want %s and no executed_at", row, tc.state)
			}
		})
	}
	if res := e.markExecuted(auth.NewServiceUser(), "aar_missing", executeBody(target, executeArtifactHash)); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("missing = %d %s", res.code, res.raw)
	}
	// Malformed bodies are refused before the store is asked.
	for name, body := range map[string]any{
		"no target":      map[string]any{"artifact_hash": executeArtifactHash},
		"no artifact":    map[string]any{"target": target},
		"empty artifact": executeBody(target, ""),
		"unknown field":  map[string]any{"target": target, "artifact_hash": executeArtifactHash, "state": "executed"},
		"not an object":  `["x"]`,
	} {
		if res := e.markExecuted(auth.NewServiceUser(), consumed["id"].(string), body); res.code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, res.code, res.raw)
		}
	}
	// Nothing above spent the consumed request.
	if res := e.markExecuted(auth.NewServiceUser(), consumed["id"].(string), executeBody(target, executeArtifactHash)); res.code != http.StatusOK {
		t.Fatalf("execute after refusals = %d %s", res.code, res.raw)
	}
}

// Only the requesting service marks its own request, as for consume: every
// other caller is refused and the request stays consumed.
func TestActionApprovals_OnlyTheRequestingServiceMarksExecuted(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.consumedApproval("k-exec-who")
	id, target := a["id"].(string), a["target"].(string)
	body := executeBody(target, executeArtifactHash)
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"tenant user":             e.user("alice"),
		"human admin":             rootAdmin,
		"surface":                 surface,
		"relayed":                 auth.NewRelayedUser("root", []string{"admins", e.tenant}, surface),
		"unbound agent run token": auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", RunID: "art_test"}),
	} {
		res := e.markExecuted(u, id, body)
		if res.code != http.StatusForbidden || code(res) != aarCodeRequesterForbidden {
			t.Errorf("%s execute = %d %s", name, res.code, res.raw)
		}
		if n := e.auditRefusals("action_approval.execute_refused", id, aarCodeRequesterForbidden); n < 1 {
			t.Errorf("%s refusal not audited", name)
		}
	}
	if res := e.markExecuted(nil, id, body); res.code != http.StatusUnauthorized {
		t.Errorf("anonymous execute = %d %s", res.code, res.raw)
	}
	// A run bound to the request's execution is an approval requester
	// (mctlhq/mctl-agents#717 S4), but this request is the service's: it
	// reads as absent to the run.
	run := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: e.tenant + "-exec", RunID: "art_test", Scope: auth.AgentScopeInvestigate})
	if res := e.markExecuted(run, id, body); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Errorf("bound agent run execute = %d %s", res.code, res.raw)
	}

	// A consumed request another service made answers 404 to this one, as
	// consume does, and is left as it was.
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	other := strings.Replace(id, "aar_", "aar_other", 1)
	if _, err := pool.Exec(context.Background(), `INSERT INTO action_approval_requests
		SELECT $2, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version,
		       artifact_hash, work_item_id, idempotency_key || '-other', 'service:someone-else', intent_hash,
		       state, expires_at, created_at, decided_by, decided_at, reason, consumed_at, schema_version
		FROM action_approval_requests WHERE id=$1`, id, other); err != nil {
		t.Fatal(err)
	}
	if res := e.markExecuted(auth.NewServiceUser(), other, body); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Errorf("another service's request = %d %s", res.code, res.raw)
	}
	if row := e.approvalRow(other); row["state"] != "consumed" {
		t.Errorf("another service's request reads %v", row["state"])
	}

	// Nothing was marked by the refusals.
	if row := e.approvalRow(id); row["state"] != "consumed" || row["executed_at"] != nil {
		t.Fatalf("after refusals = %v", row)
	}
	if res := e.markExecuted(auth.NewServiceUser(), id, body); res.code != http.StatusOK {
		t.Fatalf("requester execute = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_ExecuteIsSingleUseUnderConcurrency(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.consumedApproval("k-exec-race")
	id := a["id"].(string)
	payload := `{"target":"` + a["target"].(string) + `","artifact_hash":"` + executeArtifactHash + `"}`

	const racers = 8
	codes := make([]int, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest("POST", "/api/v1/action-approvals/"+id+"/execute", strings.NewReader(payload))
			req = req.WithContext(auth.WithUser(req.Context(), auth.NewServiceUser()))
			rec := httptest.NewRecorder()
			e.router.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}()
	}
	close(start)
	wg.Wait()
	won := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			won++
		case http.StatusConflict:
		default:
			t.Fatalf("racer = %d", c)
		}
	}
	if won != 1 {
		t.Fatalf("%d executes succeeded, want exactly 1 (%v)", won, codes)
	}
	if n := e.auditOps("action_approval.execute", id); n != 1 {
		t.Fatalf("execute audited %d times", n)
	}
	if n := e.auditRefusals("action_approval.execute_refused", id, aarCodeExecuted); n != racers-1 {
		t.Fatalf("losing executes audited %d times, want %d", n, racers-1)
	}
}
