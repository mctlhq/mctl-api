package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// attachExecution attaches a running engine execution to a work item through
// the HTTP layer, the same path mctl-agents would use, and returns its id.
func (e *workItemsEnv) attachExecution(user *auth.User, itemID, ref, phase string) string {
	e.t.Helper()
	res := e.do(user, "POST", "/api/v1/work-items/"+itemID+"/executions", map[string]any{
		"engine": "temporal", "engine_ref": ref, "phase": phase,
	})
	if res.code != http.StatusCreated {
		e.t.Fatalf("attach execution = %d %s", res.code, res.raw)
	}
	exec := res.body["execution"].(map[string]any)
	return exec["id"].(string)
}

func (e *workItemsEnv) mintRunToken(user *auth.User, body map[string]any) wiResponse {
	e.t.Helper()
	return e.do(user, "POST", "/api/v1/agent-run-tokens", body)
}

func TestMintAgentRunToken_OnlyDirectServiceMayMint(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")

	human := e.user("alice")
	res := e.mintRunToken(human, map[string]any{"agent": "implementer", "execution_id": execID})
	if res.code != http.StatusForbidden {
		t.Fatalf("human mint = %d %s, want 403", res.code, res.raw)
	}
	if code(res) != artCodeRequesterForbidden {
		t.Errorf("code = %q, want %q", code(res), artCodeRequesterForbidden)
	}
	if n := e.auditOpCount("agent_run_token.mint_refused", artCodeRequesterForbidden); n != 1 {
		t.Errorf("mint_refused audit rows = %d, want 1", n)
	}

	// A bare surface principal (not the static service token) is not
	// "direct service" either.
	surface := auth.NewSurfaceUser("telegram")
	res = e.mintRunToken(surface, map[string]any{"agent": "implementer", "execution_id": execID})
	if res.code != http.StatusForbidden {
		t.Fatalf("surface mint = %d %s, want 403", res.code, res.raw)
	}
}

func TestMintAgentRunToken_MintsAndBindsTheExecutionAndWorkItem(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")

	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{
		"agent": "implementer", "execution_id": execID, "permissions": []string{"usage:write"},
	})
	if res.code != http.StatusCreated {
		t.Fatalf("mint = %d %s", res.code, res.raw)
	}
	token, _ := res.body["token"].(string)
	if !strings.HasPrefix(token, auth.AgentRunTokenPrefix) {
		t.Errorf("token = %q, want prefix %q", token, auth.AgentRunTokenPrefix)
	}
	if res.body["execution_id"] != execID {
		t.Errorf("execution_id = %v, want %v", res.body["execution_id"], execID)
	}
	if res.body["work_item_id"] != item["id"] {
		t.Errorf("work_item_id = %v, want %v (taken from the execution, never the caller)", res.body["work_item_id"], item["id"])
	}

	// The plaintext token appears nowhere in the audit trail.
	entries := e.audit.List(1000)
	found := false
	for i := range entries {
		if entries[i].Operation != "agent_run_token.mint" {
			continue
		}
		found = true
		for k, v := range entries[i].Parameters {
			if strings.Contains(v, token) {
				t.Fatalf("plaintext token leaked into audit field %q: %q", k, v)
			}
		}
		if entries[i].Parameters["execution_id"] != execID {
			t.Errorf("audit execution_id = %q, want %q", entries[i].Parameters["execution_id"], execID)
		}
	}
	if !found {
		t.Fatal("expected one agent_run_token.mint audit row")
	}
}

func TestMintAgentRunToken_RefusesUnknownExecution(t *testing.T) {
	e := newWorkItemsEnv(t)
	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{"agent": "implementer", "execution_id": "we_does-not-exist"})
	if res.code != http.StatusNotFound {
		t.Fatalf("mint = %d %s, want 404", res.code, res.raw)
	}
	if code(res) != artCodeExecutionNotFound {
		t.Errorf("code = %q, want %q", code(res), artCodeExecutionNotFound)
	}
}

func TestMintAgentRunToken_RefusesTerminalExecution(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Succeeded")

	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{"agent": "implementer", "execution_id": execID})
	if res.code != http.StatusConflict {
		t.Fatalf("mint = %d %s, want 409", res.code, res.raw)
	}
	if code(res) != artCodeExecutionTerminal {
		t.Errorf("code = %q, want %q", code(res), artCodeExecutionTerminal)
	}
	if n := e.auditOpCount("agent_run_token.mint_refused", artCodeExecutionTerminal); n != 1 {
		t.Errorf("mint_refused audit rows = %d, want 1", n)
	}
}

func TestMintAgentRunToken_RefusesAnOversizedTTL(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")

	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{
		"agent": "implementer", "execution_id": execID, "ttl_seconds": 999999,
	})
	if res.code != http.StatusBadRequest {
		t.Fatalf("mint = %d %s, want 400", res.code, res.raw)
	}
	if code(res) != artCodeInvalidTTL {
		t.Errorf("code = %q, want %q", code(res), artCodeInvalidTTL)
	}
}

// A ttl_seconds large enough to overflow int64 when multiplied by
// time.Second must still be refused as an invalid TTL, not silently wrap
// into a small or negative Duration that slips past the ceiling.
func TestMintAgentRunToken_RefusesATTLThatWouldOverflow(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")

	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{
		"agent": "implementer", "execution_id": execID, "ttl_seconds": 10_000_000_000,
	})
	if res.code != http.StatusBadRequest {
		t.Fatalf("mint = %d %s, want 400", res.code, res.raw)
	}
	if code(res) != artCodeInvalidTTL {
		t.Errorf("code = %q, want %q", code(res), artCodeInvalidTTL)
	}
}

// The body may never name a subject: the same forbiddenIdentityFields gate
// every other work-item route already enforces.
func TestMintAgentRunToken_RejectsABodyThatNamesASubject(t *testing.T) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")

	res := e.mintRunToken(auth.NewServiceUser(), map[string]any{
		"agent": "implementer", "execution_id": execID, "subject": "github:alice",
	})
	if res.code != http.StatusBadRequest {
		t.Fatalf("mint = %d %s, want 400", res.code, res.raw)
	}
	if code(res) != wiCodeActorNotAccepted {
		t.Errorf("code = %q, want %q", code(res), wiCodeActorNotAccepted)
	}
}

// auditOpCount counts failed audit rows for op whose "reason" matches code.
func (e *workItemsEnv) auditOpCount(op, code string) int {
	n := 0
	entries := e.audit.List(1000)
	for i := range entries {
		entry := &entries[i]
		if entry.Operation == op && entry.Status == "failed" && entry.Parameters["reason"] == code {
			n++
		}
	}
	return n
}
