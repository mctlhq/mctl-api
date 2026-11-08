package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.temporal.io/api/serviceerror"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func orchestratorUser() *auth.User {
	return auth.NewOrchestratorDevLoopUser(auth.Identity{Provider: "zitadel", Issuer: "https://auth.example", Subject: "3300000000000001"})
}

func orchestratorRouter(t *testing.T, fake *fakeDevLoopClient) (http.Handler, *audit.Logger) {
	t.Helper()
	log := audit.NewLogger()
	return NewRouter(Options{
		AuthMiddleware: injectUser(orchestratorUser()),
		MCPServer:      mctlmcp.NewServer("http://127.0.0.1:1", ""),
		TemporalClient: fake,
		AuditLog:       log,
	}), log
}

func serve(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, bytes.NewBufferString(body)))
	return rec
}

// Every route but the three it needs is refused before a handler runs, with
// a distinct code for approve and for the direct-Argo investigate path, and
// every refusal is audited.
func TestOrchestratorDevLoop_GateRefusals(t *testing.T) {
	t.Setenv(orchestratorDevLoopReposEnv, "mctlhq/mctl-api")
	fake := &fakeDevLoopClient{}
	router, log := orchestratorRouter(t, fake)
	cases := []struct{ method, path, code string }{
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-963/approve", codeOrchestratorApproveForbidden},
		{http.MethodPost, "/api/v1/operations/mctl-agents-investigate/execute", codeOrchestratorTemporalRequired},
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-963/abandon", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-963/approval", codeOrchestratorRouteNotAllowed},
		{http.MethodPost, "/mcp", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/mcp", codeOrchestratorRouteNotAllowed},
		{http.MethodPost, "/api/v1/operations/mctl-agents-approve/execute", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/api/v1/tenants", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/api/v1/workflows/dev-loop-mctlhq-mctl-api-963", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/start", codeOrchestratorRouteNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1", codeOrchestratorRepoNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-extra-1", codeOrchestratorRepoNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-MCTL-API-963", codeOrchestratorRepoNotAllowed},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api%2D963", codeOrchestratorRouteNotAllowed},
	}
	for _, c := range cases {
		rec := serve(router, c.method, c.path, "{}")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%s %s: got %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), c.code)
		}
	}
	if fake.startCalls != 0 || fake.lastApprovedWorkflow != "" || fake.abandonCalls != 0 {
		t.Fatalf("a refused request reached Temporal: %+v", fake)
	}
	denied := 0
	for _, e := range log.List(100) {
		if e.Operation == orchestratorDevLoopAuditOperation && e.Status == "denied" && e.UserID == auth.OrchestratorDevLoopUserID && e.Parameters["code"] != "" {
			denied++
		}
	}
	if denied != len(cases) {
		t.Fatalf("audited refusals: got %d, want %d", denied, len(cases))
	}
}

// A start for an allowed repository reaches Temporal on the dev-loop path;
// one for any other repository, or with an empty allow-list, does not.
func TestOrchestratorDevLoop_StartIsConfinedToTheAllowList(t *testing.T) {
	t.Setenv(orchestratorDevLoopReposEnv, " mctlhq/mctl-api , ")
	fake := &fakeDevLoopClient{describeErr: serviceerror.NewNotFound("workflow not found"), workflowID: "dev-loop-mctlhq-mctl-api-963", runID: "run-1"}
	router, log := orchestratorRouter(t, fake)

	rec := serve(router, http.MethodPost, orchestratorDevLoopStartRoute, `{"issue_url":"https://github.com/mctlhq/mctl-api/issues/963"}`)
	if rec.Code != http.StatusAccepted || fake.startCalls != 1 {
		t.Fatalf("allowed start: got %d %s, startCalls=%d", rec.Code, rec.Body.String(), fake.startCalls)
	}
	var started *audit.Entry
	for _, e := range log.List(100) {
		if e.Operation == "dev-loop-start" {
			e := e
			started = &e
		}
	}
	if started == nil || started.UserID != auth.OrchestratorDevLoopUserID || started.Status != "succeeded" {
		t.Fatalf("start audit row: %+v", started)
	}
	// The handler's row is the start's only record: the gate writes no
	// "allowed" row a later refusal could contradict.
	if n := countOrchestratorRows(log, "allowed"); n != 0 {
		t.Fatalf("gate wrote %d allowed rows for a start", n)
	}

	for _, url := range []string{
		"https://github.com/mctlhq/mctl-telegram/issues/1",
		"https://github.com/mctlhq/mctl-api-fork/issues/1",
		// Same issue, other case: a different workflow id, so a case-folded
		// match would start a second loop for it.
		"https://github.com/mctlhq/MCTL-API/issues/963",
	} {
		rec := serve(router, http.MethodPost, orchestratorDevLoopStartRoute, `{"issue_url":"`+url+`"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeOrchestratorRepoNotAllowed) {
			t.Errorf("%s: got %d %s, want 403 %s", url, rec.Code, rec.Body.String(), codeOrchestratorRepoNotAllowed)
		}
	}
	if fake.startCalls != 1 {
		t.Fatalf("a refused start reached Temporal: startCalls=%d", fake.startCalls)
	}
	if a, d := countOrchestratorRows(log, "allowed"), countOrchestratorRows(log, "denied"); a != 0 || d != 3 {
		t.Fatalf("refused starts: %d allowed and %d denied rows, want 0 and 3", a, d)
	}

	// A malformed start is audited too, once, as denied.
	for _, body := range []string{`not json`, `{}`, `{"issue_url":"https://example.com/x"}`} {
		rec := serve(router, http.MethodPost, orchestratorDevLoopStartRoute, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", body, rec.Code)
		}
	}
	if d := countOrchestratorRows(log, "denied"); d != 6 {
		t.Fatalf("malformed starts: %d denied rows in all, want 6", d)
	}

	t.Setenv(orchestratorDevLoopReposEnv, "")
	rec = serve(router, http.MethodPost, orchestratorDevLoopStartRoute, `{"issue_url":"https://github.com/mctlhq/mctl-api/issues/963"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeOrchestratorRepoNotAllowed) || fake.startCalls != 1 {
		t.Fatalf("empty allow-list: got %d %s, startCalls=%d", rec.Code, rec.Body.String(), fake.startCalls)
	}
}

// The read of an allowed repository's loop, and whoami, pass and are audited.
func TestOrchestratorDevLoop_ReadIsAdmittedAndAudited(t *testing.T) {
	t.Setenv(orchestratorDevLoopReposEnv, "mctlhq/mctl-api")
	fake := &fakeDevLoopClient{describeStatus: "Running"}
	router, log := orchestratorRouter(t, fake)
	rec := serve(router, http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-963", "")
	if rec.Code != http.StatusOK || fake.lastDescribedWorkflow != "dev-loop-mctlhq-mctl-api-963" {
		t.Fatalf("read: got %d %s, described %q", rec.Code, rec.Body.String(), fake.lastDescribedWorkflow)
	}
	if rec := serve(router, http.MethodGet, "/api/v1/whoami", ""); rec.Code == http.StatusForbidden {
		t.Fatalf("whoami: got %d %s", rec.Code, rec.Body.String())
	}
	if n := countOrchestratorRows(log, "allowed"); n != 2 {
		t.Fatalf("audited admitted requests: got %d, want 2", n)
	}
}

func countOrchestratorRows(log *audit.Logger, status string) int {
	n := 0
	for _, e := range log.List(100) {
		if e.Operation == orchestratorDevLoopAuditOperation && e.Status == status && e.UserID == auth.OrchestratorDevLoopUserID {
			n++
		}
	}
	return n
}

// Defence in depth behind the gate: the approve handler itself refuses the
// orchestrator, which is not a human admin.
func TestOrchestratorDevLoop_ApproveHandlerRefusesIt(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-963/approve", bytes.NewBufferString(`{}`))
	req = req.WithContext(auth.WithUser(req.Context(), orchestratorUser()))
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusForbidden || fake.lastApprovedWorkflow != "" {
		t.Fatalf("approve: got %d %s, approved %q", rec.Code, rec.Body.String(), fake.lastApprovedWorkflow)
	}
}
