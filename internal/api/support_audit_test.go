package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

type supAuditPrincipal string

func (p supAuditPrincipal) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(p), nil
}

func auditedSupportRun(t *testing.T, tenant string) *auth.User {
	t.Helper()
	u := supportRun(tenant)
	if err := auth.AttachPrincipal(context.Background(), supAuditPrincipal("prn_SUPPORT_AGENT"), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSupportAudit_RESTAdmittedWritesOneRow(t *testing.T) {
	log := audit.NewLogger()
	router := supportStubRouter(&Handlers{opts: Options{AuditLog: log}})
	if rec := serveUser(router, auditedSupportRun(t, "labs"), "GET", "/api/v1/status/labs/app?secret=1"); rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if n := len(log.List(0)); n != 0 {
		t.Fatalf("List must hide support rows, got %d", n)
	}
	rows, _ := log.ListSupport(context.Background(), audit.SupportFilter{Tenant: "labs"})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.Operation != audit.OperationSupportRequest || e.Tenant != "labs" || e.PrincipalID != "pr_alice" ||
		e.ViaPrincipalID != "prn_SUPPORT_AGENT" || e.ViaExecutionID != "we_sup1" || e.Status != "succeeded" ||
		e.Parameters["http_status"] != "200" || e.Parameters["layer"] != "rest" ||
		e.Parameters["route"] != "GET /api/v1/status/labs/app" {
		t.Errorf("row = %+v", e)
	}
}

func TestSupportAudit_RESTDeniedRow(t *testing.T) {
	log := audit.NewLogger()
	router := supportStubRouter(&Handlers{opts: Options{AuditLog: log}})
	if rec := serveUser(router, auditedSupportRun(t, "labs"), "GET", "/api/v1/status/karabu/app"); rec.Code != 403 {
		t.Fatalf("code = %d", rec.Code)
	}
	rows, _ := log.ListSupport(context.Background(), audit.SupportFilter{ExecutionID: "we_sup1"})
	if len(rows) != 1 || rows[0].Operation != "agent_scope.denied" || rows[0].Status != "denied" ||
		rows[0].Tenant != "labs" || rows[0].PrincipalID != "pr_alice" || rows[0].ViaPrincipalID != "prn_SUPPORT_AGENT" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestSupportAudit_ServerErrorAndPanicAreFailed(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AuditLog: log}}
	r := chi.NewRouter()
	r.Use(h.agentScopeGate)
	r.Get("/api/v1/status/{t}/{a}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	r.Get("/api/v1/resources/{t}", func(http.ResponseWriter, *http.Request) { panic("boom") })
	serveUser(r, auditedSupportRun(t, "labs"), "GET", "/api/v1/status/labs/app")
	func() {
		defer func() { _ = recover() }()
		serveUser(r, auditedSupportRun(t, "labs"), "GET", "/api/v1/resources/labs")
	}()
	rows, _ := log.ListSupport(context.Background(), audit.SupportFilter{Tenant: "labs"})
	if len(rows) != 2 || rows[0].Status != "failed" || rows[1].Status != "failed" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestSupportAudit_OtherTokensWriteNothing(t *testing.T) {
	log := audit.NewLogger()
	router := scopeStubRouter(&Handlers{opts: Options{AuditLog: log}})
	serveUser(router, investigatorRun("wi_own"), "GET", "/api/v1/whoami")
	serveUser(router, auth.NewServiceUser(), "GET", "/api/v1/whoami")
	for _, e := range log.List(0) {
		if e.Operation == audit.OperationSupportRequest {
			t.Fatalf("unexpected support row %+v", e)
		}
	}
}

func TestSupportAudit_ForgedParentHeaderStillWritesRow(t *testing.T) {
	log := audit.NewLogger()
	srv := mctlmcp.NewServer("http://127.0.0.1", "t")
	router := supportStubRouter(&Handlers{opts: Options{AuditLog: log, MCPServer: srv}})
	rec := serveUserFrom(router, auditedSupportRun(t, "labs"), "127.0.0.1:1234", "GET", "/api/v1/status/labs/app", mctlmcp.AuditParentHeader, "unknown")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	rows, _ := log.ListSupport(context.Background(), audit.SupportFilter{Tenant: "labs"})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
}

func serveUserFrom(router http.Handler, u *auth.User, remote, method, path string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestSupportAudit_AdminRead(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AuditLog: log}}
	router := supportStubRouter(h)
	serveUser(router, auditedSupportRun(t, "labs"), "GET", "/api/v1/status/labs/app")
	other := auth.NewAgentUser("mctl-support", auth.AgentRun{
		Agent: "mctl-support", ExecutionID: "we_other", WorkItemID: "wi_o", RunID: "art_o",
		Scope: auth.AgentScopeSupport, Tenant: "karabu", RequestedBy: "pr_bob",
	})
	serveUser(router, other, "GET", "/api/v1/status/karabu/app")

	read := chi.NewRouter()
	read.Get("/api/v1/audit/support", h.ListSupportAudit)
	get := func(u *auth.User, q string) (int, map[string]any) {
		rec := serveUser(read, u, "GET", "/api/v1/audit/support"+q)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	admin := auth.NewServiceUser()
	if !admin.IsAdmin() {
		t.Skip("service user is not an admin")
	}
	if c, _ := get(auditedSupportRun(t, "labs"), "?tenant=labs"); c != 403 {
		t.Errorf("non-admin = %d", c)
	}
	if c, _ := get(admin, ""); c != 400 {
		t.Errorf("no filter = %d", c)
	}
	c, body := get(admin, "?tenant=labs")
	items, _ := body["items"].([]any)
	if c != 200 || len(items) != 1 {
		t.Fatalf("tenant=labs: %d %v", c, body)
	}
	row := items[0].(map[string]any)
	if row["viaExecutionId"] != "we_sup1" || row["userPrincipalId"] != "pr_alice" || row["viaPrincipalId"] != "prn_SUPPORT_AGENT" || row["tenant"] != "labs" {
		t.Errorf("row = %v", row)
	}
	if _, body := get(admin, "?execution_id=we_other"); len(body["items"].([]any)) != 1 {
		t.Errorf("execution filter = %v", body)
	}
}
