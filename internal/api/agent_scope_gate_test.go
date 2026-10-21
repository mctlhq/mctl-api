package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func investigatorRun(workItemID string) *auth.User {
	return auth.NewAgentUser("issue-investigator", auth.AgentRun{
		Agent: "issue-investigator", ExecutionID: "we_scope1", WorkItemID: workItemID, RunID: "art_scope1",
		Scope: auth.AgentScopeInvestigate,
	})
}

// scopeStubRouter puts agentScopeGate in front of handlers that answer 200
// whenever the caller passes the tenant check, the same check the real
// mutating handlers make, so a request the gate lets through is one a
// handler would carry out.
func scopeStubRouter(h *Handlers) http.Handler {
	ok := func(w http.ResponseWriter, r *http.Request) {
		if u := auth.UserFromContext(r.Context()); u == nil || !u.HasTenantAccess("admins") {
			writeError(w, http.StatusForbidden, "no tenant access")
			return
		}
		if scope := auth.ShadowAgentScopeFromContext(r.Context()); scope != "" {
			w.Header().Set("X-Seen-Shadow", scope)
		}
		w.WriteHeader(http.StatusOK)
	}
	r := chi.NewRouter()
	r.Use(h.agentScopeGate)
	r.Get("/api/v1/tenants", ok)
	r.Get("/api/v1/work-items/{id}", ok)
	r.Get("/api/v1/work-items/{id}/executions", ok)
	r.Get("/api/v1/audit", ok)
	r.Post("/api/v1/incidents/{id}/resolve", ok)
	r.Post("/api/v1/work-items/{id}/executions", ok)
	r.Post("/mcp", ok)
	return r
}

func serveUser(router http.Handler, u *auth.User, method, path string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(`{}`))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAgentScopeGate_ScopedRunReachesOnlyItsScope(t *testing.T) {
	log := audit.NewLogger()
	router := scopeStubRouter(&Handlers{opts: Options{AuditLog: log}})
	run := investigatorRun("wi_own")

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/tenants", http.StatusOK},
		{http.MethodGet, "/api/v1/work-items/wi_own", http.StatusOK},
		{http.MethodGet, "/api/v1/work-items/wi_own/executions", http.StatusOK},
		{http.MethodPost, "/mcp", http.StatusOK},
		// Not its work item.
		{http.MethodGet, "/api/v1/work-items/wi_other", http.StatusForbidden},
		// A read the scope does not list.
		{http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		// Mutations, even on its own work item.
		{http.MethodPost, "/api/v1/incidents/inc-1/resolve", http.StatusForbidden},
		{http.MethodPost, "/api/v1/work-items/wi_own/executions", http.StatusForbidden},
	} {
		rec := serveUser(router, run, c.method, c.path)
		if rec.Code != c.want {
			t.Errorf("%s %s = %d %s, want %d", c.method, c.path, rec.Code, rec.Body.String(), c.want)
			continue
		}
		if c.want == http.StatusForbidden {
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body["code"] != mctlmcp.AgentScopeCodeDenied {
				t.Errorf("%s %s code = %v, want %s", c.method, c.path, body["code"], mctlmcp.AgentScopeCodeDenied)
			}
		}
	}

	denied := 0
	for _, e := range log.List(0) {
		if e.Operation != "agent_scope.denied" {
			continue
		}
		denied++
		if e.Parameters["execution_id"] != "we_scope1" || e.Parameters["agent_run_id"] != "art_scope1" || e.Parameters["scope"] != "investigate" {
			t.Errorf("denied audit row lacks the run: %v", e.Parameters)
		}
	}
	if denied != 4 {
		t.Errorf("agent_scope.denied audit rows = %d, want 4", denied)
	}
}

func TestAgentScopeGate_UnscopedRunTokenIsUnchanged(t *testing.T) {
	router := scopeStubRouter(&Handlers{opts: Options{AuditLog: audit.NewLogger()}})
	unscoped := auth.NewAgentUser("issue-investigator", auth.AgentRun{ExecutionID: "we_x", WorkItemID: "wi_x", RunID: "art_x"})
	// The gate lets it through; the handler's own tenant check still
	// refuses it, as it always did.
	rec := serveUser(router, unscoped, http.MethodPost, "/api/v1/incidents/inc-1/resolve")
	if rec.Code != http.StatusForbidden || bytes.Contains(rec.Body.Bytes(), []byte(mctlmcp.AgentScopeCodeDenied)) {
		t.Fatalf("unscoped run = %d %s, want the handler's own 403", rec.Code, rec.Body.String())
	}
}

func TestAgentScopeGate_UnknownScopeAdmitsNothing(t *testing.T) {
	router := scopeStubRouter(&Handlers{opts: Options{AuditLog: audit.NewLogger()}})
	u := auth.NewAgentUser("issue-investigator", auth.AgentRun{WorkItemID: "wi_x", Scope: "no-such-scope"})
	if rec := serveUser(router, u, http.MethodGet, "/api/v1/tenants"); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown scope GET = %d, want 403", rec.Code)
	}
}

func TestAgentScopeGate_ShadowCountsAndNeverRefuses(t *testing.T) {
	router := scopeStubRouter(&Handlers{opts: Options{AuditLog: audit.NewLogger()}})
	deny := mctlmcp.AgentScopeDecisions.WithLabelValues("investigate", "shadow", "rest", "deny")
	allow := mctlmcp.AgentScopeDecisions.WithLabelValues("investigate", "shadow", "rest", "allow_unbound")
	deny0, allow0 := testutil.ToFloat64(deny), testutil.ToFloat64(allow)

	svc := auth.NewServiceUser()
	rec := serveUser(router, svc, http.MethodPost, "/api/v1/incidents/inc-1/resolve", auth.AgentScopeShadowHeader, "investigate")
	if rec.Code != http.StatusOK {
		t.Fatalf("shadowed mutation = %d, want 200: shadow never refuses", rec.Code)
	}
	if rec.Header().Get("X-Seen-Shadow") != "investigate" {
		t.Error("shadow scope not carried on the context")
	}
	serveUser(router, svc, http.MethodGet, "/api/v1/work-items/wi_any", auth.AgentScopeShadowHeader, "investigate")
	if got := testutil.ToFloat64(deny) - deny0; got != 1 {
		t.Errorf("shadow deny count += %v, want 1", got)
	}
	if got := testutil.ToFloat64(allow) - allow0; got != 1 {
		t.Errorf("shadow allow_unbound count += %v, want 1: a bound route admitted without its work item", got)
	}

	// A caller other than the direct service cannot use the header.
	human := &auth.User{ID: "alice", Groups: []string{"admins"}}
	rec = serveUser(router, human, http.MethodGet, "/api/v1/tenants", auth.AgentScopeShadowHeader, "investigate")
	if rec.Header().Get("X-Seen-Shadow") != "" {
		t.Error("a non-service caller's shadow header was honoured")
	}
}

// TestAgentScopeGate_ScopedRunCannotResolveAnIncident is #737's acceptance
// on the real handler: an agent run cannot change an incident, and the
// incident stays open. Two layers refuse it -- the scope gate, and the
// handler's tenant-role check, since an agent holds no tenant role. The
// test also requires the refusal to be the gate's, so it fails without the
// gate even though the role check would still keep the incident open.
func TestAgentScopeGate_ScopedRunCannotResolveAnIncident(t *testing.T) {
	store := newTestAlertStore(t)
	seedIncidents(t, store, "scope-res-0001")
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AlertStore: store, AuditLog: log}}
	r := chi.NewRouter()
	r.Use(h.agentScopeGate)
	r.Post("/api/v1/incidents/{id}/resolve", h.ResolveIncident)

	rec := serveUser(r, investigatorRun("wi_own"), http.MethodPost, "/api/v1/incidents/scope-res-0001/resolve")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped resolve = %d %s, want 403", rec.Code, rec.Body.String())
	}
	got, err := store.Get(t.Context(), "scope-res-0001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != alerts.StatusOpen {
		t.Fatalf("incident status = %q after a refused resolve, want open", got.Status)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != mctlmcp.AgentScopeCodeDenied {
		t.Errorf("refused by %v, want the scope gate (%s) first", body["code"], mctlmcp.AgentScopeCodeDenied)
	}
}
