package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func supportRun(tenant string) *auth.User {
	return auth.NewAgentUser("mctl-support", auth.AgentRun{
		Agent: "mctl-support", ExecutionID: "we_sup1", WorkItemID: "wi_sup1", RunID: "art_sup1",
		Scope: auth.AgentScopeSupport, Tenant: tenant, RequestedBy: "pr_alice",
	})
}

func supportStubRouter(h *Handlers) http.Handler {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	r := chi.NewRouter()
	r.Use(h.agentScopeGate)
	for _, p := range []string{
		"/api/v1/status/{t}/{a}", "/api/v1/services/{t}/{a}", "/api/v1/services", "/api/v1/workflows",
		"/api/v1/domains", "/api/v1/incidents", "/api/v1/tenants", "/api/v1/resources/{t}",
	} {
		r.Get(p, ok)
	}
	r.Post("/api/v1/operations/{name}/execute", ok)
	r.Post("/api/v1/agent-run-tokens/self/revoke", ok)
	return r
}

func TestSupportGate_EnforcesTheBoundTenant(t *testing.T) {
	log := audit.NewLogger()
	router := supportStubRouter(&Handlers{opts: Options{AuditLog: log}})
	deny := mctlmcp.AgentScopeDecisions.WithLabelValues("support", "enforce", "rest", "deny")
	deny0 := testutil.ToFloat64(deny)
	run := supportRun("labs")

	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/v1/status/labs/app", 200},
		{"GET", "/api/v1/status/karabu/app", 403},
		{"GET", "/api/v1/resources/karabu", 403},
		{"GET", "/api/v1/services?team=labs", 200},
		{"GET", "/api/v1/services", 403},
		{"GET", "/api/v1/services?team=karabu", 403},
		{"GET", "/api/v1/services?team=labs&team=karabu", 403},
		{"GET", "/api/v1/workflows", 403},
		{"GET", "/api/v1/workflows?team=labs", 200},
		{"GET", "/api/v1/domains", 403},
		{"GET", "/api/v1/domains?team=labs", 200},
		{"GET", "/api/v1/incidents", 403},
		{"GET", "/api/v1/incidents?tenant=labs", 200},
		{"GET", "/api/v1/incidents?tenant=karabu", 403},
		{"GET", "/api/v1/tenants", 403},
		{"POST", "/api/v1/operations/deploy-service/execute", 403},
	}
	denied := 0
	for _, c := range cases {
		rec := serveUser(router, run, c.method, c.path)
		if rec.Code != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, rec.Code, c.want)
		}
		if c.want == 403 {
			denied++
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body["code"] != mctlmcp.AgentScopeCodeDenied {
				t.Errorf("%s %s code = %v", c.method, c.path, body["code"])
			}
		}
	}
	if got := testutil.ToFloat64(deny) - deny0; int(got) != denied {
		t.Errorf("deny counter += %v, want %d", got, denied)
	}
	rows := 0
	for _, e := range log.List(0) {
		if e.Operation == "agent_scope.denied" {
			rows++
			if e.Parameters["bound_tenant"] != "labs" || e.Parameters["scope"] != "support" {
				t.Errorf("denied audit row = %v", e.Parameters)
			}
		}
	}
	if rows != denied {
		t.Errorf("agent_scope.denied rows = %d, want %d", rows, denied)
	}
	// Self-revoke is always allowed.
	if rec := serveUser(router, run, "POST", "/api/v1/agent-run-tokens/self/revoke"); rec.Code != 200 {
		t.Errorf("self-revoke = %d", rec.Code)
	}
}

func TestSupportGate_ShadowOfBoundScopeIsUnevaluable(t *testing.T) {
	router := supportStubRouter(&Handlers{opts: Options{AuditLog: audit.NewLogger()}})
	c := mctlmcp.AgentScopeDecisions.WithLabelValues("support", "shadow", "rest", "shadow_unbound_tenant")
	c0 := testutil.ToFloat64(c)
	rec := serveUser(router, auth.NewServiceUser(), "POST", "/api/v1/operations/deploy-service/execute", auth.AgentScopeShadowHeader, "support")
	if rec.Code != 200 {
		t.Fatalf("shadowed request = %d, want 200", rec.Code)
	}
	if got := testutil.ToFloat64(c) - c0; got != 1 {
		t.Errorf("shadow_unbound_tenant += %v, want 1", got)
	}
}

func TestSupportHandlers_DataDerivedTenant(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-other", Parameters: map[string]string{"team_name": "karabu"}})
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-noteam", Parameters: map[string]string{"x": "y"}})
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-own", Parameters: map[string]string{"team_name": "labs"}})
	h := &Handlers{opts: Options{AuditLog: log}}
	r := chi.NewRouter()
	r.Get("/api/v1/workflows/{name}", h.GetWorkflow)
	r.Get("/api/v1/workflows", h.ListWorkflows)
	run := supportRun("labs")

	for _, name := range []string{"wf-other", "wf-noteam", "mctl-agents-cron-1"} {
		if rec := serveUser(r, run, "GET", "/api/v1/workflows/"+name); rec.Code != http.StatusForbidden {
			t.Errorf("GetWorkflow(%s) = %d, want 403", name, rec.Code)
		}
	}

	rec := serveUser(r, run, "GET", "/api/v1/workflows")
	var body struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Items) != 1 || body.Items[0]["workflowName"] != "wf-own" {
		t.Errorf("ListWorkflows items = %v, want only wf-own", body.Items)
	}
}

// supportTenants answers the tenant lookups a mint test names: "nowhere" is
// a definite absence, "broken" is a checkout that cannot be read, anything
// else exists.
type supportTenants struct{ GitReader }

func (supportTenants) GetTenant(name string) (*gitops.Tenant, error) {
	if name == "nowhere" {
		return nil, errors.New("not found")
	}
	return &gitops.Tenant{Name: name}, nil
}

func (supportTenants) TenantExists(name string) (bool, error) {
	switch name {
	case "nowhere":
		return false, nil
	case "broken":
		return false, errors.New("checkout unreadable")
	}
	return true, nil
}

type supportPrincipals struct{}

func (supportPrincipals) ResolvePrincipal(_ context.Context, id auth.Identity) (string, error) {
	return "prn_" + id.Subject, nil
}

func supportHuman(login string, groups ...string) *auth.User {
	u := auth.NewGitHubUser(login, groups)
	_ = auth.AttachPrincipal(context.Background(), supportPrincipals{}, u)
	return u
}

func TestMintSupportToken(t *testing.T) {
	e := newWorkItemsEnv(t)
	e.h.opts.GitReader = supportTenants{}
	// The bound tenant is the env's own: the execution a support token binds
	// to must be one of that tenant's work items.
	ten := e.tenant
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-1", "Running")
	mint := func(u *auth.User, tenant string, extra map[string]any) wiResponse {
		body := map[string]any{"agent": "mctl-support", "execution_id": execID, "scope": "support"}
		if tenant != "" {
			body["tenant"] = tenant
		}
		for k, v := range extra {
			body[k] = v
		}
		return e.mintRunToken(u, body)
	}

	res := mint(supportHuman("alice", ten), ten, nil)
	if res.code != http.StatusCreated || res.body["tenant"] != ten {
		t.Fatalf("member mint = %d %s", res.code, res.raw)
	}
	if exp, _ := time.Parse(time.RFC3339Nano, res.body["expires_at"].(string)); time.Until(exp) > 11*time.Minute {
		t.Errorf("default ttl too long: %v", exp)
	}

	before := e.auditOpCount("agent_run_token.mint_refused", artCodeTenantForbidden)
	if res := mint(supportHuman("bob", "karabu"), ten, nil); res.code != http.StatusForbidden || code(res) != artCodeTenantForbidden {
		t.Errorf("non-member mint = %d %s", res.code, res.raw)
	}
	if n := e.auditOpCount("agent_run_token.mint_refused", artCodeTenantForbidden) - before; n != 1 {
		t.Errorf("refusal audit rows = %d, want 1", n)
	}

	// Admin override: allowed, and the mint audit row says so.
	if res := mint(supportHuman("root", "admins"), ten, nil); res.code != http.StatusCreated {
		t.Errorf("admin mint = %d %s", res.code, res.raw)
	}
	overrides := 0
	for _, entry := range e.audit.List(1000) {
		if entry.Operation == "agent_run_token.mint" && entry.Parameters["admin_override"] == "true" {
			overrides++
		}
	}
	if overrides != 1 {
		t.Errorf("mint audit rows with admin_override=true = %d, want 1", overrides)
	}

	if res := mint(supportHuman("alice", ten), "", nil); res.code != http.StatusBadRequest || code(res) != artCodeTenantRequired {
		t.Errorf("missing tenant = %d %s", res.code, res.raw)
	}
	if res := mint(supportHuman("root", "admins"), "nowhere", nil); res.code != http.StatusNotFound || code(res) != artCodeTenantNotFound {
		t.Errorf("unknown tenant = %d %s", res.code, res.raw)
	}
	// A non-member gets the same 403 for a missing tenant as for a foreign
	// one: the mint endpoint is not a tenant-name oracle.
	if res := mint(supportHuman("mallory", "other"), "nowhere", nil); res.code != http.StatusForbidden || code(res) != artCodeTenantForbidden {
		t.Errorf("non-member, unknown tenant = %d %s", res.code, res.raw)
	}
	if res := mint(supportHuman("mallory", "other"), ten, nil); res.code != http.StatusForbidden || code(res) != artCodeTenantForbidden {
		t.Errorf("non-member, existing tenant = %d %s", res.code, res.raw)
	}
	// A checkout that cannot be read is not an absent tenant.
	if res := mint(supportHuman("root", "admins"), "broken", nil); res.code != http.StatusServiceUnavailable || code(res) != artCodeTenantLookupFailed {
		t.Errorf("unreadable tenant lookup = %d %s", res.code, res.raw)
	}
	if res := mint(supportHuman("alice", ten), ten, map[string]any{"ttl_seconds": 3601}); res.code != http.StatusBadRequest || code(res) != artCodeInvalidTTL {
		t.Errorf("long ttl = %d %s", res.code, res.raw)
	}
	// The scope defines the permissions; a member cannot add any.
	if res := mint(supportHuman("alice", ten), ten, map[string]any{"permissions": []string{"security.remediate"}}); res.code != http.StatusBadRequest || code(res) != artCodePermissionsUnexpected {
		t.Errorf("member mint with permissions = %d %s", res.code, res.raw)
	}
	if res := mint(supportHuman("root", "admins"), ten, map[string]any{"permissions": []string{"usage.write"}}); res.code != http.StatusBadRequest || code(res) != artCodePermissionsUnexpected {
		t.Errorf("admin mint with permissions = %d %s", res.code, res.raw)
	}
	// The execution must be the bound tenant's own: a live execution of
	// another tenant's work item is refused, for a member and for an admin.
	other := ten + "-other"
	otherItem := e.open(auth.NewServiceUser(), map[string]any{"tenant": other})
	otherExec := e.attachExecution(auth.NewServiceUser(), otherItem["id"].(string), "run-other", "Running")
	for _, u := range []*auth.User{supportHuman("alice", ten), supportHuman("root", "admins")} {
		res := mint(u, ten, map[string]any{"execution_id": otherExec})
		if res.code != http.StatusForbidden || code(res) != artCodeExecutionForeign {
			t.Errorf("foreign execution mint by %s = %d %s", u.ID, res.code, res.raw)
		}
		if _, ok := res.body["token"]; ok {
			t.Fatal("a refused mint returned a token")
		}
	}
	if res := mint(supportHuman("alice", ten), ten, map[string]any{"execution_id": "we_missing"}); res.code != http.StatusNotFound || code(res) != artCodeExecutionNotFound {
		t.Errorf("unknown execution = %d %s", res.code, res.raw)
	}
	if res := mint(auth.NewServiceUser(), ten, nil); res.code != http.StatusForbidden || code(res) != artCodeRequesterForbidden {
		t.Errorf("service principal mint = %d %s", res.code, res.raw)
	}
	agent := auth.NewAgentUser("issue-investigator", auth.AgentRun{Scope: auth.AgentScopeInvestigate})
	if res := mint(agent, ten, nil); res.code != http.StatusForbidden {
		t.Errorf("agent mint = %d %s", res.code, res.raw)
	}
	res = e.mintRunToken(auth.NewServiceUser(), map[string]any{
		"agent": "issue-investigator", "execution_id": execID, "scope": "investigate", "tenant": ten,
	})
	if res.code != http.StatusBadRequest || code(res) != artCodeTenantUnexpected {
		t.Errorf("tenant on investigate = %d %s", res.code, res.raw)
	}
}
