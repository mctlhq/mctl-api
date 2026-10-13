package api_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Operations on an existing service act on the Argo CD Application
// <team>-<component>. The service must exist for that team in gitops before
// anything is submitted, and a checkout that cannot answer refuses.

// serviceOps are the operations gated on an existing service, with a body
// naming erpact's service "web".
var serviceOps = map[string]map[string]string{
	"retire-service":       retireBody,
	"rollback-service":     rollbackBody,
	"remove-custom-domain": removeDomainBody,
	"add-custom-domain":    {"team_name": "erpact", "service_name": "web", "domain": "app.example.com"},
	"preview-deploy":       {"team_name": "erpact", "component_name": "web", "image_tag": "1.2.3"},
	"deploy-service":       {"action": "deploy", "team_name": "erpact", "component_name": "web", "image_tag": "1.2.3"},
}

func withComponent(body map[string]string, component string) map[string]string {
	out := map[string]string{}
	for k, v := range body {
		out[k] = v
	}
	if _, ok := out["service_name"]; ok {
		out["service_name"] = component
	} else {
		out["component_name"] = component
	}
	return out
}

func TestServiceOps_RefuseAServiceThatDoesNotExist(t *testing.T) {
	for op, body := range serviceOps {
		t.Run(op, func(t *testing.T) {
			f := newRoleFixture(t)
			w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", withComponent(body, "app"), member("olga-owner"))
			if w.Code != http.StatusNotFound {
				t.Fatalf("status %d, want 404; body %s", w.Code, w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("submitted %v for a service that does not exist", f.exec.submitted)
			}
			if a := f.lastAudit(t); a.Status != "denied" {
				t.Errorf("audit status %q, want denied", a.Status)
			}
		})
	}
}

func TestServiceOps_FailedReadRefuses(t *testing.T) {
	for op, body := range serviceOps {
		t.Run(op, func(t *testing.T) {
			f := newRoleFixture(t)
			f.git.serviceExistsErr = errors.New("checkout stale")
			w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", body, member("olga-owner"))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503; body %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "checkout stale") {
				t.Errorf("internal error leaked to the caller: %s", w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("submitted %v although the service could not be checked", f.exec.submitted)
			}
		})
	}
}

func TestServiceOps_ExistingServiceProceeds(t *testing.T) {
	for op, body := range serviceOps {
		t.Run(op, func(t *testing.T) {
			f := newRoleFixture(t)
			w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", body, member("olga-owner"))
			if w.Code != http.StatusAccepted {
				t.Fatalf("status %d, want 202; body %s", w.Code, w.Body.String())
			}
			if f.git.serviceExistsCalls != 1 {
				t.Errorf("ServiceExists called %d times, want 1", f.git.serviceExistsCalls)
			}
		})
	}
}

// Admins are held to it too: the check is about which Application the
// workflow acts on, not about who asks.
func TestRetireService_AdminIsCheckedToo(t *testing.T) {
	f := newRoleFixture(t)
	admin := &auth.User{ID: "root-admin", Groups: []string{"admins"}}
	w := postAs(t, f.router, "/api/v1/operations/retire-service/execute", withComponent(retireBody, "app"), admin)
	if w.Code != http.StatusNotFound || len(f.exec.submitted) != 0 {
		t.Fatalf("status %d, submitted %v; want 404 and nothing submitted", w.Code, f.exec.submitted)
	}
}

// Onboarding creates the service, so it is not gated on existence; a
// reserved name is still refused for it.
func TestDeployOnboard_NotGatedOnExistence(t *testing.T) {
	f := newRoleFixture(t)
	body := map[string]string{"action": "onboard", "team_name": "erpact", "component_name": "fresh", "image_tag": "1.0.0"}
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, member("olga-owner"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d; body %s", w.Code, w.Body.String())
	}
	if f.git.serviceExistsCalls != 0 {
		t.Errorf("onboard consulted ServiceExists %d times", f.git.serviceExistsCalls)
	}

	f = newRoleFixture(t)
	body["component_name"] = "control" // erpact-control is a platform Application
	w = postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, member("olga-owner"))
	if w.Code != http.StatusBadRequest || len(f.exec.submitted) != 0 {
		t.Fatalf("status %d, submitted %v; want 400 and nothing submitted", w.Code, f.exec.submitted)
	}
	if !strings.Contains(w.Body.String(), "reserved for platform use") {
		t.Errorf("body %s", w.Body.String())
	}
}

// The MCP tool goes through the same REST handler, so it is refused the same
// way.
func TestRetireService_MCPRefusesAServiceThatDoesNotExist(t *testing.T) {
	f := newRoleFixture(t)
	users := map[string]*auth.User{"tok-owner": member("olga-owner")}
	backend := httptest.NewServer(tokenAuth(users)(f.router))
	defer backend.Close()
	text, isError := callTool(t, mctlmcp.NewServer(backend.URL, ""), "tok-owner", "mctl_retire_service",
		map[string]string{"team_name": "erpact", "component_name": "app", "confirm": "yes"})
	if !isError || !strings.Contains(text, "not found") {
		t.Fatalf("isError=%v text=%q; want a not-found refusal", isError, text)
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted %v", f.exec.submitted)
	}
}

// ── create-tenant names ──────────────────────────────────────────────────────

func newCreateTenantFixture(t *testing.T) *roleFixture {
	t.Helper()
	f := newRoleFixture(t)
	for _, n := range []string{"admins", "karabu", "labs", "mctl", "ovk"} {
		f.git.tenants = append(f.git.tenants, gitops.Tenant{Name: n})
	}
	return f
}

func TestCreateTenant_RefusesPlatformApplicationNames(t *testing.T) {
	users := map[string]*auth.User{"tok-new": resolvedUser(auth.NewGitHubUser("newcomer", nil))}
	for _, name := range []string{"root", "shared", "tenant", "loki", "otel", "external", "cloudnative", "grafana", "reflector", "valkey"} {
		t.Run(name, func(t *testing.T) {
			f := newCreateTenantFixture(t)
			w := postAs(t, f.router, "/api/v1/operations/create-tenant/execute", map[string]string{"tenant_name": name}, users["tok-new"])
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "reserved") {
				t.Fatalf("REST: status %d body %s; want 400 reserved", w.Code, w.Body.String())
			}

			mf := newCreateTenantFixture(t)
			backend := httptest.NewServer(tokenAuth(users)(mf.router))
			defer backend.Close()
			text, isError := callTool(t, mctlmcp.NewServer(backend.URL, ""), "tok-new", "mctl_create_tenant",
				map[string]string{"tenant_name": name})
			if !isError || !strings.Contains(text, "reserved") {
				t.Fatalf("MCP: isError=%v text=%q; want reserved", isError, text)
			}
			if len(f.exec.submitted)+len(mf.exec.submitted) != 0 {
				t.Fatalf("submitted REST %v MCP %v", f.exec.submitted, mf.exec.submitted)
			}
		})
	}
}

func TestCreateTenant_RefusesNamesOverlappingAnExistingTenant(t *testing.T) {
	users := map[string]*auth.User{"tok-new": resolvedUser(auth.NewGitHubUser("newcomer", nil))}
	for _, name := range []string{"labs-mctl", "admins-mctl", "erpact-oidc", "ovk-x"} {
		t.Run(name, func(t *testing.T) {
			f := newCreateTenantFixture(t)
			w := postAs(t, f.router, "/api/v1/operations/create-tenant/execute", map[string]string{"tenant_name": name}, users["tok-new"])
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "overlaps") {
				t.Fatalf("REST: status %d body %s; want 400 overlaps", w.Code, w.Body.String())
			}

			mf := newCreateTenantFixture(t)
			backend := httptest.NewServer(tokenAuth(users)(mf.router))
			defer backend.Close()
			text, isError := callTool(t, mctlmcp.NewServer(backend.URL, ""), "tok-new", "mctl_create_tenant",
				map[string]string{"tenant_name": name})
			if !isError || !strings.Contains(text, "overlaps") {
				t.Fatalf("MCP: isError=%v text=%q; want overlaps", isError, text)
			}
			if len(f.exec.submitted)+len(mf.exec.submitted) != 0 {
				t.Fatalf("submitted REST %v MCP %v", f.exec.submitted, mf.exec.submitted)
			}
		})
	}
}

func TestCreateTenant_TenantListReadFailureRefuses(t *testing.T) {
	f := newCreateTenantFixture(t)
	f.git.tenantNamesErr = errors.New("checkout stale")
	w := postAs(t, f.router, "/api/v1/operations/create-tenant/execute", map[string]string{"tenant_name": "acme"}, resolvedUser(auth.NewGitHubUser("newcomer", nil)))
	if w.Code != http.StatusServiceUnavailable || len(f.exec.submitted) != 0 {
		t.Fatalf("status %d, submitted %v; want 503 and nothing submitted", w.Code, f.exec.submitted)
	}
}

func TestCreateTenant_OrdinaryNameStillAccepted(t *testing.T) {
	f := newCreateTenantFixture(t)
	w := postAs(t, f.router, "/api/v1/operations/create-tenant/execute", map[string]string{"tenant_name": "acme"}, resolvedUser(auth.NewGitHubUser("newcomer", nil)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d; body %s", w.Code, w.Body.String())
	}
}

// An admin re-running create-tenant for an existing tenant is neither
// reserved nor a collision with itself.
func TestCreateTenant_ExistingTenantNamesStayValidForAdmins(t *testing.T) {
	admin := resolvedUser(auth.NewGitHubUser("root-admin", []string{"admins"}))
	for _, name := range []string{"admins", "erpact", "karabu", "labs", "mctl", "ovk"} {
		t.Run(name, func(t *testing.T) {
			f := newCreateTenantFixture(t)
			w := postAs(t, f.router, "/api/v1/operations/create-tenant/execute", map[string]string{"tenant_name": name}, admin)
			if w.Code != http.StatusAccepted {
				t.Fatalf("status %d; body %s", w.Code, w.Body.String())
			}
		})
	}
}

// Every registry operation that names a service is classified here, so an
// operation added later fails this test until someone decides whether it is
// gated. The gate is fail-closed: unlisted operations are gated.
func TestServiceOps_GatingTableCoversRegistry(t *testing.T) {
	notGated := map[string]bool{"provision-database": true, "preview-delete": true}
	fill := map[string]string{
		"team_name": "erpact", "component_name": "missing", "service_name": "missing", "app_name": "missing",
		"action": "deploy", "target_tag": "1.2.3", "image_tag": "1.2.3", "domain": "app.example.com",
		"preview_id": "abc123",
	}
	reg := operations.NewRegistry()
	seen := 0
	for _, op := range reg.List() {
		if _, _, ok := operations.ServiceTarget(op, fill); !ok || op.HandlerOnly {
			continue
		}
		seen++
		body := map[string]string{}
		for _, p := range op.Parameters {
			if v, ok := fill[p.Name]; ok {
				body[p.Name] = v
			}
		}
		f := newRoleFixture(t)
		w := postAs(t, f.router, "/api/v1/operations/"+op.Name+"/execute", body, member("olga-owner"))
		want := http.StatusNotFound
		if notGated[op.Name] {
			want = http.StatusAccepted
		}
		if w.Code != want {
			t.Errorf("%s: status %d, want %d (gated=%v); body %s", op.Name, w.Code, want, !notGated[op.Name], w.Body.String())
		}
	}
	if seen < 8 {
		t.Errorf("only %d service operations found; the table walk is broken", seen)
	}
}
