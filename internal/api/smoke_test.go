package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeGitReader struct {
	tenants  []gitops.Tenant
	services []gitops.Service
}

func (f *fakeGitReader) ListTenants() ([]gitops.Tenant, error) { return f.tenants, nil }
func (f *fakeGitReader) GetTenant(name string) (*gitops.Tenant, error) {
	for i, t := range f.tenants {
		if t.Name == name {
			return &f.tenants[i], nil
		}
	}
	return nil, fmt.Errorf("tenant not found: %s", name)
}
func (f *fakeGitReader) ListServices(teamFilter string) ([]gitops.Service, error) {
	if teamFilter == "" {
		return f.services, nil
	}
	var out []gitops.Service
	for _, s := range f.services {
		if s.Team == teamFilter {
			out = append(out, s)
		}
	}
	return out, nil
}
func (f *fakeGitReader) GetService(team, app string) (*gitops.Service, error) {
	for i, s := range f.services {
		if s.Team == team && s.Name == app {
			return &f.services[i], nil
		}
	}
	return nil, fmt.Errorf("service not found: %s/%s", team, app)
}

type fakeArgoCD struct {
	apps map[string]*argocd.AppStatus
}

func (f *fakeArgoCD) GetAppStatus(name string) (*argocd.AppStatus, error) {
	if s, ok := f.apps[name]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("app not found: %s", name)
}

type fakeExecutor struct {
	submitted []string
}

func (f *fakeExecutor) Submit(_ context.Context, op operations.Operation, _ map[string]string, userID, namespace string) (*operations.SubmitResult, error) {
	f.submitted = append(f.submitted, op.Name)
	return &operations.SubmitResult{
		WorkflowName: "smoke-test-workflow-abc123",
		Namespace:    namespace,
		RequestID:    "abc123",
		Status:       "Pending",
	}, nil
}

// ── test fixtures ─────────────────────────────────────────────────────────────

func newTestRouter(t *testing.T) (http.Handler, *fakeExecutor) {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false") // dev mode: auto-admin user

	gitReader := &fakeGitReader{
		tenants: []gitops.Tenant{
			{Name: "admins", DisplayName: "Admins", Quotas: map[string]string{"pods": "20"}},
			{Name: "tests", DisplayName: "Tests", Quotas: map[string]string{"pods": "10"}},
		},
		services: []gitops.Service{
			{Team: "admins", Name: "mctl-web", ImageTag: "2.1.0", ComponentType: "base-service"},
			{Team: "tests", Name: "my-app", ImageTag: "1.0.0", ComponentType: "base-service"},
		},
	}
	argoClient := &fakeArgoCD{
		apps: map[string]*argocd.AppStatus{
			"admins-mctl-web": {Name: "admins-mctl-web", Health: "Healthy", SyncStatus: "Synced"},
		},
	}
	exec := &fakeExecutor{}

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry: operations.NewRegistry(),
		GitReader: gitReader,
		ArgoCD:   argoClient,
		AuditLog: audit.NewLogger(),
		Executor: exec,
	})
	return router, exec
}

// ── helpers ───────────────────────────────────────────────────────────────────

func get(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func post(t *testing.T, router http.Handler, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if w.Code != expected {
		t.Errorf("expected status %d, got %d; body: %s", expected, w.Code, w.Body.String())
	}
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode JSON response: %v; body: %s", err, w.Body.String())
	}
	return out
}

// ── smoke tests ───────────────────────────────────────────────────────────────

func TestSmoke_HealthChecks(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("healthz returns 200", func(t *testing.T) {
		w := get(t, router, "/healthz")
		assertStatus(t, w, http.StatusOK)
	})

	t.Run("readyz returns 200", func(t *testing.T) {
		w := get(t, router, "/readyz")
		assertStatus(t, w, http.StatusOK)
	})
}

func TestSmoke_Operations(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("list operations returns all builtin ops", func(t *testing.T) {
		w := get(t, router, "/api/v1/operations")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		count, ok := body["count"].(float64)
		if !ok || count == 0 {
			t.Errorf("expected non-zero operations count, got: %v", body["count"])
		}
	})

	t.Run("get known operation returns details", func(t *testing.T) {
		w := get(t, router, "/api/v1/operations/deploy-service")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["name"] != "deploy-service" {
			t.Errorf("expected name=deploy-service, got: %v", body["name"])
		}
	})

	t.Run("get unknown operation returns 404", func(t *testing.T) {
		w := get(t, router, "/api/v1/operations/does-not-exist")
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_Tenants(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("list tenants returns all tenants", func(t *testing.T) {
		w := get(t, router, "/api/v1/tenants")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 2 {
			t.Errorf("expected 2 tenants, got: %v", body["count"])
		}
	})

	t.Run("get existing tenant returns details", func(t *testing.T) {
		w := get(t, router, "/api/v1/tenants/admins")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		tenant := body["tenant"].(map[string]interface{})
		if tenant["name"] != "admins" {
			t.Errorf("expected tenant name=admins, got: %v", tenant["name"])
		}
	})

	t.Run("get unknown tenant returns 404", func(t *testing.T) {
		w := get(t, router, "/api/v1/tenants/ghost")
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_Services(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("list all services returns all services", func(t *testing.T) {
		w := get(t, router, "/api/v1/services")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 2 {
			t.Errorf("expected 2 services, got: %v", body["count"])
		}
	})

	t.Run("list services filtered by team", func(t *testing.T) {
		w := get(t, router, "/api/v1/services?team=admins")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 1 {
			t.Errorf("expected 1 service for team=admins, got: %v", body["count"])
		}
	})

	t.Run("get existing service returns details", func(t *testing.T) {
		w := get(t, router, "/api/v1/services/admins/mctl-web")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["name"] != "mctl-web" {
			t.Errorf("expected name=mctl-web, got: %v", body["name"])
		}
	})

	t.Run("get unknown service returns 404", func(t *testing.T) {
		w := get(t, router, "/api/v1/services/admins/ghost")
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_ServiceStatus(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("get status of known ArgoCD app", func(t *testing.T) {
		w := get(t, router, "/api/v1/status/admins/mctl-web")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		argoStatus := body["argocd"].(map[string]interface{})
		if argoStatus["health"] != "Healthy" {
			t.Errorf("expected health=Healthy, got: %v", argoStatus["health"])
		}
	})

	t.Run("get status of unknown app returns 404", func(t *testing.T) {
		w := get(t, router, "/api/v1/status/tests/ghost")
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_ExecuteOperation(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("deploy-service with valid params submits workflow", func(t *testing.T) {
		w := post(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":          "onboard",
			"team_name":       "tests",
			"component_name":  "my-app",
			"dockerfile_repo": "myorg/my-app",
			"git_tag":         "v1.0.0",
		})
		assertStatus(t, w, http.StatusAccepted)
		body := decodeJSON(t, w)
		if body["operation"] != "deploy-service" {
			t.Errorf("expected operation=deploy-service, got: %v", body["operation"])
		}
		if len(exec.submitted) == 0 || exec.submitted[len(exec.submitted)-1] != "deploy-service" {
			t.Errorf("expected executor to have submitted deploy-service, got: %v", exec.submitted)
		}
	})

	t.Run("deploy-service with missing required param returns 400", func(t *testing.T) {
		w := post(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":    "onboard",
			"team_name": "tests",
			// missing component_name
		})
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("deploy-service with invalid action enum returns 400", func(t *testing.T) {
		w := post(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":         "bad-action",
			"team_name":      "tests",
			"component_name": "my-app",
		})
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("execute unknown operation returns 404", func(t *testing.T) {
		w := post(t, router, "/api/v1/operations/does-not-exist/execute", map[string]string{})
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_Auth(t *testing.T) {
	t.Run("unauthenticated request returns 401 when AUTH_REQUIRED=true", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "true")
		router, _ := newTestRouter(t)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		// no Authorization header
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assertStatus(t, w, http.StatusUnauthorized)
	})
}

func TestSmoke_Workflow(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("get unknown workflow returns status unknown", func(t *testing.T) {
		w := get(t, router, "/api/v1/workflows/nonexistent-workflow")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["status"] != "unknown" {
			t.Errorf("expected status=unknown for nonexistent workflow, got: %v", body["status"])
		}
	})

	t.Run("list workflows returns empty list", func(t *testing.T) {
		w := get(t, router, "/api/v1/workflows")
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 0 {
			t.Errorf("expected count=0, got: %v", body["count"])
		}
	})
}
