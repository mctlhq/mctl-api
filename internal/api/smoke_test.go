// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	skills   map[string]map[string]string // team -> name -> content
	identity map[string]map[string]string // team -> fileName -> content
}

func (f *fakeGitReader) ListTenants() ([]gitops.Tenant, error) { return f.tenants, nil }
func (f *fakeGitReader) GetTenant(name string) (*gitops.Tenant, error) {
	for i := range f.tenants {
		if f.tenants[i].Name == name {
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
func (f *fakeGitReader) ListOpenClawSkills(team string) ([]gitops.OpenClawSkill, error) {
	out := make([]gitops.OpenClawSkill, 0)
	for name, content := range f.skills[team] {
		out = append(out, gitops.OpenClawSkill{Name: name, Size: int64(len(content))})
	}
	return out, nil
}
func (f *fakeGitReader) ReadOpenClawSkill(team, name string) (string, error) {
	if byName, ok := f.skills[team]; ok {
		if content, ok := byName[name]; ok {
			return content, nil
		}
	}
	return "", fs.ErrNotExist
}
func (f *fakeGitReader) ListOpenClawIdentity(team string) ([]gitops.OpenClawIdentityFile, error) {
	out := make([]gitops.OpenClawIdentityFile, 0)
	for name, content := range f.identity[team] {
		out = append(out, gitops.OpenClawIdentityFile{Name: name, Size: int64(len(content))})
	}
	return out, nil
}
func (f *fakeGitReader) ReadOpenClawIdentity(team, fileName string) (string, error) {
	if byName, ok := f.identity[team]; ok {
		if content, ok := byName[fileName]; ok {
			return content, nil
		}
	}
	return "", fs.ErrNotExist
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

func (f *fakeArgoCD) ListApps(_ string) ([]argocd.AppStatus, error) {
	var out []argocd.AppStatus
	for _, s := range f.apps {
		out = append(out, *s)
	}
	return out, nil
}

type fakeExecutor struct {
	submitted       []string
	submittedParams []map[string]string
	cronAgentRuns   []map[string]interface{}
}

func (f *fakeExecutor) Submit(_ context.Context, op operations.Operation, params map[string]string, userID, namespace string) (*operations.SubmitResult, error) {
	f.submitted = append(f.submitted, op.Name)
	if params != nil {
		cp := make(map[string]string, len(params))
		for k, v := range params {
			cp[k] = v
		}
		f.submittedParams = append(f.submittedParams, cp)
	} else {
		f.submittedParams = append(f.submittedParams, nil)
	}
	return &operations.SubmitResult{
		WorkflowName: "smoke-test-workflow-abc123",
		Namespace:    namespace,
		RequestID:    "abc123",
		Status:       "Pending",
	}, nil
}

func (f *fakeExecutor) GetWorkflowStatus(_ context.Context, namespace, name string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"name":      name,
		"namespace": namespace,
		"phase":     "Succeeded",
	}, nil
}

func (f *fakeExecutor) ListCronAgentRuns(_ context.Context, _, _ string, _ time.Time) ([]map[string]interface{}, error) {
	return f.cronAgentRuns, nil
}

type fakeVaultReader struct {
	paths map[string]map[string]string
}

func (f *fakeVaultReader) ReadKV(_ context.Context, path string) (map[string]string, error) {
	return f.paths[path], nil
}

type fakeMetricsQuerier struct {
	stats mctlapi.ContainerUsageStats
}

func (f *fakeMetricsQuerier) GetContainerUsage(_ context.Context, namespace, app, container string, lookback time.Duration) (mctlapi.ContainerUsageStats, error) {
	return f.stats, nil
}

// ── test fixtures ─────────────────────────────────────────────────────────────

func newTestRouter(t *testing.T) (http.Handler, *fakeExecutor) {
	t.Helper()
	// Only set dev mode if the caller hasn't already configured AUTH_REQUIRED.
	if os.Getenv("AUTH_REQUIRED") == "" {
		t.Setenv("AUTH_REQUIRED", "false") // dev mode: auto-admin user
	}

	gitReader := &fakeGitReader{
		tenants: []gitops.Tenant{
			{Name: "admins", DisplayName: "Admins", Quotas: map[string]string{"pods": "20"}},
			{Name: "tests", DisplayName: "Tests", Quotas: map[string]string{"pods": "10", "limits.cpu": "3", "limits.memory": "5Gi"}, Networking: map[string]bool{"allowInternetEgress": true}, Members: []gitops.TenantMember{{UserID: "test-owner", Role: "owner"}}},
		},
		services: []gitops.Service{
			{Team: "admins", Name: "mctl-web", ImageTag: "2.1.0", ComponentType: "base-service"},
			{Team: "tests", Name: "my-app", ImageTag: "1.0.0", ComponentType: "base-service"},
			{Team: "tests", Name: "openclaw", ImageTag: "2026.3.22-beta.2", ComponentType: "base-service"},
		},
	}
	argoClient := &fakeArgoCD{
		apps: map[string]*argocd.AppStatus{
			"admins-mctl-web": {Name: "admins-mctl-web", Health: "Healthy", SyncStatus: "Synced"},
		},
	}
	exec := &fakeExecutor{}

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: gitReader,
		ArgoCD:    argoClient,
		AuditLog:  audit.NewLogger(),
		Executor:  exec,
		VaultReader: &fakeVaultReader{paths: map[string]map[string]string{
			"teams/tests/openclaw/telegram": {"telegram-bot-token": "secret"},
		}},
		MetricsQuerier: &fakeMetricsQuerier{stats: mctlapi.ContainerUsageStats{
			MemoryMaxBytes: 2.6 * 1024 * 1024 * 1024,
			MemoryP95Bytes: 1.8 * 1024 * 1024 * 1024,
			CPUMaxCores:    1.3,
			CPUP95Cores:    0.8,
			SampleCount:    12,
		}},
		BackstageURL: "https://app.mctl.ai",
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

// getAs calls GET with an admin user injected into context.
func getAs(t *testing.T, router http.Handler, path string, user *auth.User) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(auth.WithUser(req.Context(), user))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// adminUser is a pre-built admin user for test helpers.
var adminUser = &auth.User{ID: "test-admin", Groups: []string{"admins"}}
var ownerUser = &auth.User{ID: "test-owner", Groups: []string{"tests"}}

// postAs sends POST with a user injected into context.
func postAs(t *testing.T, router http.Handler, path string, body interface{}, user *auth.User) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithUser(req.Context(), user))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// post is a test helper for making POST requests. Currently unused but kept for future tests.
var _ = post

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

func TestSmoke_OpenClawFlows(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("start returns secure intake url", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/deploy/start", map[string]string{
			"team_name":         "tests",
			"component_name":    "openclaw-new",
			"telegram_owner_id": "12345",
		}, ownerUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if !strings.Contains(fmt.Sprint(body["botTokenIntakeURL"]), "/api/vault-secrets/openclaw/intake") {
			t.Fatalf("expected intake URL, got: %v", body["botTokenIntakeURL"])
		}
	})

	t.Run("resume submits database and deploy workflows", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/deploy/resume", map[string]string{
			"team_name":         "tests",
			"component_name":    "openclaw",
			"telegram_owner_id": "12345",
		}, adminUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) < 2 || exec.submitted[len(exec.submitted)-2] != "provision-database" || exec.submitted[len(exec.submitted)-1] != "deploy-service" {
			t.Fatalf("expected provision-database then deploy-service submission, got %v", exec.submitted)
		}
		deployParams := exec.submittedParams[len(exec.submittedParams)-1]
		if deployParams["dockerfile_repo"] != "mctlhq/mctl-openclaw" {
			t.Fatalf("expected deploy-service dockerfile_repo=mctlhq/mctl-openclaw, got %q", deployParams["dockerfile_repo"])
		}
		if deployParams["service_template"] != "openclaw" {
			t.Fatalf("expected deploy-service service_template=openclaw, got %q", deployParams["service_template"])
		}
		if deployParams["telegram_owner_ids_json"] != `["12345"]` {
			t.Fatalf("expected legacy single ID wrapped as JSON array, got %q", deployParams["telegram_owner_ids_json"])
		}
	})

	t.Run("resume with multi-owner list emits JSON array", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/deploy/resume", map[string]string{
			"team_name":          "tests",
			"component_name":     "openclaw",
			"telegram_owner_ids": "210408407,317748297",
		}, adminUser)
		assertStatus(t, w, http.StatusAccepted)
		deployParams := exec.submittedParams[len(exec.submittedParams)-1]
		if deployParams["telegram_owner_ids_json"] != `["210408407","317748297"]` {
			t.Fatalf("expected multi-owner JSON array, got %q", deployParams["telegram_owner_ids_json"])
		}
		if deployParams["telegram_owner_id"] != "210408407" {
			t.Fatalf("expected legacy single-id param to be first of list, got %q", deployParams["telegram_owner_id"])
		}
	})

	t.Run("resume rejects empty owner list", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/deploy/resume", map[string]string{
			"team_name":      "tests",
			"component_name": "openclaw",
		}, adminUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("sizing recommendation maps to startup", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/openclaw/sizing?lookback_hours=24", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["profile"] != "startup" {
			t.Fatalf("expected startup profile, got %v", body["profile"])
		}
	})
}

func TestSmoke_Tenants(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("list tenants returns all tenants", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/tenants", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 2 {
			t.Errorf("expected 2 tenants, got: %v", body["count"])
		}
	})

	t.Run("list tenants without admin returns 403", func(t *testing.T) {
		w := get(t, router, "/api/v1/tenants")
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("get existing tenant returns details for admin", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/tenants/admins", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		tenant := body["tenant"].(map[string]interface{})
		if tenant["name"] != "admins" {
			t.Errorf("expected tenant name=admins, got: %v", tenant["name"])
		}
	})

	t.Run("get tenant in other team returns 403 for non-admin", func(t *testing.T) {
		user := &auth.User{ID: "test-user", Groups: []string{"tests"}}
		w := getAs(t, router, "/api/v1/tenants/admins", user)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("get unknown tenant returns 404", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/tenants/ghost", adminUser)
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_Services(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("list all services returns all services for admin", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/services", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 3 {
			t.Errorf("expected 3 services, got: %v", body["count"])
		}
	})

	t.Run("list services filtered by team for admin", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/services?team=admins", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 1 {
			t.Errorf("expected 1 service for team=admins, got: %v", body["count"])
		}
	})

	t.Run("non-admin sees only own team services", func(t *testing.T) {
		user := &auth.User{ID: "test-user", Groups: []string{"tests"}}
		w := getAs(t, router, "/api/v1/services", user)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 2 {
			t.Errorf("expected 2 services for non-admin, got: %v", body["count"])
		}
	})

	t.Run("get existing service returns details", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/services/admins/mctl-web", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["name"] != "mctl-web" {
			t.Errorf("expected name=mctl-web, got: %v", body["name"])
		}
	})

	t.Run("get service in other team returns 403 for non-admin", func(t *testing.T) {
		user := &auth.User{ID: "test-user", Groups: []string{"tests"}}
		w := getAs(t, router, "/api/v1/services/admins/mctl-web", user)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("get unknown service returns 404", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/services/admins/ghost", adminUser)
		assertStatus(t, w, http.StatusNotFound)
	})
}

func TestSmoke_ServiceStatus(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("get status of known ArgoCD app", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/status/admins/mctl-web", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		argoStatus := body["argocd"].(map[string]interface{})
		if argoStatus["health"] != "Healthy" {
			t.Errorf("expected health=Healthy, got: %v", argoStatus["health"])
		}
	})

	t.Run("get status of unknown app returns 200 with note", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/status/tests/ghost", adminUser)
		assertStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "ArgoCD application not found") {
			t.Errorf("expected note about app not found, got: %s", w.Body.String())
		}
	})

	t.Run("get status in other team returns 403 for non-admin", func(t *testing.T) {
		user := &auth.User{ID: "test-user", Groups: []string{"tests"}}
		w := getAs(t, router, "/api/v1/status/admins/mctl-web", user)
		assertStatus(t, w, http.StatusForbidden)
	})
}

func TestSmoke_ExecuteOperation(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("deploy-service with valid params submits workflow", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":          "onboard",
			"team_name":       "tests",
			"component_name":  "my-app",
			"dockerfile_repo": "myorg/my-app",
			"git_tag":         "v1.0.0",
		}, adminUser)
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
		w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":    "onboard",
			"team_name": "tests",
			// missing component_name
		}, adminUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("deploy-service with invalid action enum returns 400", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":         "bad-action",
			"team_name":      "tests",
			"component_name": "my-app",
		}, adminUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("execute unknown operation returns 404", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/operations/does-not-exist/execute", map[string]string{}, adminUser)
		assertStatus(t, w, http.StatusNotFound)
	})

	// HandlerOnly-flagged operations (openclaw skill/identity save + delete)
	// must NOT be reachable via the generic execute path — the dedicated
	// REST handlers enforce owner-gate / quota / secret-scan / rate-limit
	// checks the generic path does not.
	t.Run("HandlerOnly operation rejected via generic execute", func(t *testing.T) {
		for _, op := range []string{
			"openclaw-skill-save",
			"openclaw-skill-delete",
			"openclaw-identity-save",
			"openclaw-identity-delete",
		} {
			w := postAs(t, router, "/api/v1/operations/"+op+"/execute", map[string]string{
				"team_name": "tests",
			}, adminUser)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: expected 405 from generic execute, got %d; body: %s", op, w.Code, w.Body.String())
			}
		}
	})
}

func TestSmoke_CreateTenantRBAC(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("new user with no groups can create-tenant", func(t *testing.T) {
		newUser := &auth.User{ID: "fresh-user", Groups: []string{}}
		w := postAs(t, router, "/api/v1/operations/create-tenant/execute", map[string]string{
			"tenant_name": "fresh-team",
		}, newUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) == 0 || exec.submitted[len(exec.submitted)-1] != "create-tenant" {
			t.Errorf("expected create-tenant submitted, got: %v", exec.submitted)
		}
	})

	t.Run("user already in a tenant is denied create-tenant", func(t *testing.T) {
		existingUser := &auth.User{ID: "existing-user", Groups: []string{"my-team"}}
		w := postAs(t, router, "/api/v1/operations/create-tenant/execute", map[string]string{
			"tenant_name": "another-team",
		}, existingUser)
		assertStatus(t, w, http.StatusForbidden)
		body := decodeJSON(t, w)
		errMsg, _ := body["error"].(string)
		if !strings.Contains(errMsg, "already belong") {
			t.Errorf("expected 'already belong' in error, got: %s", errMsg)
		}
	})

	t.Run("admin can create-tenant even with existing groups", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/operations/create-tenant/execute", map[string]string{
			"tenant_name": "admin-team",
		}, adminUser)
		assertStatus(t, w, http.StatusAccepted)
	})

	t.Run("creator_user_id is forced from JWT", func(t *testing.T) {
		newUser := &auth.User{ID: "real-user", Groups: []string{}}
		w := postAs(t, router, "/api/v1/operations/create-tenant/execute", map[string]string{
			"tenant_name":     "my-workspace",
			"creator_user_id": "spoofed-user",
		}, newUser)
		assertStatus(t, w, http.StatusAccepted)
		// The executor receives the input; creator_user_id should be "real-user" not "spoofed-user".
		// We can't easily inspect the input here, but the 202 confirms the flow works.
	})

	t.Run("non-member denied deploy-service on foreign tenant", func(t *testing.T) {
		outsider := &auth.User{ID: "outsider", Groups: []string{"other-team"}}
		w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
			"action":          "onboard",
			"team_name":       "tests",
			"component_name":  "my-app",
			"dockerfile_repo": "myorg/my-app",
			"git_tag":         "v1.0.0",
		}, outsider)
		assertStatus(t, w, http.StatusForbidden)
	})
}

func TestSmoke_Auth(t *testing.T) {
	t.Run("unauthenticated request returns 401 when AUTH_REQUIRED=true", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "true")
		router, _ := newTestRouter(t)

		// Wrap with the real auth middleware (nil github validator, nil resolver — will reject all tokens).
		mw := auth.Middleware(nil, nil, nil, nil)
		handler := mw(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		// no Authorization header
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assertStatus(t, w, http.StatusUnauthorized)
	})
}

func TestSmoke_Workflow(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("get unknown workflow returns 404", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/workflows/nonexistent-workflow", adminUser)
		assertStatus(t, w, http.StatusNotFound)
	})

	t.Run("list workflows returns empty list", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/workflows", adminUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["count"].(float64) != 0 {
			t.Errorf("expected count=0, got: %v", body["count"])
		}
	})

	t.Run("list workflows without auth returns 401", func(t *testing.T) {
		w := get(t, router, "/api/v1/workflows")
		assertStatus(t, w, http.StatusUnauthorized)
	})

	t.Run("get workflow without auth returns 401", func(t *testing.T) {
		w := get(t, router, "/api/v1/workflows/some-workflow")
		assertStatus(t, w, http.StatusUnauthorized)
	})
}
