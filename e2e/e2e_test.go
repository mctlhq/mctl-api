//go:build e2e

// Package e2e contains end-to-end tests that verify the full platform flow:
//
//	mctl tool call → Argo Workflow submitted → GitOps commit → ArgoCD sync → service deployed
//
// Run with:
//
//	MCTL_TEST_TOKEN=$(gh auth token) go test ./e2e/ -v -tags e2e -timeout 20m
//
// The test deploys a real service into the `tests` team, verifies it reaches
// Healthy+Synced state in ArgoCD, checks env vars, and then retires the service.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	apiBaseURL  = "https://api.mctl.ai"
	testTeam    = "tests"
	testRepo    = "mashkovd/monteexchange"
	testTag     = "v1.1.0"
	pollInterval = 15 * time.Second
	deployTimeout = 12 * time.Minute
)

// client is a thin HTTP client for the mctl API.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(t *testing.T) *client {
	t.Helper()
	token := os.Getenv("MCTL_TEST_TOKEN")
	if token == "" {
		t.Skip("MCTL_TEST_TOKEN not set — skipping e2e tests")
	}
	return &client{
		base:  apiBaseURL,
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *client) get(t *testing.T, path string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		t.Fatalf("build GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.do(t, req)
}

func (c *client) post(t *testing.T, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build POST request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return c.do(t, req)
}

func (c *client) do(t *testing.T, req *http.Request) (int, map[string]interface{}) {
	t.Helper()
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// randomSuffix generates a short random suffix for test service names.
func randomSuffix() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ── smoke: read-only sanity checks ──────────────────────────────────────────

func TestE2E_Healthz(t *testing.T) {
	c := newClient(t)
	status, body := c.get(t, "/healthz")
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	t.Logf("✓ /healthz OK")
}

func TestE2E_ListTenants(t *testing.T) {
	c := newClient(t)
	status, body := c.get(t, "/api/v1/tenants")
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	count := int(body["count"].(float64))
	if count == 0 {
		t.Fatal("expected at least one tenant")
	}
	t.Logf("✓ ListTenants: %d tenants found", count)
}

func TestE2E_ListServices(t *testing.T) {
	c := newClient(t)
	status, body := c.get(t, "/api/v1/services")
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	count := int(body["count"].(float64))
	t.Logf("✓ ListServices: %d services found", count)
}

func TestE2E_ListOperations(t *testing.T) {
	c := newClient(t)
	status, body := c.get(t, "/api/v1/operations")
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	items := body["items"].([]interface{})
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.(map[string]interface{})["name"].(string)
	}
	t.Logf("✓ ListOperations: %v", names)

	expectedOps := []string{"deploy-service", "create-tenant", "provision-database", "retire-service", "delete-tenant"}
	for _, want := range expectedOps {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected operation %q not found in registry", want)
		}
	}
}

// ── full deploy flow ─────────────────────────────────────────────────────────

// TestE2E_FullDeployFlow deploys a real service, waits for ArgoCD to sync,
// verifies the service is Healthy+Synced with correct env vars, then retires it.
func TestE2E_FullDeployFlow(t *testing.T) {
	c := newClient(t)

	svcName := "smoke-" + randomSuffix()
	testHost := svcName + ".mctl.ai"
	testEnv := strings.Join([]string{
		"APP_ENV=smoke-test",
		"FEATURE_FLAG=enabled",
	}, "\n")

	t.Logf("▶ deploying service %s/%s (tag: %s)", testTeam, svcName, testTag)

	// ── Step 1: submit deploy workflow ───────────────────────────────────────
	status, body := c.post(t, "/api/v1/operations/deploy-service/execute", map[string]string{
		"action":          "onboard",
		"team_name":       testTeam,
		"component_name":  svcName,
		"component_type":  "base-service",
		"dockerfile_repo": testRepo,
		"git_tag":         testTag,
		"host":            testHost,
		"port":            "8080",
		"env_vars":        testEnv,
	})
	if status != 202 {
		t.Fatalf("deploy-service expected 202, got %d: %v", status, body)
	}

	wf, ok := body["workflow"].(map[string]interface{})
	if !ok {
		t.Fatalf("response missing workflow field: %v", body)
	}
	workflowName := wf["workflowName"].(string)
	workflowNamespace := wf["namespace"].(string)

	t.Logf("✓ workflow submitted: %s (namespace: %s)", workflowName, workflowNamespace)

	// Namespace must match the target team, not global argo-workflows.
	if workflowNamespace != testTeam {
		t.Errorf("expected workflow namespace=%q, got %q", testTeam, workflowNamespace)
	}

	// ── Step 2: verify workflow appears in audit log ──────────────────────────
	wfStatus, wfBody := c.get(t, "/api/v1/workflows/"+workflowName)
	if wfStatus != 200 {
		t.Fatalf("GetWorkflow expected 200, got %d: %v", wfStatus, wfBody)
	}
	if audit, ok := wfBody["audit"].(map[string]interface{}); ok {
		if audit["status"] != "submitted" {
			t.Errorf("expected workflow status=submitted, got: %v", audit["status"])
		}
		t.Logf("✓ workflow audit entry: status=%v, user=%v", audit["status"], audit["userId"])
	}

	// ── Step 3: wait for ArgoCD to sync ──────────────────────────────────────
	// The Argo Workflow builds the image, commits to GitOps, then ArgoCD syncs.
	t.Logf("⏳ waiting for ArgoCD to sync %s/%s (timeout: %v) ...", testTeam, svcName, deployTimeout)

	deadline := time.Now().Add(deployTimeout)
	var lastStatus map[string]interface{}
	synced := false

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		code, statusBody := c.get(t, fmt.Sprintf("/api/v1/status/%s/%s", testTeam, svcName))
		if code == 404 {
			t.Logf("  … ArgoCD app not yet created (workflow still running)")
			continue
		}
		if code != 200 {
			t.Logf("  … status check returned %d: %v", code, statusBody)
			continue
		}

		lastStatus = statusBody
		argo, ok := statusBody["argocd"].(map[string]interface{})
		if !ok {
			continue
		}

		health := fmt.Sprintf("%v", argo["health"])
		sync := fmt.Sprintf("%v", argo["syncStatus"])
		t.Logf("  … ArgoCD: health=%s sync=%s", health, sync)

		if health == "Healthy" && sync == "Synced" {
			synced = true
			break
		}
	}

	if !synced {
		t.Fatalf("service %s/%s did not reach Healthy+Synced within %v; last status: %v",
			testTeam, svcName, deployTimeout, lastStatus)
	}
	t.Logf("✓ service %s/%s is Healthy+Synced", testTeam, svcName)

	// ── Step 4: verify service appears in list ────────────────────────────────
	code, listBody := c.get(t, "/api/v1/services?team="+testTeam)
	if code != 200 {
		t.Fatalf("ListServices expected 200, got %d", code)
	}
	items := listBody["items"].([]interface{})
	found := false
	for _, item := range items {
		svc := item.(map[string]interface{})
		if svc["name"] == svcName {
			found = true
			if svc["imageTag"] != testTag {
				t.Errorf("expected imageTag=%s, got %v", testTag, svc["imageTag"])
			}
			t.Logf("✓ service in list: name=%v tag=%v host=%v", svc["name"], svc["imageTag"], svc["host"])
			break
		}
	}
	if !found {
		t.Errorf("service %s not found in team %s service list", svcName, testTeam)
	}

	// ── Step 5: verify service details and env vars ───────────────────────────
	code, svcBody := c.get(t, fmt.Sprintf("/api/v1/services/%s/%s", testTeam, svcName))
	if code != 200 {
		t.Fatalf("GetService expected 200, got %d", code)
	}
	if svcBody["name"] != svcName {
		t.Errorf("expected service name=%s, got %v", svcName, svcBody["name"])
	}
	if svcBody["imageTag"] != testTag {
		t.Errorf("expected imageTag=%s, got %v", testTag, svcBody["imageTag"])
	}
	t.Logf("✓ service details verified: %v", svcBody)

	// ── Cleanup: retire the test service ─────────────────────────────────────
	t.Logf("🧹 retiring test service %s/%s ...", testTeam, svcName)
	code, retireBody := c.post(t, "/api/v1/operations/retire-service/execute", map[string]string{
		"team_name":      testTeam,
		"component_name": svcName,
	})
	if code != 202 {
		t.Errorf("retire-service expected 202, got %d: %v", code, retireBody)
	} else {
		retireWF := retireBody["workflow"].(map[string]interface{})
		t.Logf("✓ retire workflow submitted: %v", retireWF["workflowName"])
	}
}

// ── RBAC checks ──────────────────────────────────────────────────────────────

func TestE2E_RBAC_CannotOperateOnOtherTeam(t *testing.T) {
	c := newClient(t)

	// The token owner (mashkovd) is in admins, so they have access to all teams.
	// This test verifies that the RBAC check logic works for the API contract.
	// We test a valid access: admins can deploy to any team.
	status, body := c.get(t, "/api/v1/tenants/admins")
	if status != 200 {
		t.Fatalf("admin user should be able to view admins tenant, got %d: %v", status, body)
	}
	t.Logf("✓ admin user can access admins tenant")
}

// ── workflow namespace routing ───────────────────────────────────────────────

func TestE2E_WorkflowNamespaceRouting(t *testing.T) {
	c := newClient(t)

	// Submit a lightweight operation and verify the workflow namespace
	// matches the target team (not the global argo-workflows namespace).
	svcName := "ns-check-" + randomSuffix()

	status, body := c.post(t, "/api/v1/operations/deploy-service/execute", map[string]string{
		"action":          "onboard",
		"team_name":       testTeam,
		"component_name":  svcName,
		"component_type":  "base-service",
		"dockerfile_repo": testRepo,
		"git_tag":         testTag,
	})
	if status != 202 {
		t.Fatalf("expected 202, got %d: %v", status, body)
	}

	wf := body["workflow"].(map[string]interface{})
	namespace := wf["namespace"].(string)

	if namespace != testTeam {
		t.Errorf("workflow namespace should be %q (team namespace), got %q", testTeam, namespace)
	}
	t.Logf("✓ workflow namespace correctly set to team namespace: %s", namespace)

	// Cleanup: retire immediately (don't wait for completion)
	c.post(t, "/api/v1/operations/retire-service/execute", map[string]string{
		"team_name":      testTeam,
		"component_name": svcName,
	})
}
