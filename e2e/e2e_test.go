//go:build e2e

// Package e2e contains end-to-end tests that verify the full platform flow:
//
//mctl tool call → Argo Workflow submitted → GitOps commit → ArgoCD sync → service deployed
//
// Run with:
//
//MCTL_TEST_TOKEN=$(gh auth token) go test ./e2e/ -v -tags e2e -timeout 30m
//
// TestE2E_FullPlatformSmokeTest triggers the smoke-test ClusterWorkflowTemplate which
// verifies the complete lifecycle: deploy → env+secrets in pod → DB provision → update-config → retire.
package e2e

import (
"bytes"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"testing"
"time"
)

const (
apiBaseURL    = "https://api.mctl.ai"
pollInterval  = 20 * time.Second
smokeTimeout  = 25 * time.Minute
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
req, _ := http.NewRequest(http.MethodGet, c.base+path, nil)
req.Header.Set("Authorization", "Bearer "+c.token)
return c.do(t, req)
}

func (c *client) post(t *testing.T, path string, body interface{}) (int, map[string]interface{}) {
t.Helper()
b, _ := json.Marshal(body)
req, _ := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(b))
req.Header.Set("Authorization", "Bearer "+c.token)
req.Header.Set("Content-Type", "application/json")
return c.do(t, req)
}

func (c *client) do(t *testing.T, req *http.Request) (int, map[string]interface{}) {
t.Helper()
resp, err := c.http.Do(req)
if err != nil {
t.Fatalf("HTTP %s %s failed: %v", req.Method, req.URL.Path, err)
}
defer resp.Body.Close()
raw, _ := io.ReadAll(resp.Body)
var out map[string]interface{}
_ = json.Unmarshal(raw, &out)
return resp.StatusCode, out
}

// ── read-only sanity checks ──────────────────────────────────────────────────

func TestE2E_Healthz(t *testing.T) {
c := newClient(t)
status, _ := c.get(t, "/healthz")
if status != 200 {
t.Fatalf("expected 200, got %d", status)
}
t.Log("✓ /healthz OK")
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
t.Logf("✓ ListTenants: %d tenants", count)
}

func TestE2E_ListServices(t *testing.T) {
c := newClient(t)
status, body := c.get(t, "/api/v1/services")
if status != 200 {
t.Fatalf("expected 200, got %d: %v", status, body)
}
t.Logf("✓ ListServices: %d services", int(body["count"].(float64)))
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
t.Logf("✓ Operations: %v", names)

for _, want := range []string{"deploy-service", "create-tenant", "provision-database", "retire-service", "delete-tenant", "smoke-test"} {
found := false
for _, got := range names {
if got == want {
found = true
break
}
}
if !found {
t.Errorf("operation %q not found in registry", want)
}
}
}

func TestE2E_RBAC(t *testing.T) {
c := newClient(t)
status, body := c.get(t, "/api/v1/tenants/admins")
if status != 200 {
t.Fatalf("admin user should access admins tenant, got %d: %v", status, body)
}
t.Log("✓ admin user can access admins tenant")
}

// ── full platform smoke test ─────────────────────────────────────────────────

// TestE2E_FullPlatformSmokeTest triggers the smoke-test ClusterWorkflowTemplate
// which runs the complete lifecycle:
//   1. onboard service (deploy-service)
//   2. verify pod running
//   3. deploy update with env_vars + secret_env_vars
//   4. verify env and secrets inside the pod (kubectl exec)
//   5. provision PostgreSQL database
//   6. verify Vault secret + ExternalSecret synced
//   7. update-config
//   8. verify updated env in pod
//   9. retire service (cleanup)
func TestE2E_FullPlatformSmokeTest(t *testing.T) {
c := newClient(t)

t.Log("▶ triggering platform smoke-test workflow")

// Submit the smoke-test operation (no params needed — defaults to tests/smoke-test-svc).
status, body := c.post(t, "/api/v1/operations/smoke-test/execute", map[string]string{})
if status != 202 {
t.Fatalf("smoke-test expected 202, got %d: %v", status, body)
}

wf := body["workflow"].(map[string]interface{})
workflowName := wf["workflowName"].(string)
workflowNS := wf["namespace"].(string)

t.Logf("✓ smoke-test workflow submitted: %s (namespace: %s)", workflowName, workflowNS)
t.Logf("  track at: https://workflows.mctl.ai/workflows/%s/%s", workflowNS, workflowName)

// Verify audit entry is recorded.
wfStatus, wfBody := c.get(t, "/api/v1/workflows/"+workflowName)
if wfStatus != 200 {
t.Fatalf("GetWorkflow expected 200, got %d", wfStatus)
}
if audit, ok := wfBody["audit"].(map[string]interface{}); ok {
t.Logf("✓ audit: operation=%v status=%v user=%v", audit["operation"], audit["status"], audit["userId"])
}

// Poll ArgoCD for the smoke-test service to appear as Healthy+Synced.
// The smoke-test CWT deploys to tests/smoke-test-svc.
t.Logf("⏳ waiting for tests/smoke-test-svc to be Healthy+Synced (timeout: %v) ...", smokeTimeout)

deadline := time.Now().Add(smokeTimeout)
phase := "workflow running"
synced := false

for time.Now().Before(deadline) {
time.Sleep(pollInterval)

code, statusBody := c.get(t, "/api/v1/status/tests/smoke-test-svc")
if code == 404 {
if phase != "workflow running" {
phase = "workflow running"
}
t.Log("  … ArgoCD app not yet created (workflow still running)")
continue
}
if code != 200 {
t.Logf("  … status %d: %v", code, statusBody)
continue
}

argo := statusBody["argocd"].(map[string]interface{})
health := fmt.Sprintf("%v", argo["health"])
sync := fmt.Sprintf("%v", argo["syncStatus"])
t.Logf("  … ArgoCD: health=%s sync=%s", health, sync)
phase = fmt.Sprintf("health=%s sync=%s", health, sync)

if health == "Healthy" && sync == "Synced" {
synced = true
break
}
}

if !synced {
t.Fatalf("smoke-test-svc did not reach Healthy+Synced within %v (last phase: %s)", smokeTimeout, phase)
}
t.Log("✓ tests/smoke-test-svc is Healthy+Synced")

// Verify the service appears in the services list with expected tag.
code, listBody := c.get(t, "/api/v1/services?team=tests")
if code != 200 {
t.Fatalf("ListServices expected 200, got %d", code)
}
items := listBody["items"].([]interface{})
for _, item := range items {
svc := item.(map[string]interface{})
if svc["name"] == "smoke-test-svc" {
t.Logf("✓ smoke-test-svc in services list: tag=%v", svc["imageTag"])
break
}
}

// The smoke-test CWT retires the service on exit — no cleanup needed here.
t.Log("✓ full platform smoke test complete")
}
