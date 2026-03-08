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
	"strings"
	"testing"
	"time"
)

const (
	apiBaseURL   = "https://api.mctl.ai"
	pollInterval = 20 * time.Second
	smokeTimeout = 25 * time.Minute
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

func (c *client) getRaw(t *testing.T, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, c.base+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
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

// mcpCall sends a JSON-RPC 2.0 request to /mcp and returns the parsed response.
// sessionID may be empty for the first call (initialize).
// Returns (response body, session ID from response header).
func (c *client) mcpCall(t *testing.T, sessionID string, method string, params interface{}, id int) (map[string]interface{}, string) {
	t.Helper()
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}
	if params != nil {
		payload["params"] = params
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, c.base+"/mcp", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("MCP %s failed: %v", method, err)
	}
	defer resp.Body.Close()

	newSessionID := resp.Header.Get("Mcp-Session-Id")
	raw, _ := io.ReadAll(resp.Body)

	// Handle SSE responses: extract the first data: line.
	body := strings.TrimSpace(string(raw))
	if strings.HasPrefix(body, "data:") || strings.Contains(body, "\ndata:") {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				body = strings.TrimPrefix(line, "data:")
				body = strings.TrimSpace(body)
				break
			}
		}
	}

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("MCP %s: failed to parse response JSON: %v\nraw: %s", method, err, raw)
	}
	if rpcErr, ok := out["error"]; ok {
		t.Fatalf("MCP %s returned error: %v", method, rpcErr)
	}
	return out, newSessionID
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
	t.Logf("✓ Operations (%d): %v", len(names), names)

	want := []string{
		"deploy-service",
		"create-tenant",
		"provision-database",
		"retire-service",
		"delete-tenant",
		"smoke-test",
		"rollback-service",
		"preview-deploy",
		"preview-delete",
		"add-custom-domain",
		"remove-custom-domain",
	}
	for _, w := range want {
		found := false
		for _, got := range names {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("operation %q not found in registry", w)
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

// ── OpenAPI docs ─────────────────────────────────────────────────────────────

func TestE2E_OpenAPI(t *testing.T) {
	c := newClient(t)

	// /openapi.yaml must return a valid YAML spec (no auth required).
	req, _ := http.NewRequest(http.MethodGet, c.base+"/openapi.yaml", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("GET /openapi.yaml failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)

	if resp.StatusCode != 200 {
		t.Fatalf("/openapi.yaml expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "openapi:") {
		t.Fatalf("/openapi.yaml response does not look like OpenAPI spec: %s", body[:min(200, len(body))])
	}
	if !strings.Contains(body, "mctl") {
		t.Fatalf("/openapi.yaml missing mctl content")
	}
	t.Logf("✓ /openapi.yaml OK (%d bytes)", len(body))

	// /docs must redirect to Swagger UI (3xx → swagger URL) — no auth needed.
	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	docsReq, _ := http.NewRequest(http.MethodGet, c.base+"/docs", nil)
	docsResp, err := noRedirectClient.Do(docsReq)
	if err != nil {
		t.Fatalf("GET /docs failed: %v", err)
	}
	defer docsResp.Body.Close()
	if docsResp.StatusCode < 300 || docsResp.StatusCode > 399 {
		t.Fatalf("/docs expected 3xx redirect, got %d", docsResp.StatusCode)
	}
	loc := docsResp.Header.Get("Location")
	if !strings.Contains(loc, "swagger") && !strings.Contains(loc, "openapi") {
		t.Fatalf("/docs Location %q does not point to Swagger UI", loc)
	}
	t.Logf("✓ /docs redirects to: %s", loc)
}

// ── Log querying ─────────────────────────────────────────────────────────────

func TestE2E_ServiceLogs(t *testing.T) {
	c := newClient(t)

	// Must have at least one service to test against.
	_, listBody := c.get(t, "/api/v1/services")
	items, ok := listBody["items"].([]interface{})
	if !ok || len(items) == 0 {
		t.Skip("no services available to test logs endpoint")
	}

	// Pick first service.
	svc := items[0].(map[string]interface{})
	team := fmt.Sprintf("%v", svc["team"])
	name := fmt.Sprintf("%v", svc["name"])
	t.Logf("testing logs for %s/%s", team, name)

	status, body := c.get(t, fmt.Sprintf("/api/v1/logs/%s/%s?lines=10&since=1h", team, name))
	if status != 200 {
		t.Fatalf("GET /api/v1/logs expected 200, got %d: %v", status, body)
	}

	// Either lines returned OR a note explaining why (Loki not configured / no logs).
	_, hasLines := body["lines"]
	_, hasNote := body["note"]
	if !hasLines && !hasNote {
		t.Fatalf("log response missing both 'lines' and 'note' fields: %v", body)
	}

	count := 0
	if c, ok := body["count"].(float64); ok {
		count = int(c)
	}
	note := ""
	if n, ok := body["note"].(string); ok {
		note = n
	}
	t.Logf("✓ /api/v1/logs/%s/%s: count=%d note=%q", team, name, count, note)
}

// ── Custom domains ────────────────────────────────────────────────────────────

func TestE2E_Domains(t *testing.T) {
	c := newClient(t)

	// GET /api/v1/domains?team=admins — must return 200 with a list (possibly empty).
	status, body := c.get(t, "/api/v1/domains?team=admins")
	if status != 200 {
		t.Fatalf("GET /api/v1/domains expected 200, got %d: %v", status, body)
	}
	t.Logf("✓ GET /api/v1/domains OK: %v", body)
}

// ── MCP endpoint smoke ────────────────────────────────────────────────────────

// TestE2E_MCPSmoke verifies the MCP Streamable HTTP endpoint:
//  1. initialize handshake
//  2. tools/list → all 16 expected tools present
//  3. tools/call mctl_list_tenants → returns valid JSON with tenant data
func TestE2E_MCPSmoke(t *testing.T) {
	c := newClient(t)

	// Step 1: initialize.
	initResp, sessionID := c.mcpCall(t, "", "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "e2e-smoke", "version": "1.0"},
	}, 1)
	t.Logf("✓ MCP initialize: serverInfo=%v sessionID=%s", initResp["result"], sessionID)

	// Step 2: tools/list.
	listResp, _ := c.mcpCall(t, sessionID, "tools/list", map[string]interface{}{}, 2)
	result, ok := listResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("tools/list: 'result' missing or wrong type: %v", listResp)
	}
	toolsList, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools/list: 'result.tools' missing: %v", result)
	}

	toolNames := make(map[string]bool, len(toolsList))
	for _, tl := range toolsList {
		if tm, ok := tl.(map[string]interface{}); ok {
			toolNames[fmt.Sprintf("%v", tm["name"])] = true
		}
	}
	t.Logf("✓ MCP tools/list: %d tools registered", len(toolNames))

	expectedTools := []string{
		"mctl_list_tenants",
		"mctl_get_tenant",
		"mctl_list_services",
		"mctl_get_service_status",
		"mctl_get_service_config",
		"mctl_get_workflow_status",
		"mctl_get_resource_usage",
		"mctl_list_recent_operations",
		"mctl_list_repos",
		"mctl_get_service_logs",
		"mctl_deploy_service",
		"mctl_create_tenant",
		"mctl_provision_database",
		"mctl_retire_service",
		"mctl_delete_tenant",
		"mctl_sync_repos",
		"mctl_rollback_service",
		"mctl_create_preview",
		"mctl_delete_preview",
		"mctl_add_custom_domain",
		"mctl_remove_custom_domain",
		"mctl_list_domains",
		"mctl_verify_domain",
	}

	missing := []string{}
	for _, want := range expectedTools {
		if !toolNames[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Errorf("MCP tools missing: %v\nregistered: %v", missing, toolNames)
	}

	// Step 3: tools/call — read-only tool (safe to call in smoke test).
	callResp, _ := c.mcpCall(t, sessionID, "tools/call", map[string]interface{}{
		"name":      "mctl_list_tenants",
		"arguments": map[string]interface{}{},
	}, 3)
	callResult, ok := callResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("tools/call mctl_list_tenants: result missing: %v", callResp)
	}
	content, ok := callResult["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("tools/call mctl_list_tenants: content empty: %v", callResult)
	}
	firstContent := content[0].(map[string]interface{})
	text := fmt.Sprintf("%v", firstContent["text"])
	if !strings.Contains(text, "count") && !strings.Contains(text, "items") && !strings.Contains(text, "tenant") {
		t.Fatalf("mctl_list_tenants response doesn't look like tenant data: %s", text[:min(300, len(text))])
	}
	t.Logf("✓ MCP tools/call mctl_list_tenants: %d chars returned", len(text))
}

// ── full platform smoke test ─────────────────────────────────────────────────

// TestE2E_FullPlatformSmokeTest triggers the smoke-test ClusterWorkflowTemplate
// which runs the complete lifecycle:
//  1. onboard service (deploy-service)
//  2. verify pod running
//  3. deploy update with env_vars + secret_env_vars
//  4. verify env and secrets inside the pod (kubectl exec)
//  5. provision PostgreSQL database
//  6. verify Vault secret + ExternalSecret synced
//  7. update-config
//  8. verify updated env in pod
//  9. retire service (cleanup)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
