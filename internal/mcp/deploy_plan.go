package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *Server) toolDeployPlan() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_deploy_plan",
		mcplib.WithTitleAnnotation("Plan Preview Deploy"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Compute an immutable preview deploy plan for a DeployIntent (for example the draft_intent from mctl_deploy_analyze, possibly edited).

Planning changes nothing: it writes no gitops file and touches no cluster. The only write is one stored plan row. The server compiles the effective preview Helm values for the service at the pinned revision and gitops commit, and returns the plan id, a unified diff, the preview host, the digest and the approval the plan will need. Secret references are redacted.

Only environment=preview is planned. environment=production is refused (prod_requires_promote), and a service that does not exist yet in gitops is refused (onboard_requires_preview_onboard). Approval is a later step and is not granted by planning.

Planning the same intent twice gives the same digest. Pass idempotency_key to get the stored plan back (replayed=true) on a retry.`),
		mcplib.WithObject("intent", mcplib.Required(), mcplib.Description("The DeployIntent object")),
		mcplib.WithString("idempotency_key", mcplib.Description("Optional key; repeating it with the same intent returns the stored plan")),
		mcplib.WithNumber("ttl_seconds", mcplib.Description("Plan lifetime in seconds, 60 to 86400 (default 1800)")),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		intent, ok := args["intent"]
		if !ok || intent == nil {
			return mcplib.NewToolResultError("intent is required"), nil
		}
		body := map[string]any{"intent": intent}
		if k, _ := args["idempotency_key"].(string); k != "" {
			body["idempotency_key"] = k
		}
		if v, ok := args["ttl_seconds"]; ok && v != nil {
			body["ttl_seconds"] = v
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/deploy/plan", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to plan deploy: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

func (s *Server) toolGetDeployPlan() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_deploy_plan",
		mcplib.WithTitleAnnotation("Get Deploy Plan"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription("Read a stored deploy plan by id (dpl_...): its digest, diff, preview host, required approval and whether it has expired. Visible to members of the plan's tenant and platform admins; any other caller gets deploy_plan_not_found."),
		mcplib.WithString("id", mcplib.Required(), mcplib.Description("Plan id, as returned by mctl_deploy_plan")),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		out, err := s.deployPlanRequest(ctx, http.MethodGet, "/api/v1/deploy/plans/"+url.PathEscape(id), nil)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to read deploy plan: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

// deployPlanRequest calls the REST route and, unlike doRequest, keeps the
// API's machine-readable code in the error, because the deploy-plan codes
// (prod_requires_promote, onboard_requires_preview_onboard, ...) are the
// contract a caller acts on.
func (s *Server) deployPlanRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.apiURL+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Mctl-Surface", "mcp")
	if token := s.effectiveToken(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(out, &apiErr) == nil && (apiErr.Error != "" || apiErr.Code != "") {
			return nil, fmt.Errorf("%s: %s (HTTP %d)", apiErr.Code, apiErr.Error, resp.StatusCode)
		}
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}
