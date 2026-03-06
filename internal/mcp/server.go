package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// Server is the MCP server that exposes platform operations as AI tools.
type Server struct {
	apiURL     string
	apiToken   string
	httpClient *http.Client
}

// NewServer creates a new MCP server.
func NewServer(apiURL, apiToken string) *Server {
	return &Server{
		apiURL:   strings.TrimRight(apiURL, "/"),
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewStreamableHTTPHandler returns an HTTP handler that serves the MCP Streamable HTTP transport.
// Mount at /mcp in the authenticated route group (single endpoint, all methods).
// Streamable HTTP is the primary transport in the current MCP spec: single POST/GET endpoint,
// auth headers on every request, works cleanly with reverse proxies.
// The context function forwards the auth context (user + raw token) to tool handlers.
func (s *Server) NewStreamableHTTPHandler() http.Handler {
	return server.NewStreamableHTTPServer(
		s.NewMCPServer(),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			// Forward the request context (contains auth user + raw token set by middleware).
			return r.Context()
		}),
	)
}

// NewMCPServer creates the mcp-go Server with all tool definitions.
func (s *Server) NewMCPServer() *server.MCPServer {
	srv := server.NewMCPServer(
		"mctl",
		"0.1.0",
		server.WithToolCapabilities(true),
	)

	// Read tools (safe, always available).
	srv.AddTool(s.toolListTenants())
	srv.AddTool(s.toolListServices())
	srv.AddTool(s.toolGetServiceStatus())
	srv.AddTool(s.toolGetWorkflowStatus())
	srv.AddTool(s.toolGetResourceUsage())

	// Write tools (trigger workflows).
	srv.AddTool(s.toolDeployService())
	srv.AddTool(s.toolCreateTenant())
	srv.AddTool(s.toolProvisionDatabase())

	return srv
}

// --- Read Tools ---

func (s *Server) toolListTenants() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_tenants",
		mcplib.WithDescription("List all team workspaces on the mctl.ai platform with their resource quotas and member counts. Use this to see what teams exist and their configuration."),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, err := s.apiGet(ctx, "/api/v1/tenants")
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list tenants: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolListServices() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_services",
		mcplib.WithDescription("List deployed services on the platform. Shows service name, team, image tag, host, and database status. Optionally filter by team name."),
		mcplib.WithString("team",
			mcplib.Description("Filter by team name (optional). If omitted, lists all services."),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		path := "/api/v1/services"
		if team, ok := args["team"].(string); ok && team != "" {
			path += "?team=" + team
		}
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list services: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetServiceStatus() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_service_status",
		mcplib.WithDescription("Get detailed status of a service including ArgoCD sync state, health status, and service configuration. Use this to check if a service is healthy and up-to-date."),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("service",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team := args["team"].(string)
		service := args["service"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/status/%s/%s", team, service))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get status for %s/%s: %v", team, service, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetWorkflowStatus() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_workflow_status",
		mcplib.WithDescription("Get status and logs of an Argo Workflow run. Use this after triggering an operation (deploy, create tenant, etc.) to check if it completed successfully."),
		mcplib.WithString("workflow_name",
			mcplib.Required(),
			mcplib.Description("Workflow name (returned from operation calls like mctl_deploy_service)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		name := args["workflow_name"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/workflows/%s", name))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get workflow %s: %v", name, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetResourceUsage() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_resource_usage",
		mcplib.WithDescription("Get resource quota usage for a team workspace: CPU, memory, pods used vs allocated. Use this to check if a team is running low on resources."),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team := args["team"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/resources/%s", team))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get resource usage for %s: %v", team, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// --- Write Tools ---

func (s *Server) toolDeployService() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_deploy_service",
		mcplib.WithDescription(`Deploy a service to the mctl.ai platform.

Actions:
- "onboard": First-time deploy. Builds Docker image, creates Helm manifests, commits to GitOps repo.
- "deploy": Update an existing service to a new version. Rebuilds and updates image tag.
- "update-config": Change environment variables or secrets without rebuilding.

The service will be available at {host} after ArgoCD syncs (typically 1-2 minutes).
For background workers, omit the host parameter.`),
		mcplib.WithString("action",
			mcplib.Required(),
			mcplib.Description("Operation type: onboard (first deploy), deploy (update version), update-config (change env)"),
			mcplib.Enum("onboard", "deploy", "update-config"),
		),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team (workspace) name, e.g. 'billing'"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name, e.g. 'payment-api'"),
		),
		mcplib.WithString("component_type",
			mcplib.Description("Chart type: base-service (with HTTP/ingress) or worker-service (background). Default: base-service"),
			mcplib.Enum("base-service", "worker-service"),
		),
		mcplib.WithString("dockerfile_repo",
			mcplib.Description("GitHub repo containing Dockerfile, e.g. 'mctlhq/my-app'. Required for onboard/deploy."),
		),
		mcplib.WithString("git_tag",
			mcplib.Description("Git tag to build, e.g. 'v1.0.0'. Required for onboard/deploy."),
		),
		mcplib.WithString("port",
			mcplib.Description("Service port (default: 8080)"),
		),
		mcplib.WithString("host",
			mcplib.Description("Ingress hostname, e.g. 'my-app.mctl.ai'. Omit for background workers."),
		),
		mcplib.WithString("env_vars",
			mcplib.Description("Plaintext environment variables, newline-separated KEY=value"),
		),
		mcplib.WithString("provision_database",
			mcplib.Description("Also provision a PostgreSQL database: 'true' or 'false' (default: false)"),
			mcplib.Enum("true", "false"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/deploy-service/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to deploy service: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolCreateTenant() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_create_tenant",
		mcplib.WithDescription(`Create a new team workspace on the mctl.ai platform.

This provisions:
- Kubernetes namespace with resource quotas
- Network policies (intra-namespace + configurable egress)
- Vault secret scope for the team
- ArgoCD RBAC (team members can view/sync their apps)
- SSO access to Argo Workflows UI

The workspace name must be unique, DNS-safe (lowercase letters, numbers, hyphens).`),
		mcplib.WithString("tenant_name",
			mcplib.Required(),
			mcplib.Description("Workspace name (DNS-safe, 2-63 chars, e.g. 'billing', 'data-team')"),
		),
		mcplib.WithString("display_name",
			mcplib.Description("Human-readable team name (e.g. 'Billing Team')"),
		),
		mcplib.WithString("description",
			mcplib.Description("Team description"),
		),
		mcplib.WithString("quota_cpu_req",
			mcplib.Description("CPU request quota (default: 1)"),
		),
		mcplib.WithString("quota_memory_req",
			mcplib.Description("Memory request quota (default: 2Gi)"),
		),
		mcplib.WithString("quota_pods",
			mcplib.Description("Maximum pods (default: 10)"),
		),
		mcplib.WithString("contact_email",
			mcplib.Description("Team contact email"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/create-tenant/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to create tenant: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolProvisionDatabase() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_provision_database",
		mcplib.WithDescription(`Provision a PostgreSQL database on the shared CNPG cluster.

This creates:
- PostgreSQL database and role named {team}-{app}
- Auto-generated password stored in Vault at teams/{team}/{app}/database
- ExternalSecret that syncs Vault credentials to a Kubernetes Secret
- Connection details available as environment variables (DATABASE_URL, DB_HOST, etc.)

The database name follows the convention: {team_name}-{app_name}.`),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("app_name",
			mcplib.Required(),
			mcplib.Description("Application name"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/provision-database/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to provision database: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// --- HTTP helpers ---

// effectiveToken returns the token from context (SSE mode) or falls back to s.apiToken (stdio mode).
func (s *Server) effectiveToken(ctx context.Context) string {
	if t := auth.TokenFromContext(ctx); t != "" {
		return t
	}
	return s.apiToken
}

func (s *Server) apiGet(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.apiURL+path, nil)
	if err != nil {
		return nil, err
	}
	return s.doRequest(req, s.effectiveToken(ctx))
}

func (s *Server) apiPost(ctx context.Context, path string, body map[string]string) ([]byte, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.apiURL+path, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return s.doRequest(req, s.effectiveToken(ctx))
}

func (s *Server) doRequest(req *http.Request, token string) ([]byte, error) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func extractStringParams(args map[string]any) map[string]string {
	result := make(map[string]string, len(args))
	for k, v := range args {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}
