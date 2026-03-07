package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	srv.AddTool(s.toolGetTenant())
	srv.AddTool(s.toolListServices())
	srv.AddTool(s.toolGetServiceStatus())
	srv.AddTool(s.toolGetServiceConfig())
	srv.AddTool(s.toolGetWorkflowStatus())
	srv.AddTool(s.toolGetResourceUsage())
	srv.AddTool(s.toolListRecentOperations())
	srv.AddTool(s.toolListRepos())

	// Write tools (trigger workflows).
	srv.AddTool(s.toolDeployService())
	srv.AddTool(s.toolCreateTenant())
	srv.AddTool(s.toolProvisionDatabase())
	srv.AddTool(s.toolRetireService())
	srv.AddTool(s.toolDeleteTenant())
	srv.AddTool(s.toolSyncRepos())
	srv.AddTool(s.toolRollbackService())
	srv.AddTool(s.toolCreatePreview())
	srv.AddTool(s.toolDeletePreview())

	return srv
}

// --- Read Tools ---

func (s *Server) toolListTenants() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_tenants",
		mcplib.WithDescription("List all team workspaces on the mctl.ai platform with their resource quotas and member counts. Requires admin access."),
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
			path += "?team=" + url.QueryEscape(team)
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
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/status/%s/%s", url.PathEscape(team), url.PathEscape(service)))
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
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/workflows/%s", url.PathEscape(name)))
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
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/resources/%s", url.PathEscape(team)))
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

The service domain is auto-generated as {team_name}-{component_name}.mctl.ai.
Custom domains can be added after deployment using mctl_add_custom_domain.
For background workers, set component_type to 'worker-service' (no ingress).

Repository access for building:
- Use mctl_list_repos(team) to see available repos, and mctl_sync_repos(team) to discover new ones.
- Repos in the mctlhq GitHub org are accessed automatically via the platform GitHub App.
- For repos outside the org (private), store a PAT in Vault first:
  Vault path: secret/data/teams/{team_name}/{component_name}/repo-pat → {"pat": "ghp_..."}
- Public repos work without any credentials.

Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
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
		mcplib.WithString("env_vars",
			mcplib.Description("Plaintext environment variables, newline-separated KEY=value"),
		),
		mcplib.WithString("provision_database",
			mcplib.Description("Also provision a PostgreSQL database: 'true' or 'false' (default: false)"),
			mcplib.Enum("true", "false"),
		),
		mcplib.WithString("autoscaling_enabled",
			mcplib.Description("Enable HPA autoscaling: 'true' or 'false' (default: false)"),
			mcplib.Enum("true", "false"),
		),
		mcplib.WithString("min_replicas",
			mcplib.Description("Minimum replica count when autoscaling is enabled (default: 1)"),
		),
		mcplib.WithString("max_replicas",
			mcplib.Description("Maximum replica count when autoscaling is enabled (default: 5)"),
		),
		mcplib.WithString("cpu_threshold",
			mcplib.Description("CPU utilization % to trigger scale-up (default: 80)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		// Auto-generate domain: workflow computes {team}-{service}.mctl.ai
		if _, hasHost := params["host"]; !hasHost {
			componentType := params["component_type"]
			if componentType == "" {
				componentType = "base-service"
			}
			if componentType == "worker-service" {
				params["host"] = "none"
			} else {
				params["host"] = "auto"
			}
		}
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

The workspace name must be unique, DNS-safe (lowercase letters, numbers, hyphens).

Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
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

The database name follows the convention: {team_name}-{app_name}.

Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
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

func (s *Server) toolGetTenant() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_tenant",
		mcplib.WithDescription("Get details of a specific team workspace: members, quotas, and deployed services."),
		mcplib.WithString("name",
			mcplib.Required(),
			mcplib.Description("Tenant (workspace) name"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		name := args["name"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/tenants/%s", url.PathEscape(name)))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get tenant %s: %v", name, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetServiceConfig() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_service_config",
		mcplib.WithDescription("Get full configuration of a service from the GitOps repo: image tag, host, port, component type, and database status. Use this when you need full details beyond what list_services provides."),
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
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/services/%s/%s", url.PathEscape(team), url.PathEscape(service)))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get config for %s/%s: %v", team, service, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolListRecentOperations() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_recent_operations",
		mcplib.WithDescription("List the most recent platform operations from the audit log (up to 50 entries). Shows who ran what operation, when, and what workflow was triggered. Useful for reviewing recent activity before making changes."),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, err := s.apiGet(ctx, "/api/v1/audit")
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list recent operations: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolRetireService() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_retire_service",
		mcplib.WithDescription(`DESTRUCTIVE: Remove a service from the platform permanently.

Deletes GitOps manifests, Vault secrets, ArgoCD Application, and all Kubernetes resources.
This action is irreversible — all data and configuration will be lost.

Confirm the team and service names carefully before calling this tool.
Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name to retire"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/retire-service/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to retire service: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolDeleteTenant() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_delete_tenant",
		mcplib.WithDescription(`DESTRUCTIVE: Delete a team workspace and all its platform resources permanently.

Removes the Kubernetes namespace, ArgoCD RBAC, and Vault policy.
All services in the workspace must be retired first (use mctl_retire_service).
This action is irreversible.

Confirm the tenant name carefully before calling this tool.
Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
		mcplib.WithString("tenant_name",
			mcplib.Required(),
			mcplib.Description("Workspace name to delete"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/delete-tenant/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to delete tenant: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolListRepos() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_repos",
		mcplib.WithDescription(`List GitHub repositories available to a team for deployment.

Shows repos from GitHub App installations registered for the team.
Admins see organization repos (mctlhq) + personal repos.
Other teams see personal repos + repos added via GitHub App popup.

If no repos are returned, run mctl_sync_repos first to discover installations.
For repos outside GitHub App scope, store a PAT in Vault (see mctl_deploy_service help).`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name to list repos for"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team := args["team"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/repos?team=%s", url.QueryEscape(team)))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list repos for team %s: %v", team, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolSyncRepos() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_sync_repos",
		mcplib.WithDescription(`Discover and register GitHub repositories for a team.

Scans GitHub App installations accessible to the user and registers found repos for the team.
After sync, repos appear in mctl_list_repos and in the Backstage onboard-service UI.

For admins: discovers organization installations (mctlhq) + user's personal repos.
For other teams: discovers user's personal repos only (org repos are added via GitHub App popup in Backstage UI).

If the GitHub App is not installed on your account, visit: https://github.com/apps/mctl-app/installations/new`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name to sync repos for"),
		),
		mcplib.WithString("user",
			mcplib.Description("GitHub username (defaults to authenticated user)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		params := make(map[string]string)
		params["team"] = args["team"].(string)
		if user, ok := args["user"].(string); ok && user != "" {
			params["user"] = user
		}
		body, err := s.apiPost(ctx, "/api/v1/repos/sync", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to sync repos: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolRollbackService() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_rollback_service",
		mcplib.WithDescription(`Roll back a service to a previously deployed image tag.

Updates image.tag in the GitOps values.yaml and triggers an ArgoCD sync.
Use mctl_get_service_config first to see the current image tag, then specify a previous tag.

Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name to roll back"),
		),
		mcplib.WithString("target_tag",
			mcplib.Required(),
			mcplib.Description("Image tag to roll back to (e.g. '1.2.3'). Use mctl_get_service_config to find available tags."),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/rollback-service/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to rollback service: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolCreatePreview() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_create_preview",
		mcplib.WithDescription(`Deploy an ephemeral preview environment for a service.

Uses an existing built image tag — no rebuild required.
The preview is accessible at {app}-{preview_id}.preview.mctl.ai.
It is automatically deleted after ttl_hours (default: 24).

Returns workflow_name and preview_id. Poll mctl_get_workflow_status to track progress.`),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name to preview"),
		),
		mcplib.WithString("image_tag",
			mcplib.Required(),
			mcplib.Description("Existing image tag to deploy (must already be built)"),
		),
		mcplib.WithString("ttl_hours",
			mcplib.Description("Preview lifetime in hours (default: 24)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/preview-deploy/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to create preview: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolDeletePreview() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_delete_preview",
		mcplib.WithDescription("Remove a preview environment and all its Kubernetes resources immediately."),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
		mcplib.WithString("preview_id",
			mcplib.Required(),
			mcplib.Description("Preview ID returned by mctl_create_preview"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		body, err := s.apiPost(ctx, "/api/v1/operations/preview-delete/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to delete preview: %v", err)), nil
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
	defer resp.Body.Close() //nolint:errcheck

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
