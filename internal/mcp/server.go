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

	// Auth tools.
	srv.AddTool(s.toolWhoami())

	// Read tools (safe, always available).
	srv.AddTool(s.toolListTenants())
	srv.AddTool(s.toolGetTenant())
	srv.AddTool(s.toolListServices())
	srv.AddTool(s.toolGetServiceStatus())
	srv.AddTool(s.toolGetServiceConfig())
	srv.AddTool(s.toolListWorkflows())
	srv.AddTool(s.toolGetWorkflowStatus())
	srv.AddTool(s.toolGetResourceUsage())
	srv.AddTool(s.toolListRecentOperations())
	srv.AddTool(s.toolListOperations())
	srv.AddTool(s.toolGetOperation())
	srv.AddTool(s.toolListRepos())
	srv.AddTool(s.toolGrantRepoAccess())
	srv.AddTool(s.toolGetServiceLogs())
	srv.AddTool(s.toolListPreviews())

	// Write tools (trigger workflows).
	srv.AddTool(s.toolScaleService())
	srv.AddTool(s.toolDeployService())
	srv.AddTool(s.toolCreateTenant())
	srv.AddTool(s.toolProvisionDatabase())
	srv.AddTool(s.toolRetireService())
	srv.AddTool(s.toolDeleteTenant())
	srv.AddTool(s.toolSyncRepos())
	srv.AddTool(s.toolRollbackService())
	srv.AddTool(s.toolCreatePreview())
	srv.AddTool(s.toolDeletePreview())
	srv.AddTool(s.toolAddCustomDomain())
	srv.AddTool(s.toolRemoveCustomDomain())
	srv.AddTool(s.toolListDomains())
	srv.AddTool(s.toolVerifyDomain())

	// Incident tools.
	srv.AddTool(s.toolListIncidents())
	srv.AddTool(s.toolGetIncident())
	srv.AddTool(s.toolIncidentSummary())
	srv.AddTool(s.toolAcknowledgeIncident())
	srv.AddTool(s.toolResolveIncident())

	return srv
}

// --- Auth Tools ---

func (s *Server) toolWhoami() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_whoami",
		mcplib.WithTitleAnnotation("Check Identity"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`Check your current authentication status on the mctl platform.

Returns your user ID, team memberships, admin status, and accessible namespaces.
Authentication is handled automatically by the MCP connector's OAuth flow.
To switch accounts, disconnect and reconnect the mctl connector in your client settings.`),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, err := s.apiGet(ctx, "/api/v1/whoami")
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get identity: %v", err)), nil
		}

		var identity struct {
			ID         string   `json:"id"`
			Groups     []string `json:"groups"`
			IsAdmin    bool     `json:"isAdmin"`
			Namespaces []string `json:"namespaces"`
		}
		_ = json.Unmarshal(body, &identity)

		msg := fmt.Sprintf("Authenticated to %s\n\nUser: %s\nAdmin: %v\nTeams: %v\nAccessible namespaces: %v",
			s.apiURL, identity.ID, identity.IsAdmin, identity.Groups, identity.Namespaces)
		return mcplib.NewToolResultText(msg), nil
	}

	return tool, handler
}

// --- Read Tools ---

func (s *Server) toolListTenants() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_tenants",
		mcplib.WithTitleAnnotation("List Workspaces"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription("List all team workspaces on the platform with their resource quotas and member counts. Requires admin access."),
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
		mcplib.WithTitleAnnotation("List Services"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Get Service Status"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Get Workflow Status"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Get Resource Usage"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Deploy Service"),
		mcplib.WithDescription(`Deploy a service to the platform.

Actions:
- "onboard": First-time deploy. Builds Docker image, creates Helm manifests, commits to GitOps repo.
- "deploy": Update an existing service to a new version. Rebuilds and updates image tag.
- "update-config": Change environment variables or secrets without rebuilding.

The service domain is auto-generated as {team_name}-{component_name}.{platform_domain}.
Custom domains can be added after deployment using mctl_add_custom_domain.
For background workers, set component_type to 'worker-service' (no ingress).

Repository access for building:
- Use mctl_list_repos(team) to see available repos, and mctl_sync_repos(team) to discover new ones.
- Repos in the configured GitHub org are accessed automatically via the platform GitHub App.
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
			mcplib.Description("GitHub repo containing Dockerfile, e.g. 'myorg/my-app'. Required for onboard/deploy."),
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
		mcplib.WithString("clear_env",
			mcplib.Description("Clear existing plaintext environment variables: 'true' or 'false' (default: false)"),
			mcplib.Enum("true", "false"),
		),
		mcplib.WithString("clear_secrets",
			mcplib.Description("Clear existing secret environment variables: 'true' or 'false' (default: false)"),
			mcplib.Enum("true", "false"),
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
		mcplib.WithString("service_template",
			mcplib.Description("Service template preset. 'openclaw' pre-configures resources, probes, volumes, and gateway token for OpenClaw deployments. Default: 'default'"),
			mcplib.Enum("default", "openclaw"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		// Auto-generate domain: workflow computes {team}-{service}.{platform_domain}
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
		// When update-config explicitly passes empty env_vars/secret_env_vars,
		// use __CLEAR__ sentinel so the workflow clears existing values
		if params["action"] == "update-config" || params["action"] == "deploy" {
			if v, ok := req.GetArguments()["env_vars"]; ok {
				if s, _ := v.(string); s == "" {
					params["env_vars"] = "__CLEAR__"
				}
			}
			if v, ok := req.GetArguments()["secret_env_vars"]; ok {
				if s, _ := v.(string); s == "" {
					params["secret_env_vars"] = "__CLEAR__"
				}
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
		mcplib.WithTitleAnnotation("Create Workspace"),
		mcplib.WithDescription(`Create a new team workspace on the platform.

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
		mcplib.WithTitleAnnotation("Provision Database"),
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
		mcplib.WithTitleAnnotation("Get Workspace Details"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Get Service Config"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Recent Activity"),
		mcplib.WithReadOnlyHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Retire Service"),
		mcplib.WithDestructiveHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("Delete Workspace"),
		mcplib.WithDestructiveHintAnnotation(true),
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
		mcplib.WithTitleAnnotation("List Repositories"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`List GitHub repositories available to a team for deployment.

Shows repos from GitHub App installations registered for the team.
Admins see organization repos + personal repos.
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

func (s *Server) toolGrantRepoAccess() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_grant_repo_access",
		mcplib.WithTitleAnnotation("Grant Repo Access"),
		mcplib.WithDescription(`Generate a GitHub App installation URL to grant the platform access to a repository.

Use this when mctl_list_repos returns no repos, or when a specific private repo is not yet accessible.
The returned URL must be opened in a browser — the user installs the GitHub App on their account or org,
which grants the platform access to clone and build from that repo.

After the browser flow completes, run mctl_sync_repos to register the newly accessible repos.`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name that needs access to the repo"),
		),
		mcplib.WithString("repo",
			mcplib.Required(),
			mcplib.Description("Full repository name, e.g. 'myorg/my-app'"),
		),
		mcplib.WithString("service",
			mcplib.Description("Service name (optional, defaults to '_auto')"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team := args["team"].(string)
		repo := args["repo"].(string)
		service := ""
		if s, ok := args["service"].(string); ok {
			service = s
		}

		apiPath := fmt.Sprintf("/api/v1/repos/install-url?team=%s&repo=%s",
			url.QueryEscape(team), url.QueryEscape(repo))
		if service != "" {
			apiPath += "&service=" + url.QueryEscape(service)
		}

		body, err := s.apiGet(ctx, apiPath)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get install URL: %v", err)), nil
		}

		var result struct {
			URL   string `json:"url"`
			State string `json:"state"`
		}
		_ = json.Unmarshal(body, &result)
		if result.URL == "" {
			return mcplib.NewToolResultText(string(body)), nil
		}

		msg := fmt.Sprintf(
			"To grant the platform access to %q, open this URL in your browser and install the GitHub App:\n\n%s\n\nAfter completing the installation, run mctl_sync_repos (team=%q) to register the newly accessible repositories.",
			repo, result.URL, team,
		)
		return mcplib.NewToolResultText(msg), nil
	}

	return tool, handler
}

func (s *Server) toolSyncRepos() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_sync_repos",
		mcplib.WithTitleAnnotation("Sync Repositories"),
		mcplib.WithDescription(`Discover and register GitHub repositories for a team.

Scans GitHub App installations accessible to the user and registers found repos for the team.
After sync, repos appear in mctl_list_repos and in the Backstage onboard-service UI.

For admins: discovers organization installations + user's personal repos.
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

// --- Custom Domain Tools ---

func (s *Server) toolListDomains() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_domains",
		mcplib.WithTitleAnnotation("List Domains"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription("List custom domains for a team or specific service. Shows domain, auto-generated domain ({team}-{service}.{platform_domain}), status (pending/verified/active), and verification timestamp."),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("service",
			mcplib.Description("Service name (optional, filters to specific service)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team, _ := args["team"].(string)
		service, _ := args["service"].(string)
		path := "/api/v1/domains?team=" + url.QueryEscape(team)
		if service != "" {
			path += "&service=" + url.QueryEscape(service)
		}
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list domains: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolAddCustomDomain() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_add_custom_domain",
		mcplib.WithTitleAnnotation("Add Custom Domain"),
		mcplib.WithDescription(`Add a custom domain to a service.

The service must already be deployed (it gets an auto-generated domain: {team}-{service}.{platform_domain}).

Steps:
1. Registers domain in the platform database
2. Triggers the add-custom-domain workflow which:
   - Verifies DNS: domain must have a CNAME pointing to {team}-{service}.{platform_domain}
   - Updates service ingress configuration
   - Provisions TLS certificate via HTTP-01 challenge

Before calling this, tell the user to create a CNAME record:
  {domain} CNAME → {team}-{service}.{platform_domain}

Returns the registered domain info. Use mctl_verify_domain to check DNS status.`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("service",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
		mcplib.WithString("domain",
			mcplib.Required(),
			mcplib.Description("Custom domain to add, e.g. 'api.mycompany.com'"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		params := map[string]string{
			"team":    args["team"].(string),
			"service": args["service"].(string),
			"domain":  args["domain"].(string),
		}
		// Register domain in Backstage DB
		body, err := s.apiPost(ctx, "/api/v1/domains", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to register domain: %v", err)), nil
		}

		// Trigger the add-custom-domain workflow
		wfParams := map[string]string{
			"team_name":    params["team"],
			"service_name": params["service"],
			"domain":       params["domain"],
		}
		wfBody, err := s.apiPost(ctx, "/api/v1/operations/add-custom-domain/execute", wfParams)
		if err != nil {
			return mcplib.NewToolResultText(fmt.Sprintf("Domain registered but workflow failed: %v\nRegistration: %s", err, string(body))), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf("Domain registered:\n%s\n\nWorkflow triggered:\n%s", string(body), string(wfBody))), nil
	}

	return tool, handler
}

func (s *Server) toolRemoveCustomDomain() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_remove_custom_domain",
		mcplib.WithTitleAnnotation("Remove Custom Domain"),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithDescription("Remove a custom domain from a service. This removes it from the ingress configuration and database. The auto-generated {team}-{service}.{platform_domain} domain is not affected."),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("service",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
		mcplib.WithString("domain",
			mcplib.Required(),
			mcplib.Description("Custom domain to remove"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		// Trigger the remove-custom-domain workflow
		wfParams := map[string]string{
			"team_name":    args["team"].(string),
			"service_name": args["service"].(string),
			"domain":       args["domain"].(string),
		}
		body, err := s.apiPost(ctx, "/api/v1/operations/remove-custom-domain/execute", wfParams)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to remove domain: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolVerifyDomain() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_verify_domain",
		mcplib.WithTitleAnnotation("Verify Domain DNS"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription("Check if a custom domain's DNS is correctly configured. Verifies that the CNAME record points to the expected {team}-{service}.{platform_domain} target."),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("service",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team, _ := args["team"].(string)
		service, _ := args["service"].(string)
		// List domains to find IDs, then verify each
		path := "/api/v1/domains?team=" + url.QueryEscape(team) + "&service=" + url.QueryEscape(service)
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list domains: %v", err)), nil
		}

		var resp struct {
			Domains []struct {
				ID     string `json:"id"`
				Domain string `json:"domain"`
			} `json:"domains"`
		}
		if json.Unmarshal(body, &resp) != nil || len(resp.Domains) == 0 { //nolint:nilerr
			return mcplib.NewToolResultText("No custom domains found for " + team + "/" + service), nil
		}

		var results []string
		for _, d := range resp.Domains {
			vBody, vErr := s.apiPost(ctx, "/api/v1/domains/"+d.ID+"/verify", nil)
			if vErr != nil {
				results = append(results, fmt.Sprintf("%s: verification failed: %v", d.Domain, vErr))
			} else {
				results = append(results, fmt.Sprintf("%s: %s", d.Domain, string(vBody)))
			}
		}
		return mcplib.NewToolResultText(strings.Join(results, "\n")), nil
	}

	return tool, handler
}

func (s *Server) toolRollbackService() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_rollback_service",
		mcplib.WithTitleAnnotation("Rollback Service"),
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
		mcplib.WithTitleAnnotation("Create Preview"),
		mcplib.WithDescription(`Deploy an ephemeral preview environment for a service.

Uses an existing built image tag — no rebuild required.
The preview is accessible at {app}-{preview_id}.preview.{platform_domain}.
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
		mcplib.WithTitleAnnotation("Delete Preview"),
		mcplib.WithDestructiveHintAnnotation(true),
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

func (s *Server) toolGetServiceLogs() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_service_logs",
		mcplib.WithTitleAnnotation("Get Service Logs"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`Fetch recent log lines for a service from Loki.

Returns log lines sorted by timestamp (most recent first).
Use this when debugging service issues or investigating errors.

Parameters:
- lines: number of log lines to return (default 100, max 1000)
- since: time window — e.g. "15m", "1h", "6h", "24h" (default "1h")

Requires in-cluster deployment with Loki enabled (LOKI_URL env var).`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("service",
			mcplib.Required(),
			mcplib.Description("Service name"),
		),
		mcplib.WithString("lines",
			mcplib.Description("Number of log lines to return (default: 100, max: 1000)"),
		),
		mcplib.WithString("since",
			mcplib.Description("Time window: 15m, 1h, 6h, 24h (default: 1h)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team, _ := args["team"].(string)
		service, _ := args["service"].(string)

		path := fmt.Sprintf("/api/v1/logs/%s/%s", url.PathEscape(team), url.PathEscape(service))

		q := url.Values{}
		if lines, ok := args["lines"].(string); ok && lines != "" {
			q.Set("lines", lines)
		}
		if since, ok := args["since"].(string); ok && since != "" {
			q.Set("since", since)
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}

		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get logs for %s/%s: %v", team, service, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// --- Discovery Tools ---

func (s *Server) toolListWorkflows() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_workflows",
		mcplib.WithTitleAnnotation("List Workflows"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`List recent Argo Workflow runs for a team.

Shows workflows that were submitted for the team's namespace (team-{name}).
Use this to find workflow names before calling mctl_get_workflow_status.
Admins can see workflows across all namespaces.`),
		mcplib.WithString("team",
			mcplib.Description("Team name to filter workflows (optional for admins)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		path := "/api/v1/workflows"
		if team, ok := args["team"].(string); ok && team != "" {
			path += "?team=" + url.QueryEscape(team)
		}
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list workflows: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolListOperations() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_operations",
		mcplib.WithTitleAnnotation("List Operations"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription("List all available platform operations with their parameters, risk levels, and descriptions. Use this to discover what actions are available on the platform."),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, err := s.apiGet(ctx, "/api/v1/operations")
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list operations: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetOperation() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_operation",
		mcplib.WithTitleAnnotation("Get Operation Details"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription("Get detailed schema of a specific platform operation: all parameters with types, defaults, validation patterns, and risk level. Use this to understand exactly what an operation requires before executing it."),
		mcplib.WithString("name",
			mcplib.Required(),
			mcplib.Description("Operation name (e.g. 'deploy-service', 'create-tenant')"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		name := args["name"].(string)
		body, err := s.apiGet(ctx, fmt.Sprintf("/api/v1/operations/%s", url.PathEscape(name)))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get operation %s: %v", name, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolScaleService() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_scale_service",
		mcplib.WithTitleAnnotation("Scale Service"),
		mcplib.WithDescription(`Scale a service by updating its autoscaling configuration.

Enables or disables HPA autoscaling and sets min/max replica counts and CPU threshold.
This is a convenience wrapper around deploy-service with action=update-config.

Returns workflow_name. Poll mctl_get_workflow_status(workflow_name) to track progress.`),
		mcplib.WithString("team_name",
			mcplib.Required(),
			mcplib.Description("Team name that owns the service"),
		),
		mcplib.WithString("component_name",
			mcplib.Required(),
			mcplib.Description("Service name to scale"),
		),
		mcplib.WithString("autoscaling_enabled",
			mcplib.Required(),
			mcplib.Description("Enable HPA autoscaling: 'true' or 'false'"),
			mcplib.Enum("true", "false"),
		),
		mcplib.WithString("min_replicas",
			mcplib.Description("Minimum replica count (default: 1)"),
		),
		mcplib.WithString("max_replicas",
			mcplib.Description("Maximum replica count (default: 5)"),
		),
		mcplib.WithString("cpu_threshold",
			mcplib.Description("CPU utilization % to trigger scale-up (default: 80)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		params := extractStringParams(req.GetArguments())
		params["action"] = "update-config"
		body, err := s.apiPost(ctx, "/api/v1/operations/deploy-service/execute", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to scale service: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolListPreviews() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_previews",
		mcplib.WithTitleAnnotation("List Previews"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`List active preview environments for a team.

Shows all preview ArgoCD applications with their health status, sync state, and namespace.
Preview environments follow the naming pattern: preview-{team}-{service}-{id}.

Use this to check which previews are running before creating new ones or cleaning up stale ones.`),
		mcplib.WithString("team",
			mcplib.Required(),
			mcplib.Description("Team name"),
		),
		mcplib.WithString("service",
			mcplib.Description("Service name (optional, filters to specific service)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		team := args["team"].(string)
		path := "/api/v1/previews?team=" + url.QueryEscape(team)
		if svc, ok := args["service"].(string); ok && svc != "" {
			path += "&service=" + url.QueryEscape(svc)
		}
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list previews for %s: %v", team, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// --- Incident Tools ---

func (s *Server) toolListIncidents() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_incidents",
		mcplib.WithTitleAnnotation("List Incidents"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`List platform incidents (alerts from AlertManager, GitHub Actions failures, polling).

Returns incidents with their status, severity, and summary. Filter by team, service, status, or severity.
Default: returns open incidents, most recent first.`),
		mcplib.WithString("team",
			mcplib.Description("Filter by team/tenant name"),
		),
		mcplib.WithString("service",
			mcplib.Description("Filter by service name"),
		),
		mcplib.WithString("status",
			mcplib.Description("Filter by status: open, analyzing, fix_proposed, resolved, suppressed, acknowledged (default: open)"),
		),
		mcplib.WithString("severity",
			mcplib.Description("Filter by severity: critical, warning, info"),
		),
		mcplib.WithString("limit",
			mcplib.Description("Maximum number of results (default: 20)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		path := "/api/v1/incidents?"
		if v, ok := args["team"].(string); ok && v != "" {
			path += "tenant=" + url.QueryEscape(v) + "&"
		}
		if v, ok := args["service"].(string); ok && v != "" {
			path += "service=" + url.QueryEscape(v) + "&"
		}
		if v, ok := args["status"].(string); ok && v != "" {
			path += "status=" + url.QueryEscape(v) + "&"
		} else {
			path += "status=open&"
		}
		if v, ok := args["severity"].(string); ok && v != "" {
			path += "severity=" + url.QueryEscape(v) + "&"
		}
		if v, ok := args["limit"].(string); ok && v != "" {
			path += "limit=" + url.QueryEscape(v) + "&"
		} else {
			path += "limit=20&"
		}
		path = strings.TrimRight(path, "&?")

		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to list incidents: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolGetIncident() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_incident",
		mcplib.WithTitleAnnotation("Get Incident Detail"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`Get full details of an incident including evidence, analysis, and PR information.

Accepts a full incident ID or an 8-character prefix (as shown in Telegram notifications).
Returns the incident with all collected evidence (logs, alerts, workflow data).`),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description("Incident ID (full UUID or 8-char prefix)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := req.GetArguments()["id"].(string)
		body, err := s.apiGet(ctx, "/api/v1/incidents/"+url.PathEscape(id))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get incident %s: %v", id, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolIncidentSummary() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_incident_summary",
		mcplib.WithTitleAnnotation("Incident Summary"),
		mcplib.WithDescription(`Get aggregate counts of active incidents by status, severity, and type.

Useful for a quick overview of platform health. Excludes resolved and suppressed incidents.`),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, err := s.apiGet(ctx, "/api/v1/incidents/summary")
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get incident summary: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolAcknowledgeIncident() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_acknowledge_incident",
		mcplib.WithTitleAnnotation("Acknowledge Incident"),
		mcplib.WithDescription(`Mark an incident as acknowledged/reviewed.

Records the current user as the acknowledger. Use this when you've reviewed an incident
and want to signal that someone is aware of it.`),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description("Incident ID (full UUID or 8-char prefix)"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := req.GetArguments()["id"].(string)
		body, err := s.apiPost(ctx, "/api/v1/incidents/"+url.PathEscape(id)+"/ack", nil)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to acknowledge incident %s: %v", id, err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func (s *Server) toolResolveIncident() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_resolve_incident",
		mcplib.WithTitleAnnotation("Resolve Incident"),
		mcplib.WithDescription(`Mark an incident as resolved.

Optionally provide a reason for the resolution. This closes the incident and records
the resolution timestamp.`),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description("Incident ID (full UUID or 8-char prefix)"),
		),
		mcplib.WithString("reason",
			mcplib.Description("Optional resolution reason"),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		id := args["id"].(string)
		params := make(map[string]string)
		if v, ok := args["reason"].(string); ok && v != "" {
			params["reason"] = v
		}
		body, err := s.apiPost(ctx, "/api/v1/incidents/"+url.PathEscape(id)+"/resolve", params)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to resolve incident %s: %v", id, err)), nil
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
