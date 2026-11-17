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

Only environment=preview is planned. environment=production is refused (prod_requires_promote), and a service that does not exist yet in gitops is planned as an onboard: its preview values are compiled from the intent over a platform base (image built from source, registry pull secret), and applying it needs an owner's approval. Approval is a later step and is not granted by planning.

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

func (s *Server) toolPromoteDeployment() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_promote_deployment",
		mcplib.WithTitleAnnotation("Plan Promotion To Production"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Plan the promotion of one verified preview deployment to production (mctl-api#1049).

Pass the deployment_id (dep_...) of a preview that succeeded, was observed healthy and reported the image digest it ran. The server reads that digest from the deployment record; there is no digest, tag or revision argument, so a caller cannot promote an image no preview ran. The plan pins that image by digest in the service's production values.

Planning changes nothing but one stored plan row. Applying needs a deploy.apply grant decided by an owner on a fresh-sign-in page: request one with mctl_request_deploy_approval, then apply with mctl_deploy_apply. Available only for the platform's own workspace for now.`),
		mcplib.WithString("deployment_id", mcplib.Required(), mcplib.Description("Preview deployment id (dep_...), as returned by mctl_deploy_apply")),
		mcplib.WithNumber("ttl_seconds", mcplib.Description("Plan lifetime in seconds, 60 to 86400 (default 1800)")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		id, _ := args["deployment_id"].(string)
		if id == "" {
			return mcplib.NewToolResultError("deployment_id is required"), nil
		}
		body := map[string]any{"deployment_id": id}
		if v, ok := args["ttl_seconds"]; ok && v != nil {
			body["ttl_seconds"] = v
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/deploy/promote", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to plan promotion: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

func (s *Server) toolRollbackDeployment() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_rollback_deployment",
		mcplib.WithTitleAnnotation("Plan Rollback Of Production"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Plan the rollback of a service's production to the state of one earlier production deployment (mctl-api#1049).

Pass the deployment_id (dep_...) of a production deployment that succeeded, was observed healthy and recorded its gitops commit and image digest. The server reads both from the deployment record; there is no commit, digest or revision argument. The rollback restores the service's values.yaml as it was at that commit and the health gate must then see that digest.

Planning changes nothing but one stored plan row. Applying needs a deploy.apply grant decided by an owner on a fresh-sign-in page: request one with mctl_request_deploy_approval, then apply with mctl_deploy_apply. Available only for the platform's own workspace for now. mctl_rollback_revision refuses production deployments.`),
		mcplib.WithString("deployment_id", mcplib.Required(), mcplib.Description("Production deployment id (dep_...) to restore")),
		mcplib.WithNumber("ttl_seconds", mcplib.Description("Plan lifetime in seconds, 60 to 86400 (default 1800)")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		id, _ := args["deployment_id"].(string)
		if id == "" {
			return mcplib.NewToolResultError("deployment_id is required"), nil
		}
		body := map[string]any{"deployment_id": id}
		if v, ok := args["ttl_seconds"]; ok && v != nil {
			body["ttl_seconds"] = v
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/deploy/rollback", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to plan rollback: %v", err)), nil
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

func (s *Server) toolGetDeployment() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_deployment",
		mcplib.WithTitleAnnotation("Get Deployment"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Read the record of one applied deploy plan: the plan and its digest, the source revision and gitops commit, the grant and the owner who decided it, who applied it, the submitted workflow and its status (submitting, submitted, submit_failed).

Fields the platform has not observed yet are absent, and health reads unknown until it is observed. Read unknown as unknown, never as healthy. Visible to members of the tenant and platform admins; any other caller gets deployment_not_found.`),
		mcplib.WithString("id", mcplib.Required(), mcplib.Description("Deployment id (dep_...) from mctl_deploy_apply, or the applied plan's id (dpl_...)")),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		out, err := s.deployPlanRequest(ctx, http.MethodGet, "/api/v1/deploy/deployments/"+url.PathEscape(id), nil)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to read deployment: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

func (s *Server) toolRequestDeployApproval() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_request_deploy_approval",
		mcplib.WithTitleAnnotation("Request Deploy Approval"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Ask for the human grant a deploy plan needs before it can be applied. Returns a pending approval (aar_...) bound to the plan's id and digest.

This grants nothing. An owner of the plan's tenant decides it on a page where they sign in fresh; no tool, token or agent can decide it, and confirm is not a thing here. Give the person the decide_url from the answer and ask them to open it: the page shows them the plan's diff and lets them approve or reject it. Without a decide_url the page is not enabled and the grant cannot be decided.

Calling again for the same plan returns the same approval with its current state (pending, approved, denied, consumed or expired), so use it to check whether the owner has decided.

Refused with deploy_apply_not_reproducible when the plan cannot be applied as planned: the intent changes runtime, env, resources or secrets (preview-deploy renders the gitops values), or the build context is not the repository root.`),
		mcplib.WithString("plan_id", mcplib.Required(), mcplib.Description("Plan id (dpl_...), as returned by mctl_deploy_plan")),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, err := req.RequireString("plan_id")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/deploy/plans/"+url.PathEscape(id)+"/approval", map[string]any{})
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to request deploy approval: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

func (s *Server) toolDeployApply() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_deploy_apply",
		mcplib.WithTitleAnnotation("Apply Deploy Plan"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Apply an approved deploy plan: spend the owner's grant once and start the preview deploy exactly as planned (same preview id, host, gitops commit and image revision). Returns the workflow and the preview URL.

Needs the approval id from mctl_request_deploy_approval, decided by an owner of the tenant. Without an approved grant for this exact plan the apply is refused (deploy_apply_grant_required, approval_intent_mismatch, approval_not_approved, approval_consumed, approval_expired); there is no confirm parameter and none is accepted. A grant is single use: after a failed submit, request a new one.`),
		mcplib.WithString("plan_id", mcplib.Required(), mcplib.Description("Plan id (dpl_...)")),
		mcplib.WithString("approval_id", mcplib.Required(), mcplib.Description("Approval id (aar_...) from mctl_request_deploy_approval, approved by a tenant owner")),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		plan, err := req.RequireString("plan_id")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		approval, err := req.RequireString("approval_id")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		// Only these two fields: anything else the caller passes, confirm
		// included, never reaches the API.
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/deploy/apply",
			map[string]any{"plan_id": plan, "approval_id": approval})
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to apply deploy plan: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

// deployPlanRequest calls the REST route and, unlike doRequest, keeps the
// API's machine-readable code in the error, because the deploy-plan codes
// (prod_requires_promote, deploy_revision_not_a_sha, ...) are the
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
