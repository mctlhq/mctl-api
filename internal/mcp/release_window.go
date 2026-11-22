package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// mctl_propose_release_window: the sync-window write path as one tool with two
// calls. The tool never decides anything: the owner decides on a page, and the
// second call only spends that decision.
func (s *Server) toolProposeReleaseWindow() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_propose_release_window",
		mcplib.WithTitleAnnotation("Propose Release Window"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Admin-only. Ask for ONE Argo CD deny sync window (a time when the listed Applications may not sync) in two calls.

Call 1 (project, applications, schedule, duration): reads the current gitops commit and checks the Applications exist in Argo CD, then returns a pending approval (aar_...) with a decide_url. This changes nothing. The owner opens the decide_url, signs in fresh with a second factor, sees the window and approves or rejects it. Calling again with the same window and the same gitops commit returns the same approval with its current state, so use it to check whether the owner has decided. If the gitops main moved since, a new request is made.

Call 2 (approval_id, nothing else): once the owner approved, spends that approval once by dispatching the release-window-pr.yml workflow in mctl-gitops. The workflow opens the pull request release-window/<id>; it does not merge it. The window exists only after a person merges that pull request. Returns the workflow runs link and the branch (GitHub gives no run id for a dispatch). A dispatch GitHub did not accept leaves the approval intact, so the call can be repeated; if the workflow refuses because gitops main moved, request again.

Only the project apps or platform, 1-20 applications of that project, deny windows only, and only the requester can execute. Never touches the default project.`),
		mcplib.WithString("approval_id", mcplib.Description("Call 2: the approval id (aar_...) the owner approved. Give only this; the window fields are then not accepted.")),
		mcplib.WithString("project", mcplib.Description("Call 1: Argo CD AppProject, apps or platform")),
		mcplib.WithArray("applications", mcplib.Description("Call 1: Application names in that project, e.g. [\"labs-mctl-web\"]"), mcplib.WithStringItems()),
		mcplib.WithString("schedule", mcplib.Description("Call 1: cron schedule in Argo CD syntax, UTC, e.g. \"0 22 * * 5\"")),
		mcplib.WithString("duration", mcplib.Description("Call 1: how long the window lasts, hours then minutes, e.g. 48h or 1h30m")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		if id := stringArg(req, "approval_id"); id != "" {
			for _, k := range []string{"project", "applications", "schedule", "duration"} {
				if v, ok := args[k]; ok && v != nil && v != "" {
					return mcplib.NewToolResultError("approval_id is the second call: give it alone, without " + k), nil
				}
			}
			out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/release/windows/"+url.PathEscape(id)+"/execute", map[string]any{})
			if err != nil {
				return mcplib.NewToolResultError(fmt.Sprintf("Failed to execute release window: %v", err)), nil
			}
			return mcplib.NewToolResultText(string(out)), nil
		}
		body := map[string]any{
			"project":      stringArg(req, "project"),
			"applications": args["applications"],
			"schedule":     stringArg(req, "schedule"),
			"duration":     stringArg(req, "duration"),
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/release/windows", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to request release window: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}
