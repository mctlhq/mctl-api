package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// mctl_propose_window_removal: the removal of one Argo CD deny sync window as
// one tool with two calls, the mirror of mctl_propose_release_window. It is a
// separate tool and a separate approval kind on purpose: an approval to add a
// window can never be spent as one to lift it. The tool never decides
// anything: the owner decides on a page, and the second call only spends that
// decision.
func (s *Server) toolProposeWindowRemoval() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_propose_window_removal",
		mcplib.WithTitleAnnotation("Propose Window Removal"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Admin-only. Ask for the REMOVAL of ONE Argo CD deny sync window (so the listed Applications may sync again in that time) in two calls. The window is named exactly as mctl_get_sync_windows and the AppProject hold it: project, the Applications of the window in sorted order, its schedule and its duration.

Call 1 (project, applications, schedule, duration): reads the current gitops commit and checks with Argo CD that the project holds exactly one deny window with exactly these Applications, this schedule and this duration, then returns a pending approval (aar_...) with a decide_url. This changes nothing. The owner opens the decide_url, signs in fresh with a second factor, sees the window to be removed and approves or rejects it. Calling again with the same window and the same gitops commit returns the same approval with its current state, so use it to check whether the owner has decided. If the gitops main moved since, a new request is made.

Call 2 (approval_id, nothing else): once the owner approved, spends that approval once by dispatching the release-window-removal-pr.yml workflow in mctl-gitops. The workflow opens the pull request release-window-removal/<id>, which deletes the window, and queues it for merge: the owner's MFA approval is the only review and no person merges it. The window is gone once that pull request has merged and Argo CD has synced it; a failing check leaves the pull request open and the window in place. Returns the workflow runs link and the branch (GitHub gives no run id for a dispatch). A dispatch GitHub did not accept leaves the approval intact, so the call can be repeated; if the workflow refuses because gitops main moved or the window is not held exactly once, request again.

Only the project apps or platform, deny windows only, and only the requester can execute. An approval to add a window cannot be used here. Never touches the default project.`),
		mcplib.WithString("approval_id", mcplib.Description("Call 2: the approval id (aar_...) the owner approved. Give only this; the window fields are then not accepted.")),
		mcplib.WithString("project", mcplib.Description("Call 1: Argo CD AppProject that holds the window, apps or platform")),
		mcplib.WithArray("applications", mcplib.Description("Call 1: the Application names of the window, sorted, e.g. [\"labs-portfolio\"]"), mcplib.WithStringItems()),
		mcplib.WithString("schedule", mcplib.Description("Call 1: the window's cron schedule in Argo CD syntax, UTC, e.g. \"0 3 * * 0\"")),
		mcplib.WithString("duration", mcplib.Description("Call 1: the window's duration, hours then minutes, e.g. 1h or 1h30m")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		if id := stringArg(req, "approval_id"); id != "" {
			for _, k := range []string{"project", "applications", "schedule", "duration"} {
				if v, ok := args[k]; ok && v != nil && v != "" {
					return mcplib.NewToolResultError("approval_id is the second call: give it alone, without " + k), nil
				}
			}
			out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/release/window-removals/"+url.PathEscape(id)+"/execute", map[string]any{})
			if err != nil {
				return mcplib.NewToolResultError(fmt.Sprintf("Failed to execute release window removal: %v", err)), nil
			}
			return mcplib.NewToolResultText(string(out)), nil
		}
		body := map[string]any{
			"project":      stringArg(req, "project"),
			"applications": args["applications"],
			"schedule":     stringArg(req, "schedule"),
			"duration":     stringArg(req, "duration"),
		}
		out, err := s.deployPlanRequest(ctx, http.MethodPost, "/api/v1/release/window-removals", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to request release window removal: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}
