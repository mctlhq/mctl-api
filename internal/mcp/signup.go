package mcp

import (
	"context"
	"net/url"
	"strconv"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *Server) toolListSignupRequests() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_signup_requests", mcplib.WithTitleAnnotation("List signup requests"), mcplib.WithDestructiveHintAnnotation(false), mcplib.WithDescription("Direct human administrator only. Read a bounded page of private invitation requests and saved decisions. Follow cursor until complete=true; an error is not an empty queue."), mcplib.WithReadOnlyHintAnnotation(true), mcplib.WithString("cursor"))
	return tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		data, err := s.apiGet(ctx, "/api/v1/admin/signup/requests?cursor="+url.QueryEscape(stringArg(req, "cursor")))
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return mcplib.NewToolResultText(string(data)), nil
	}
}
func (s *Server) toolDecideSignupRequest() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_decide_signup_request", mcplib.WithTitleAnnotation("Decide signup request"), mcplib.WithIdempotentHintAnnotation(true), mcplib.WithDescription("Direct human administrator only. Save an immutable approved/rejected invitation decision and notify the applicant by email. Approval verifies the public GitHub numeric identity and reserves one funded workspace slot; zero capacity refuses without granting access. Unused approval expires in seven days. reason is included in the applicant email. Read capacity and the request first."), mcplib.WithReadOnlyHintAnnotation(false), mcplib.WithDestructiveHintAnnotation(true), mcplib.WithString("request_id", mcplib.Required()), mcplib.WithString("decision", mcplib.Required(), mcplib.Enum("approved", "rejected")), mcplib.WithString("reason", mcplib.Required()), mcplib.WithString("github", mcplib.Description("Required only when no GitHub login was supplied on the request.")), mcplib.WithString("confirm", mcplib.Required(), mcplib.Enum("yes")))
	return tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		if result := requireConfirm(req.GetArguments(), "decide signup invitation"); result != nil {
			return result, nil
		}
		body := map[string]string{"decision": stringArg(req, "decision"), "reason": stringArg(req, "reason"), "github": stringArg(req, "github"), "confirm": "yes"}
		data, err := s.apiPost(ctx, "/api/v1/admin/signup/requests/"+url.PathEscape(stringArg(req, "request_id"))+"/decision", body)
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return mcplib.NewToolResultText(string(data)), nil
	}
}
func (s *Server) toolSignupCapacity() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_signup_capacity", mcplib.WithTitleAnnotation("Manage signup capacity"), mcplib.WithIdempotentHintAnnotation(true), mcplib.WithDescription("Direct human administrator only. Without slots, read funded slots, used reservations and availability. Setting slots requires confirm=yes and a resource assessment reason; it does not resize Kubernetes or calculate physical capacity. Default zero; never increase before reviewing production+preview resources and headroom. Cannot reduce below live reservations."), mcplib.WithReadOnlyHintAnnotation(false), mcplib.WithDestructiveHintAnnotation(true), mcplib.WithString("slots"), mcplib.WithString("reason"), mcplib.WithString("confirm", mcplib.Enum("yes")))
	return tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		var data []byte
		var err error
		value := stringArg(req, "slots")
		if value == "" {
			data, err = s.apiGet(ctx, "/api/v1/admin/signup/capacity")
		} else {
			if result := requireConfirm(req.GetArguments(), "set funded signup capacity"); result != nil {
				return result, nil
			}
			n, e := strconv.Atoi(value)
			if e != nil {
				return mcplib.NewToolResultError("slots must be an integer: " + e.Error()), nil //nolint:nilerr // MCP reports tool errors in the result, not the transport.
			}
			data, err = s.apiPostJSON(ctx, "/api/v1/admin/signup/capacity", map[string]any{"slots": n, "reason": stringArg(req, "reason"), "confirm": "yes"})
		}
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		return mcplib.NewToolResultText(string(data)), nil
	}
}
