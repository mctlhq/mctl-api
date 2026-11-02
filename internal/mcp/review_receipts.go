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
	"net/http"
	"net/url"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Review receipts (mctl-api#897): MCP as a second surface over
// POST /api/v1/review-receipts/manual and GET /api/v1/review-gate. Both carry
// the caller's own token, so the API stays the only authorization check.

var reviewGateSubjectArgs = []string{
	"kind", "service", "slug", "gitops_commit", "content_digest", "approval_ref",
	"repository", "report_root", "report_path", "source_sha", "base_sha", "head_sha",
	"inventory_digest", "digest_version",
}

// jsonArg decodes a tool argument that is a JSON object (or array when
// wantArray) given as a string, or already structured.
func jsonArg(req mcplib.CallToolRequest, name string, wantArray bool) (any, *mcplib.CallToolResult) {
	raw, present := req.GetArguments()[name]
	if !present || raw == nil {
		return nil, mcplib.NewToolResultError(name + " is required")
	}
	if s, ok := raw.(string); ok {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, mcplib.NewToolResultError(name + " must be valid JSON: " + err.Error())
		}
		raw = v
	}
	switch raw.(type) {
	case []any:
		if !wantArray {
			return nil, mcplib.NewToolResultError(name + " must be a JSON object")
		}
	case map[string]any:
		if wantArray {
			return nil, mcplib.NewToolResultError(name + " must be a JSON array")
		}
	default:
		return nil, mcplib.NewToolResultError(name + " has the wrong JSON type")
	}
	return raw, nil
}

func (s *Server) toolSubmitReviewAssertion() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_submit_review_assertion",
		mcplib.WithDescription(`Human-admin-only. Records a manual ADVISORY review assertion against an open manual-mode review request (POST /api/v1/review-receipts/manual). The receipt is always manual and advisory: it never satisfies required_assurance=independent. The reviewer, assurance, mode, tenant and time are set by the server; a caller cannot supply them. Refused for service, relayed and surface callers, for a closed or worker-mode request, and when the subject binding differs from the request's.`),
		mcplib.WithTitleAnnotation("Submit manual review assertion"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithString("request_id", mcplib.Required(), mcplib.Description("The review request id (rr_...).")),
		mcplib.WithString("subject", mcplib.Required(), mcplib.Description("The review subject as a JSON object (Tier A ReviewSubject).")),
		mcplib.WithString("outcome", mcplib.Required(), mcplib.Description("Review outcome."),
			mcplib.Enum("PASS", "CHANGES_REQUESTED", "NEEDS_HUMAN", "UNOBSERVABLE")),
		mcplib.WithString("criteria", mcplib.Required(), mcplib.Description(`JSON array of {"id","status"} rubric criteria; status is met, unmet or unobserved.`)),
		mcplib.WithString("findings_ref", mcplib.Required(), mcplib.Description(`JSON object {"name","kind","content_hash"} naming the findings artifact.`)),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		requestID, errResult := strictStringArg(req, "request_id")
		if errResult != nil {
			return errResult, nil
		}
		outcome, errResult := strictStringArg(req, "outcome")
		if errResult != nil {
			return errResult, nil
		}
		if strings.TrimSpace(requestID) == "" || strings.TrimSpace(outcome) == "" {
			return mcplib.NewToolResultError("request_id and outcome are required"), nil
		}
		subject, errResult := jsonArg(req, "subject", false)
		if errResult != nil {
			return errResult, nil
		}
		criteria, errResult := jsonArg(req, "criteria", true)
		if errResult != nil {
			return errResult, nil
		}
		findings, errResult := jsonArg(req, "findings_ref", false)
		if errResult != nil {
			return errResult, nil
		}
		body, err := s.apiPostJSON(ctx, "/api/v1/review-receipts/manual", map[string]any{
			"request_id": strings.TrimSpace(requestID), "subject": subject, "outcome": outcome,
			"criteria": criteria, "findings_ref": findings,
		})
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to submit review assertion: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}
	return tool, handler
}

func (s *Server) toolGetReviewGate() (mcplib.Tool, server.ToolHandlerFunc) {
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(`Admin-only. Evaluates the review gate for one live subject (GET /api/v1/review-gate) and returns the verdict with the full input it was computed from: the matching review request and the complete receipt pool. A manual advisory receipt never satisfies required_assurance=independent (verdict advisory_only). The pool is complete or the call fails: a 503 means UNKNOWN, never "no receipts".`),
		mcplib.WithString("required_assurance", mcplib.Description("independent (default) or any."),
			mcplib.Enum("independent", "any")),
	}
	for _, name := range reviewGateSubjectArgs {
		opts = append(opts, mcplib.WithString(name, mcplib.Description("Live subject field: "+name+".")))
	}
	tool := mcplib.NewTool("mctl_get_review_gate",
		mcplib.WithTitleAnnotation("Review gate"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
	)
	for _, o := range opts {
		o(&tool)
	}

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		q := url.Values{}
		for _, name := range append([]string{"required_assurance"}, reviewGateSubjectArgs...) {
			raw, errResult := strictStringArg(req, name)
			if errResult != nil {
				return errResult, nil
			}
			if v := strings.TrimSpace(raw); v != "" {
				q.Set(name, v)
			}
		}
		body, status, err := s.apiGetStatus(ctx, "/api/v1/review-gate?"+q.Encode())
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get review gate: %v", err)), nil
		}
		if status == http.StatusServiceUnavailable {
			return mcplib.NewToolResultError("review store unavailable: the gate is UNKNOWN, not satisfied: " + strings.TrimSpace(string(body))), nil
		}
		if status < 200 || status >= 300 {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get review gate (HTTP %d): %s", status, strings.TrimSpace(string(body)))), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}
	return tool, handler
}
