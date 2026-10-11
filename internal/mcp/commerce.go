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
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Tenant-scoped commerce reads (mctl-api#569): MCP as a second surface over
// the commerce REST routes. Every call carries the caller's own token, so the
// tenant check lives in the API; a foreign tenant and a missing id yield the
// same API body and therefore the same tool error.

const commerceReadNote = `Read-only. A tenant outside your authority answers "not found", exactly like a missing id. Amounts are integer minor units of the stated currency.`

var commerceTenantPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var commerceTenantArg = mcplib.WithString("tenant",
	mcplib.Required(),
	mcplib.Description("Tenant (workspace) name, e.g. 'billing'."),
)

// commerceTenantPath validates tenant and returns its commerce route prefix.
func commerceTenantPath(req mcplib.CallToolRequest) (string, *mcplib.CallToolResult) {
	tenant := strings.TrimSpace(stringArg(req, "tenant"))
	if tenant == "" {
		return "", mcplib.NewToolResultError("missing required argument: tenant")
	}
	if !commerceTenantPattern.MatchString(tenant) {
		return "", mcplib.NewToolResultError("tenant must be a lowercase DNS-safe name (letters, digits and '-')")
	}
	return "/api/v1/commerce/tenants/" + url.PathEscape(tenant), nil
}

func (s *Server) toolGetCommerceBudget() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_commerce_budget",
		mcplib.WithTitleAnnotation("Commerce budget balance"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`The commerce budget balance of one tenant: available_minor, reserved_minor, committed_minor, pending_liability_minor, currency and funds_mode.

`+commerceReadNote),
		commerceTenantArg,
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		base, errResult := commerceTenantPath(req)
		if errResult != nil {
			return errResult, nil
		}
		return s.workItemCall(ctx, http.MethodGet, base+"/budget", nil, "commerce budget")
	}
	return tool, handler
}

func (s *Server) toolListCommerceInvocations() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_commerce_invocations",
		mcplib.WithTitleAnnotation("Commerce invocations"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Lists one tenant's commerce invocations, optionally filtered by capability, phase and period. Never returns arguments, results or payment proofs.

`+commerceReadNote),
		commerceTenantArg,
		mcplib.WithString("capability_id", mcplib.Description("Only invocations of this capability (an mctl:// URI).")),
		mcplib.WithString("phase", mcplib.Description("Only invocations in this phase, e.g. accepted, finalized, refused.")),
		mcplib.WithString("since", mcplib.Description("Only invocations created at or after this RFC 3339 time.")),
		mcplib.WithString("until", mcplib.Description("Only invocations created before this RFC 3339 time.")),
		mcplib.WithNumber("limit", mcplib.Description("Maximum rows to return.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		base, errResult := commerceTenantPath(req)
		if errResult != nil {
			return errResult, nil
		}
		q := url.Values{}
		for _, name := range []string{"capability_id", "phase", "since", "until"} {
			if v := strings.TrimSpace(stringArg(req, name)); v != "" {
				q.Set(name, v)
			}
		}
		if raw, present := req.GetArguments()["limit"]; present && raw != nil {
			n, ok := raw.(float64)
			if !ok || n < 1 || n != math.Trunc(n) || n > 1<<31 {
				return mcplib.NewToolResultError("limit must be a positive integer"), nil
			}
			q.Set("limit", strconv.FormatInt(int64(n), 10))
		}
		path := base + "/invocations"
		if enc := q.Encode(); enc != "" {
			path += "?" + enc
		}
		return s.workItemCall(ctx, http.MethodGet, path, nil, "commerce invocations")
	}
	return tool, handler
}

func (s *Server) toolGetCommerceReceipt() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_commerce_receipt",
		mcplib.WithTitleAnnotation("Commerce receipt"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`The receipt of one commerce invocation: terms, quote digest, price, the five facts (execution outcome, usage, charge, payment, settlement), phase, timestamps and the approval/policy decision reference. Never returns arguments, results, payment proofs or idempotency keys.

`+commerceReadNote),
		commerceTenantArg,
		mcplib.WithString("invocation_id", mcplib.Required(), mcplib.Description(`Invocation id ("inv_...").`)),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		base, errResult := commerceTenantPath(req)
		if errResult != nil {
			return errResult, nil
		}
		id, errResult := requiredIDArg(req, "invocation_id")
		if errResult != nil {
			return errResult, nil
		}
		return s.workItemCall(ctx, http.MethodGet, base+"/invocations/"+id+"/receipt", nil, "commerce receipt")
	}
	return tool, handler
}
