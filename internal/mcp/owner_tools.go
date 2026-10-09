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
	"fmt"
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// TenantOwnerChecker answers whether a caller owns a tenant. It is injected
// because internal/api imports this package, not the other way round.
// (true, nil) means owner or platform admin; (false, nil) is a decided no;
// an error means the role could not be read. tools/list treats both of the
// latter as "not an owner" and hides the tools; tools/call keeps them apart:
// a decided no is "not found", an error is an explicit could-not-verify.
type TenantOwnerChecker interface {
	IsTenantOwner(ctx context.Context, user *auth.User, tenant string) (bool, error)
}

// SetTenantOwnerChecker wires the role lookup behind the owner-only tool
// filter. The in-process HTTP server sets it while the router is built,
// before any request is served; the atomic keeps a late set race-free.
func (s *Server) SetTenantOwnerChecker(c TenantOwnerChecker) {
	if c == nil {
		s.ownerChecker.Store(nil)
		return
	}
	s.ownerChecker.Store(&c)
}

// ownerOnlyTools maps a tool to the tenant whose owners alone may see and
// call it. The erpact site tools are the Option A stopgap of mctl-api#486:
// enabled on the shared portal by owner decision 2026-10-09, with this
// filter as the visibility control (the REST handlers re-check the role).
var ownerOnlyTools = map[string]string{
	"mctl_erpact_list_sites":  "erpact",
	"mctl_erpact_create_site": "erpact",
	"mctl_erpact_site_status": "erpact",
}

// ownerOnlyToolFilter drops the owner-only tools unless the caller is an
// owner of the tool's tenant or a platform admin.
//
// With no checker configured (the stdio binary, cmd/mcp, where one shared
// token is used and there is no per-caller identity) nothing is filtered:
// the API enforces the role when the tool is called. Where a checker is set
// (the HTTP server) it fails closed: no caller or a failed lookup hides the
// tools. The role is resolved at most once per tenant per call.
//
// mcp-go applies this filter to tools/list (the whole tool list) and again
// to tools/call (a one-element slice holding only the called tool). A failed
// lookup must stay hidden on tools/list, but on tools/call "not found" would
// report "could not observe" as "observed absent", so there the tool is let
// through and ownerOnlyCallMiddleware answers with an explicit error. A
// decided "not an owner" is filtered on both paths.
func (s *Server) ownerOnlyToolFilter(ctx context.Context, tools []mcp.Tool) []mcp.Tool {
	cp := s.ownerChecker.Load()
	if cp == nil {
		return tools
	}
	checker := *cp
	user := auth.UserFromContext(ctx)
	isCall := len(tools) == 1
	verdict := map[string]bool{}
	allowed := func(tool, tenant string) bool {
		if v, done := verdict[tenant]; done {
			return v
		}
		ok := false
		if user != nil {
			var err error
			ok, err = checker.IsTenantOwner(ctx, user, tenant)
			if err != nil {
				slog.Warn("owner-only tools hidden: role lookup failed", "tool", tool, "tenant", tenant, "error", err)
				// On tools/call defer to the middleware, which reports it.
				ok = isCall
			}
		}
		verdict[tenant] = ok
		return ok
	}
	out := make([]mcp.Tool, 0, len(tools))
	for i := range tools {
		if tenant, restricted := ownerOnlyTools[tools[i].Name]; restricted && !allowed(tools[i].Name, tenant) {
			continue
		}
		out = append(out, tools[i])
	}
	return out
}

// ownerOnlyCallMiddleware runs after the tool filter on tools/call. It is the
// only place that reports a failed role lookup as such: the filter lets an
// owner-only tool through on a lookup error (see ownerOnlyToolFilter) and this
// re-checks the role, so an unreadable role answers "could not verify" rather
// than "tool not found". A decided non-owner never gets here, the filter has
// already refused it; if the second lookup now decides "no", it is refused
// the same way.
func (s *Server) ownerOnlyCallMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tenant, restricted := ownerOnlyTools[req.Params.Name]
		cp := s.ownerChecker.Load()
		if !restricted || cp == nil {
			return next(ctx, req)
		}
		user := auth.UserFromContext(ctx)
		if user == nil {
			return nil, fmt.Errorf("tool '%s' not found", req.Params.Name)
		}
		ok, err := (*cp).IsTenantOwner(ctx, user, tenant)
		if err != nil {
			slog.Warn("owner-only tool call refused: role lookup failed", "tool", req.Params.Name, "tenant", tenant, "error", err)
			return mcp.NewToolResultError(fmt.Sprintf(
				"could not verify your role for tenant %q (the role lookup failed); this is not a denial, try again shortly", tenant)), nil
		}
		if !ok {
			return nil, fmt.Errorf("tool '%s' not found", req.Params.Name)
		}
		return next(ctx, req)
	}
}
