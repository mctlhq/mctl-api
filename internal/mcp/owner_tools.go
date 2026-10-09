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
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// TenantOwnerChecker answers whether a caller owns a tenant. It is injected
// because internal/api imports this package, not the other way round.
// (true, nil) means owner or platform admin; (false, nil) is a decided no;
// an error means the role could not be read. Callers treat both of the
// latter as "not an owner".
type TenantOwnerChecker interface {
	IsTenantOwner(user *auth.User, tenant string) (bool, error)
}

// SetTenantOwnerChecker wires the role lookup behind the owner-only tool
// filter. It must be called before NewStreamableHTTPHandler.
func (s *Server) SetTenantOwnerChecker(c TenantOwnerChecker) { s.ownerChecker = c }

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
// owner of the tool's tenant or a platform admin. It fails closed: no
// caller, no checker or a failed lookup all hide the tools.
func (s *Server) ownerOnlyToolFilter(ctx context.Context, tools []mcp.Tool) []mcp.Tool {
	user := auth.UserFromContext(ctx)
	out := make([]mcp.Tool, 0, len(tools))
	for _, t := range tools {
		tenant, restricted := ownerOnlyTools[t.Name]
		if !restricted {
			out = append(out, t)
			continue
		}
		if user == nil || s.ownerChecker == nil {
			continue
		}
		ok, err := s.ownerChecker.IsTenantOwner(user, tenant)
		if err != nil {
			slog.Warn("owner-only tool hidden: role lookup failed", "tool", t.Name, "tenant", tenant, "error", err)
			continue
		}
		if ok {
			out = append(out, t)
		}
	}
	return out
}
