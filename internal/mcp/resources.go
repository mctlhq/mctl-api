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

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// registerResources registers MCP Resources on the server.
func (s *Server) registerResources() {
	// 1. mctl://platform/overview
	overviewRes := mcplib.NewResource(
		"mctl://platform/overview",
		"MCTL Platform Overview",
		mcplib.WithResourceDescription("System architectural summary and API capabilities"),
		mcplib.WithMIMEType("text/plain"),
	)

	s.mcpServer.AddResource(overviewRes, func(ctx context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
		overviewText := "# MCTL Control Plane Overview\n\n" +
			"MCTL is an AI-Native Kubernetes Infrastructure Management Platform.\n" +
			"Core Capabilities:\n" +
			"- Tenant & Workspace isolation\n" +
			"- GitOps synchronization via ArgoCD\n" +
			"- Self-healing agent workflows via Temporal\n" +
			"- Unified MCP & REST API interface\n\n" +
			"For live status use mctl_get_service_status or mctl_list_tenants."

		return []mcplib.ResourceContents{
			mcplib.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     overviewText,
			},
		}, nil
	})

	// 2. mctl://operations/catalog
	catalogRes := mcplib.NewResource(
		"mctl://operations/catalog",
		"MCTL Operations Catalog",
		mcplib.WithResourceDescription("Catalog of all registered platform operations with risk levels"),
		mcplib.WithMIMEType("text/plain"),
	)

	s.mcpServer.AddResource(catalogRes, func(ctx context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
		reg := operations.NewRegistry()
		ops := reg.List()

		text := "# Registered Platform Operations Catalog\n\n"
		// Indexed rather than `for _, op := range ops`: Operation is 144 bytes
		// and copying it per iteration is what golangci-lint's gocritic
		// rangeValCopy flags. Only three string fields are read here.
		for i := range ops {
			op := &ops[i]
			text += "- **" + op.Name + "** (" + string(op.RiskLevel) + "): " + op.Description + "\n"
		}

		return []mcplib.ResourceContents{
			mcplib.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     text,
			},
		}, nil
	})
}
