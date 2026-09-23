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
	"net/url"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Roadmap read tools (mctl-api#333). Both wrap the REST read model, which
// selects from the RoadmapPublication mctlhq/.github publishes; neither
// evaluates readiness or touches GitHub.

const roadmapProvenanceNote = `Every answer carries provenance: the roadmap-state commit, the evaluator and manifest revisions, the observation's capturedAt and its age in seconds. The answer is only as fresh as that capture — judge it before acting. An error saying the publication is unavailable means "cannot say", never "nothing is ready".`

func (s *Server) toolGetEpicStatus() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_epic_status",
		mcplib.WithTitleAnnotation("Roadmap epic status"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Status of one roadmap epic (an EpicDefinition in mctlhq/.github), from the published RoadmapPublication: the epic's lifecycle, title and goal, its manifest path and digest, the RoadmapReadySet (every work item's state — complete, ready, blocked or unknown — with typed blockers and the issue it is bound to) and the RoadmapHealth (allRequired completion and drift diagnostics), both exactly as published.

Read-only: it never labels, approves, starts a DevLoop or writes to GitHub. Readiness is the Roadmap Control Plane's answer, not recomputed here; an unbound or unobserved item is "unknown", which is never ready.

`+roadmapProvenanceNote),
		mcplib.WithString("epic",
			mcplib.Required(),
			mcplib.Description(`Epic name (e.g. "lifecycle-ownership") or its root issue (e.g. "mctlhq/.github#57").`),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		epic := strings.TrimSpace(stringArg(req, "epic"))
		if epic == "" {
			return mcplib.NewToolResultError("missing required argument: epic"), nil
		}
		body, err := s.apiGet(ctx, "/api/v1/roadmap/epic-status?"+url.Values{"epic": {epic}}.Encode())
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to read epic status: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}
	return tool, handler
}

func (s *Server) toolGetReadyWorkItems() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_ready_work_items",
		mcplib.WithTitleAnnotation("Ready roadmap work items"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Roadmap work items that are ready to start now, from the published RoadmapPublication: for one epic, or for every epic whose lifecycle is "active" when no epic is given. Each item is the published ready-set entry (id, required, repository/issue, phase, dependsOn), grouped under its epic with the manifest it came from.

required_only defaults to true — the safe wave-selection default. Several items may be ready at once when the dependency graph allows it; choosing between them is a priority decision this tool does not make. Read-only: it never starts or approves anything.

`+roadmapProvenanceNote),
		mcplib.WithString("epic",
			mcplib.Description(`Epic name or root issue ("mctlhq/.github#42"). Omit for every active epic.`),
		),
		mcplib.WithString("required_only",
			mcplib.Description(`"false" to include optional items. Defaults to true.`),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		q := url.Values{}
		if epic := strings.TrimSpace(stringArg(req, "epic")); epic != "" {
			q.Set("epic", epic)
		}
		if v := strings.TrimSpace(stringArg(req, "required_only")); v != "" {
			q.Set("required_only", v)
		}
		path := "/api/v1/roadmap/ready"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		body, err := s.apiGet(ctx, path)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to read ready work items: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}
	return tool, handler
}
