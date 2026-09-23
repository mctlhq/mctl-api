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
	"io"
	"net/http"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Governed wave start (mctl-api#334): plan, then start exactly that plan.

const waveFlowNote = `The flow is always: mctl_plan_epic_wave → show the plan to the user → mctl_start_epic_wave with that plan's epic, required_only, plan_hash, provenance.state_revision and its selected ids, unchanged. Starting a wave never approves a proposal: every DevLoop it starts still waits for a human approval.`

func (s *Server) toolPlanEpicWave() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_plan_epic_wave",
		mcplib.WithTitleAnnotation("Plan a roadmap epic wave"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Plan "start the next wave for this epic" without starting anything: the exact ready work items of one roadmap epic that a wave would start, from the published RoadmapPublication. Each selected item carries its issue and the exact DevLoop workflow id it would get; ready items that cannot be started (not bound to an exact issue) are listed as refused, never dropped.

Only items the published ready set lists as ready are eligible; required_only defaults to true. With items, exactly those ids are planned or the plan fails with invalid_selection naming each refused id — never a subset. The answer says whether the plan is executable now: the publication must be no older than the configured maximum (default 30 minutes).

`+waveFlowNote+`

`+roadmapProvenanceNote),
		mcplib.WithString("epic",
			mcplib.Required(),
			mcplib.Description(`Epic name (e.g. "enterprise-mcp") or its root issue (e.g. "mctlhq/.github#35").`),
		),
		mcplib.WithBoolean("required_only",
			mcplib.Description(`false to make optional items eligible. Defaults to true.`),
		),
		mcplib.WithArray("items",
			mcplib.Description(`Exact work-item ids to plan. Omit for every eligible item.`),
			mcplib.WithStringItems(),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, errResult := waveBody(req, false)
		if errResult != nil {
			return errResult, nil
		}
		return s.wavePost(ctx, "/api/v1/roadmap/waves/plan", body, "plan the wave")
	}
	return tool, handler
}

func (s *Server) toolStartEpicWave() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_start_epic_wave",
		mcplib.WithTitleAnnotation("Start a planned roadmap epic wave"),
		// Not destructive: it only starts DevLoops, each of which stops at a
		// proposal awaiting human approval. Idempotent: re-running the same
		// plan starts nothing twice.
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Start a wave planned with mctl_plan_epic_wave: one DevLoopWorkflow per selected work item, with the exact workflow ids the plan named. Admin-only.

mctl-api reloads the latest verified RoadmapPublication and starts only if it is the very publication the plan came from (plan_stale otherwise), it is no older than the configured maximum (publication_too_old otherwise), and the request re-derives the identical plan (invalid_selection otherwise). Nothing is started on any refusal — never a subset. Per item the answer reports started, already_running, already_exists (a closed DevLoop is not restarted) or failed; re-running the same plan starts nothing twice. Cost: each started DevLoop runs an investigator (~$3 each).

`+waveFlowNote),
		mcplib.WithString("epic", mcplib.Required(), mcplib.Description(`The plan's epic, as planned.`)),
		mcplib.WithBoolean("required_only", mcplib.Description(`The plan's required_only. Defaults to true.`)),
		mcplib.WithArray("items", mcplib.Required(),
			mcplib.Description(`The plan's selected ids, all of them.`), mcplib.WithStringItems()),
		mcplib.WithString("plan_hash", mcplib.Required(), mcplib.Description(`The plan's plan_hash.`)),
		mcplib.WithString("state_revision", mcplib.Required(), mcplib.Description(`The plan's provenance.state_revision.`)),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, errResult := waveBody(req, true)
		if errResult != nil {
			return errResult, nil
		}
		return s.wavePost(ctx, "/api/v1/roadmap/waves/execute", body, "start the wave")
	}
	return tool, handler
}

// waveBody builds the REST body from the tool arguments, refusing a wrong
// type rather than dropping it.
func waveBody(req mcplib.CallToolRequest, execute bool) (map[string]any, *mcplib.CallToolResult) {
	args := req.GetArguments()
	body := map[string]any{}
	epic := strings.TrimSpace(stringArg(req, "epic"))
	if epic == "" {
		return nil, mcplib.NewToolResultError("missing required argument: epic")
	}
	body["epic"] = epic
	switch v := args["required_only"].(type) {
	case nil:
	case bool:
		body["required_only"] = v
	default:
		return nil, mcplib.NewToolResultError("required_only must be a boolean")
	}
	switch v := args["items"].(type) {
	case nil:
	case []any:
		items := make([]string, 0, len(v))
		for _, it := range v {
			id, ok := it.(string)
			if !ok {
				return nil, mcplib.NewToolResultError("items must be work-item ids (strings)")
			}
			items = append(items, id)
		}
		body["items"] = items
	default:
		return nil, mcplib.NewToolResultError("items must be an array of work-item ids")
	}
	if execute {
		for _, k := range []string{"plan_hash", "state_revision"} {
			v := strings.TrimSpace(stringArg(req, k))
			if v == "" {
				return nil, mcplib.NewToolResultError("missing required argument: " + k + " (plan first with mctl_plan_epic_wave)")
			}
			body[k] = v
		}
		if _, ok := body["items"]; !ok {
			return nil, mcplib.NewToolResultError("missing required argument: items (the plan's selected ids)")
		}
	}
	return body, nil
}

func (s *Server) wavePost(ctx context.Context, path string, body map[string]any, what string) (*mcplib.CallToolResult, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+path, strings.NewReader(string(data)))
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token := s.effectiveToken(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: %v", what, err)), nil
	}
	defer resp.Body.Close() //nolint:errcheck
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: reading response: %v", what, err)), nil
	}
	if resp.StatusCode < 400 {
		return mcplib.NewToolResultText(string(out)), nil
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(out, &apiErr)
	hint := ""
	switch apiErr.Code {
	case "plan_stale":
		hint = " The publication changed since the plan: plan again and show the new plan to the user."
	case "publication_too_old":
		hint = " The latest publication is too old to act on: wait for the next roadmap publication, then plan again."
	case "invalid_selection":
		hint = " Nothing was started. Use the plan's exact selected ids, or plan again."
	case "roadmap_unavailable":
		hint = " Readiness is UNKNOWN, not empty."
	case "wave_execution_disabled":
		hint = " Wave execution is switched off by server configuration: do not retry or replan; only an operator can fix it."
	}
	return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s (HTTP %d):%s %s", what, resp.StatusCode, hint, strings.TrimSpace(string(out)))), nil
}
