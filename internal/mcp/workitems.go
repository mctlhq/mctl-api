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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Canonical WorkItem tools (mctl-api#341): MCP as a second surface over the
// workitem/v1 REST API. Every call carries the caller's own token, so actor
// resolution, tenant visibility and policy are evaluated by the API for this
// call, never inherited from whichever surface created the item.
//
// The one write is an execution REQUEST. Like every surface, MCP never names
// an engine, an engine run or an execution id: the platform supplies those
// when it fulfils the request (mctl-api#368).

// workItemSurface is the provenance label the write tool records. It is a
// label, not an identity: who asked is requested_by, taken from the token.
const workItemSurface = "mcp"

const workItemReadNote = `Read-only. Visibility is the API's: an item outside your tenants answers "not found", exactly like an id that does not exist.`

var workItemIDArg = mcplib.WithString("work_item_id",
	mcplib.Required(),
	mcplib.Description(`Canonical WorkItem id ("wi_..."), as shown by any surface that created or linked it.`),
)

func (s *Server) toolGetWorkItem() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_work_item",
		mcplib.WithTitleAnnotation("Work item"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`One canonical WorkItem: state, state_version, tenant, origin surface, latest_execution and latest_snapshot. state_version is the value mctl_request_work_item_execution expects.

`+workItemReadNote),
		workItemIDArg,
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredPathArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		return s.workItemCall(ctx, http.MethodGet, "/api/v1/work-items/"+id, nil, "work item")
	}
	return tool, handler
}

func (s *Server) toolListWorkItemExecutions() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_work_item_executions",
		mcplib.WithTitleAnnotation("Work item executions"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Every execution attached to one WorkItem, oldest first, with the engine and engine_ref the platform recorded and the surface that requested it.

`+workItemReadNote),
		workItemIDArg,
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredPathArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		return s.workItemCall(ctx, http.MethodGet, "/api/v1/work-items/"+id+"/executions", nil, "work item executions")
	}
	return tool, handler
}

func (s *Server) toolListWorkItemSnapshots() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_work_item_snapshots",
		mcplib.WithTitleAnnotation("Work item context snapshots"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`The immutable ContextSnapshots sealed for one WorkItem, or one of them in full when snapshot_id is given. A resumed execution seals a NEW snapshot that names the one it resumed from; a sealed snapshot never changes.

`+workItemReadNote),
		workItemIDArg,
		mcplib.WithString("snapshot_id",
			mcplib.Description(`A snapshot id ("cs_...") to read in full. Omit to list.`),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredPathArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		path := "/api/v1/work-items/" + id + "/snapshots"
		sid, errResult := pathID(req, "snapshot_id", false)
		if errResult != nil {
			return errResult, nil
		}
		if sid != "" {
			path += "/" + sid
		}
		return s.workItemCall(ctx, http.MethodGet, path, nil, "work item snapshots")
	}
	return tool, handler
}

func (s *Server) toolListWorkItemExecutionRequests() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_work_item_execution_requests",
		mcplib.WithTitleAnnotation("Work item execution requests"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Execution requests made for one WorkItem, or one of them when request_id is given: kind, state (pending, claimed, fulfilled, rejected), requested_by, surface and, once fulfilled, the execution_id the platform created.

`+workItemReadNote),
		workItemIDArg,
		mcplib.WithString("request_id",
			mcplib.Description(`An execution request id ("xr_...") to read. Omit to list.`),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredPathArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		path := "/api/v1/work-items/" + id + "/execution-requests"
		rid, errResult := pathID(req, "request_id", false)
		if errResult != nil {
			return errResult, nil
		}
		if rid != "" {
			path += "/" + rid
		}
		return s.workItemCall(ctx, http.MethodGet, path, nil, "work item execution requests")
	}
	return tool, handler
}

func (s *Server) toolRequestWorkItemExecution() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_request_work_item_execution",
		mcplib.WithTitleAnnotation("Request a work item execution"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Asks the platform to start or resume one WorkItem. It records an execution REQUEST and nothing else: the execution platform claims it, runs it and attaches the new execution and its ContextSnapshot to the SAME WorkItem. The request names no engine, run or execution id; those are the platform's.

You are the requester: requested_by is taken from your authentication, never from an argument, and your access to the item's tenant is checked now, whatever surface created the item. The request is recorded with surface "mcp". A token that relays for another surface is refused here (400 invalid): that surface records its own requests.

Fails closed rather than forking work:
- expected_state_version must equal the item's current state_version (read it with mctl_get_work_item), or the call is refused;
- only one open request per item: a second one is refused with execution_request_open, naming the open request;
- a resume while an execution is still running is refused with execution_active.

Idempotent by idempotency_key: repeating the same call with the same key returns the original request ("replayed": true) instead of making a second one; the same key with different arguments is refused with idempotency_key_reused.`),
		workItemIDArg,
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Enum("start", "resume"),
			mcplib.Description(`"resume" continues the item from an earlier execution; "start" begins its first one.`),
		),
		mcplib.WithNumber("expected_state_version",
			mcplib.Required(),
			mcplib.Description("The item's current state_version, from mctl_get_work_item."),
		),
		mcplib.WithString("resumed_from_execution_id",
			mcplib.Description(`For kind "resume": the execution ("we_...") to resume from. Its sealed snapshot becomes the parent of the new one.`),
		),
		mcplib.WithString("idempotency_key",
			mcplib.Required(),
			mcplib.Description("A key you choose for this one request (at most 512 bytes). Reuse it only to retry the same request."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredPathArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		kind := strings.TrimSpace(stringArg(req, "kind"))
		if kind != "start" && kind != "resume" {
			return mcplib.NewToolResultError(`kind must be "start" or "resume"`), nil
		}
		version, ok := req.GetArguments()["expected_state_version"].(float64)
		// State versions start at 1; 2^53 is where a float64 stops holding
		// every integer.
		if !ok || version < 1 || version != math.Trunc(version) || version > 1<<53 {
			return mcplib.NewToolResultError("expected_state_version must be a positive integer"), nil
		}
		key := strings.TrimSpace(stringArg(req, "idempotency_key"))
		if key == "" {
			return mcplib.NewToolResultError("missing required argument: idempotency_key"), nil
		}
		body := map[string]any{
			"kind":                   kind,
			"expected_state_version": int64(version),
			"surface":                workItemSurface,
			"idempotency_key":        key,
		}
		from, errResult := pathID(req, "resumed_from_execution_id", false)
		if errResult != nil {
			return errResult, nil
		}
		if from != "" {
			body["resumed_from_execution_id"] = from
		}
		return s.workItemCall(ctx, http.MethodPost, "/api/v1/work-items/"+id+"/execution-requests", body, "request work item execution")
	}
	return tool, handler
}

// workItemIDPattern is the shape of every id these tools put in a path
// (wi_, we_, cs_, xr_ ...). Escaping alone would let "." or ".." through as a
// segment that a normalizing proxy resolves out of /work-items/{id}.
var workItemIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// pathID returns a trimmed id that is safe as one path segment, or "" with
// an error result.
func pathID(req mcplib.CallToolRequest, name string, required bool) (string, *mcplib.CallToolResult) {
	v := strings.TrimSpace(stringArg(req, name))
	switch {
	case v == "" && required:
		return "", mcplib.NewToolResultError("missing required argument: " + name)
	case v != "" && !workItemIDPattern.MatchString(v):
		return "", mcplib.NewToolResultError(name + " must be an id such as wi_..., made of letters, digits, '_' and '-'")
	}
	return v, nil
}

// requiredPathArg is pathID for a required argument.
func requiredPathArg(req mcplib.CallToolRequest, name string) (string, *mcplib.CallToolResult) {
	return pathID(req, name, true)
}

// workItemCall keeps the API's typed refusals intact. doRequest collapses an
// error to its message, but a client of these tools branches on the code
// (execution_request_open, execution_active, a stale state_version) and needs
// the details that name the open request or the running execution.
func (s *Server) workItemCall(ctx context.Context, method, path string, body any, what string) (*mcplib.CallToolResult, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: %v", what, err)), nil
		}
		reader = bytes.NewReader(raw)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, s.apiURL+path, reader)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: %v", what, err)), nil
	}
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if token := s.effectiveToken(ctx); token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: request failed: %v", what, err)), nil
	}
	defer resp.Body.Close() //nolint:errcheck
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s: reading response: %v", what, err)), nil
	}
	if resp.StatusCode < 400 {
		// 200 on a create is the replay of an earlier request with the same
		// key; say so, so a retry is not mistaken for a second request.
		if method == http.MethodPost && resp.StatusCode == http.StatusOK {
			var doc map[string]any
			if json.Unmarshal(respBody, &doc) == nil {
				doc["replayed"] = true
				if out, err := json.Marshal(doc); err == nil {
					return mcplib.NewToolResultText(string(out)), nil
				}
			}
		}
		return mcplib.NewToolResultText(string(respBody)), nil
	}
	return mcplib.NewToolResultError(fmt.Sprintf("Failed to %s (HTTP %d): %s", what, resp.StatusCode, strings.TrimSpace(string(respBody)))), nil
}
