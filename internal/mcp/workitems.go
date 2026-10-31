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
	"net/url"
	"regexp"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/workitems"
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
		id, errResult := requiredIDArg(req, "work_item_id")
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
		id, errResult := requiredIDArg(req, "work_item_id")
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
		id, errResult := requiredIDArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		path := "/api/v1/work-items/" + id + "/snapshots"
		sid, errResult := idArg(req, "snapshot_id", false)
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
		id, errResult := requiredIDArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		path := "/api/v1/work-items/" + id + "/execution-requests"
		rid, errResult := idArg(req, "request_id", false)
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
		id, errResult := requiredIDArg(req, "work_item_id")
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
		from, errResult := idArg(req, "resumed_from_execution_id", false)
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

func (s *Server) toolCreateWorkItem() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_create_work_item",
		mcplib.WithTitleAnnotation("Create a work item"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Creates a canonical WorkItem in a tenant and returns it, including its "wi_" id. Creating starts no execution.

Who acts comes from your authentication, never from an argument. The tenant is checked against your own access (403 tenant_forbidden), and a role below developer, for example viewer, is refused (403 tenant_role_forbidden). A private item is visible only to its creator.

idempotency_key is required: repeating the same call with the same key returns the original item. The same key with different arguments is refused with 409 idempotency_key_reused, and an external_key that is already in use is refused with 409 external_key_in_use. "replayed": true means an existing item was returned, either by a retry with the same key or because external_key matched an existing open item.

No discovery tool exists: pass the returned "wi_" id explicitly to another client, which can then call mctl_list_work_item_intents.`),
		mcplib.WithString("tenant", mcplib.Required(), mcplib.Description("Tenant (workspace) name the item belongs to.")),
		mcplib.WithString("title", mcplib.Required(), mcplib.Description("Short title of the work item.")),
		mcplib.WithString("idempotency_key", mcplib.Required(),
			mcplib.Description("A key you choose for this one creation. Reuse it only to retry the same call.")),
		mcplib.WithString("visibility", mcplib.Enum("tenant", "private"),
			mcplib.Description(`"tenant" (default) or "private" (visible only to you).`)),
		mcplib.WithString("external_key", mcplib.Description("Optional correlation key from the originating system.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		tenant := strings.TrimSpace(stringArg(req, "tenant"))
		if tenant == "" {
			return mcplib.NewToolResultError("missing required argument: tenant"), nil
		}
		title := strings.TrimSpace(stringArg(req, "title"))
		if title == "" {
			return mcplib.NewToolResultError("missing required argument: title"), nil
		}
		key := strings.TrimSpace(stringArg(req, "idempotency_key"))
		if key == "" {
			return mcplib.NewToolResultError("missing required argument: idempotency_key"), nil
		}
		body := map[string]any{
			"tenant":          tenant,
			"title":           title,
			"idempotency_key": key,
			"origin_surface":  workItemSurface,
		}
		if v := strings.TrimSpace(stringArg(req, "visibility")); v != "" {
			if v != "tenant" && v != "private" {
				return mcplib.NewToolResultError(`visibility must be "tenant" or "private"`), nil
			}
			body["visibility"] = v
		}
		if v := strings.TrimSpace(stringArg(req, "external_key")); v != "" {
			body["external_key"] = v
		}
		return s.workItemCall(ctx, http.MethodPost, "/api/v1/work-items", body, "create work item")
	}
	return tool, handler
}

func (s *Server) toolAppendWorkItemIntent() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_append_work_item_intent",
		mcplib.WithTitleAnnotation("Append a work item intent"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Appends what was asked, as free text, to one WorkItem so another client can read it with mctl_list_work_item_intents. An intent is provenance, not approval, and appending starts no execution.

The text is at most 8 KiB and is sent unchanged, never truncated. Text that contains a secret-shaped value is refused with 400 secret_in_text and is not stored. Who acts comes from your authentication; a viewer is refused (403 tenant_role_forbidden), and an item that is private to someone else or in a foreign tenant answers 404 work_item_not_found.

idempotency_key is required: the same key and text return the original intent ("replayed": true); the same key with different text is refused with 409 idempotency_key_reused.`),
		workItemIDArg,
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("The intent text (at most 8 KiB). Never include secrets.")),
		mcplib.WithString("idempotency_key", mcplib.Required(),
			mcplib.Description("A key you choose for this one append. Reuse it only to retry the same call.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredIDArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		text := stringArg(req, "text")
		if strings.TrimSpace(text) == "" {
			return mcplib.NewToolResultError("missing required argument: text"), nil
		}
		key := strings.TrimSpace(stringArg(req, "idempotency_key"))
		if key == "" {
			return mcplib.NewToolResultError("missing required argument: idempotency_key"), nil
		}
		body := map[string]any{
			"text":            text,
			"idempotency_key": key,
			"surface":         workItemSurface,
		}
		return s.workItemCall(ctx, http.MethodPost, "/api/v1/work-items/"+id+"/intents", body, "append work item intent")
	}
	return tool, handler
}

func (s *Server) toolListWorkItemIntents() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_list_work_item_intents",
		mcplib.WithTitleAnnotation("Work item intents"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`The intents appended to one WorkItem, oldest first, as a page: intents, truncated and limit. While truncated is true, call again with after_id set to the last id returned.

An intent with text_redacted: true had its text removed by retention. The text is unavailable; it is not an empty instruction, and clients must never reconstruct it.

`+workItemReadNote),
		workItemIDArg,
		mcplib.WithNumber("after_id", mcplib.Description("Return only intents with an id greater than this (a non-negative integer).")),
		mcplib.WithNumber("limit", mcplib.Description("Page size, an integer from 1 to 100.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, errResult := requiredIDArg(req, "work_item_id")
		if errResult != nil {
			return errResult, nil
		}
		q := url.Values{}
		if raw, present := req.GetArguments()["after_id"]; present && raw != nil {
			v, ok := raw.(float64)
			if !ok || v < 0 || v != math.Trunc(v) || v > 1<<53 {
				return mcplib.NewToolResultError("after_id must be a non-negative integer"), nil
			}
			q.Set("after_id", strconv.FormatInt(int64(v), 10))
		}
		if raw, present := req.GetArguments()["limit"]; present && raw != nil {
			v, ok := raw.(float64)
			if !ok || v < 1 || v != math.Trunc(v) || v > workitems.MaxIntentPageLimit {
				return mcplib.NewToolResultError(fmt.Sprintf("limit must be an integer from 1 to %d", workitems.MaxIntentPageLimit)), nil
			}
			q.Set("limit", strconv.FormatInt(int64(v), 10))
		}
		path := "/api/v1/work-items/" + id + "/intents"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return s.workItemCall(ctx, http.MethodGet, path, nil, "work item intents")
	}
	return tool, handler
}

// workItemIDPattern is the shape of every id these tools send (wi_, we_, cs_,
// xr_ ...). In a path, escaping alone would let "." or ".." through as a
// segment that a normalizing proxy resolves out of /work-items/{id}.
var workItemIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// idArg returns a trimmed id argument of the expected shape, which is also
// safe as one path segment, or "" with an error result.
func idArg(req mcplib.CallToolRequest, name string, required bool) (string, *mcplib.CallToolResult) {
	raw, present := req.GetArguments()[name]
	str, isString := raw.(string)
	if present && !isString {
		return "", mcplib.NewToolResultError(name + " must be a string id")
	}
	v := strings.TrimSpace(str)
	switch {
	case v == "" && required:
		return "", mcplib.NewToolResultError("missing required argument: " + name)
	case v != "" && !workItemIDPattern.MatchString(v):
		return "", mcplib.NewToolResultError(name + " must be an id made of letters, digits, '_' and '-'")
	}
	return v, nil
}

// requiredIDArg is idArg for a required argument.
func requiredIDArg(req mcplib.CallToolRequest, name string) (string, *mcplib.CallToolResult) {
	return idArg(req, name, true)
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
