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
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/usage"
)

// Model-usage ledger reads (mctl-api#651, ADR-012): MCP as a second surface
// over GET /api/v1/usage/summary. The call carries the caller's own token, so
// requireUsageAdmin stays the only authorization check.

var usageStringArgs = []string{
	"workflow_id", "run_id", "execution_id", "work_item_id", "repository",
	"agent", "stage", "provider", "model", "outcome", "since", "until",
}

var usageTokenFields = []string{
	"input_tokens", "output_tokens", "cache_read_tokens",
	"cache_write_tokens", "reasoning_tokens", "web_search_requests",
}

var usageCostFields = []string{"provider_reported_cost", "calculated_cost", "invoice_reconciled_cost"}

var usageCostSemantics = map[string]string{
	"provider_reported_cost":  "cost reported by the model provider on the invocation",
	"calculated_cost":         "list-price estimate computed by mctl-api from the pricing catalog (pricing_version per record); not provider-billed and not invoice spend. Only price_source=mctl_catalog rows are priced from the catalog: provider_free rows carry 0, unknown rows carry null and are still counted in token totals; group_by=price_source separates them",
	"invoice_reconciled_cost": "spend reconciled against a provider invoice; null until reconciliation exists",
}

// usageGroupByValues is the closed group_by set plus the two aliases.
func usageGroupByValues() []string {
	return []string{
		string(usage.GroupByAgent), string(usage.GroupByStage), string(usage.GroupByModel),
		string(usage.GroupByProvider), string(usage.GroupByRepo), string(usage.GroupByWorkflow),
		string(usage.GroupByWorkItem), string(usage.GroupByExecution), string(usage.GroupByOutcome),
		string(usage.GroupByPriceSource),
		"stage", "model",
	}
}

func (s *Server) toolGetUsageSummary() (mcplib.Tool, server.ToolHandlerFunc) {
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(`Admin-only. Summarises the durable model-usage ledger (GET /api/v1/usage/summary): tokens and cost per bucket, for example per DevLoop stage of one workflow_id. Default group_by is devloop_stage.

Costs are three separate numbers and are never added together: provider_reported_cost, calculated_cost (a list-price estimate, neither provider-billed nor invoice spend) and invoice_reconciled_cost. A null cost means not recorded, not zero.

"total" (sums of the returned buckets) is present only when truncated is false; a truncated list is clipped by record count and gets total_unavailable_reason instead. If the ledger is unavailable the call fails with usage UNKNOWN, not zero. A missing stage bucket means no rows were recorded for it: producer coverage is incomplete (mctl-agents#507).`),
		mcplib.WithString("group_by",
			mcplib.Description("Bucket dimension; default devloop_stage. Aliases: stage, model."),
			mcplib.Enum(usageGroupByValues()...)),
	}
	for _, name := range usageStringArgs {
		opts = append(opts, mcplib.WithString(name, mcplib.Description("Filter: "+name+".")))
	}
	opts = append(opts,
		mcplib.WithNumber("issue", mcplib.Description("Issue number; requires repository.")),
		mcplib.WithNumber("pr", mcplib.Description("Pull request number; requires repository.")),
		mcplib.WithNumber("limit", mcplib.Description("Maximum buckets, 1.."+strconv.Itoa(usage.MaxQueryLimit)+".")),
	)
	tool := mcplib.NewTool("mctl_get_usage_summary",
		mcplib.WithTitleAnnotation("Model usage summary"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
	)
	for _, o := range opts {
		o(&tool)
	}

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		q := url.Values{}
		for _, name := range usageStringArgs {
			raw, errResult := strictStringArg(req, name)
			if errResult != nil {
				return errResult, nil
			}
			if v := strings.TrimSpace(raw); v != "" {
				q.Set(name, v)
			}
		}
		for _, name := range []string{"issue", "pr", "limit"} {
			raw, present := req.GetArguments()[name]
			if !present || raw == nil {
				continue
			}
			n, ok := raw.(float64)
			max := float64(math.MaxInt32)
			if name == "limit" {
				max = usage.MaxQueryLimit
			}
			if !ok || n < 1 || n != math.Trunc(n) || n > max {
				if name == "limit" {
					return mcplib.NewToolResultError("limit must be an integer in 1.." + strconv.Itoa(usage.MaxQueryLimit)), nil
				}
				return mcplib.NewToolResultError(name + " must be a positive integer"), nil
			}
			q.Set(name, strconv.FormatInt(int64(n), 10))
		}
		groupBy := string(usage.GroupByStage)
		rawGB, errResult := strictStringArg(req, "group_by")
		if errResult != nil {
			return errResult, nil
		}
		if v := strings.TrimSpace(rawGB); v != "" {
			switch v {
			case "stage":
				v = string(usage.GroupByStage)
			case "model":
				v = string(usage.GroupByModel)
			}
			gb, ok := usage.ParseGroupBy(v)
			if !ok {
				return mcplib.NewToolResultError("group_by must be one of: " + strings.Join(usageGroupByValues(), ", ")), nil
			}
			groupBy = string(gb)
		}
		q.Set("group_by", groupBy)

		body, status, err := s.apiGetStatus(ctx, "/api/v1/usage/summary?"+q.Encode())
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get usage summary: %v", err)), nil
		}
		if status == http.StatusServiceUnavailable {
			return mcplib.NewToolResultError("usage ledger unavailable: spend is UNKNOWN, not zero: " + strings.TrimSpace(string(body))), nil
		}
		if status < 200 || status >= 300 {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to get usage summary (HTTP %d): %s", status, strings.TrimSpace(string(body)))), nil
		}
		out, err := buildUsageSummary(body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to read usage summary: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(out)), nil
	}
	return tool, handler
}

// usageSummaryOut is the tool's output; the API fields are re-emitted as
// received.
type usageSummaryOut struct {
	GroupBy                json.RawMessage              `json:"group_by"`
	Buckets                []map[string]json.RawMessage `json:"buckets"`
	Truncated              bool                         `json:"truncated"`
	TruncatedBy            json.RawMessage              `json:"truncated_by,omitempty"`
	Limit                  json.RawMessage              `json:"limit,omitempty"`
	Total                  map[string]json.RawMessage   `json:"total,omitempty"`
	TotalUnavailableReason string                       `json:"total_unavailable_reason,omitempty"`
	CostSemantics          map[string]string            `json:"cost_semantics"`
	Note                   string                       `json:"note,omitempty"`
}

func buildUsageSummary(body []byte) ([]byte, error) {
	var in struct {
		GroupBy     json.RawMessage              `json:"group_by"`
		Buckets     []map[string]json.RawMessage `json:"buckets"`
		Truncated   bool                         `json:"truncated"`
		TruncatedBy json.RawMessage              `json:"truncated_by"`
		Limit       json.RawMessage              `json:"limit"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	out := usageSummaryOut{
		GroupBy:       in.GroupBy,
		Buckets:       in.Buckets,
		Truncated:     in.Truncated,
		Limit:         in.Limit,
		CostSemantics: usageCostSemantics,
	}
	if out.Buckets == nil {
		out.Buckets = []map[string]json.RawMessage{}
	}
	if len(in.TruncatedBy) > 0 && string(in.TruncatedBy) != "null" {
		out.TruncatedBy = in.TruncatedBy
	}
	if in.Truncated {
		out.TotalUnavailableReason = fmt.Sprintf("bucket list truncated by record_count at limit %s; a sum of the returned buckets would understate usage. Narrow the filter or raise limit.", string(in.Limit))
	} else {
		total, err := sumUsageBuckets(out.Buckets)
		if err != nil {
			return nil, err
		}
		out.Total = total
		if len(out.Buckets) == 0 {
			out.Note = "no ledger records matched this filter; this is not evidence of zero spend for uninstrumented producers"
		}
	}
	return json.Marshal(out)
}

func isNullJSON(raw json.RawMessage, present bool) bool {
	return !present || len(raw) == 0 || string(raw) == "null"
}

// sumUsageBuckets sums the returned buckets. Tokens are int64 sums, costs are
// summed separately in exact decimal arithmetic; a field absent from every
// bucket stays null.
func sumUsageBuckets(buckets []map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	total := map[string]json.RawMessage{}
	var count int64
	for _, b := range buckets {
		raw, ok := b["count"]
		if isNullJSON(raw, ok) {
			continue
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bucket count %q: %w", raw, err)
		}
		count += n
	}
	total["count"] = json.RawMessage(strconv.FormatInt(count, 10))

	for _, f := range usageTokenFields {
		var sum int64
		seen := false
		for _, b := range buckets {
			raw, ok := b[f]
			if isNullJSON(raw, ok) {
				continue
			}
			n, err := strconv.ParseInt(string(raw), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bucket %s %q: %w", f, raw, err)
			}
			sum += n
			seen = true
		}
		if seen {
			total[f] = json.RawMessage(strconv.FormatInt(sum, 10))
		} else {
			total[f] = json.RawMessage("null")
		}
	}
	for _, f := range usageCostFields {
		sum := new(big.Rat)
		seen := false
		for _, b := range buckets {
			raw, ok := b[f]
			if isNullJSON(raw, ok) {
				continue
			}
			r, ok := new(big.Rat).SetString(string(raw))
			if !ok {
				return nil, fmt.Errorf("bucket %s %q is not a number", f, raw)
			}
			sum.Add(sum, r)
			seen = true
		}
		if !seen {
			total[f] = json.RawMessage("null")
			continue
		}
		s := sum.FloatString(18)
		if strings.Contains(s, ".") {
			s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
		}
		total[f] = json.RawMessage(s)
	}
	return total, nil
}
