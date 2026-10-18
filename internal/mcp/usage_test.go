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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type usageCall struct {
	query url.Values
	auth  string
}

func usageBackend(t *testing.T, status int, reply string) (*httptest.Server, *[]usageCall) {
	t.Helper()
	var calls []usageCall
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, usageCall{query: r.URL.Query(), auth: r.Header.Get("Authorization")})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func decodeUsage(t *testing.T, text string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, text)
	}
	return m
}

func TestUsageSummaryTotalsStages(t *testing.T) {
	ts, calls := usageBackend(t, 200, `{"group_by":"devloop_stage","truncated":false,"limit":200,"buckets":[
{"key":"investigator","count":1,"input_tokens":100,"calculated_cost":1.25},
{"key":"implementer","count":2,"input_tokens":300,"cache_read_tokens":50,"calculated_cost":3.40}]}`)
	r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{"workflow_id": "dev-loop-mctlhq-mctl-agents-663"})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	q := (*calls)[0].query
	if q.Get("workflow_id") != "dev-loop-mctlhq-mctl-agents-663" || q.Get("group_by") != "devloop_stage" {
		t.Errorf("query = %v", q)
	}
	if (*calls)[0].auth != "Bearer test-token" {
		t.Errorf("auth = %q", (*calls)[0].auth)
	}
	m := decodeUsage(t, resultText(t, r))
	if len(m["buckets"].([]any)) != 2 {
		t.Errorf("buckets changed")
	}
	tot := m["total"].(map[string]any)
	if tot["count"] != float64(3) || tot["input_tokens"] != float64(400) || tot["cache_read_tokens"] != float64(50) || tot["calculated_cost"] != 4.65 {
		t.Errorf("total = %v", tot)
	}
	if tot["provider_reported_cost"] != nil || tot["invoice_reconciled_cost"] != nil || tot["output_tokens"] != nil {
		t.Errorf("absent fields must be null: %v", tot)
	}
}

func TestUsageSummaryTruncatedHasNoTotal(t *testing.T) {
	ts, _ := usageBackend(t, 200, `{"group_by":"agent","truncated":true,"truncated_by":"record_count","limit":2,"buckets":[{"key":"a","count":1},{"key":"b","count":1}]}`)
	r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{})
	m := decodeUsage(t, resultText(t, r))
	if _, ok := m["total"]; ok {
		t.Error("total present on truncated result")
	}
	if m["total_unavailable_reason"] == nil || m["truncated"] != true || m["truncated_by"] != "record_count" || m["limit"] != float64(2) {
		t.Errorf("out = %v", m)
	}
}

func TestUsageSummaryKeepsCostsApart(t *testing.T) {
	ts, _ := usageBackend(t, 200, `{"group_by":"agent","truncated":false,"limit":200,"buckets":[{"key":"a","count":1,"provider_reported_cost":0.5,"calculated_cost":0.7,"invoice_reconciled_cost":0.9}]}`)
	r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{})
	m := decodeUsage(t, resultText(t, r))
	tot := m["total"].(map[string]any)
	if tot["provider_reported_cost"] != 0.5 || tot["calculated_cost"] != 0.7 || tot["invoice_reconciled_cost"] != 0.9 {
		t.Errorf("total = %v", tot)
	}
	cs := m["cost_semantics"].(map[string]any)["calculated_cost"].(string)
	if !strings.Contains(cs, "estimate") || !strings.Contains(cs, "not provider-billed") {
		t.Errorf("semantics = %q", cs)
	}
}

func TestUsageSummaryErrors(t *testing.T) {
	ts, _ := usageBackend(t, 503, `usage ledger not configured`)
	r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{})
	if !r.IsError || !strings.Contains(resultText(t, r), "UNKNOWN, not zero") {
		t.Errorf("503: %v %s", r.IsError, resultText(t, r))
	}
	ts, _ = usageBackend(t, 403, `usage ledger is admin-only`)
	r = callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{})
	if !r.IsError || !strings.Contains(resultText(t, r), "usage ledger is admin-only") {
		t.Errorf("403: %v %s", r.IsError, resultText(t, r))
	}
}

func TestUsageSummaryArgValidation(t *testing.T) {
	ts, calls := usageBackend(t, 200, `{"group_by":"x","truncated":false,"buckets":[]}`)
	for _, args := range []map[string]any{
		{"workflow_id": 5},
		{"repository": "r", "issue": float64(0)},
		{"repository": "r", "issue": 1.5},
		{"limit": float64(1001)},
		{"group_by": "bogus"},
	} {
		r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, args)
		if !r.IsError {
			t.Errorf("%v accepted", args)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("%d requests made for invalid args", len(*calls))
	}
	callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{"group_by": "stage"})
	callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{"group_by": "model"})
	if (*calls)[0].query.Get("group_by") != "devloop_stage" || (*calls)[1].query.Get("group_by") != "canonical_model" {
		t.Errorf("aliases not normalised: %v", *calls)
	}
}

func TestUsageSummaryFilterMappingAndEmpty(t *testing.T) {
	ts, calls := usageBackend(t, 200, `{"group_by":"agent","truncated":false,"limit":200,"buckets":[]}`)
	r := callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{
		"workflow_id": "w", "run_id": "r", "execution_id": "e", "work_item_id": "wi", "repository": "o/r",
		"agent": "a", "stage": "s", "provider": "p", "model": "m", "outcome": "ok",
		"since": "2026-10-01T00:00:00Z", "until": "2026-10-02T00:00:00Z", "issue": float64(3), "pr": float64(4), "limit": float64(10),
		"group_by": "agent",
	})
	q := (*calls)[0].query
	for k, v := range map[string]string{"workflow_id": "w", "run_id": "r", "execution_id": "e", "work_item_id": "wi",
		"repository": "o/r", "agent": "a", "stage": "s", "provider": "p", "model": "m", "outcome": "ok",
		"since": "2026-10-01T00:00:00Z", "until": "2026-10-02T00:00:00Z", "issue": "3", "pr": "4", "limit": "10", "group_by": "agent"} {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	m := decodeUsage(t, resultText(t, r))
	tot := m["total"].(map[string]any)
	if tot["count"] != float64(0) || tot["calculated_cost"] != nil || m["note"] == nil {
		t.Errorf("empty out = %v", m)
	}
	callRoadmapTool(t, (*Server).toolGetUsageSummary, ts.URL, map[string]any{"workflow_id": ""})
	if _, ok := (*calls)[1].query["workflow_id"]; ok {
		t.Error("empty string was sent")
	}
}
