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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestCommerceToolsCallTheTenantRoutes(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{"ok":true}`)
	cases := []struct {
		build func(*Server) (mcplib.Tool, server.ToolHandlerFunc)
		args  map[string]any
		want  string
	}{
		{(*Server).toolGetCommerceBudget, map[string]any{"tenant": "acme"}, "GET /api/v1/commerce/tenants/acme/budget"},
		{(*Server).toolListCommerceInvocations, map[string]any{"tenant": "acme"}, "GET /api/v1/commerce/tenants/acme/invocations"},
		{(*Server).toolListCommerceInvocations, map[string]any{
			"tenant": "acme", "capability_id": "mctl://a/b c", "phase": "finalized", "since": "2026-10-01T00:00:00Z", "limit": float64(5),
		}, "GET /api/v1/commerce/tenants/acme/invocations"},
		{(*Server).toolGetCommerceReceipt, map[string]any{"tenant": "acme", "invocation_id": "inv_1"}, "GET /api/v1/commerce/tenants/acme/invocations/inv_1/receipt"},
	}
	for _, c := range cases {
		r := callRoadmapTool(t, c.build, ts.URL, c.args)
		if r.IsError {
			t.Fatalf("%v: %s", c.args, resultText(t, r))
		}
		got := (*calls)[len(*calls)-1]
		if got.line != c.want {
			t.Errorf("%v: called %q, want %q", c.args, got.line, c.want)
		}
		if got.auth != "Bearer test-token" {
			t.Errorf("Authorization = %q", got.auth)
		}
		if resultText(t, r) != `{"ok":true}` {
			t.Errorf("body not returned verbatim: %s", resultText(t, r))
		}
	}
}

func TestListCommerceInvocationsEncodesTheQuery(t *testing.T) {
	var raw string
	ts := queryBackend(t, &raw)
	r := callRoadmapTool(t, (*Server).toolListCommerceInvocations, ts, map[string]any{
		"tenant": "acme", "capability_id": "mctl://a/b c?x=1&y", "phase": "finalized", "limit": float64(5),
	})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	want := "capability_id=mctl%3A%2F%2Fa%2Fb+c%3Fx%3D1%26y&limit=5&phase=finalized"
	if raw != want {
		t.Fatalf("query = %q, want %q", raw, want)
	}
}

func TestCommerceToolsGiveTheSameErrorForTwoNotFounds(t *testing.T) {
	ts, _ := workItemBackend(t, http.StatusNotFound, "not found")
	a := callRoadmapTool(t, (*Server).toolGetCommerceReceipt, ts.URL, map[string]any{"tenant": "other", "invocation_id": "inv_1"})
	b := callRoadmapTool(t, (*Server).toolGetCommerceReceipt, ts.URL, map[string]any{"tenant": "acme", "invocation_id": "inv_1"})
	if !a.IsError || !b.IsError || resultText(t, a) != resultText(t, b) {
		t.Fatalf("errors differ: %q vs %q", resultText(t, a), resultText(t, b))
	}
}

func TestCommerceToolsRefuseBadArgumentsWithoutCalling(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{}`)
	for name, args := range map[string]map[string]any{
		"no tenant":         {"invocation_id": "inv_1"},
		"slash tenant":      {"tenant": "a/b", "invocation_id": "inv_1"},
		"dotdot tenant":     {"tenant": "..", "invocation_id": "inv_1"},
		"backslash tenant":  {"tenant": `a\b`, "invocation_id": "inv_1"},
		"dot tenant":        {"tenant": " . ", "invocation_id": "inv_1"},
		"control tenant":    {"tenant": "a\nb", "invocation_id": "inv_1"},
		"numeric tenant":    {"tenant": float64(1), "invocation_id": "inv_1"},
		"no invocation":     {"tenant": "acme"},
		"dotdot invocation": {"tenant": "acme", "invocation_id": ".."},
		"slash invocation":  {"tenant": "acme", "invocation_id": "a/b"},
	} {
		if r := callRoadmapTool(t, (*Server).toolGetCommerceReceipt, ts.URL, args); !r.IsError {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, args := range map[string]map[string]any{
		"no tenant":          {},
		"bad limit":          {"tenant": "acme", "limit": float64(0)},
		"fraction limit":     {"tenant": "acme", "limit": 1.5},
		"string limit":       {"tenant": "acme", "limit": "5"},
		"limit over 500":     {"tenant": "acme", "limit": float64(501)},
		"numeric phase":      {"tenant": "acme", "phase": float64(42)},
		"bool since":         {"tenant": "acme", "since": true},
		"numeric capability": {"tenant": "acme", "capability_id": float64(1)},
		"list until":         {"tenant": "acme", "until": []any{"x"}},
	} {
		if r := callRoadmapTool(t, (*Server).toolListCommerceInvocations, ts.URL, args); !r.IsError {
			t.Errorf("list %s: accepted", name)
		}
	}
	if r := callRoadmapTool(t, (*Server).toolGetCommerceBudget, ts.URL, map[string]any{}); !r.IsError {
		t.Error("budget without tenant accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("refused calls reached the API: %v", *calls)
	}
}

// Review of #573: tenants are IdP group names, so the tool applies the
// API's normalization instead of a DNS-label pattern the route never had.
func TestCommerceToolsNormalizeTenantsLikeTheAPI(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{}`)
	for _, c := range []struct{ tenant, want string }{
		{" Acme ", "GET /api/v1/commerce/tenants/acme/budget"},
		{"team_one", "GET /api/v1/commerce/tenants/team_one/budget"},
		{"a.b", "GET /api/v1/commerce/tenants/a.b/budget"},
		{strings.Repeat("x", 70), "GET /api/v1/commerce/tenants/" + strings.Repeat("x", 70) + "/budget"},
	} {
		if r := callRoadmapTool(t, (*Server).toolGetCommerceBudget, ts.URL, map[string]any{"tenant": c.tenant}); r.IsError {
			t.Fatalf("%q refused: %s", c.tenant, resultText(t, r))
		}
		if got := (*calls)[len(*calls)-1].line; got != c.want {
			t.Errorf("%q: called %q, want %q", c.tenant, got, c.want)
		}
	}
}

func TestListCommerceInvocationsAcceptsTheAPILimitBound(t *testing.T) {
	var raw string
	ts := queryBackend(t, &raw)
	if r := callRoadmapTool(t, (*Server).toolListCommerceInvocations, ts, map[string]any{
		"tenant": "acme", "limit": float64(500),
	}); r.IsError || raw != "limit=500" {
		t.Fatalf("limit 500: error=%v query=%q", r.IsError, raw)
	}
}

// Review of #577: a mistyped id is named as such, not reported missing, and
// the limit bound the caller reads comes from the one constant.
func TestCommerceToolsNameTheMistypedArgument(t *testing.T) {
	ts, _ := workItemBackend(t, http.StatusOK, `{}`)
	r := callRoadmapTool(t, (*Server).toolGetCommerceReceipt, ts.URL, map[string]any{"tenant": "acme", "invocation_id": float64(7)})
	if !r.IsError || !strings.Contains(resultText(t, r), "invocation_id must be a string") {
		t.Fatalf("numeric invocation_id: %s", resultText(t, r))
	}
	r = callRoadmapTool(t, (*Server).toolListCommerceInvocations, ts.URL, map[string]any{"tenant": "acme", "phase": float64(42)})
	if !r.IsError || !strings.Contains(resultText(t, r), "phase must be a string") {
		t.Fatalf("numeric phase: %s", resultText(t, r))
	}
	r = callRoadmapTool(t, (*Server).toolListCommerceInvocations, ts.URL, map[string]any{"tenant": "acme", "limit": float64(501)})
	if !r.IsError || !strings.Contains(resultText(t, r), "1.."+strconv.Itoa(commerceListLimitMax)) {
		t.Fatalf("limit message: %s", resultText(t, r))
	}
}

func queryBackend(t *testing.T, raw *string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*raw = r.URL.RawQuery
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}
