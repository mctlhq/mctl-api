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
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type workItemCallRecord struct {
	line string
	auth string
	body map[string]any
	keys []string
}

func workItemBackend(t *testing.T, status int, reply string) (*httptest.Server, *[]workItemCallRecord) {
	t.Helper()
	var calls []workItemCallRecord
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec := workItemCallRecord{line: r.Method + " " + r.URL.EscapedPath(), auth: r.Header.Get("Authorization")}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
			for k := range rec.body {
				rec.keys = append(rec.keys, k)
			}
			sort.Strings(rec.keys)
		}
		calls = append(calls, rec)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func TestWorkItemReadToolsCallTheCanonicalAPI(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{"ok":true}`)
	cases := []struct {
		build func(*Server) (mcplib.Tool, server.ToolHandlerFunc)
		args  map[string]any
		want  string
	}{
		{(*Server).toolGetWorkItem, map[string]any{"work_item_id": "wi_1"}, "GET /api/v1/work-items/wi_1"},
		{(*Server).toolListWorkItemExecutions, map[string]any{"work_item_id": "wi_1"}, "GET /api/v1/work-items/wi_1/executions"},
		{(*Server).toolListWorkItemSnapshots, map[string]any{"work_item_id": "wi_1"}, "GET /api/v1/work-items/wi_1/snapshots"},
		{(*Server).toolListWorkItemSnapshots, map[string]any{"work_item_id": "wi_1", "snapshot_id": "cs_2"}, "GET /api/v1/work-items/wi_1/snapshots/cs_2"},
		{(*Server).toolListWorkItemExecutionRequests, map[string]any{"work_item_id": "wi_1"}, "GET /api/v1/work-items/wi_1/execution-requests"},
		{(*Server).toolListWorkItemExecutionRequests, map[string]any{"work_item_id": "wi_1", "request_id": "xr_3"}, "GET /api/v1/work-items/wi_1/execution-requests/xr_3"},
		// An id cannot climb out of its path segment.
		{(*Server).toolGetWorkItem, map[string]any{"work_item_id": "../tenants"}, "GET /api/v1/work-items/..%2Ftenants"},
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
			t.Errorf("%v: Authorization = %q, want the caller's token", c.args, got.auth)
		}
	}
}

func TestRequestWorkItemExecutionSendsARequestNotAnExecution(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusCreated, `{"execution_request":{"id":"xr_1"}}`)
	r := callRoadmapTool(t, (*Server).toolRequestWorkItemExecution, ts.URL, map[string]any{
		"work_item_id": "wi_1", "kind": "resume", "expected_state_version": float64(7),
		"resumed_from_execution_id": "we_1", "idempotency_key": "k1",
		// Arguments the tool does not declare must not reach the body: a
		// surface never names the run, the actor, or its own provenance.
		"engine": "temporal", "engine_ref": "run", "execution_id": "we_x", "surface": "telegram", "actor": "someone",
	})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	got := (*calls)[0]
	if got.line != "POST /api/v1/work-items/wi_1/execution-requests" {
		t.Fatalf("called %q", got.line)
	}
	if want := "expected_state_version,idempotency_key,kind,resumed_from_execution_id,surface"; strings.Join(got.keys, ",") != want {
		t.Fatalf("body keys = %v, want %s", got.keys, want)
	}
	b := got.body
	if b["kind"] != "resume" || b["expected_state_version"] != float64(7) || b["resumed_from_execution_id"] != "we_1" ||
		b["idempotency_key"] != "k1" || b["surface"] != "mcp" {
		t.Fatalf("body = %v", b)
	}
	if strings.Contains(resultText(t, r), "replayed") {
		t.Fatalf("a 201 is a new request, not a replay: %s", resultText(t, r))
	}
}

func TestRequestWorkItemExecutionRefusesBadArgumentsWithoutCalling(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusCreated, `{}`)
	valid := func() map[string]any {
		return map[string]any{"work_item_id": "wi_1", "kind": "resume", "expected_state_version": float64(1), "idempotency_key": "k"}
	}
	for name, mutate := range map[string]func(map[string]any){
		"no work item":       func(a map[string]any) { delete(a, "work_item_id") },
		"blank work item":    func(a map[string]any) { a["work_item_id"] = "  " },
		"unknown kind":       func(a map[string]any) { a["kind"] = "run" },
		"no version":         func(a map[string]any) { delete(a, "expected_state_version") },
		"string version":     func(a map[string]any) { a["expected_state_version"] = "1" },
		"negative version":   func(a map[string]any) { a["expected_state_version"] = float64(-1) },
		"fractional version": func(a map[string]any) { a["expected_state_version"] = 1.5 },
		"no key":             func(a map[string]any) { delete(a, "idempotency_key") },
		"blank key":          func(a map[string]any) { a["idempotency_key"] = " " },
	} {
		args := valid()
		mutate(args)
		if r := callRoadmapTool(t, (*Server).toolRequestWorkItemExecution, ts.URL, args); !r.IsError {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("refused calls still reached the API: %v", *calls)
	}
}

func TestRequestWorkItemExecutionMarksAReplay(t *testing.T) {
	ts, _ := workItemBackend(t, http.StatusOK, `{"execution_request":{"id":"xr_1"}}`)
	r := callRoadmapTool(t, (*Server).toolRequestWorkItemExecution, ts.URL, map[string]any{
		"work_item_id": "wi_1", "kind": "resume", "expected_state_version": float64(1), "idempotency_key": "k",
	})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(resultText(t, r)), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["replayed"] != true {
		t.Fatalf("a 200 on create is the replay of the same key, got %v", doc)
	}
	if xr, _ := doc["execution_request"].(map[string]any); xr["id"] != "xr_1" {
		t.Fatalf("the replay must carry the original request, got %v", doc)
	}
}

func TestWorkItemToolsKeepTheTypedRefusal(t *testing.T) {
	reply := `{"error":"an execution request is already open","code":"execution_request_open","details":{"execution_request_id":"xr_open","state":"pending"}}`
	ts, _ := workItemBackend(t, http.StatusConflict, reply)
	r := callRoadmapTool(t, (*Server).toolRequestWorkItemExecution, ts.URL, map[string]any{
		"work_item_id": "wi_1", "kind": "resume", "expected_state_version": float64(1), "idempotency_key": "k2",
	})
	if !r.IsError {
		t.Fatal("a 409 must be an error result")
	}
	text := resultText(t, r)
	for _, want := range []string{"HTTP 409", "execution_request_open", "xr_open"} {
		if !strings.Contains(text, want) {
			t.Errorf("error %q lost %q", text, want)
		}
	}
}
