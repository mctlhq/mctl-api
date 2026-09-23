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
	"strings"
	"testing"
)

func waveBackend(t *testing.T, status int, reply string) (*httptest.Server, *[]map[string]any, *[]string) {
	t.Helper()
	var bodies []map[string]any
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		bodies = append(bodies, b)
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(ts.Close)
	return ts, &bodies, &paths
}

func TestEpicWaveToolsSendThePlanUnchanged(t *testing.T) {
	ts, bodies, paths := waveBackend(t, http.StatusOK, `{"ok":true}`)
	plan := callRoadmapTool(t, (*Server).toolPlanEpicWave, ts.URL, map[string]any{
		"epic": "enterprise-mcp", "required_only": false, "items": []any{"a", "b"},
	})
	start := callRoadmapTool(t, (*Server).toolStartEpicWave, ts.URL, map[string]any{
		"epic": "enterprise-mcp", "items": []any{"a", "b"}, "plan_hash": "h", "state_revision": "r",
	})
	if plan.IsError || start.IsError {
		t.Fatalf("plan %v start %v", resultText(t, plan), resultText(t, start))
	}
	if (*paths)[0] != "POST /api/v1/roadmap/waves/plan" || (*paths)[1] != "POST /api/v1/roadmap/waves/execute" {
		t.Fatalf("paths = %v", *paths)
	}
	if b := (*bodies)[0]; b["required_only"] != false || len(b["items"].([]any)) != 2 {
		t.Fatalf("plan body = %v", b)
	}
	if b := (*bodies)[1]; b["plan_hash"] != "h" || b["state_revision"] != "r" || b["epic"] != "enterprise-mcp" {
		t.Fatalf("start body = %v", b)
	}
}

func TestEpicWaveToolsRefuseBadArgumentsWithoutCalling(t *testing.T) {
	ts, bodies, _ := waveBackend(t, http.StatusOK, `{}`)
	for _, args := range []map[string]any{
		{},
		{"epic": "e", "required_only": "yes"},
		{"epic": "e", "items": "a,b"},
		{"epic": "e", "items": []any{1}},
	} {
		if r := callRoadmapTool(t, (*Server).toolPlanEpicWave, ts.URL, args); !r.IsError {
			t.Errorf("plan %v accepted", args)
		}
	}
	for _, args := range []map[string]any{
		{"epic": "e", "items": []any{"a"}, "state_revision": "r"},
		{"epic": "e", "items": []any{"a"}, "plan_hash": "h"},
		{"epic": "e", "plan_hash": "h", "state_revision": "r"},
	} {
		if r := callRoadmapTool(t, (*Server).toolStartEpicWave, ts.URL, args); !r.IsError {
			t.Errorf("start %v accepted", args)
		}
	}
	if len(*bodies) != 0 {
		t.Fatalf("a refused call reached the API: %v", *bodies)
	}
}

func TestStartEpicWaveExplainsTypedRefusals(t *testing.T) {
	for code, want := range map[string]string{
		"plan_stale":              "plan again",
		"publication_too_old":     "too old",
		"invalid_selection":       "Nothing was started",
		"wave_execution_disabled": "do not retry",
		"epic_completed":          "not active",
		"epic_paused":             "not active",
	} {
		ts, _, _ := waveBackend(t, http.StatusConflict, `{"code":"`+code+`","error":"x"}`)
		r := callRoadmapTool(t, (*Server).toolStartEpicWave, ts.URL, map[string]any{
			"epic": "e", "items": []any{"a"}, "plan_hash": "h", "state_revision": "r",
		})
		if !r.IsError || !strings.Contains(resultText(t, r), want) || !strings.Contains(resultText(t, r), code) {
			t.Errorf("%s: %v", code, resultText(t, r))
		}
	}
}
