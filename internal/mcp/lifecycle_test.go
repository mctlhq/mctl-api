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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/lifecycle"
)

// lifecycleEnvelope is the parsed tool output. Declared here rather than
// reused from the handler so a change to the response shape shows up as a
// failing test rather than as two structs moving together.
type lifecycleEnvelope struct {
	Mode      string `json:"mode"`
	Count     int    `json:"count"`
	Truncated bool   `json:"truncated"`
	AsOf      string `json:"as_of"`
	Records   []struct {
		Ownership  map[string]any       `json:"ownership"`
		Derived    lifecycle.Derived    `json:"derived"`
		Legacy     lifecycleLegacy      `json:"legacy"`
		Divergence lifecycle.Divergence `json:"divergence"`
		Events     []json.RawMessage    `json:"events"`
	} `json:"records"`
}

func callLifecycleTool(t *testing.T, apiURL string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := srv.toolGetLifecycleOwnership()
	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: "mctl_get_lifecycle_ownership", Arguments: args},
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return result
}

func resultText(t *testing.T, result *mcplib.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result carries no content")
	}
	text, ok := mcplib.AsTextContent(result.Content[0])
	if !ok {
		t.Fatalf("result content is not text: %+v", result.Content[0])
	}
	return text.Text
}

func decodeEnvelope(t *testing.T, result *mcplib.CallToolResult) lifecycleEnvelope {
	t.Helper()
	if result.IsError {
		t.Fatalf("expected success, got error: %s", resultText(t, result))
	}
	var env lifecycleEnvelope
	if err := json.Unmarshal([]byte(resultText(t, result)), &env); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, resultText(t, result))
	}
	return env
}

// ownershipJSON is what the API's ownershipResponse serialises to, including
// the derived block this tool depends on.
func ownershipJSON(id, ownerType, ownerID, state, proposalRef string, held bool, status string) string {
	return fmt.Sprintf(`{
		"entity":{"kind":"pull-request","id":%q},
		"phase":"review-remediation",
		"owner":{"type":%q,"id":%q},
		"state":%q,
		"proposal_ref":%q,
		"dead":false,"stuck":false,"healthy":true,
		"derived":{"status":%q,"dead":%t,"held":%t,"handoff_stalled":false,
		           "seconds_since_seen":10,"seconds_since_progress":10,
		           "bounds_known":true,"liveness_bound_seconds":36000,"progress_bound_seconds":86400}
	}`, id, ownerType, ownerID, state, proposalRef, status, !held, held)
}

// backendFor answers the three routes the tool uses.
func backendFor(t *testing.T, record, devLoop string, devLoopStatus int) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/lifecycle/ownership/record":
			_, _ = w.Write([]byte(record))
		case "/api/v1/lifecycle/ownership":
			_, _ = w.Write([]byte(`{"ownership":[` + record + `],"count":1}`))
		case "/api/v1/lifecycle/events":
			_, _ = w.Write([]byte(`{"events":[{"id":1,"to_state":"active"}],"count":1}`))
		default: // the dev-loop describe route
			w.WriteHeader(devLoopStatus)
			_, _ = w.Write([]byte(devLoop))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

// A record read must answer with the SAME shape a list read does: an array.
// The dual shape this tool sits on top of is the defect mctl-api#302 item 7
// removed one layer down, and re-creating it here would put it straight back.
func TestLifecycleTool_RecordModeStillAnswersAnArray(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "devloop-workflow", "dev-loop-mctlhq-mctl-web-7",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)
	backend, _ := backendFor(t, rec, `{"status":"Running","shepherd_in_loop":true}`, http.StatusOK)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if env.Mode != "record" {
		t.Errorf("mode: got %q, want record", env.Mode)
	}
	if env.Count != 1 || len(env.Records) != 1 {
		t.Fatalf("count %d, records %d; want exactly one of each", env.Count, len(env.Records))
	}
	if env.AsOf == "" {
		t.Error("as_of is empty; it exists so a later pagination change is not a schema change")
	}
}

// A store that holds nothing for the entity is an ANSWER: zero records, not an
// error, and emphatically not the 503 below.
func TestLifecycleTool_NoRecordIsAnEmptyArrayNotAnError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no ownership record for this entity phase"}`))
	}))
	defer backend.Close()

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if env.Count != 0 || len(env.Records) != 0 {
		t.Fatalf("count %d, records %d; want zero of each", env.Count, len(env.Records))
	}
}

// A 503 must surface as an error carrying the API's own sentence. Reporting it
// as an empty result would read as "nothing owns this", which is the one
// mistranslation this whole surface exists to refuse.
func TestLifecycleTool_StoreUnavailableIsAnErrorNotAnEmptyResult(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"lifecycle ownership store not configured"}`))
	}))
	defer backend.Close()

	result := callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	})
	if !result.IsError {
		t.Fatal("a 503 answered as a successful result")
	}
	text := resultText(t, result)
	if !strings.Contains(text, "503") || !strings.Contains(text, "not configured") {
		t.Errorf("the 503 did not pass through verbatim: %q", text)
	}
}

// The legacy probe is three-valued. Each row here is a path on which the
// shepherd's own bool answers False -- i.e. "nobody owns this" -- and the table
// pins which of those are real answers and which are absences.
func TestLifecycleTool_LegacyAnswerIsThreeValued(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ownerType   string
		proposalRef string
		devLoop     string
		devLoopCode int
		wantAnswer  string
		wantClass   string
	}{
		{
			name: "both name the DevLoop", ownerType: "devloop-workflow",
			proposalRef: "mctl-web/issue-7-a-thing",
			devLoop:     `{"status":"Running","shepherd_in_loop":true}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerOwned, wantClass: lifecycle.DivergeAgree,
		},
		{
			// Both stand down, and they name different holders. Not dangerous,
			// but it is the class that reveals a mis-wired comparison -- the
			// soak requires having seen at least one.
			name: "held by someone else while a DevLoop drives it", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"status":"Running","shepherd_in_loop":true}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerOwned, wantClass: lifecycle.DivergeOwnerMismatch,
		},
		{
			name: "completed is free", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"status":"Completed"}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerFree, wantClass: lifecycle.DivergeStoreForbids,
		},
		{
			name: "no such workflow is free", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"error":"not found"}`, devLoopCode: http.StatusNotFound,
			wantAnswer: legacyAnswerFree, wantClass: lifecycle.DivergeStoreForbids,
		},
		{
			name: "running without the shepherd_in_loop field is UNKNOWN", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"status":"Running"}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerUnknown, wantClass: lifecycle.DivergeLegacyUnknown,
		},
		{
			name: "running and declining to shepherd is free", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"status":"Running","shepherd_in_loop":false}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerFree, wantClass: lifecycle.DivergeStoreForbids,
		},
		{
			name: "a slug with no issue prefix never had a DevLoop", proposalRef: "mctl-web/incident-2026-09-01",
			devLoop: `{}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerFree, wantClass: lifecycle.DivergeStoreForbids,
		},
		{
			name: "no proposal_ref is UNKNOWN, not free", proposalRef: "",
			devLoop: `{}`, devLoopCode: http.StatusOK,
			wantAnswer: legacyAnswerUnknown, wantClass: lifecycle.DivergeLegacyUnknown,
		},
		{
			name: "an unreadable describe is UNKNOWN", proposalRef: "mctl-web/issue-7-a-thing",
			devLoop: `{"error":"boom"}`, devLoopCode: http.StatusInternalServerError,
			wantAnswer: legacyAnswerUnknown, wantClass: lifecycle.DivergeLegacyUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A held record throughout, so the class varies only with the
			// legacy answer.
			ownerType := tc.ownerType
			if ownerType == "" {
				ownerType = "shepherd"
			}
			rec := ownershipJSON("mctlhq/mctl-web#42", ownerType, "shepherd:mctl-web",
				"active", tc.proposalRef, true, lifecycle.StatusHealthy)
			backend, _ := backendFor(t, rec, tc.devLoop, tc.devLoopCode)

			env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
				"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
			}))
			got := env.Records[0]
			if got.Legacy.Answer != tc.wantAnswer {
				t.Errorf("legacy answer: got %q, want %q (reason: %q)",
					got.Legacy.Answer, tc.wantAnswer, got.Legacy.Reason)
			}
			if got.Divergence.Class != tc.wantClass {
				t.Errorf("divergence class: got %q, want %q", got.Divergence.Class, tc.wantClass)
			}
		})
	}
}

// The dangerous class, end to end: the store holds no live owner while a
// DevLoopWorkflow is driving the entity.
func TestLifecycleTool_ReportsTheDangerousClass(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"released", "mctl-web/issue-7-a-thing", false, lifecycle.StatusReleased)
	backend, _ := backendFor(t, rec, `{"status":"Running","shepherd_in_loop":true}`, http.StatusOK)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	d := env.Records[0].Divergence
	if d.Class != lifecycle.DivergeStorePermits {
		t.Fatalf("class: got %q, want %q", d.Class, lifecycle.DivergeStorePermits)
	}
	if !d.Dangerous {
		t.Error("the one dangerous class came back with dangerous=false")
	}
}

// include_legacy=false must not quietly look like a measurement: the class is
// legacy-unknown and the reason says why, rather than the tool reporting
// agreement it never established.
func TestLifecycleTool_LegacyCanBeSkippedAndSaysSo(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)
	backend, paths := backendFor(t, rec, `{"status":"Running","shepherd_in_loop":true}`, http.StatusOK)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		"include_legacy": "false",
	}))
	if env.Records[0].Divergence.Class != lifecycle.DivergeLegacyUnknown {
		t.Errorf("class: got %q, want %q", env.Records[0].Divergence.Class, lifecycle.DivergeLegacyUnknown)
	}
	for _, p := range *paths {
		if p != "/api/v1/lifecycle/ownership/record" {
			t.Errorf("include_legacy=false still called %s", p)
		}
	}
}

// A typo must fall back to the DEFAULT, not to false: include_legacy=yes
// silently turning every divergence into legacy-unknown would look exactly
// like a measured result.
func TestLifecycleTool_UnparseableBoolFallsBackToTheDefault(t *testing.T) {
	if got := parseBoolArg("yes", true); !got {
		t.Error(`parseBoolArg("yes", true) = false; an unrecognised value must keep the default`)
	}
	if got := parseBoolArg("", false); got {
		t.Error(`parseBoolArg("", false) = true`)
	}
	if got := parseBoolArg("true", false); !got {
		t.Error(`parseBoolArg("true", false) = false`)
	}
}

func TestLifecycleTool_EventsAreAlwaysAnArray(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)
	backend, _ := backendFor(t, rec, `{"status":"Running","shepherd_in_loop":true}`, http.StatusOK)

	off := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if off.Records[0].Events == nil {
		t.Error("events is null with include_events off; it must be an empty array")
	}
	on := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		"include_events": "true",
	}))
	if len(on.Records[0].Events) != 1 {
		t.Errorf("events: got %d, want 1", len(on.Records[0].Events))
	}
}

func TestEntityIDForPullRequestURL(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "https://github.com/mctlhq/mctl-web/pull/42", want: "mctlhq/mctl-web#42"},
		{in: "https://github.com/mctlhq/mctl-web/pull/42/", want: "mctlhq/mctl-web#42"},
		{in: "https://github.com/someone/a.fork/pull/1", want: "someone/a.fork#1"},
		{in: "https://github.com/mctlhq/mctl-web/issues/42", wantErr: true},
		{in: "mctlhq/mctl-web#42", wantErr: true},
	} {
		got, err := entityIDForPullRequestURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLifecycleTool_RejectsIDAndPRURLTogether(t *testing.T) {
	backend, _ := backendFor(t, `{}`, `{}`, http.StatusOK)
	result := callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation",
		"id": "mctlhq/mctl-web#42", "pr_url": "https://github.com/mctlhq/mctl-web/pull/42",
	})
	if !result.IsError {
		t.Fatal("id and pr_url together were accepted")
	}
}
