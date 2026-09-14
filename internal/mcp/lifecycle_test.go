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
	"strconv"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/lifecycle"
)

// lifecycleEnvelope is the parsed tool output. Declared here rather than
// reused from the handler so a change to the response shape shows up as a
// failing test rather than as two structs moving together.
type lifecycleEnvelope struct {
	Mode         string `json:"mode"`
	Count        int    `json:"count"`
	Truncated    bool   `json:"truncated"`
	FanoutCapped bool   `json:"fanout_capped"`
	AsOf         string `json:"as_of"`
	Records      []struct {
		Ownership  map[string]any       `json:"ownership"`
		Derived    lifecycle.Derived    `json:"derived"`
		Legacy     lifecycleLegacy      `json:"legacy"`
		Divergence lifecycle.Divergence `json:"divergence"`
		Events     lifecycleEvents      `json:"events"`
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
	if off.Records[0].Events.Items == nil {
		t.Error("events.items is null with include_events off; it must be an empty array")
	}
	if off.Records[0].Events.Available {
		t.Error("events.available is true without include_events")
	}
	on := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		"include_events": "true",
	}))
	if !on.Records[0].Events.Available || len(on.Records[0].Events.Items) != 1 {
		t.Errorf("events: available=%t, %d items; want available with 1",
			on.Records[0].Events.Available, len(on.Records[0].Events.Items))
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

// --- list mode ---------------------------------------------------------

// listBackend answers the list route with n records and counts describe calls.
func listBackend(t *testing.T, n int) (*httptest.Server, *int) {
	t.Helper()
	records := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		records = append(records, ownershipJSON(
			fmt.Sprintf("mctlhq/mctl-web#%d", i), "shepherd", "shepherd:mctl-web",
			"active", fmt.Sprintf("mctl-web/issue-%d-a-thing", i), true, lifecycle.StatusHealthy))
	}
	describes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/lifecycle/ownership" {
			_, _ = w.Write([]byte(`{"ownership":[` + strings.Join(records, ",") + `],"count":` +
				strconv.Itoa(n) + `}`))
			return
		}
		describes++
		_, _ = w.Write([]byte(`{"status":"Running","shepherd_in_loop":true,"shepherd_in_loop_known":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &describes
}

// The cap bounds the PROBE, not the result: an operator listing a long store
// still gets every record, and the ones past the cap say why their legacy
// block is empty. A cap that has never fired is a cap nobody has watched.
func TestLifecycleTool_ListModeCapsTheLegacyProbeNotTheRecords(t *testing.T) {
	n := lifecycleLegacyFanoutCap + 1
	backend, describes := listBackend(t, n)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation",
	}))
	if env.Mode != "list" {
		t.Fatalf("mode: got %q, want list", env.Mode)
	}
	if env.Count != n || len(env.Records) != n {
		t.Fatalf("count %d, records %d; want %d of each", env.Count, len(env.Records), n)
	}
	if *describes != lifecycleLegacyFanoutCap {
		t.Errorf("legacy probe ran %d times, want %d", *describes, lifecycleLegacyFanoutCap)
	}
	if !env.Records[lifecycleLegacyFanoutCap-1].Legacy.Available {
		t.Error("the last probed record has no legacy answer")
	}
	capped := env.Records[lifecycleLegacyFanoutCap].Legacy
	if capped.Answer != legacyAnswerUnknown || !strings.Contains(capped.Reason, "capped") {
		t.Errorf("the record past the cap: answer %q, reason %q", capped.Answer, capped.Reason)
	}
	if !env.FanoutCapped {
		t.Error("fanout_capped is false while the legacy probe was capped")
	}
	// NOT `truncated`: that one answers a different question -- whether the
	// STORE holds more rows than these. A paginating consumer reading one bit
	// for both would request a page that does not exist.
	if env.Truncated {
		t.Error("a capped fan-out set truncated, which is about the store's page")
	}
}

// The STORE truncates too, and used to do so invisibly: List defaults to 100
// rows. A full page reported as complete tells the operator this is everything
// the store holds.
func TestLifecycleTool_AFullPageReportsTruncated(t *testing.T) {
	backend, _ := listBackend(t, 3)
	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation",
		"limit": "3", "include_legacy": "false",
	}))
	if !env.Truncated {
		t.Error("a page as long as the limit reported truncated=false")
	}

	short := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation",
		"limit": "4", "include_legacy": "false",
	}))
	if short.Truncated {
		t.Error("a short page reported truncated=true")
	}
}

// --- answers that must not be fabricated -------------------------------

// An mctl-api that does not serve `derived` must not make every held record
// look like the one dangerous class. The zero value is held=false, and
// held=false beside a legacy answer of `owned` IS store-permits-old-forbids.
func TestLifecycleTool_ARecordWithoutDerivedIsDerivedLocally(t *testing.T) {
	// No "derived" key at all, and a record that is plainly held: active, with
	// a fresh last_seen_at inside the 10h liveness bound for this phase.
	seen := time.Now().UTC().Format(time.RFC3339Nano)
	rec := fmt.Sprintf(`{
		"entity":{"kind":"pull-request","id":"mctlhq/mctl-web#42"},
		"phase":"review-remediation",
		"owner":{"type":"devloop-workflow","id":"dev-loop-mctlhq-mctl-web-7"},
		"state":"active","proposal_ref":"mctl-web/issue-7-a-thing",
		"last_seen_at":%q,"last_progress_at":%q,
		"dead":false,"stuck":false,"healthy":true
	}`, seen, seen)
	backend, _ := backendFor(t, rec, `{"status":"Running","shepherd_in_loop":true}`, http.StatusOK)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	got := env.Records[0]
	if got.Derived.Status != lifecycle.StatusHealthy {
		t.Errorf("derived.status: got %q, want %q -- an empty status is not in the closed vocabulary",
			got.Derived.Status, lifecycle.StatusHealthy)
	}
	if !got.Derived.Held {
		t.Error("derived.held is false for an active, live record")
	}
	if got.Divergence.Class != lifecycle.DivergeAgree || got.Divergence.Dangerous {
		t.Errorf("class %q (dangerous=%t); a missing derived block fabricated a divergence",
			got.Divergence.Class, got.Divergence.Dangerous)
	}
}

// chi answers a MISSING ROUTE with 404 and plain text. Reading that as "the
// store holds nothing" makes an mctl-api without the route indistinguishable
// from an empty store -- which is the post-deploy check itself.
func TestLifecycleTool_AMissingRouteIsNotAnEmptyStore(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found\n"))
	}))
	defer backend.Close()

	result := callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	})
	if !result.IsError {
		t.Fatalf("a routing 404 was reported as an empty store: %s", resultText(t, result))
	}
}

// WorkflowIDForProposalRef fails two ways, and only one of them is an answer.
func TestLifecycleTool_AnUnreadableProposalRefIsUnknownNotFree(t *testing.T) {
	for _, tc := range []struct {
		name        string
		proposalRef string
		wantAnswer  string
	}{
		{name: "no service part", proposalRef: "issue-7-a-thing", wantAnswer: legacyAnswerUnknown},
		{name: "empty slug", proposalRef: "mctl-web/", wantAnswer: legacyAnswerUnknown},
		{name: "never had a DevLoop", proposalRef: "mctl-web/incident-1", wantAnswer: legacyAnswerFree},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
				"active", tc.proposalRef, true, lifecycle.StatusHealthy)
			backend, _ := backendFor(t, rec, `{}`, http.StatusOK)
			env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
				"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
			}))
			if got := env.Records[0].Legacy.Answer; got != tc.wantAnswer {
				t.Errorf("legacy answer: got %q, want %q", got, tc.wantAnswer)
			}
		})
	}
}

// mctl-api reports shepherd_in_loop=false both for a live execution declining
// to shepherd and for a query it could not complete. Only the second is an
// absence, and only shepherd_in_loop_known can tell them apart.
func TestLifecycleTool_AFailedShepherdQueryIsUnknownNotFree(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)

	backend, _ := backendFor(t, rec,
		`{"status":"Running","shepherd_in_loop":false,"shepherd_in_loop_known":false}`, http.StatusOK)
	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if got := env.Records[0].Legacy.Answer; got != legacyAnswerUnknown {
		t.Errorf("a failed query answered %q; a worker outage is not a legacy answer", got)
	}

	known, _ := backendFor(t, rec,
		`{"status":"Running","shepherd_in_loop":false,"shepherd_in_loop_known":true}`, http.StatusOK)
	env = decodeEnvelope(t, callLifecycleTool(t, known.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if got := env.Records[0].Legacy.Answer; got != legacyAnswerFree {
		t.Errorf("a completed query reporting false answered %q, want %q", got, legacyAnswerFree)
	}
}

// A pull request URL determines the kind; a contradictory one is a mistake, not
// a lookup that happens to find nothing.
func TestLifecycleTool_RejectsAKindThatContradictsPRURL(t *testing.T) {
	backend, _ := backendFor(t, `{}`, `{}`, http.StatusOK)
	result := callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "devloop-proposal", "phase": "review-remediation",
		"pr_url": "https://github.com/mctlhq/mctl-web/pull/42",
	})
	if !result.IsError {
		t.Fatal("a contradictory kind was accepted")
	}
}

func TestLifecycleTool_FailedEventsReadSaysSo(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/lifecycle/ownership/record":
			_, _ = w.Write([]byte(rec))
		case "/api/v1/lifecycle/events":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"lifecycle store error"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"Completed"}`))
		}
	}))
	defer backend.Close()

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		"include_events": "true",
	}))
	events := env.Records[0].Events
	if events.Available {
		t.Error("a failed events read reported available=true")
	}
	if events.Reason == "" {
		t.Error("an empty history and an unread one are the same JSON without a reason")
	}
	if events.Items == nil {
		t.Error("events.items is null")
	}
}

// An execution status the describe route could not determine is not a
// statement about whether a DevLoop is driving the entity.
func TestLifecycleTool_AnUndeterminedStatusIsUnknown(t *testing.T) {
	rec := ownershipJSON("mctlhq/mctl-web#42", "shepherd", "shepherd:mctl-web",
		"active", "mctl-web/issue-7-a-thing", true, lifecycle.StatusHealthy)

	for _, describe := range []string{`{"status":"Unknown"}`, `{"workflow_id":"x"}`} {
		backend, _ := backendFor(t, rec, describe, http.StatusOK)
		env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
			"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		}))
		got := env.Records[0]
		if got.Legacy.Answer != legacyAnswerUnknown {
			t.Errorf("%s answered %q, want %q", describe, got.Legacy.Answer, legacyAnswerUnknown)
		}
		// `available` and the class matter as much as the answer: available
		// would say the question was put and got an answer, and the class is
		// what the soak counts.
		if got.Legacy.Available {
			t.Errorf("%s reported available=true", describe)
		}
		if got.Divergence.Class != lifecycle.DivergeLegacyUnknown {
			t.Errorf("%s classified %q, want %q", describe, got.Divergence.Class,
				lifecycle.DivergeLegacyUnknown)
		}
	}
}

// The events read is capped for the same reason the legacy probe is: at the
// store's default page that would be 100 serial reads in one tool call.
func TestLifecycleTool_ListModeCapsTheEventsRead(t *testing.T) {
	n := lifecycleEventsFanoutCap + 1
	backend, _ := listBackend(t, n)

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation",
		"include_events": "true", "include_legacy": "false",
	}))
	if len(env.Records) != n {
		t.Fatalf("records: got %d, want %d", len(env.Records), n)
	}
	if !env.Records[lifecycleEventsFanoutCap-1].Events.Available {
		t.Error("the last probed record has no events")
	}
	capped := env.Records[lifecycleEventsFanoutCap].Events
	if capped.Available || !strings.Contains(capped.Reason, "capped") {
		t.Errorf("the record past the cap: available=%t, reason %q", capped.Available, capped.Reason)
	}
	if !env.FanoutCapped {
		t.Error("fanout_capped is false while the events read was capped")
	}
}

// A row with no proposal ref but a DevLoop-shaped stored id can still be
// probed. Rows answered legacy-unknown are rows the comparison did not cover,
// and this tool exists to measure a rate.
func TestLifecycleTool_FallsBackToTheStoredWorkflowID(t *testing.T) {
	rec := `{
		"entity":{"kind":"pull-request","id":"mctlhq/mctl-web#42"},
		"phase":"review-remediation",
		"owner":{"type":"shepherd","id":"shepherd:mctl-web"},
		"state":"active","temporal_workflow_id":"dev-loop-mctlhq-mctl-web-99",
		"dead":false,"stuck":false,"healthy":true,
		"derived":{"status":"healthy","dead":false,"held":true}
	}`
	var describedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/lifecycle/ownership/record" {
			_, _ = w.Write([]byte(rec))
			return
		}
		describedPath = r.URL.Path
		_, _ = w.Write([]byte(`{"status":"Running","shepherd_in_loop":true,"shepherd_in_loop_known":true}`))
	}))
	defer backend.Close()

	env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
		"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
	}))
	if !strings.HasSuffix(describedPath, "dev-loop-mctlhq-mctl-web-99") {
		t.Errorf("described %q; the stored temporal_workflow_id was not used", describedPath)
	}
	if env.Records[0].Legacy.Answer != legacyAnswerOwned {
		t.Errorf("legacy answer: got %q", env.Records[0].Legacy.Answer)
	}
}

// temporal_workflow_id records the OWNER's workflow, whatever that owner is —
// a pr-steward or shepherd row carries its own, and DescribeDevLoop does not
// check the type. Two consequences, both tested here.
func TestLifecycleTool_DoesNotProbeANonDevLoopWorkflowID(t *testing.T) {
	t.Run("a non-DevLoop stored id is not a legacy answer", func(t *testing.T) {
		rec := `{
			"entity":{"kind":"pull-request","id":"mctlhq/mctl-web#42"},
			"phase":"review-remediation",
			"owner":{"type":"pr-steward","id":"pr-steward:mctlhq/mctl-web"},
			"state":"active","temporal_workflow_id":"wf-steward",
			"dead":false,"stuck":false,"healthy":true,
			"derived":{"status":"healthy","dead":false,"held":true}
		}`
		probed := false
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/lifecycle/ownership/record" {
				_, _ = w.Write([]byte(rec))
				return
			}
			probed = true
			// A finished steward workflow. Probed, it would read "free".
			_, _ = w.Write([]byte(`{"status":"Completed"}`))
		}))
		defer backend.Close()

		env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
			"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		}))
		if probed {
			t.Error("described a workflow that is not a DevLoop; the legacy question is about a DevLoop")
		}
		if got := env.Records[0].Legacy.Answer; got != legacyAnswerUnknown {
			t.Errorf("legacy answer: got %q, want %q", got, legacyAnswerUnknown)
		}
	})

	t.Run("proposal_ref wins over a stored id", func(t *testing.T) {
		// The row that made the ordering load-bearing: a steward owner with
		// its own workflow id AND a proposal ref naming the real DevLoop.
		// Probing the stored id first reported `agree` where the truth is the
		// dangerous class.
		rec := `{
			"entity":{"kind":"pull-request","id":"mctlhq/mctl-web#42"},
			"phase":"review-remediation",
			"owner":{"type":"pr-steward","id":"pr-steward:mctlhq/mctl-web"},
			"state":"released","proposal_ref":"mctl-web/issue-7-a-thing",
			"temporal_workflow_id":"wf-steward",
			"dead":false,"stuck":false,"healthy":false,
			"derived":{"status":"released","dead":false,"held":false}
		}`
		var describedPath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/lifecycle/ownership/record" {
				_, _ = w.Write([]byte(rec))
				return
			}
			describedPath = r.URL.Path
			_, _ = w.Write([]byte(`{"status":"Running","shepherd_in_loop":true,"shepherd_in_loop_known":true}`))
		}))
		defer backend.Close()

		env := decodeEnvelope(t, callLifecycleTool(t, backend.URL, map[string]any{
			"kind": "pull-request", "phase": "review-remediation", "id": "mctlhq/mctl-web#42",
		}))
		if !strings.HasSuffix(describedPath, "dev-loop-mctlhq-mctl-web-7") {
			t.Errorf("described %q; proposal_ref must win over the stored owner workflow", describedPath)
		}
		d := env.Records[0].Divergence
		if d.Class != lifecycle.DivergeStorePermits || !d.Dangerous {
			t.Errorf("class %q (dangerous=%t); probing the stored id would report agree here",
				d.Class, d.Dangerous)
		}
	})
}
