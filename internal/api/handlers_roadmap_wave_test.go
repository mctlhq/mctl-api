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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.temporal.io/api/serviceerror"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/roadmap"
)

// The live fixture's observation was captured at 2026-09-23T09:09:33Z.
var waveCaptured = time.Date(2026, 9, 23, 9, 9, 33, 0, time.UTC)

// waveSource serves the live fixture at a revision the test can move.
type waveSource struct {
	roadmapDirSource
	rev *string
}

func (s waveSource) Revision() (string, error) { return *s.rev, nil }
func (s waveSource) ReadFiles(names ...string) (map[string][]byte, string, error) {
	files, _, err := s.roadmapDirSource.ReadFiles(names...)
	return files, *s.rev, err
}

// waveDevLoop records starts and answers Describe per workflow.
type waveDevLoop struct {
	fakeDevLoopClient
	statuses    map[string]string // workflow id -> status; absent = NotFound
	describeErr map[string]error
	startErr    map[string]error
	hang        map[string]bool // Describe waits for its deadline
	slow        time.Duration   // Describe and Start each take this long
	started     []string
}

func (f *waveDevLoop) DescribeDevLoop(ctx context.Context, workflowID string) (string, error) {
	if f.hang[workflowID] {
		<-ctx.Done()
	}
	f.pause(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := f.describeErr[workflowID]; err != nil {
		return "", err
	}
	if st, ok := f.statuses[workflowID]; ok {
		return st, nil
	}
	return "", serviceerror.NewNotFound("workflow not found")
}

func (f *waveDevLoop) pause(ctx context.Context) {
	if f.slow > 0 {
		select {
		case <-time.After(f.slow):
		case <-ctx.Done():
		}
	}
}

func (f *waveDevLoop) StartDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	f.pause(ctx)
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	wf := "dev-loop-mctlhq-" + strings.Replace(strings.TrimPrefix(issueURL, "https://github.com/mctlhq/"), "/issues/", "-", 1)
	if err := f.startErr[wf]; err != nil {
		return "", "", err
	}
	f.started = append(f.started, wf)
	f.statuses[wf] = "Running"
	return wf, "run-" + wf, nil
}

type waveEnv struct {
	t     *testing.T
	h     *Handlers
	rev   string
	tc    *waveDevLoop
	audit *audit.Logger
}

func newWaveEnv(t *testing.T) *waveEnv {
	t.Helper()
	prev := waveNow
	waveNow = func() time.Time { return waveCaptured.Add(5 * time.Minute) }
	t.Cleanup(func() { waveNow = prev })
	e := &waveEnv{t: t, rev: "0123abc", tc: &waveDevLoop{statuses: map[string]string{}}, audit: audit.NewLogger()}
	src := waveSource{roadmapDirSource{dir: filepath.Join("..", "roadmap", "testdata", "live")}, &e.rev}
	e.h = &Handlers{opts: Options{Roadmap: roadmap.NewReader(src), TemporalClient: e.tc, AuditLog: e.audit}}
	return e
}

func (e *waveEnv) post(u *auth.User, path string, body any) (int, map[string]any) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	if u != nil {
		req = req.WithContext(auth.WithUser(req.Context(), u))
	}
	r := chi.NewRouter()
	r.Post("/api/v1/roadmap/waves/plan", e.h.PlanRoadmapWave)
	r.Post("/api/v1/roadmap/waves/execute", e.h.ExecuteRoadmapWave)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

var (
	waveAdmin = auth.NewGitHubUser("root", []string{"admins"})
	waveUser  = auth.NewGitHubUser("alice", []string{"acme"})
)

// plan returns the plan and the execute body that names it exactly.
func (e *waveEnv) plan(epic string, items ...string) (map[string]any, map[string]any) {
	e.t.Helper()
	body := map[string]any{"epic": epic}
	if len(items) > 0 {
		body["items"] = items
	}
	code, resp := e.post(waveUser, "/api/v1/roadmap/waves/plan", body)
	if code != http.StatusOK {
		e.t.Fatalf("plan = %d %v", code, resp)
	}
	plan := resp["plan"].(map[string]any)
	var ids []string
	for _, it := range plan["selected"].([]any) {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	return resp, map[string]any{
		"epic": epic, "items": ids, "plan_hash": plan["plan_hash"],
		"state_revision": plan["provenance"].(map[string]any)["state_revision"],
	}
}

func outcomes(resp map[string]any) map[string]string {
	out := map[string]string{}
	for _, o := range resp["outcomes"].([]any) {
		m := o.(map[string]any)
		out[m["workflow_id"].(string)] = m["outcome"].(string)
	}
	return out
}

func TestRoadmapWave_PlanThenExecuteStartsExactlyThePlan(t *testing.T) {
	e := newWaveEnv(t)
	resp, exec := e.plan("enterprise-mcp")
	if resp["executable"] != true || resp["max_age_seconds"] != float64(1800) {
		t.Fatalf("plan = %v", resp)
	}
	ids := exec["items"].([]string)
	if len(ids) < 2 || len(e.tc.started) != 0 {
		t.Fatalf("planning selected %v and started %v", ids, e.tc.started)
	}
	// One of them already has a DevLoop.
	wfs := []string{}
	for _, it := range resp["plan"].(map[string]any)["selected"].([]any) {
		wfs = append(wfs, it.(map[string]any)["workflow_id"].(string))
	}
	e.tc.statuses[wfs[0]] = "Running"

	code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec)
	if code != http.StatusOK {
		t.Fatalf("execute = %d %v", code, out)
	}
	got := outcomes(out)
	if got[wfs[0]] != waveOutcomeAlreadyRunning || len(e.tc.started) != len(wfs)-1 {
		t.Fatalf("outcomes %v, started %v", got, e.tc.started)
	}
	for _, wf := range wfs[1:] {
		if got[wf] != waveOutcomeStarted {
			t.Errorf("%s = %s", wf, got[wf])
		}
	}
	// Retrying the same wave starts nothing twice.
	if code, out = e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusOK {
		t.Fatalf("retry = %d %v", code, out)
	}
	for wf, o := range outcomes(out) {
		if o != waveOutcomeAlreadyRunning {
			t.Errorf("retry: %s = %s", wf, o)
		}
	}
	if len(e.tc.started) != len(wfs)-1 {
		t.Fatalf("retry started again: %v", e.tc.started)
	}
	// Never approves.
	if e.tc.lastApprovedWorkflow != "" {
		t.Fatalf("a wave approved %s", e.tc.lastApprovedWorkflow)
	}

	// Audit explains what was started and from what.
	var entry *audit.Entry
	for _, a := range e.audit.List(10) {
		if a.Operation == "roadmap-wave-execute" && a.Status == "succeeded" {
			a := a
			entry = &a
			break
		}
	}
	if entry == nil || entry.UserID != "root" {
		t.Fatalf("no audit for the wave: %+v", e.audit.List(10))
	}
	for _, k := range []string{"operation_id", "plan_hash", "epic", "root_issue", "manifest_path", "manifest_sha256",
		"manifest_revision", "state_revision", "evaluator_revision", "observation_captured_at", "items", "issue_refs", "workflow_ids", "outcomes"} {
		if entry.Parameters[k] == "" {
			t.Errorf("audit misses %s: %v", k, entry.Parameters)
		}
	}
}

func TestRoadmapWave_ExecuteFailsClosed(t *testing.T) {
	e := newWaveEnv(t)
	_, exec := e.plan("enterprise-mcp")
	ids := exec["items"].([]string)
	with := func(k string, v any) map[string]any {
		out := map[string]any{}
		for kk, vv := range exec {
			out[kk] = vv
		}
		out[k] = v
		return out
	}

	for _, c := range []struct {
		name string
		body map[string]any
		code int
		want string
	}{
		// A subset of the plan is not the plan.
		{"subset", with("items", ids[:1]), http.StatusConflict, roadmapCodeInvalidSelection},
		{"required_only changed", with("required_only", false), http.StatusConflict, roadmapCodeInvalidSelection},
		{"forged hash", with("plan_hash", strings.Repeat("0", 64)), http.StatusConflict, roadmapCodeInvalidSelection},
		{"blocked item added", with("items", append(append([]string{}, ids...), "mcp-tasks")), http.StatusConflict, roadmapCodeInvalidSelection},
		{"other state_revision", with("state_revision", "fffffff"), http.StatusConflict, roadmapCodePlanStale},
		{"no plan", map[string]any{"epic": "enterprise-mcp"}, http.StatusBadRequest, roadmapCodeInvalid},
	} {
		if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", c.body); code != c.code || out["code"] != c.want {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}

	// The publication moves on after planning.
	e.rev = "4567def"
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusConflict || out["code"] != roadmapCodePlanStale {
		t.Errorf("moved publication: %d %v", code, out)
	}
	e.rev = "0123abc"

	// Too old: 31 minutes after capture.
	waveNow = func() time.Time { return waveCaptured.Add(31 * time.Minute) }
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusConflict || out["code"] != roadmapCodeTooOld {
		t.Errorf("old publication: %d %v", code, out)
	}
	// A configured bound applies.
	e.h.opts.RoadmapWaveMaxAge = time.Hour
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusOK {
		t.Errorf("within a 1h bound: %d %v", code, out)
	}
	started := len(e.tc.started)
	e.h.opts.RoadmapWaveMaxAge = -1
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusServiceUnavailable || out["code"] != roadmapCodeWaveDisabled {
		t.Errorf("invalid bound: %d %v", code, out)
	}
	e.h.opts.RoadmapWaveMaxAge = 0
	waveNow = func() time.Time { return waveCaptured.Add(5 * time.Minute) }

	// Only an admin executes; planning needs no admin and starts nothing.
	if code, _ := e.post(waveUser, "/api/v1/roadmap/waves/execute", exec); code != http.StatusForbidden {
		t.Errorf("non-admin execute = %d", code)
	}
	if code, _ := e.post(nil, "/api/v1/roadmap/waves/plan", map[string]any{"epic": "enterprise-mcp"}); code != http.StatusUnauthorized {
		t.Errorf("anonymous plan = %d", code)
	}
	if len(e.tc.started) != started {
		t.Fatalf("a refused request started %v", e.tc.started[started:])
	}
	var refusals int
	for _, a := range e.audit.List(100) {
		if a.Operation == "roadmap-wave-execute" && a.Status == "failed" {
			refusals++
		}
	}
	if refusals < 8 {
		t.Errorf("refusals audited = %d", refusals)
	}
}

func TestRoadmapWave_ItemFailuresAreReportedPerItem(t *testing.T) {
	e := newWaveEnv(t)
	resp, exec := e.plan("enterprise-mcp")
	var wfs []string
	for _, it := range resp["plan"].(map[string]any)["selected"].([]any) {
		wfs = append(wfs, it.(map[string]any)["workflow_id"].(string))
	}
	e.tc.describeErr = map[string]error{wfs[0]: errors.New("temporal unavailable")}
	e.tc.startErr = map[string]error{wfs[1]: errors.New("start refused")}
	code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec)
	if code != http.StatusOK {
		t.Fatalf("execute = %d %v", code, out)
	}
	got := outcomes(out)
	if got[wfs[0]] != waveOutcomeFailed || got[wfs[1]] != waveOutcomeFailed {
		t.Fatalf("outcomes = %v", got)
	}
	// An unreadable DevLoop is never started blind.
	for _, wf := range e.tc.started {
		if wf == wfs[0] {
			t.Fatal("started a DevLoop whose state could not be read")
		}
	}
	e.tc.describeErr, e.tc.startErr = nil, nil
	e.tc.statuses[wfs[0]] = "Completed"
	_, out = e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec)
	if outcomes(out)[wfs[0]] != waveOutcomeAlreadyExists {
		t.Fatalf("a closed DevLoop: %v", outcomes(out))
	}
}

func TestRoadmapWave_PlanReportsWhyItCannotRun(t *testing.T) {
	e := newWaveEnv(t)
	waveNow = func() time.Time { return waveCaptured.Add(2 * time.Hour) }
	resp, _ := e.plan("enterprise-mcp")
	if resp["executable"] != false || !strings.HasPrefix(resp["not_executable_reason"].(string), roadmapCodeTooOld) {
		t.Fatalf("old plan = %v", resp)
	}
	waveNow = func() time.Time { return waveCaptured }
	resp, _ = e.plan("unified-identity")
	if resp["executable"] != false || !strings.HasPrefix(resp["not_executable_reason"].(string), roadmapCodeInvalidSelection) {
		t.Fatalf("empty plan = %v", resp)
	}
	if code, out := e.post(waveUser, "/api/v1/roadmap/waves/plan", map[string]any{"epic": "enterprise-mcp", "items": []string{"mcp-tasks"}}); code != http.StatusConflict || out["code"] != roadmapCodeInvalidSelection {
		t.Fatalf("blocked item = %d %v", code, out)
	}
	if code, _ := e.post(waveUser, "/api/v1/roadmap/waves/plan", map[string]any{"epic": "enterprise-mcp", "priority": "p0"}); code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", code)
	}
}

func TestRoadmapWaveRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	for _, want := range []string{"POST /api/v1/roadmap/waves/plan", "POST /api/v1/roadmap/waves/execute"} {
		if !found[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}

// A publication with no observation time (a synthetic capture) is never
// fresh enough to execute from, whatever the bound.
func TestRoadmapWave_NoCaptureTimeIsNeverFresh(t *testing.T) {
	age, future := int64(60), int64(-3600)
	for _, c := range []struct {
		prov  roadmap.Provenance
		max   time.Duration
		fresh bool
	}{
		{roadmap.Provenance{}, time.Hour, false},
		{roadmap.Provenance{AgeSeconds: &age}, time.Hour, true},
		{roadmap.Provenance{AgeSeconds: &age}, 59 * time.Second, false},
		{roadmap.Provenance{AgeSeconds: &age}, -1, false},
		// Captured in the future: clock skew is not freshness.
		{roadmap.Provenance{AgeSeconds: &future}, time.Hour, false},
	} {
		if fresh, why := waveFreshness(c.prov, c.max); fresh != c.fresh || (!fresh && why == "") {
			t.Errorf("waveFreshness(%v, %v) = %v %q", c.prov.AgeSeconds, c.max, fresh, why)
		}
	}
}

// With no roadmap reader (ROADMAP_STATE_DISABLED) both routes answer
// roadmap_unavailable, and an execute of an unknown epic is refused, audited,
// and starts nothing.
func TestRoadmapWave_NoReaderAndUnknownEpicAreAuditedRefusals(t *testing.T) {
	e := newWaveEnv(t)
	_, exec := e.plan("enterprise-mcp")
	stale := map[string]any{}
	for k, v := range exec {
		stale[k] = v
	}
	stale["epic"] = "no-such-epic"
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", stale); code != http.StatusNotFound || out["code"] != roadmapCodeEpicNotFound {
		t.Errorf("unknown epic: %d %v", code, out)
	}

	e.h.opts.Roadmap = nil
	if code, out := e.post(waveUser, "/api/v1/roadmap/waves/plan", map[string]any{"epic": "enterprise-mcp"}); code != http.StatusServiceUnavailable || out["code"] != roadmapCodeUnavailable {
		t.Errorf("plan without a reader: %d %v", code, out)
	}
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusServiceUnavailable || out["code"] != roadmapCodeUnavailable {
		t.Errorf("execute without a reader: %d %v", code, out)
	}
	if len(e.tc.started) != 0 {
		t.Fatalf("started %v", e.tc.started)
	}
	reasons := map[string]bool{}
	for _, a := range e.audit.List(100) {
		if a.Operation == "roadmap-wave-execute" && a.Status == "failed" {
			reasons[a.Parameters["reason"]] = true
		}
	}
	if !reasons[roadmapCodeEpicNotFound] || !reasons[roadmapCodeUnavailable] {
		t.Errorf("audited refusals = %v", reasons)
	}
}

// An invalid ROADMAP_WAVE_MAX_AGE is the same terminal answer from plan and
// execute; a publication that is merely old is a different one.
func TestRoadmapWave_InvalidBoundIsDisabledNotTooOld(t *testing.T) {
	e := newWaveEnv(t)
	e.h.opts.RoadmapWaveMaxAge = -1
	code, resp := e.post(waveUser, "/api/v1/roadmap/waves/plan", map[string]any{"epic": "enterprise-mcp"})
	why, _ := resp["not_executable_reason"].(string)
	if code != http.StatusOK || resp["executable"] != false || !strings.HasPrefix(why, roadmapCodeWaveDisabled+":") || resp["max_age_seconds"] != float64(0) {
		t.Fatalf("plan with an invalid bound: %d %v", code, resp)
	}
}

// A malformed or incomplete execute is refused and audited.
func TestRoadmapWave_MalformedExecuteIsAudited(t *testing.T) {
	e := newWaveEnv(t)
	for _, body := range []any{
		map[string]any{"epic": "enterprise-mcp", "surprise": true},
		map[string]any{"epic": "enterprise-mcp"},
		map[string]any{"epic": " ", "items": []string{"x"}, "plan_hash": "h", "state_revision": "r"},
	} {
		if code, _ := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", body); code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, code)
		}
	}
	var audited int
	for _, a := range e.audit.List(100) {
		if a.Operation == "roadmap-wave-execute" && a.Status == "failed" && a.Parameters["reason"] == roadmapCodeInvalid {
			audited++
		}
	}
	if audited != 3 {
		t.Errorf("audited malformed executes = %d, want 3", audited)
	}
}

// A caller that goes away mid-wave does not abort the starts it began.
func TestRoadmapWave_DisconnectDoesNotAbortTheWave(t *testing.T) {
	e := newWaveEnv(t)
	_, exec := e.plan("enterprise-mcp")
	raw, _ := json.Marshal(exec)
	ctx, cancel := context.WithCancel(auth.WithUser(context.Background(), waveAdmin))
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roadmap/waves/execute", bytes.NewReader(raw)).WithContext(ctx)
	rec := httptest.NewRecorder()
	e.h.ExecuteRoadmapWave(rec, req)
	if rec.Code != http.StatusOK || len(e.tc.started) != len(exec["items"].([]string)) {
		t.Fatalf("cancelled request: %d started %v: %s", rec.Code, e.tc.started, rec.Body.String())
	}
}

// One slow item uses its own time budget, not the rest of the wave's.
func TestRoadmapWave_ASlowItemDoesNotStarveTheOthers(t *testing.T) {
	prev := roadmapWaveCallTimeout
	roadmapWaveCallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { roadmapWaveCallTimeout = prev })
	e := newWaveEnv(t)
	resp, exec := e.plan("enterprise-mcp")
	selected := resp["plan"].(map[string]any)["selected"].([]any)
	first := selected[0].(map[string]any)["workflow_id"].(string)
	e.tc.hang = map[string]bool{first: true}
	code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec)
	if code != http.StatusOK {
		t.Fatalf("execute = %d %v", code, out)
	}
	if len(e.tc.started) != len(selected)-1 {
		t.Fatalf("started %v; every item after the slow one should still start", e.tc.started)
	}
}

// A slow Describe does not eat the Start's budget: each call has its own.
func TestRoadmapWave_DescribeAndStartHaveTheirOwnBudgets(t *testing.T) {
	prev := roadmapWaveCallTimeout
	roadmapWaveCallTimeout = 80 * time.Millisecond
	t.Cleanup(func() { roadmapWaveCallTimeout = prev })
	e := newWaveEnv(t)
	_, exec := e.plan("enterprise-mcp")
	e.tc.slow = 50 * time.Millisecond // each call fits, the two together do not
	if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", exec); code != http.StatusOK || len(e.tc.started) != len(exec["items"].([]string)) {
		t.Fatalf("execute = %d, started %v: %v", code, e.tc.started, out)
	}
}

// A paused or completed epic is refused by plan and by execute, with a
// typed reason and no override; execute audits the refusal and starts
// nothing (mctl-api#363).
func TestRoadmapWave_InactiveEpicsAreRefusedWithTypedReasons(t *testing.T) {
	e := newWaveEnv(t)
	_, exec := e.plan("enterprise-mcp")
	for epic, want := range map[string]struct{ code, lifecycle string }{
		"lifecycle-ownership": {"epic_completed", "completed"},
		"edge-ai-android":     {"epic_paused", "paused"},
	} {
		code, out := e.post(waveUser, "/api/v1/roadmap/waves/plan", map[string]any{"epic": epic})
		details, _ := out["details"].(map[string]any)
		if code != http.StatusConflict || out["code"] != want.code || details["epic"] != epic || details["lifecycle"] != want.lifecycle {
			t.Errorf("plan %s: %d %v", epic, code, out)
		}
		body := map[string]any{}
		for k, v := range exec {
			body[k] = v
		}
		body["epic"] = epic
		if code, out := e.post(waveAdmin, "/api/v1/roadmap/waves/execute", body); code != http.StatusConflict || out["code"] != want.code {
			t.Errorf("execute %s: %d %v", epic, code, out)
		}
	}
	if len(e.tc.started) != 0 {
		t.Fatalf("started %v", e.tc.started)
	}
	reasons := map[string]bool{}
	for _, a := range e.audit.List(100) {
		if a.Operation == "roadmap-wave-execute" && a.Status == "failed" {
			reasons[a.Parameters["reason"]] = true
		}
	}
	if !reasons["epic_completed"] || !reasons["epic_paused"] {
		t.Errorf("audited refusals = %v", reasons)
	}
}
