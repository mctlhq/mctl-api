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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"go.temporal.io/api/serviceerror"
)

const abandonTestWorkflow = "dev-loop-mctlhq-seerrsense-73"

func abandonRequest(body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/"+abandonTestWorkflow+"/abandon", rd)
	return withChiParam(req, "workflow_id", abandonTestWorkflow)
}

func decodeAbandonResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
	}
	return got
}

func TestAbandonDevLoopWorkflow_NotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}}
	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the Temporal client isn't configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAbandonDevLoopWorkflow_RequiresAdmin(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, abandonRequest(`{"reason":"superseded"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	req := abandonRequest(`{"reason":"superseded"}`)
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.abandonCalls != 0 || fake.describeExecCalls != 0 {
		t.Fatalf("an unauthorised call reached Temporal: %d signals, %d describes", fake.abandonCalls, fake.describeExecCalls)
	}
}

// The reason is required: an abandoned loop with no recorded reason is
// indistinguishable from an accident afterwards.
func TestAbandonDevLoopWorkflow_ReasonIsRequired(t *testing.T) {
	for name, body := range map[string]string{
		"empty body":       "",
		"empty object":     `{}`,
		"blank reason":     `{"reason":"   "}`,
		"malformed JSON":   `{"reason":`,
		"wrong type":       `{"reason":42}`,
		"unknown field":    `{"reason":"superseded","force":true}`,
		"self-named actor": `{"reason":"superseded","abandoned_by":"someone-else"}`,
		"identity field":   `{"reason":"superseded","on_behalf_of":"github:alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"}}
			logger := audit.NewLogger()
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

			rec := httptest.NewRecorder()
			h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if fake.abandonCalls != 0 {
				t.Fatal("a rejected request must not signal Temporal")
			}
			if entries := logger.List(10); len(entries) != 0 {
				t.Fatalf("expected no audit entry for rejected input, got %+v", entries)
			}
		})
	}
}

func TestAbandonDevLoopWorkflow_RunningIsSignalledWithCallerAsActor(t *testing.T) {
	fake := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"}}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"  superseded by mctl-gitops#1363 "}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.abandonCalls != 1 {
		t.Fatalf("expected exactly one abandon signal, got %d", fake.abandonCalls)
	}
	// adminCtx authenticates as "tester".
	if got := fake.lastAbandonPayload["abandoned_by"]; got != "tester" {
		t.Errorf("abandoned_by: got %q, want the authenticated caller", got)
	}
	if got := fake.lastAbandonPayload["reason"]; got != "superseded by mctl-gitops#1363" {
		t.Errorf("reason: got %q", got)
	}
	got := decodeAbandonResponse(t, rec)
	if got["outcome"] != "signalled" || got["signalled"] != "abandon" || got["run_id"] != "run-1" {
		t.Errorf("unexpected response: %+v", got)
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Operation != "dev-loop-abandon" || e.Status != "succeeded" || e.WorkflowName != abandonTestWorkflow {
		t.Errorf("unexpected audit entry: %+v", e)
	}
	if e.Parameters["abandoned_by"] != "tester" || e.Parameters["reason"] != "superseded by mctl-gitops#1363" {
		t.Errorf("unexpected audit parameters: %+v", e.Parameters)
	}
}

// A retry against an execution that has already ended answers with its final
// status, and signals nothing.
func TestAbandonDevLoopWorkflow_FinishedExecutionIsReportedNotSignalled(t *testing.T) {
	fake := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Completed", RunID: "run-1"}}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.abandonCalls != 0 {
		t.Fatal("a finished execution must not be signalled")
	}
	got := decodeAbandonResponse(t, rec)
	if got["outcome"] != "already_finished" || got["status"] != "Completed" {
		t.Errorf("unexpected response: %+v", got)
	}
	if _, ok := got["signalled"]; ok {
		t.Errorf("a finished execution's answer must not claim a signal: %+v", got)
	}
}

func TestAbandonDevLoopWorkflow_UnknownWorkflowIs404(t *testing.T) {
	fake := &fakeDevLoopClient{describeExecErr: serviceerror.NewNotFound("workflow not found")}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.abandonCalls != 0 {
		t.Fatal("an unknown workflow must not be signalled")
	}
	if entries := logger.List(10); len(entries) != 1 || entries[0].Status != "failed" {
		t.Fatalf("expected one failed audit entry, got %+v", entries)
	}
}

// Fail closed: nothing that is not an observed running or finished execution
// is ever answered with a 2xx.
func TestAbandonDevLoopWorkflow_UnreadableExecutionIs502(t *testing.T) {
	for name, fake := range map[string]*fakeDevLoopClient{
		"describe fails": {describeExecErr: serviceerror.NewUnavailable("temporal frontend unreachable")},
		"unknown status": {describeExec: &temporalclient.DevLoopExecution{Status: "Unknown"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
			rec := httptest.NewRecorder()
			h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
			}
			if fake.abandonCalls != 0 {
				t.Fatal("an unreadable execution must not be signalled")
			}
		})
	}
}

func TestAbandonDevLoopWorkflow_SignalFailureIs502(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"},
		abandonErr:   serviceerror.NewUnavailable("temporal frontend unreachable"),
	}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	rec := httptest.NewRecorder()
	h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if entries := logger.List(10); len(entries) != 1 || entries[0].Status != "failed" {
		t.Fatalf("expected one failed audit entry, got %+v", entries)
	}
}

// The execution closing between the describe and the signal makes Temporal
// answer NotFound. That is answered from a second look, never assumed.
func TestAbandonDevLoopWorkflow_SignalNotFoundIsAnsweredFromASecondDescribe(t *testing.T) {
	cases := map[string]struct {
		after    *temporalclient.DevLoopExecution
		afterErr error
		wantCode int
		wantOut  string
	}{
		"closed in between":      {after: &temporalclient.DevLoopExecution{Status: "Completed", RunID: "run-1"}, wantCode: http.StatusOK, wantOut: "already_finished"},
		"still reported running": {after: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"}, wantCode: http.StatusBadGateway},
		"gone entirely":          {afterErr: serviceerror.NewNotFound("workflow not found"), wantCode: http.StatusNotFound},
		"second describe fails":  {afterErr: serviceerror.NewUnavailable("unreachable"), wantCode: http.StatusBadGateway},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeDevLoopClient{
				describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"},
				abandonErr:   serviceerror.NewNotFound("workflow execution already completed"),
				onAbandon: func(f *fakeDevLoopClient) {
					f.describeExec = tc.after
					f.describeExecErr = tc.afterErr
				},
			}
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
			rec := httptest.NewRecorder()
			h.AbandonDevLoopWorkflow(rec, adminCtx(abandonRequest(`{"reason":"superseded"}`)))
			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d: %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if fake.describeExecCalls != 2 {
				t.Errorf("expected a second describe after the NotFound signal, got %d describes", fake.describeExecCalls)
			}
			if tc.wantOut != "" {
				if got := decodeAbandonResponse(t, rec); got["outcome"] != tc.wantOut {
					t.Errorf("outcome: got %v, want %s", got["outcome"], tc.wantOut)
				}
			}
		})
	}
}
