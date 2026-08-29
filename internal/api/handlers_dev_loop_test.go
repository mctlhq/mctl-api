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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"go.temporal.io/api/serviceerror"
)

// fakeDevLoopClient implements DevLoopClient without needing a live
// Temporal server — internal/temporalclient's own tests cover the real
// client against a mocked client.Client; these tests only need to verify
// the HTTP-layer wiring (auth, status-code mapping, request validation).
type fakeDevLoopClient struct {
	startErr              error
	workflowID, runID     string
	approveErr            error
	lastApprovedWorkflow  string
	lastApprovePayload    map[string]string
	describeErr           error
	describeStatus        string
	lastDescribedWorkflow string
}

func (f *fakeDevLoopClient) StartDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	if f.startErr != nil {
		return "", "", f.startErr
	}
	return f.workflowID, f.runID, nil
}

func (f *fakeDevLoopClient) SignalApprove(ctx context.Context, workflowID string, payload map[string]string) error {
	f.lastApprovedWorkflow = workflowID
	f.lastApprovePayload = payload
	return f.approveErr
}

func (f *fakeDevLoopClient) DescribeDevLoop(ctx context.Context, workflowID string) (string, error) {
	f.lastDescribedWorkflow = workflowID
	if f.describeErr != nil {
		return "", f.describeErr
	}
	if f.describeStatus == "" {
		return "Running", nil
	}
	return f.describeStatus, nil
}

func TestStartDevLoopWorkflow_NotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}} // TemporalClient left nil

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the Temporal client isn't configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartDevLoopWorkflow_RequiresAuth(t *testing.T) {
	// A configured (fake) client, so these assertions actually exercise the
	// auth branch in requireTemporalAdmin instead of short-circuiting on the
	// nil-client 503 first — that's exactly what the DevLoopClient interface
	// (see interfaces.go) exists to make testable.
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	// No adminCtx — unauthenticated.
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartDevLoopWorkflow_MissingIssueURL(t *testing.T) {
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing issue_url, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartDevLoopWorkflow_InvalidIssueURLIs400(t *testing.T) {
	fake := &fakeDevLoopClient{startErr: temporalclient.ErrInvalidIssueURL}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"not-a-url"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for ErrInvalidIssueURL, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartDevLoopWorkflow_TemporalFailureIs502(t *testing.T) {
	fake := &fakeDevLoopClient{startErr: serviceerror.NewUnavailable("temporal frontend unreachable")}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a Temporal RPC failure (not caller input), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartDevLoopWorkflow_Success(t *testing.T) {
	fake := &fakeDevLoopClient{workflowID: "dev-loop-mctlhq-mctl-telegram-1", runID: "run-1"}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_NotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the Temporal client isn't configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_RequiresAuth(t *testing.T) {
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	// No adminCtx — unauthenticated.
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_MissingWorkflowID(t *testing.T) {
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop//approve", nil)
	req = withChiParam(req, "workflow_id", "")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an empty workflow_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_UnknownWorkflowIs404(t *testing.T) {
	fake := &fakeDevLoopClient{approveErr: serviceerror.NewNotFound("workflow not found")}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-999/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-999")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown workflow_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_TemporalFailureIs502(t *testing.T) {
	fake := &fakeDevLoopClient{approveErr: serviceerror.NewUnavailable("temporal frontend unreachable")}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a Temporal RPC failure, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApproveDevLoopWorkflow_Success(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.lastApprovedWorkflow != "dev-loop-mctlhq-mctl-telegram-1" {
		t.Fatalf("expected SignalApprove to be called with the workflow_id, got %q", fake.lastApprovedWorkflow)
	}
	// No body → approver defaults to the authenticated caller (adminCtx = "tester").
	if got := fake.lastApprovePayload["approver"]; got != "tester" {
		t.Fatalf("expected approver to default to the caller, got %q", got)
	}
}

func TestApproveDevLoopWorkflow_ExplicitApproverAndReasonPassthrough(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve",
		bytes.NewBufferString(`{"approver":"mashkovd","reason":"looks good"}`))
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := fake.lastApprovePayload["approver"]; got != "mashkovd" {
		t.Fatalf("expected explicit approver to win, got %q", got)
	}
	if got := fake.lastApprovePayload["reason"]; got != "looks good" {
		t.Fatalf("expected reason passthrough, got %q", got)
	}
}

func TestApproveDevLoopWorkflow_MalformedBodyIs400(t *testing.T) {
	fake := &fakeDevLoopClient{}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve",
		bytes.NewBufferString(`{"approver":`))
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.lastApprovedWorkflow != "" {
		t.Fatal("SignalApprove must not be called on malformed input")
	}
}

func TestGetDevLoopWorkflow_Success(t *testing.T) {
	fake := &fakeDevLoopClient{describeStatus: "Running"}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.lastDescribedWorkflow != "dev-loop-mctlhq-mctl-telegram-1" {
		t.Fatalf("expected DescribeDevLoop with the workflow_id, got %q", fake.lastDescribedWorkflow)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["status"] != "Running" {
		t.Fatalf("expected status Running, got %q", body["status"])
	}
}

func TestGetDevLoopWorkflow_UnknownWorkflowIs404(t *testing.T) {
	fake := &fakeDevLoopClient{describeErr: fmt.Errorf("wrapped: %w", serviceerror.NewNotFound("nope"))}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x/", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetDevLoopWorkflow_RequiresAuth(t *testing.T) {
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}}}
	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d: %s", rec.Code, rec.Body.String())
	}
}
