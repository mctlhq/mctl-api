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
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
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
	startCalls            int
	workflowID, runID     string
	approveErr            error
	lastApprovedWorkflow  string
	lastApprovePayload    map[string]string
	abandonErr            error
	abandonCalls          int
	lastAbandonPayload    map[string]string
	lastAbandonRunID      string
	onAbandon             func(f *fakeDevLoopClient)
	describeErr           error
	describeStatus        string
	lastDescribedWorkflow string
	describeExec          *temporalclient.DevLoopExecution
	describeExecErr       error
	describeExecCalls     int
	shepherdInLoop        bool
	shepherdInLoopErr     error
	shepherdQueries       int
	shepherdBlocks        bool
	humanInputStates      map[string]*temporalclient.HumanInputState
	humanInputErr         error
	humanInputQueries     []string
	humanInputBlocks      bool
	// Human-input signals: every delivered document, the error to return,
	// and an optional hook standing in for the workflow draining its queue.
	humanInputSignals  []map[string]any
	humanInputSignalTo []string
	signalErr          error
	onSignal           func(f *fakeDevLoopClient, workflowID string, doc map[string]any)
	// Restart-after-abandon (mctl-api#640): what DevLoopEnded answers for a
	// run, or the error it fails with, and every restart.
	ended         string
	implemented   bool
	endedErr      error
	endedReadRuns []string
	restartCalls  int
	restartRunID  string
	restartErr    error
	restartedAsWF string
	// Deadlines seen by DevLoopEnded and the restart (zero: none).
	endedDeadlineIn    time.Duration
	restartHadDeadline bool
}

func (f *fakeDevLoopClient) DevLoopEnded(ctx context.Context, workflowID, runID string) (temporalclient.DevLoopRunEnd, error) {
	f.endedReadRuns = append(f.endedReadRuns, runID)
	if d, ok := ctx.Deadline(); ok {
		f.endedDeadlineIn = time.Until(d)
	}
	if f.endedErr != nil {
		return temporalclient.DevLoopRunEnd{}, f.endedErr
	}
	return temporalclient.DevLoopRunEnd{Ended: f.ended, Implemented: f.implemented}, nil
}

func (f *fakeDevLoopClient) RestartAbandonedDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	f.restartCalls++
	_, f.restartHadDeadline = ctx.Deadline()
	if f.restartErr != nil {
		return "", "", f.restartErr
	}
	wf := f.restartedAsWF
	if wf == "" {
		wf = f.workflowID
	}
	return wf, f.restartRunID, nil
}

func (f *fakeDevLoopClient) SignalHumanInputResponse(ctx context.Context, workflowID, runID string, response map[string]any) error {
	if f.signalErr != nil {
		return f.signalErr
	}
	f.humanInputSignals = append(f.humanInputSignals, response)
	f.humanInputSignalTo = append(f.humanInputSignalTo, workflowID+"@"+runID)
	if f.onSignal != nil {
		f.onSignal(f, workflowID, response)
	}
	return nil
}

func (f *fakeDevLoopClient) QueryHumanInputState(ctx context.Context, workflowID, runID string) (*temporalclient.HumanInputState, error) {
	f.humanInputQueries = append(f.humanInputQueries, workflowID+"@"+runID)
	if f.humanInputBlocks {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.humanInputErr != nil {
		return nil, f.humanInputErr
	}
	if st, ok := f.humanInputStates[workflowID]; ok {
		return st, nil
	}
	return &temporalclient.HumanInputState{State: temporalclient.HumanInputRunning}, nil
}

func (f *fakeDevLoopClient) StartDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	f.startCalls++
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

func (f *fakeDevLoopClient) SignalAbandon(ctx context.Context, workflowID, runID string, payload map[string]string) error {
	f.abandonCalls++
	f.lastAbandonRunID = runID
	f.lastAbandonPayload = payload
	if f.onAbandon != nil {
		f.onAbandon(f)
	}
	return f.abandonErr
}

// DescribeDevLoop prefers describeExec/describeExecErr (the richer fields)
// when set, falling back to describeStatus/describeErr — so a test can
// configure either pair and both DescribeDevLoop and DescribeDevLoopExecution
// answer consistently about the same simulated execution.
func (f *fakeDevLoopClient) DescribeDevLoop(ctx context.Context, workflowID string) (string, error) {
	f.lastDescribedWorkflow = workflowID
	if f.describeExecErr != nil {
		return "", f.describeExecErr
	}
	if f.describeExec != nil {
		return f.describeExec.Status, nil
	}
	if f.describeErr != nil {
		return "", f.describeErr
	}
	if f.describeStatus == "" {
		return "Running", nil
	}
	return f.describeStatus, nil
}

// DescribeDevLoopExecution defaults to describeStatus/describeErr (via
// DescribeDevLoop) when describeExec/describeExecErr are left unset, so
// existing tests that only configure the older fields keep working.
func (f *fakeDevLoopClient) DescribeDevLoopExecution(ctx context.Context, workflowID string) (*temporalclient.DevLoopExecution, error) {
	f.describeExecCalls++
	if f.describeExecErr != nil {
		return nil, f.describeExecErr
	}
	if f.describeExec != nil {
		return f.describeExec, nil
	}
	status, err := f.DescribeDevLoop(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	return &temporalclient.DevLoopExecution{Status: status}, nil
}

func (f *fakeDevLoopClient) QueryShepherdInLoop(ctx context.Context, workflowID string) (bool, error) {
	f.shepherdQueries++
	if f.shepherdBlocks {
		// Stand in for Temporal blocking until a worker answers.
		<-ctx.Done()
		return false, ctx.Err()
	}
	if f.shepherdInLoopErr != nil {
		return false, f.shepherdInLoopErr
	}
	return f.shepherdInLoop, nil
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
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing issue_url, got %d: %s", rec.Code, rec.Body.String())
	}
	if entries := logger.List(10); len(entries) != 0 {
		t.Fatalf("expected no audit entry for a missing issue_url, got %+v", entries)
	}
}

func TestStartDevLoopWorkflow_InvalidIssueURLIs400(t *testing.T) {
	fake := &fakeDevLoopClient{startErr: temporalclient.ErrInvalidIssueURL}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"not-a-url"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for ErrInvalidIssueURL, got %d: %s", rec.Code, rec.Body.String())
	}
	if entries := logger.List(10); len(entries) != 0 {
		t.Fatalf("expected no audit entry for ErrInvalidIssueURL, got %+v", entries)
	}
}

func TestStartDevLoopWorkflow_TemporalFailureIs502(t *testing.T) {
	// No prior execution (describe is NotFound), so startDevLoop proceeds to
	// the actual start, which fails.
	fake := &fakeDevLoopClient{
		describeErr: serviceerror.NewNotFound("workflow not found"),
		startErr:    serviceerror.NewUnavailable("temporal frontend unreachable"),
	}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a Temporal RPC failure (not caller input), got %d: %s", rec.Code, rec.Body.String())
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Operation != "dev-loop-start" {
		t.Errorf("expected Operation=dev-loop-start, got %q", entry.Operation)
	}
	if entry.Status != "failed" {
		t.Errorf("expected Status=failed, got %q", entry.Status)
	}
	if entry.WorkflowName != "" {
		t.Errorf("expected empty WorkflowName on a failed start, got %q", entry.WorkflowName)
	}
	if entry.Parameters["issue_url"] != "https://github.com/mctlhq/mctl-telegram/issues/1" {
		t.Errorf("expected Parameters[issue_url] to match the request, got %q", entry.Parameters["issue_url"])
	}
}

func TestStartDevLoopWorkflow_Success(t *testing.T) {
	// No prior execution (describe is NotFound), so startDevLoop actually starts.
	fake := &fakeDevLoopClient{
		describeErr: serviceerror.NewNotFound("workflow not found"),
		workflowID:  "dev-loop-mctlhq-mctl-telegram-1", runID: "run-1",
	}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Operation != "dev-loop-start" {
		t.Errorf("expected Operation=dev-loop-start, got %q", entry.Operation)
	}
	if entry.Status != "succeeded" {
		t.Errorf("expected Status=succeeded, got %q", entry.Status)
	}
	if entry.WorkflowName != fake.workflowID {
		t.Errorf("expected WorkflowName=%q, got %q", fake.workflowID, entry.WorkflowName)
	}
	if entry.Parameters["issue_url"] != "https://github.com/mctlhq/mctl-telegram/issues/1" {
		t.Errorf("expected Parameters[issue_url] to match the request, got %q", entry.Parameters["issue_url"])
	}
	if entry.Parameters["outcome"] != devLoopOutcomeStarted {
		t.Errorf("expected Parameters[outcome]=%q, got %q", devLoopOutcomeStarted, entry.Parameters["outcome"])
	}
}

// TestStartDevLoopWorkflow_AlreadyRunningIsNotReportedAsAStart is T2: THE
// REGRESSION TEST for issue #287. StartDevLoopWorkflow's REJECT_DUPLICATE +
// USE_EXISTING policies mean a call against a running execution truly
// no-ops; the handler must say so instead of claiming a fresh start.
func TestStartDevLoopWorkflow_AlreadyRunningIsNotReportedAsAStart(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-existing"},
		// If StartDevLoopWorkflow were called, this would answer with a
		// DIFFERENT run — proof that the assertions below distinguish "did
		// not start" from "started and happened to return the same id".
		workflowID: "dev-loop-mctlhq-mctl-telegram-1", runID: "run-new",
	}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for an already-running execution, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["started"] != false {
		t.Errorf("expected started=false, got %v", body["started"])
	}
	if body["outcome"] != devLoopOutcomeAlreadyRunning {
		t.Errorf("expected outcome=%q, got %v", devLoopOutcomeAlreadyRunning, body["outcome"])
	}
	if body["run_id"] != "run-existing" {
		t.Errorf("expected run_id=run-existing (the EXISTING run), got %v", body["run_id"])
	}
	if msg, _ := body["message"].(string); strings.Contains(msg, "DevLoopWorkflow started") {
		t.Errorf("message must not claim a start, got %q", msg)
	}
	if fake.startCalls != 0 {
		t.Fatalf("StartDevLoopWorkflow must not be called for an already-running execution, got %d calls", fake.startCalls)
	}

	// T6: the audit entry names the no-op explicitly.
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Parameters["outcome"] != devLoopOutcomeAlreadyRunning {
		t.Errorf("expected Parameters[outcome]=%q, got %q", devLoopOutcomeAlreadyRunning, entry.Parameters["outcome"])
	}
	if strings.Contains(entry.Message, "DevLoopWorkflow started") {
		t.Errorf("audit message must not claim a start, got %q", entry.Message)
	}
}

// TestStartDevLoopWorkflow_NotFoundStarts is T3: describe NotFound is the
// only path that actually starts a new execution.
func TestStartDevLoopWorkflow_NotFoundStarts(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeErr: serviceerror.NewNotFound("workflow not found"),
		workflowID:  "dev-loop-mctlhq-mctl-telegram-1", runID: "run-new",
	}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["started"] != true {
		t.Errorf("expected started=true, got %v", body["started"])
	}
	if body["outcome"] != devLoopOutcomeStarted {
		t.Errorf("expected outcome=%q, got %v", devLoopOutcomeStarted, body["outcome"])
	}
	if body["run_id"] != "run-new" {
		t.Errorf("expected run_id=run-new, got %v", body["run_id"])
	}
	if fake.startCalls != 1 {
		t.Fatalf("expected exactly one start call, got %d", fake.startCalls)
	}
	entries := logger.List(10)
	if len(entries) != 1 || entries[0].Parameters["outcome"] != devLoopOutcomeStarted {
		t.Fatalf("expected one audit entry with outcome=started, got %+v", entries)
	}
}

// TestStartDevLoopWorkflow_ClosedExecutionIsAlreadyExists is T4: a closed
// prior execution (REJECT_DUPLICATE will not restart it) is reported
// already_exists, not started.
func TestStartDevLoopWorkflow_ClosedExecutionIsAlreadyExists(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Failed", RunID: "run-old"},
		workflowID:   "dev-loop-mctlhq-mctl-telegram-1", runID: "run-new",
	}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["outcome"] != devLoopOutcomeAlreadyExists {
		t.Errorf("expected outcome=%q, got %v", devLoopOutcomeAlreadyExists, body["outcome"])
	}
	if body["status"] != "Failed" {
		t.Errorf("expected status=Failed, got %v", body["status"])
	}
	if fake.startCalls != 0 {
		t.Fatalf("expected no start call for a closed execution, got %d", fake.startCalls)
	}
}

// TestStartDevLoopWorkflow_UnreadableDescribeIs502 is T5: a non-NotFound
// describe error must not be started blind, and the error must say the
// existing DevLoop could not be read.
func TestStartDevLoopWorkflow_UnreadableDescribeIs502(t *testing.T) {
	fake := &fakeDevLoopClient{describeErr: serviceerror.NewUnavailable("temporal frontend unreachable")}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.startCalls != 0 {
		t.Fatalf("must not start blind when the existing DevLoop cannot be read, got %d start calls", fake.startCalls)
	}
	if !strings.Contains(rec.Body.String(), "could not read") {
		t.Errorf("expected the body to mention the existing DevLoop could not be read, got %s", rec.Body.String())
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
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: &fakeDevLoopClient{}, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop//approve", nil)
	req = withChiParam(req, "workflow_id", "")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an empty workflow_id, got %d: %s", rec.Code, rec.Body.String())
	}
	if entries := logger.List(10); len(entries) != 0 {
		t.Fatalf("expected no audit entry for a missing workflow_id, got %+v", entries)
	}
}

func TestApproveDevLoopWorkflow_UnknownWorkflowIs404(t *testing.T) {
	fake := &fakeDevLoopClient{approveErr: serviceerror.NewNotFound("workflow not found")}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-999/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-999")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown workflow_id, got %d: %s", rec.Code, rec.Body.String())
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].Status != "failed" {
		t.Errorf("expected Status=failed, got %q", entries[0].Status)
	}
	if entries[0].Operation != "dev-loop-approve" {
		t.Errorf("expected Operation=dev-loop-approve, got %q", entries[0].Operation)
	}
	if !strings.Contains(entries[0].Message, "not found") {
		t.Errorf("expected message to mention 'not found', got %q", entries[0].Message)
	}
}

func TestApproveDevLoopWorkflow_TemporalFailureIs502(t *testing.T) {
	fake := &fakeDevLoopClient{approveErr: serviceerror.NewUnavailable("temporal frontend unreachable")}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a Temporal RPC failure, got %d: %s", rec.Code, rec.Body.String())
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].Status != "failed" {
		t.Errorf("expected Status=failed, got %q", entries[0].Status)
	}
}

func TestApproveDevLoopWorkflow_Success(t *testing.T) {
	fake := &fakeDevLoopClient{}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

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
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Operation != "dev-loop-approve" {
		t.Errorf("expected Operation=dev-loop-approve, got %q", entry.Operation)
	}
	if entry.WorkflowName != "dev-loop-mctlhq-mctl-telegram-1" {
		t.Errorf("expected WorkflowName=dev-loop-mctlhq-mctl-telegram-1, got %q", entry.WorkflowName)
	}
	if entry.Status != "succeeded" {
		t.Errorf("expected Status=succeeded, got %q", entry.Status)
	}
	if entry.Parameters["approver"] != "tester" {
		t.Errorf("expected Parameters[approver]=tester, got %q", entry.Parameters["approver"])
	}
}

// The approver is a fact about who called, not a claim in the body. A request
// that names someone else is rejected outright rather than having the field
// quietly ignored — a caller that believes it is recording an approval under
// a colleague's name must be told it is not.
func TestApproveDevLoopWorkflow_ExplicitDifferentApproverIs400(t *testing.T) {
	fake := &fakeDevLoopClient{}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve",
		bytes.NewBufferString(`{"approver":"someone-else","reason":"looks good"}`))
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a body-supplied approver, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.lastApprovePayload != nil {
		t.Fatalf("a rejected approval must not signal Temporal, got payload %+v", fake.lastApprovePayload)
	}
}

// The signalled approver is always the authenticated caller, and `reason`
// still rides along.
func TestApproveDevLoopWorkflow_ApproverComesFromCredential(t *testing.T) {
	fake := &fakeDevLoopClient{}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve",
		bytes.NewBufferString(`{"reason":"looks good"}`))
	req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ApproveDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// adminCtx authenticates as "tester".
	const want = "tester"
	if got := fake.lastApprovePayload["approver"]; got != want {
		t.Fatalf("approver: got %q, want the authenticated caller %q", got, want)
	}
	if got := fake.lastApprovePayload["reason"]; got != "looks good" {
		t.Fatalf("expected reason passthrough, got %q", got)
	}
	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d: %+v", len(entries), entries)
	}
	if got := entries[0].Parameters["approver"]; got != want {
		t.Errorf("audit Parameters[approver] = %q, want %q", got, want)
	}
	if got := entries[0].Parameters["reason"]; got != "looks good" {
		t.Errorf("expected Parameters[reason]=looks good, got %q", got)
	}
}

func TestApproveDevLoopWorkflow_MalformedBodyIs400(t *testing.T) {
	fake := &fakeDevLoopClient{}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

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
	if entries := logger.List(10); len(entries) != 0 {
		t.Fatalf("expected no audit entry for a malformed body, got %+v", entries)
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
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["status"] != "Running" {
		t.Fatalf("expected status Running, got %v", body["status"])
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

func TestGetDevLoopWorkflow_ReportsShepherdInLoop(t *testing.T) {
	fake := &fakeDevLoopClient{describeStatus: "Running", shepherdInLoop: true}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["shepherd_in_loop"] != true {
		t.Fatalf("expected shepherd_in_loop true, got %v", body["shepherd_in_loop"])
	}
}

// A worker too old to define the query handler must read as "does not tick",
// so the shepherd cron keeps sweeping that proposal (mctl-agents#213).
func TestGetDevLoopWorkflow_QueryFailureReportsNotInLoop(t *testing.T) {
	fake := &fakeDevLoopClient{describeStatus: "Running", shepherdInLoopErr: fmt.Errorf("unknown queryType %q", "shepherd_in_loop")}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a failed query must not fail the read; got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["shepherd_in_loop"] != false {
		t.Fatalf("expected shepherd_in_loop false, got %v", body["shepherd_in_loop"])
	}
}

// Querying a finished execution would fail anyway — don't spend the RPC.
func TestGetDevLoopWorkflow_NoQueryWhenNotRunning(t *testing.T) {
	fake := &fakeDevLoopClient{describeStatus: "Completed", shepherdInLoop: true}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if fake.shepherdQueries != 0 {
		t.Fatalf("expected no query for a %s workflow, got %d", fake.describeStatus, fake.shepherdQueries)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["shepherd_in_loop"] != false {
		t.Fatalf("expected shepherd_in_loop false, got %v", body["shepherd_in_loop"])
	}
}

func TestGetDevLoopWorkflow_TemporalFailureIs502(t *testing.T) {
	fake := &fakeDevLoopClient{describeErr: serviceerror.NewUnavailable("temporal frontend unreachable")}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.GetDevLoopWorkflow(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a Temporal RPC failure (not a missing workflow), got %d: %s", rec.Code, rec.Body.String())
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

// Temporal blocks a query until a worker on the task queue answers. During a
// worker outage that must degrade to false on the handler's own short
// deadline, not hang until the API-wide timeout (Codex P1 on #216).
func TestGetDevLoopWorkflow_BlockedQueryStillAnswers(t *testing.T) {
	fake := &fakeDevLoopClient{describeStatus: "Running", shepherdBlocks: true}
	h := &Handlers{opts: Options{TemporalClient: fake}}

	req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
	req = withChiParam(req, "workflow_id", "dev-loop-x")
	req = adminCtx(req)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.GetDevLoopWorkflow(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shepherdQueryTimeout + 5*time.Second):
		t.Fatal("handler did not return; the query is not bounded by its own deadline")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["shepherd_in_loop"] != false {
		t.Fatalf("expected shepherd_in_loop false, got %v", body["shepherd_in_loop"])
	}
}

// TestGetDevLoopWorkflow_KnownSeparatesAnAnswerFromAFallback pins the field
// that makes the false above readable.
//
// `shepherd_in_loop: false` is the same JSON for a live execution that declines
// to shepherd and for a query that never completed, and the two mean opposite
// things. For the sweep they are interchangeable — both leave the cron
// responsible, which is the fail-open — but a caller COMPARING this answer
// against the ownership store may not fold them together: "could not ask"
// counted as "nobody is driving it" manufactures the one divergence class that
// licenses two machines to drive one pull request.
func TestGetDevLoopWorkflow_KnownSeparatesAnAnswerFromAFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fake       *fakeDevLoopClient
		wantInLoop bool
		wantKnown  bool
	}{
		{
			name:       "running and shepherding",
			fake:       &fakeDevLoopClient{describeStatus: "Running", shepherdInLoop: true},
			wantInLoop: true, wantKnown: true,
		},
		{
			name:       "running and declining to shepherd is an answer",
			fake:       &fakeDevLoopClient{describeStatus: "Running", shepherdInLoop: false},
			wantInLoop: false, wantKnown: true,
		},
		{
			name: "a failed query is not an answer",
			fake: &fakeDevLoopClient{
				describeStatus:    "Running",
				shepherdInLoopErr: fmt.Errorf("unknown queryType %q", "shepherd_in_loop"),
			},
			wantInLoop: false, wantKnown: false,
		},
		{
			// Known, not unknown: a Completed workflow definitively is not
			// ticking a shepherd, and that false is derived from the status
			// rather than from a query that failed.
			name:       "a finished execution answers from its status",
			fake:       &fakeDevLoopClient{describeStatus: "Completed"},
			wantInLoop: false, wantKnown: true,
		},
		{
			// DescribeDevLoop's own default arm: it could not determine the
			// status. Nothing was determined, so nothing is known -- the false
			// here is not derived from anything.
			name:       "an undetermined execution status knows nothing",
			fake:       &fakeDevLoopClient{describeStatus: "Unknown"},
			wantInLoop: false, wantKnown: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{opts: Options{TemporalClient: tc.fake}}
			req := httptest.NewRequest("GET", "/api/v1/agents/dev-loop/dev-loop-x", nil)
			req = withChiParam(req, "workflow_id", "dev-loop-x")
			req = adminCtx(req)
			rec := httptest.NewRecorder()
			h.GetDevLoopWorkflow(rec, req)

			var body map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}
			if body["shepherd_in_loop"] != tc.wantInLoop {
				t.Errorf("shepherd_in_loop: got %v, want %v", body["shepherd_in_loop"], tc.wantInLoop)
			}
			if body["shepherd_in_loop_known"] != tc.wantKnown {
				t.Errorf("shepherd_in_loop_known: got %v, want %v",
					body["shepherd_in_loop_known"], tc.wantKnown)
			}
		})
	}
}

// TestStartDevLoopWorkflow_RestartOnlyAfterAbandon is mctl-api#640's table:
// every closed status crossed with what the run's result says about how it
// ended. Only a Completed run whose result says "abandoned: ..." is
// restarted; an unreadable result is failed without a start.
func TestStartDevLoopWorkflow_RestartOnlyAfterAbandon(t *testing.T) {
	const wf = "dev-loop-mctlhq-mctl-telegram-1"
	type marker struct {
		name        string
		ended       string
		implemented bool
		err         error
	}
	markers := []marker{
		{name: "abandoned", ended: temporalclient.AbandonedEndedPrefix + "superseded by #663"},
		{name: "abandoned after implement", ended: temporalclient.AbandonedEndedPrefix + "operator cleanup", implemented: true},
		{name: "other", ended: "approval wait expired"},
		{name: "absent", ended: ""},
		{name: "unreadable", err: serviceerror.NewUnavailable("temporal frontend unreachable")},
	}
	statuses := []string{"Completed", "Failed", "Terminated", "TimedOut", "Canceled", "ContinuedAsNew", "Unknown"}

	for _, status := range statuses {
		for _, m := range markers {
			t.Run(status+"/"+m.name, func(t *testing.T) {
				fake := &fakeDevLoopClient{
					describeExec: &temporalclient.DevLoopExecution{Status: status, RunID: "run-old"},
					workflowID:   wf, runID: "run-start", restartRunID: "run-new",
					ended: m.ended, implemented: m.implemented, endedErr: m.err,
				}
				logger := audit.NewLogger()
				h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}
				req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
				rec := httptest.NewRecorder()
				h.StartDevLoopWorkflow(rec, adminCtx(req))

				if fake.startCalls != 0 {
					t.Fatalf("a closed DevLoop must never go through the no-restart start, got %d calls", fake.startCalls)
				}
				var body map[string]interface{}
				_ = json.Unmarshal(rec.Body.Bytes(), &body)

				switch {
				case status != "Completed":
					// Abandon only ever ends a run as Completed: the marker is
					// not even read.
					if len(fake.endedReadRuns) != 0 {
						t.Fatalf("read the result of a %s run", status)
					}
					assertNotRestarted(t, fake, rec, body)
				case m.name == "abandoned":
					if rec.Code != http.StatusAccepted || body["outcome"] != devLoopOutcomeRestartedAfterAbandon {
						t.Fatalf("expected 202 %s, got %d %v", devLoopOutcomeRestartedAfterAbandon, rec.Code, body)
					}
					if body["started"] != true || body["run_id"] != "run-new" || body["previous_run_id"] != "run-old" {
						t.Fatalf("restart must report the new run and the abandoned one, got %v", body)
					}
					if fake.restartCalls != 1 || len(fake.endedReadRuns) != 1 || fake.endedReadRuns[0] != "run-old" {
						t.Fatalf("expected one restart after reading run-old, got %d restarts, reads %v", fake.restartCalls, fake.endedReadRuns)
					}
					entries := logger.List(10)
					if len(entries) != 1 || entries[0].Parameters["outcome"] != devLoopOutcomeRestartedAfterAbandon ||
						entries[0].Parameters["previous_run_id"] != "run-old" || entries[0].UserID == "" {
						t.Fatalf("expected one audit entry naming the actor and the abandoned run, got %+v", entries)
					}
				case m.name == "unreadable":
					if rec.Code != http.StatusBadGateway {
						t.Fatalf("an unreadable result must fail, got %d %s", rec.Code, rec.Body.String())
					}
					if fake.restartCalls != 0 {
						t.Fatal("restarted a run whose result could not be read")
					}
					entries := logger.List(10)
					if len(entries) != 1 || entries[0].Status != "failed" || entries[0].Parameters["outcome"] != devLoopOutcomeFailed {
						t.Fatalf("expected one failed audit entry, got %+v", entries)
					}
				default:
					assertNotRestarted(t, fake, rec, body)
				}
			})
		}
	}
}

func assertNotRestarted(t *testing.T, fake *fakeDevLoopClient, rec *httptest.ResponseRecorder, body map[string]interface{}) {
	t.Helper()
	if rec.Code != http.StatusOK || body["outcome"] != devLoopOutcomeAlreadyExists || body["started"] != false {
		t.Fatalf("expected 200 %s started=false, got %d %v", devLoopOutcomeAlreadyExists, rec.Code, body)
	}
	if body["run_id"] != "run-old" {
		t.Errorf("expected the existing run id, got %v", body["run_id"])
	}
	if fake.restartCalls != 0 {
		t.Fatalf("restarted a DevLoop that was not abandoned (%d calls)", fake.restartCalls)
	}
}

// A restart that Temporal refuses, or that comes back under another id or as
// the abandoned run itself, is failed, never reported as a restart.
func TestStartDevLoopWorkflow_RestartFailuresAreFailed(t *testing.T) {
	cases := map[string]struct {
		fake    *fakeDevLoopClient
		message string // what the 502 must name, so the cases stay distinct
	}{
		"start error":     {fake: &fakeDevLoopClient{restartErr: serviceerror.NewUnavailable("down")}, message: "restart after abandoned run run-old"},
		"other workflow":  {fake: &fakeDevLoopClient{restartedAsWF: "dev-loop-mctlhq-mctl-telegram-2", restartRunID: "run-new"}, message: "restarted workflow dev-loop-mctlhq-mctl-telegram-2"},
		"same run echoed": {fake: &fakeDevLoopClient{restartRunID: "run-old"}, message: "restart returned the abandoned run run-old itself"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := tc.fake
			fake.describeExec = &temporalclient.DevLoopExecution{Status: "Completed", RunID: "run-old"}
			fake.workflowID = "dev-loop-mctlhq-mctl-telegram-1"
			fake.ended = temporalclient.AbandonedEndedPrefix + "x"
			logger := audit.NewLogger()
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}
			req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
			rec := httptest.NewRecorder()
			h.StartDevLoopWorkflow(rec, adminCtx(req))
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("expected 502, got %d %s", rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, tc.message) || strings.Contains(body, `"started"`) || strings.Contains(body, `"run_id"`) {
				t.Fatalf("the 502 must name %q and claim no run, got %s", tc.message, body)
			}
			entries := logger.List(10)
			if len(entries) != 1 || entries[0].Status != "failed" || entries[0].Parameters["outcome"] != devLoopOutcomeFailed ||
				entries[0].Parameters["previous_run_id"] != "run-old" {
				t.Fatalf("expected one failed audit entry naming the abandoned run, got %+v", entries)
			}
		})
	}
}

// The result read has its own short deadline, not the describe's leftovers,
// and the restart does not inherit it.
func TestStartDevLoopWorkflow_ResultReadHasItsOwnDeadline(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Completed", RunID: "run-old"},
		workflowID:   "dev-loop-mctlhq-mctl-telegram-1", restartRunID: "run-new",
		ended: temporalclient.AbandonedEndedPrefix + "x",
	}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, adminCtx(req))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}
	if fake.endedDeadlineIn <= devLoopResultReadTimeout-time.Second || fake.endedDeadlineIn > devLoopResultReadTimeout {
		t.Fatalf("result read deadline %v, want about %v", fake.endedDeadlineIn, devLoopResultReadTimeout)
	}
	if fake.restartHadDeadline {
		t.Fatal("the restart inherited the read deadline")
	}
}

// Each skipped restart says why in the audit trail.
func TestStartDevLoopWorkflow_SkippedRestartIsExplained(t *testing.T) {
	cases := map[string]struct {
		ended       string
		implemented bool
		want        string
	}{
		"no ended":        {want: "not restarted: no ended reason recorded"},
		"other ended":     {ended: "approval wait expired", want: `not restarted: ended "approval wait expired" is not an abandon`},
		"after implement": {ended: temporalclient.AbandonedEndedPrefix + "x", implemented: true, want: "not restarted: abandoned after the implement step"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeDevLoopClient{
				describeExec: &temporalclient.DevLoopExecution{Status: "Completed", RunID: "run-old"},
				workflowID:   "dev-loop-mctlhq-mctl-telegram-1",
				ended:        tc.ended, implemented: tc.implemented,
			}
			logger := audit.NewLogger()
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}
			req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
			rec := httptest.NewRecorder()
			h.StartDevLoopWorkflow(rec, adminCtx(req))
			entries := logger.List(10)
			if rec.Code != http.StatusOK || len(entries) != 1 || !strings.Contains(entries[0].Message, tc.want) {
				t.Fatalf("expected 200 and an audit message with %q, got %d %+v", tc.want, rec.Code, entries)
			}
		})
	}
}

// A Completed run described without a run id is not restarted: the result
// read could not be pinned to it.
func TestStartDevLoopWorkflow_NoRunIDIsNotRestarted(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Completed"},
		workflowID:   "dev-loop-mctlhq-mctl-telegram-1",
		ended:        temporalclient.AbandonedEndedPrefix + "x",
	}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, adminCtx(req))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), devLoopOutcomeAlreadyExists) {
		t.Fatalf("expected 200 %s, got %d %s", devLoopOutcomeAlreadyExists, rec.Code, rec.Body.String())
	}
	if len(fake.endedReadRuns) != 0 || fake.restartCalls != 0 {
		t.Fatalf("reads %v, restarts %d", fake.endedReadRuns, fake.restartCalls)
	}
}

// A running loop is already_running: its result is never read, even when it
// would say abandoned, and nothing restarts.
func TestStartDevLoopWorkflow_RunningLoopNeverReadsTheMarker(t *testing.T) {
	fake := &fakeDevLoopClient{
		describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-live"},
		workflowID:   "dev-loop-mctlhq-mctl-telegram-1",
		ended:        temporalclient.AbandonedEndedPrefix + "x",
	}
	h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger()}}
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{"issue_url":"https://github.com/mctlhq/mctl-telegram/issues/1"}`))
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, adminCtx(req))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), devLoopOutcomeAlreadyRunning) {
		t.Fatalf("expected 200 %s, got %d %s", devLoopOutcomeAlreadyRunning, rec.Code, rec.Body.String())
	}
	if len(fake.endedReadRuns) != 0 || fake.restartCalls != 0 || fake.startCalls != 0 {
		t.Fatalf("a running loop: reads %v, restarts %d, starts %d", fake.endedReadRuns, fake.restartCalls, fake.startCalls)
	}
}
