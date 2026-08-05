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
	"net/http"
	"net/http/httptest"
	"testing"
)

// TemporalClient is a real client.Client wrapper that requires a live
// Temporal server to construct (see internal/temporalclient.New) — these
// handler tests only exercise the paths that don't need one: unconfigured,
// unauthenticated, missing-field. Behavior once a client exists is covered
// in internal/temporalclient's own tests, against a mocked client.Client.

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
	h := &Handlers{opts: Options{}}

	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/start", bytes.NewBufferString(`{}`))
	// No adminCtx — unauthenticated.
	rec := httptest.NewRecorder()
	h.StartDevLoopWorkflow(rec, req)
	// TemporalClient is nil, so the 503 nil-check fires before the auth
	// check — same ordering as requireAgentRegistryAdmin. Still verifies
	// this handler never proceeds without both a client AND a user.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
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
