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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// newTestAgentRegistryStore connects to a real Postgres instance, same
// TEST_DATABASE_URL-gated convention as newTestAlertStore and
// internal/agentregistry/store_test.go — this repo has no Postgres service
// in CI.
func newTestAgentRegistryStore(t *testing.T) *agentregistry.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed handler test")
	}

	ctx := context.Background()
	s, err := agentregistry.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cleanupPool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	cleanup := func() {
		for _, table := range []string{"agent_executions", "agent_promotions", "agent_releases", "agent_versions", "agent_definitions"} {
			_, _ = cleanupPool.Exec(ctx, "DELETE FROM "+table)
		}
	}
	t.Cleanup(func() {
		cleanup()
		cleanupPool.Close()
	})
	cleanup()
	return s
}

// withChiParam injects a chi URL parameter into the request context, the way
// the router does at dispatch time — needed here because these tests call
// handlers directly, bypassing the router.
func withChiParam(r *http.Request, name, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(name, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func adminCtx(r *http.Request) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "tester", Groups: []string{"admins"}}))
}

func TestAgentRegistryHandlers_RequireAdmin(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("GET", "/api/v1/agents/implementer/versions", nil)
	req = withChiParam(req, "name", "implementer")
	rec := httptest.NewRecorder()
	h.ListAgentVersions(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v1/agents/implementer/versions", nil)
	req = withChiParam(req, "name", "implementer")
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.ListAgentVersions(rec, req)
	if rec.Code != 403 {
		t.Fatalf("non-admin: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentRegistryHandlers_StoreNotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}} // AgentRegistry left nil

	req := httptest.NewRequest("GET", "/api/v1/agents/implementer/versions", nil)
	req = withChiParam(req, "name", "implementer")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ListAgentVersions(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when the registry isn't configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateAgentDefinition_MissingName(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"description":"x"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.CreateAgentDefinition(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing name, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateAgentDefinition_Success(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor","owner":"mctl-agents"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.CreateAgentDefinition(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishAgentVersion_UnknownAgentIs404(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	body := `{"version":"1.0.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/x","prompt_hash":"sha256:x"}`
	req := httptest.NewRequest("POST", "/api/v1/agents/no-such-agent/versions", bytes.NewBufferString(body))
	req = withChiParam(req, "name", "no-such-agent")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.PublishAgentVersion(rec, req)
	if rec.Code != 404 {
		t.Fatalf("expected 404 for an undeclared agent, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishAgentVersion_DuplicateIs409(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"shepherd"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	body := `{"version":"1.0.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/x","prompt_hash":"sha256:x"}`
	first := httptest.NewRequest("POST", "/api/v1/agents/shepherd/versions", bytes.NewBufferString(body))
	first = withChiParam(first, "name", "shepherd")
	first = adminCtx(first)
	h.PublishAgentVersion(httptest.NewRecorder(), first)

	second := httptest.NewRequest("POST", "/api/v1/agents/shepherd/versions", bytes.NewBufferString(body))
	second = withChiParam(second, "name", "shepherd")
	second = adminCtx(second)
	rec := httptest.NewRecorder()
	h.PublishAgentVersion(rec, second)
	if rec.Code != 409 {
		t.Fatalf("expected 409 republishing the same version, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishAgentVersion_TaggedImageRepositoryIsRejected(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"shepherd"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	cases := []string{
		`{"version":"1.22.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/mctlhq/mctl-agents:1.22.0","prompt_hash":"sha256:x"}`,
		`{"version":"1.22.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/mctlhq/mctl-agents@sha256:deadbeef","prompt_hash":"sha256:x"}`,
	}
	for _, body := range cases {
		req := httptest.NewRequest("POST", "/api/v1/agents/shepherd/versions", bytes.NewBufferString(body))
		req = withChiParam(req, "name", "shepherd")
		req = adminCtx(req)
		rec := httptest.NewRecorder()
		h.PublishAgentVersion(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for a tagged/digested image_repository, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestUpdateAgentRelease_RollbackWithVersionIsRejected(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("POST", "/api/v1/agents/implementer/releases",
		bytes.NewBufferString(`{"environment":"production","rollback":true,"version":"1.0.0"}`))
	req = withChiParam(req, "name", "implementer")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.UpdateAgentRelease(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for rollback+version both set, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateAgentRelease_MissingVersionWithoutRollbackIsRejected(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("POST", "/api/v1/agents/implementer/releases",
		bytes.NewBufferString(`{"environment":"production"}`))
	req = withChiParam(req, "name", "implementer")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.UpdateAgentRelease(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing version without rollback, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateAgentRelease_UnknownVersionIs404(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest("POST", "/api/v1/agents/mentor/releases",
		bytes.NewBufferString(`{"environment":"production","version":"9.9.9"}`))
	req = withChiParam(req, "name", "mentor")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.UpdateAgentRelease(rec, req)
	if rec.Code != 404 {
		t.Fatalf("expected 404 promoting an unpublished version, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateAgentRelease_PromoteThenRollback(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	publish := func(version string) {
		body := `{"version":"` + version + `","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/x","prompt_hash":"sha256:x"}`
		req := httptest.NewRequest("POST", "/api/v1/agents/mentor/versions", bytes.NewBufferString(body))
		req = withChiParam(req, "name", "mentor")
		req = adminCtx(req)
		rec := httptest.NewRecorder()
		h.PublishAgentVersion(rec, req)
		if rec.Code != 201 {
			t.Fatalf("publish %s: expected 201, got %d: %s", version, rec.Code, rec.Body.String())
		}
	}
	publish("1.0.0")
	publish("2.0.0")

	promote := func(version string) {
		req := httptest.NewRequest("POST", "/api/v1/agents/mentor/releases",
			bytes.NewBufferString(`{"environment":"production","version":"`+version+`"}`))
		req = withChiParam(req, "name", "mentor")
		req = adminCtx(req)
		rec := httptest.NewRecorder()
		h.UpdateAgentRelease(rec, req)
		if rec.Code != 200 {
			t.Fatalf("promote %s: expected 200, got %d: %s", version, rec.Code, rec.Body.String())
		}
	}
	promote("1.0.0")
	promote("2.0.0")

	rollbackReq := httptest.NewRequest("POST", "/api/v1/agents/mentor/releases",
		bytes.NewBufferString(`{"environment":"production","rollback":true}`))
	rollbackReq = withChiParam(rollbackReq, "name", "mentor")
	rollbackReq = adminCtx(rollbackReq)
	rec := httptest.NewRecorder()
	h.UpdateAgentRelease(rec, rollbackReq)
	if rec.Code != 200 {
		t.Fatalf("rollback: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	resolveReq := httptest.NewRequest("GET", "/api/v1/agents/mentor/resolve?environment=production", nil)
	resolveReq = withChiParam(resolveReq, "name", "mentor")
	resolveReq = adminCtx(resolveReq)
	rec = httptest.NewRecorder()
	h.ResolveAgentRelease(rec, resolveReq)
	if rec.Code != 200 {
		t.Fatalf("resolve after rollback: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"version":"1.0.0"`)) {
		t.Fatalf("expected resolve to reflect the rollback to 1.0.0, got %s", rec.Body.String())
	}
}

func TestUpdateAgentRelease_RollbackWithNoHistoryIs409(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest("POST", "/api/v1/agents/mentor/releases",
		bytes.NewBufferString(`{"environment":"production","rollback":true}`))
	req = withChiParam(req, "name", "mentor")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.UpdateAgentRelease(rec, req)
	if rec.Code != 409 {
		t.Fatalf("expected 409 for rollback with no promotion history, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResolveAgentRelease_MissingEnvironmentQueryParam(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("GET", "/api/v1/agents/mentor/resolve", nil)
	req = withChiParam(req, "name", "mentor")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ResolveAgentRelease(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing environment query param, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResolveAgentRelease_NotFoundIs404(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor"}`))
	createReq = adminCtx(createReq)
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest("GET", "/api/v1/agents/mentor/resolve?environment=production", nil)
	req = withChiParam(req, "name", "mentor")
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ResolveAgentRelease(rec, req)
	if rec.Code != 404 {
		t.Fatalf("expected 404 before any promotion, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRecordAgentExecution_MissingFields(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("POST", "/api/v1/agents/executions", bytes.NewBufferString(`{"agent":"issue-investigator"}`))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.RecordAgentExecution(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing temporal_workflow_id/environment/phase, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRecordAgentExecution_SucceedsForUnregisteredAgent(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	// No CreateAgentDefinition call — this is the case that matters: the
	// Temporal worker records a step before the agent has ever been
	// registered (before its first mctl_promote_agent).
	body := `{"temporal_workflow_id":"dev-loop-mctlhq-mctl-telegram-1","agent":"issue-investigator","environment":"production","argo_workflow_name":"mctl-agents-investigate-ab12cd34","phase":"Succeeded"}`
	req := httptest.NewRequest("POST", "/api/v1/agents/executions", bytes.NewBufferString(body))
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.RecordAgentExecution(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListAgentExecutions_FiltersByAgent(t *testing.T) {
	store := newTestAgentRegistryStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	seeds := []struct{ agent, argoWorkflow string }{
		{"issue-investigator", "wf-1"},
		{"issue-investigator", "wf-2"},
		{"implementer", "wf-3"},
	}
	for _, seed := range seeds {
		body := `{"temporal_workflow_id":"dev-loop-x","agent":"` + seed.agent +
			`","environment":"production","argo_workflow_name":"` + seed.argoWorkflow + `","phase":"Succeeded"}`
		req := adminCtx(httptest.NewRequest("POST", "/api/v1/agents/executions", bytes.NewBufferString(body)))
		rec := httptest.NewRecorder()
		h.RecordAgentExecution(rec, req)
		if rec.Code != 201 {
			t.Fatalf("seed %+v: expected 201, got %d: %s", seed, rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/agents/executions?agent=issue-investigator", nil)
	req = adminCtx(req)
	rec := httptest.NewRecorder()
	h.ListAgentExecutions(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"count":2`)) {
		t.Fatalf("expected count=2 for issue-investigator only, got %s", rec.Body.String())
	}
}
