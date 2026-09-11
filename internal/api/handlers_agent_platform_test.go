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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
)

// newTestAgentPlatformStore is newTestAgentRegistryStore extended with the
// v1alpha2 tables in its cleanup list.
func newTestAgentPlatformStore(t *testing.T) *agentregistry.Store {
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
	tables := []string{
		"agent_release_bindings", "agent_profile_versions", "agent_definition_versions",
		"agent_executions", "agent_promotions", "agent_releases", "agent_versions", "agent_definitions",
	}
	cleanup := func() {
		for _, table := range tables {
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

func publishDefinitionAndProfile(t *testing.T, h *Handlers, agent, defVersion, profileRange, profile, profVersion string) {
	t.Helper()
	createReq := adminCtx(httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"`+agent+`"}`)))
	h.CreateAgentDefinition(httptest.NewRecorder(), createReq)

	defBody := `{"version":"` + defVersion + `","spec":"{}","owner":"mctl-agents",` +
		`"source_manifest":{"repo":"mctlhq/mctl-agents","path":"agents/_manifests/` + agent + `/agent.yaml","git_sha":"deadbeef","content_hash":"sha256:test"},` +
		`"profile_range":"` + profileRange + `"}`
	defReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/"+agent+"/definition-versions", bytes.NewBufferString(defBody)), "name", agent))
	rec := httptest.NewRecorder()
	h.PublishDefinitionVersion(rec, defReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish definition version: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	profBody := `{"version":"` + profVersion + `","spec":"{\"maxTokens\":1,\"maxToolCalls\":1,\"timeoutSeconds\":1}","owner":"mctl-agents",` +
		`"source_manifest":{"repo":"mctlhq/platform-gitops","path":"agent-platform/profiles/` + profile + `.yaml","git_sha":"cafebabe","content_hash":"sha256:profile"}}`
	profReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agent-profiles/"+profile+"/versions", bytes.NewBufferString(profBody)), "profile", profile))
	rec = httptest.NewRecorder()
	h.PublishProfileVersion(rec, profReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish profile version: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ─── T7: status-code mapping and auth ──────────────────────────────────

func TestAgentPlatformHandlers_RequireAdmin(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	h.ListAgents(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentPlatformHandlers_StoreNotConfiguredIs503(t *testing.T) {
	h := &Handlers{opts: Options{}}

	req := adminCtx(httptest.NewRequest("GET", "/api/v1/agents", nil))
	rec := httptest.NewRecorder()
	h.ListAgents(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the registry isn't configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishDefinitionVersion_DuplicateIs409(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=1.0.0", "standard-investigate", "1.0.0")

	defBody := `{"version":"1.0.0","spec":"{}","owner":"mctl-agents",` +
		`"source_manifest":{"repo":"r","path":"p","git_sha":"s","content_hash":"c"},"profile_range":">=1.0.0"}`
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/definition-versions", bytes.NewBufferString(defBody)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.PublishDefinitionVersion(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 republishing the same version, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateBinding_IncompatibleProfileIs422(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=2.0.0 <3.0.0", "standard-investigate", "9.9.9")

	body := `{"environment":"shadow","definition_version":"1.0.0","profile":"standard-investigate","profile_version":"9.9.9"}`
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/bindings", bytes.NewBufferString(body)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.CreateBinding(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for an incompatible profile, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"code":"incompatible_profile"`)) {
		t.Fatalf("expected error code incompatible_profile, got %s", rec.Body.String())
	}
}

func TestCreateBinding_UnknownVersionIs404(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=1.0.0", "standard-investigate", "1.0.0")

	body := `{"environment":"shadow","definition_version":"9.9.9","profile":"standard-investigate","profile_version":"1.0.0"}`
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/bindings", bytes.NewBufferString(body)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.CreateBinding(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown definition version, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateBinding_FixtureSourceIs422(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=1.0.0", "standard-investigate", "1.0.0")

	body := `{"environment":"shadow","definition_version":"1.0.0","profile":"standard-investigate","profile_version":"1.0.0","binding_source":"compatibility-fixture"}`
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/bindings", bytes.NewBufferString(body)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.CreateBinding(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for a compatibility-fixture binding source, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResolveBinding_BothSelectorsIs400(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := adminCtx(withChiParam(httptest.NewRequest("GET",
		"/api/v1/agents/issue-investigator/bindings/resolve?environment=shadow&definition_version=1.0.0&profile=standard-investigate", nil),
		"name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.ResolveBinding(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 giving both selectors, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResolveBinding_NeitherSelectorIs400(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	req := adminCtx(withChiParam(httptest.NewRequest("GET", "/api/v1/agents/issue-investigator/bindings/resolve", nil), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.ResolveBinding(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 giving neither selector, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ─── T8: explicit-pin resolve ──────────────────────────────────────────

func TestResolveBinding_ExplicitPinDoesNotRequireABinding(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.4.0", ">=2.0.0 <3.0.0", "standard-investigate", "2.1.0")

	// No CreateBinding call at all.
	req := adminCtx(withChiParam(httptest.NewRequest("GET",
		"/api/v1/agents/issue-investigator/bindings/resolve?definition_version=1.4.0&profile=standard-investigate&profile_version=2.1.0", nil),
		"name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.ResolveBinding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for an explicit pin with no binding, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"apiVersion":"agents.mctl.ai/v1alpha2"`, `"version":"1.4.0"`, `"version":"2.1.0"`} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Errorf("expected response to contain %s, got %s", want, rec.Body.String())
		}
	}
}

// ─── T9: catalog (mctl_list_agents / mctl_get_agent) ───────────────────

func TestGetAgent_ShowsBothV1AndV1Alpha2State(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.4.0", ">=2.0.0 <3.0.0", "standard-investigate", "2.1.0")

	// A v1 version too.
	v1Body := `{"version":"1.0.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/x","prompt_hash":"sha256:x"}`
	v1Req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/versions", bytes.NewBufferString(v1Body)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.PublishAgentVersion(rec, v1Req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish v1 version: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	bindBody := `{"environment":"shadow","definition_version":"1.4.0","profile":"standard-investigate","profile_version":"2.1.0"}`
	bindReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/bindings", bytes.NewBufferString(bindBody)), "name", "issue-investigator"))
	rec = httptest.NewRecorder()
	h.CreateBinding(rec, bindReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create binding: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	getReq := adminCtx(withChiParam(httptest.NewRequest("GET", "/api/v1/agents/issue-investigator", nil), "name", "issue-investigator"))
	rec = httptest.NewRecorder()
	h.GetAgent(rec, getReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"version":"1.0.0"`, `"version":"1.4.0"`, `"shadow"`} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Errorf("expected GetAgent response to contain %s, got %s", want, rec.Body.String())
		}
	}
}

func TestListAgents_ReturnsActiveBindingPerEnvironment(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.4.0", ">=2.0.0 <3.0.0", "standard-investigate", "2.1.0")

	bindBody := `{"environment":"shadow","definition_version":"1.4.0","profile":"standard-investigate","profile_version":"2.1.0"}`
	bindReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/issue-investigator/bindings", bytes.NewBufferString(bindBody)), "name", "issue-investigator"))
	rec := httptest.NewRecorder()
	h.CreateBinding(rec, bindReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create binding: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	listReq := adminCtx(httptest.NewRequest("GET", "/api/v1/agents", nil))
	rec = httptest.NewRecorder()
	h.ListAgents(rec, listReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"issue-investigator"`)) {
		t.Fatalf("expected issue-investigator in the catalog, got %s", rec.Body.String())
	}
}

// ─── T10: v1 backward-compatibility regression ─────────────────────────

func TestV1Routes_UnchangedShapeAfterV1Alpha2Additions(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	createReq := adminCtx(httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"mentor"}`)))
	rec := httptest.NewRecorder()
	h.CreateAgentDefinition(rec, createReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create definition: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	versionBody := `{"version":"1.0.0","manifest_json":"{}","git_sha":"deadbeef","image_repository":"ghcr.io/x","prompt_hash":"sha256:x"}`
	versionReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/mentor/versions", bytes.NewBufferString(versionBody)), "name", "mentor"))
	rec = httptest.NewRecorder()
	h.PublishAgentVersion(rec, versionReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish version: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"image_repository":"ghcr.io/x"`)) {
		t.Fatalf("expected the v1 AgentVersion shape unchanged, got %s", rec.Body.String())
	}

	releaseReq := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/mentor/releases",
		bytes.NewBufferString(`{"environment":"production","version":"1.0.0"}`)), "name", "mentor"))
	rec = httptest.NewRecorder()
	h.UpdateAgentRelease(rec, releaseReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	resolveReq := adminCtx(withChiParam(httptest.NewRequest("GET", "/api/v1/agents/mentor/resolve?environment=production", nil), "name", "mentor"))
	rec = httptest.NewRecorder()
	h.ResolveAgentRelease(rec, resolveReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"version":"1.0.0"`)) {
		t.Fatalf("expected the v1 AgentRelease shape unchanged, got %s", rec.Body.String())
	}

	execBody := `{"temporal_workflow_id":"dev-loop-x","agent":"mentor","environment":"production","argo_workflow_name":"wf-1","phase":"Succeeded"}`
	execReq := adminCtx(httptest.NewRequest("POST", "/api/v1/agents/executions", bytes.NewBufferString(execBody)))
	rec = httptest.NewRecorder()
	h.RecordAgentExecution(rec, execReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record execution without v1alpha2 fields: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ─── T12: execution identity ────────────────────────────────────────────

func TestRecordAgentExecution_V1Alpha2FieldsRoundTrip(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}

	execBody := `{"temporal_workflow_id":"dev-loop-y","agent":"issue-investigator","environment":"shadow",` +
		`"argo_workflow_name":"wf-2","phase":"Succeeded","definition_version":"1.4.0","profile":"standard-investigate",` +
		`"profile_version":"2.1.0","binding_revision":1}`
	execReq := adminCtx(httptest.NewRequest("POST", "/api/v1/agents/executions", bytes.NewBufferString(execBody)))
	rec := httptest.NewRecorder()
	h.RecordAgentExecution(rec, execReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record execution with v1alpha2 fields: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	listReq := adminCtx(httptest.NewRequest("GET", "/api/v1/agents/executions?agent=issue-investigator", nil))
	rec = httptest.NewRecorder()
	h.ListAgentExecutions(rec, listReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("list executions: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`"definition_version":"1.4.0"`, `"profile":"standard-investigate"`,
		`"profile_version":"2.1.0"`, `"binding_revision":1`,
	} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Errorf("expected list executions response to contain %s, got %s", want, rec.Body.String())
		}
	}
}
