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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
)

const assistantInstructions = "SECRET-INSTRUCTIONS-TEXT"

// assistantDoc is a materialized TelegramAssistant document carrying every
// field the catalog must NOT return, so a leak shows up as a substring.
func assistantDoc(name, version, visibility, status string) string {
	doc := map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1",
		"kind":       "TelegramAssistant",
		"metadata": map[string]any{
			"name": name, "title": "Title " + name, "description": "Desc " + name, "version": version,
			"owner": "OWNER-LEAK", "visibility": visibility, "status": status,
			"tags": []string{"hr"}, "examples": []string{"Find me a recruiter"},
		},
		"spec": map[string]any{
			"instructions": map[string]any{"text": assistantInstructions},
			"variables": []map[string]any{
				{"name": "company", "type": "string", "required": true, "default": "Acme", "description": "Company",
					"disclosure": "DISCLOSURE-LEAK", "send": "SEND-LEAK", "profilePath": "PROFILEPATH-LEAK"},
				{"name": "api_key", "type": "string", "secret": true, "default": "SECRET-DEFAULT-LEAK", "description": "Key"},
				{"name": "tone", "type": "enum", "choices": []string{"formal", "casual"}, "description": "Tone"},
			},
			"intents":    []map[string]any{{"name": "screen", "description": "Screen a candidate", "tier": "auto", "userOverride": "OVERRIDE-LEAK"}},
			"tools":      []string{"TOOLS-LEAK"},
			"records":    map[string]any{"kind": "RECORDS-LEAK"},
			"escalation": []map[string]any{{"name": "ESCALATION-LEAK", "when": "x", "action": "y"}},
			"defaults": map[string]any{
				"mode":       "draft",
				"limits":     map[string]any{"maxReplyChars": 500},
				"ceilings":   map[string]any{"maxReplyChars": 999111},
				"disclosure": map[string]any{"policy": "always", "text": "DISCLOSURE-TEXT-LEAK"},
			},
		},
	}
	raw, _ := json.Marshal(doc)
	return string(raw)
}

// catalogLeaks are substrings that must never appear in a public response.
var catalogLeaks = []string{
	assistantInstructions, "OWNER-LEAK", "DISCLOSURE-LEAK", "SEND-LEAK", "PROFILEPATH-LEAK",
	"SECRET-DEFAULT-LEAK", "OVERRIDE-LEAK", "TOOLS-LEAK", "RECORDS-LEAK", "ESCALATION-LEAK",
	"999111", "DISCLOSURE-TEXT-LEAK", "mctlhq/mctl-telegram", "assistants/", "sourceManifest",
}

func publishAssistant(t *testing.T, h *Handlers, name, version, visibility, status string) {
	t.Helper()
	h.CreateAgentDefinition(httptest.NewRecorder(), adminCtx(httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"`+name+`"}`))))
	body, _ := json.Marshal(map[string]any{
		"version": version, "spec": assistantDoc(name, version, visibility, status), "owner": "mctl-telegram",
		"source_manifest": map[string]string{
			"repo": "mctlhq/mctl-telegram", "path": "assistants/" + name + "/assistant.yaml",
			"git_sha": "deadbeef", "content_hash": "sha256:" + name + version,
		},
	})
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/api/v1/agents/"+name+"/definition-versions", bytes.NewReader(body)), "name", name))
	rec := httptest.NewRecorder()
	h.PublishDefinitionVersion(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish %s@%s: expected 201, got %d: %s", name, version, rec.Code, rec.Body.String())
	}
}

func setAssistantLifecycle(t *testing.T, h *Handlers, name, version, lifecycle string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"lifecycle":"`+lifecycle+`"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", name)
	rctx.URLParams.Add("version", version)
	req = adminCtx(req.WithContext(withRouteCtx(req, rctx)))
	rec := httptest.NewRecorder()
	h.SetDefinitionVersionLifecycle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set lifecycle %s@%s %s: %d %s", name, version, lifecycle, rec.Code, rec.Body.String())
	}
}

func withRouteCtx(r *http.Request, rctx *chi.Context) context.Context {
	return context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
}

func versionReq(method, path, name, version string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", name)
	rctx.URLParams.Add("version", version)
	return req.WithContext(withRouteCtx(req, rctx))
}

// seedAssistantCatalog publishes one assistant per filtering case.
func seedAssistantCatalog(t *testing.T, h *Handlers) {
	t.Helper()
	publishAssistant(t, h, "public-active", "0.1.0", "public", "active")
	publishAssistant(t, h, "public-active", "0.2.0", "public", "active")
	publishAssistant(t, h, "public-deprecated-status", "1.0.0", "public", "deprecated")
	publishAssistant(t, h, "admin-only", "1.0.0", "admin", "active")
	publishAssistant(t, h, "draft-one", "1.0.0", "public", "draft")
	publishAssistant(t, h, "lifecycle-deprecated", "1.0.0", "public", "active")
	setAssistantLifecycle(t, h, "lifecycle-deprecated", "1.0.0", agentregistry.LifecycleDeprecated)
	publishAssistant(t, h, "lifecycle-disabled", "1.0.0", "public", "active")
	setAssistantLifecycle(t, h, "lifecycle-disabled", "1.0.0", agentregistry.LifecycleDisabled)
	// An AgentDefinition in the same table must never surface here, even
	// one whose spec happens to carry assistant-shaped public metadata.
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=1.0.0", "standard-investigate", "1.0.0")
	if _, err := h.opts.AgentRegistry.PublishDefinitionVersion(context.Background(), &agentregistry.DefinitionVersion{
		Agent: "issue-investigator", Version: "2.0.0", Owner: "mctl-agents", ProfileRange: ">=1.0.0",
		SpecJSON:       `{"kind":"AgentDefinition","metadata":{"name":"issue-investigator","visibility":"public","status":"active"}}`,
		SourceManifest: agentregistry.SourceManifest{GitSHA: "x", ContentHash: "sha256:x"},
	}); err != nil {
		t.Fatalf("publish AgentDefinition 2.0.0: %v", err)
	}
}

func assertNoLeak(t *testing.T, body string) {
	t.Helper()
	for _, leak := range catalogLeaks {
		if strings.Contains(body, leak) {
			t.Errorf("public catalog response leaks %q: %s", leak, body)
		}
	}
}

func TestAssistantCatalog_ListFilters(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	seedAssistantCatalog(t, h)

	rec := httptest.NewRecorder()
	h.ListAssistantCatalog(rec, httptest.NewRequest("GET", "/api/v1/assistant-catalog", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, rec.Body.String())

	var resp struct {
		Items []assistantCatalogEntry `json:"items"`
		Count int                     `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, item := range resp.Items {
		got = append(got, item.Name+"@"+item.Version)
	}
	want := "public-active@0.2.0,public-active@0.1.0,public-deprecated-status@1.0.0"
	if strings.Join(got, ",") != want || resp.Count != 3 {
		t.Fatalf("listed %v (count %d), want %s", got, resp.Count, want)
	}

	first := resp.Items[0]
	if first.Title != "Title public-active" || first.Lifecycle != agentregistry.LifecyclePublished ||
		first.Digest != "sha256:public-active0.2.0" || first.Defaults.Mode != "draft" ||
		first.Defaults.Disclosure.Policy != "always" || string(first.Defaults.Limits) != `{"maxReplyChars":500}` {
		t.Fatalf("unexpected projection: %+v", first)
	}
	if len(first.Variables) != 3 || string(first.Variables[0].Default) != `"Acme"` || first.Variables[1].Default != nil ||
		len(first.Variables[2].Choices) != 2 {
		t.Fatalf("unexpected variables: %+v", first.Variables)
	}
	if len(first.Intents) != 1 || first.Intents[0].Tier != "auto" {
		t.Fatalf("unexpected intents: %+v", first.Intents)
	}
}

func TestAssistantCatalog_GetVersion(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	seedAssistantCatalog(t, h)

	for _, c := range []struct {
		name, version string
		status        int
		lifecycle     string
	}{
		{"public-active", "0.1.0", http.StatusOK, agentregistry.LifecyclePublished},
		{"lifecycle-deprecated", "1.0.0", http.StatusOK, agentregistry.LifecycleDeprecated},
		{"lifecycle-disabled", "1.0.0", http.StatusNotFound, ""},
		{"admin-only", "1.0.0", http.StatusNotFound, ""},
		{"draft-one", "1.0.0", http.StatusNotFound, ""},
		{"issue-investigator", "1.0.0", http.StatusNotFound, ""},
		{"issue-investigator", "2.0.0", http.StatusNotFound, ""},
		{"public-active", "9.9.9", http.StatusNotFound, ""},
		{"nobody", "1.0.0", http.StatusNotFound, ""},
	} {
		rec := httptest.NewRecorder()
		h.GetAssistantCatalogVersion(rec, versionReq("GET", "/", c.name, c.version))
		if rec.Code != c.status {
			t.Errorf("%s@%s: expected %d, got %d: %s", c.name, c.version, c.status, rec.Code, rec.Body.String())
			continue
		}
		assertNoLeak(t, rec.Body.String())
		if c.status == http.StatusOK {
			var entry assistantCatalogEntry
			_ = json.Unmarshal(rec.Body.Bytes(), &entry)
			if entry.Lifecycle != c.lifecycle {
				t.Errorf("%s@%s: lifecycle %q, want %q", c.name, c.version, entry.Lifecycle, c.lifecycle)
			}
		}
	}
}

func TestAssistantCatalog_PublishRefusesTenantVisibility(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	h.CreateAgentDefinition(httptest.NewRecorder(), adminCtx(httptest.NewRequest("POST", "/api/v1/agents", bytes.NewBufferString(`{"name":"t1"}`))))
	body, _ := json.Marshal(map[string]any{
		"version": "1.0.0", "spec": assistantDoc("t1", "1.0.0", "tenant", "active"), "owner": "o",
		"source_manifest": map[string]string{"git_sha": "x", "content_hash": "sha256:x"},
	})
	rec := httptest.NewRecorder()
	h.PublishDefinitionVersion(rec, adminCtx(withChiParam(httptest.NewRequest("POST", "/", bytes.NewReader(body)), "name", "t1")))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_spec") {
		t.Fatalf("expected 400 invalid_spec, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPublicAssistant_Filter is the read-side filter on its own, without a
// database: tenant (or any unknown visibility), admin and draft are never
// public, whatever the publish check lets through.
func TestPublicAssistant_Filter(t *testing.T) {
	for _, c := range []struct {
		visibility, status string
		want               bool
	}{
		{"public", "active", true},
		{"public", "deprecated", true},
		{"public", "draft", false},
		{"admin", "active", false},
		{"tenant", "active", false},
		{"", "active", false},
		{"Public", "active", false},
	} {
		doc, err := agentregistry.ParseAssistantDocument(assistantDoc("a", "1.0.0", c.visibility, c.status))
		if err != nil {
			t.Fatal(err)
		}
		if got := publicAssistant(doc); got != c.want {
			t.Errorf("visibility %q status %q: publicAssistant = %v, want %v", c.visibility, c.status, got, c.want)
		}
	}
	doc, _ := agentregistry.ParseAssistantDocument(`{"kind":"AgentDefinition","metadata":{"visibility":"public","status":"active"}}`)
	if publicAssistant(doc) {
		t.Error("a non-TelegramAssistant kind must never be public")
	}
}

func TestAssistantDefinition_Auth(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	seedAssistantCatalog(t, h)

	for _, c := range []struct {
		name   string
		user   *auth.User
		status int
	}{
		{"unauthenticated", nil, http.StatusUnauthorized},
		{"tenant user", &auth.User{ID: "alice", Groups: []string{"tenant-a"}}, http.StatusForbidden},
		{"portal surface", auth.NewSurfaceUser("portal"), http.StatusForbidden},
		// The platform service principal is an admin and already reads
		// full specs through the admin registry routes.
		{"service", auth.NewServiceUser(), http.StatusOK},
		{"telegram surface", auth.NewSurfaceUser("telegram"), http.StatusOK},
		{"admin", &auth.User{ID: "root", Groups: []string{"admins"}}, http.StatusOK},
	} {
		req := versionReq("GET", "/", "admin-only", "1.0.0")
		if c.user != nil {
			req = withUser(req, c.user)
		}
		rec := httptest.NewRecorder()
		h.GetAssistantDefinition(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s: expected %d, got %d: %s", c.name, c.status, rec.Code, rec.Body.String())
			continue
		}
		hasInstructions := strings.Contains(rec.Body.String(), assistantInstructions)
		if (c.status == http.StatusOK) != hasInstructions {
			t.Errorf("%s: status %d but instructions present = %v", c.name, rec.Code, hasInstructions)
		}
	}
}

func TestAssistantDefinition_ReturnsEveryLifecycle(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	seedAssistantCatalog(t, h)
	tg := auth.NewSurfaceUser("telegram")

	for _, c := range []struct {
		name, version string
		status        int
		lifecycle     string
	}{
		{"public-active", "0.2.0", http.StatusOK, agentregistry.LifecyclePublished},
		{"draft-one", "1.0.0", http.StatusOK, agentregistry.LifecyclePublished},
		{"lifecycle-deprecated", "1.0.0", http.StatusOK, agentregistry.LifecycleDeprecated},
		{"lifecycle-disabled", "1.0.0", http.StatusOK, agentregistry.LifecycleDisabled},
		{"issue-investigator", "1.0.0", http.StatusNotFound, ""},
		{"issue-investigator", "2.0.0", http.StatusNotFound, ""},
		{"nobody", "1.0.0", http.StatusNotFound, ""},
	} {
		rec := httptest.NewRecorder()
		h.GetAssistantDefinition(rec, withUser(versionReq("GET", "/", c.name, c.version), tg))
		if rec.Code != c.status {
			t.Errorf("%s@%s: expected %d, got %d: %s", c.name, c.version, c.status, rec.Code, rec.Body.String())
			continue
		}
		if c.status != http.StatusOK {
			continue
		}
		var resp struct {
			Name        string          `json:"name"`
			Version     string          `json:"version"`
			Lifecycle   string          `json:"lifecycle"`
			ContentHash string          `json:"contentHash"`
			Definition  json.RawMessage `json:"definition"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Lifecycle != c.lifecycle || resp.ContentHash != "sha256:"+c.name+c.version || resp.Name != c.name {
			t.Errorf("%s@%s: unexpected envelope %+v", c.name, c.version, resp)
		}
		var def map[string]any
		if err := json.Unmarshal(resp.Definition, &def); err != nil || def["kind"] != "TelegramAssistant" {
			t.Errorf("%s@%s: definition is not the stored document: %s", c.name, c.version, resp.Definition)
		}
	}
}

// TestSurfaceGate_AssistantDefinitionNeedsNoActor: the Telegram worker reads
// definitions on its own behalf (a lifecycle refresh has no end user), so
// the gate admits that one route without X-MCTL-Surface-Actor, and still
// demands it on every other non-relay surface route.
func TestSurfaceGate_AssistantDefinitionNeedsNoActor(t *testing.T) {
	h := &Handlers{}
	reached := false
	gate := h.surfacePrincipalGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	tg := auth.NewSurfaceUser("telegram")

	req := withUser(httptest.NewRequest("GET", "/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0/definition", nil), tg)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if !reached {
		t.Fatalf("definition route without an actor: gate refused with %d: %s", rec.Code, rec.Body.String())
	}

	reached = false
	req = withUser(httptest.NewRequest("POST", "/api/v1/surface-identities/redeem", nil), tg)
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if reached || rec.Code != http.StatusBadRequest {
		t.Fatalf("redeem without an actor: expected 400 from the gate, got reached=%v %d", reached, rec.Code)
	}

	// The public projection is not on the surface allowlist: it is served
	// outside the authenticated group, so a surface never needs it here.
	reached = false
	req = withUser(httptest.NewRequest("GET", "/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0", nil), tg)
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("non-allowlisted route: expected 403, got reached=%v %d", reached, rec.Code)
	}
}

// TestAssistantCatalogRoutes: the public reads are reachable without
// authentication through the real router, and the definition read is not —
// it resolves through the authenticated /api/v1 mount even though the
// public routes share its prefix.
func TestAssistantCatalogRoutes(t *testing.T) {
	denyAll := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusUnauthorized, "authentication required")
		})
	}
	router := NewRouter(Options{AuthMiddleware: denyAll})
	for path, want := range map[string]int{
		// No registry is configured: reaching the handler answers 503.
		"/api/v1/assistant-catalog":                                        http.StatusServiceUnavailable,
		"/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0":            http.StatusServiceUnavailable,
		"/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0/definition": http.StatusUnauthorized,
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: expected %d, got %d: %s", path, want, rec.Code, rec.Body.String())
		}
	}
}

// TestCreateBinding_TelegramAssistantIs422: a bind request against a
// profile-less definition answers a typed 422 naming the reason, never the
// unparseable-range 500 its empty range would otherwise produce.
func TestCreateBinding_TelegramAssistantIs422(t *testing.T) {
	store := newTestAgentPlatformStore(t)
	h := &Handlers{opts: Options{AgentRegistry: store}}
	publishAssistant(t, h, "hr-recruiter", "0.1.0", "public", "active")
	publishDefinitionAndProfile(t, h, "issue-investigator", "1.0.0", ">=1.0.0", "standard-investigate", "1.0.0")

	body := `{"environment":"shadow","definition_version":"0.1.0","profile":"standard-investigate","profile_version":"1.0.0"}`
	req := adminCtx(withChiParam(httptest.NewRequest("POST", "/", bytes.NewBufferString(body)), "name", "hr-recruiter"))
	rec := httptest.NewRecorder()
	h.CreateBinding(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "profileless_definition") {
		t.Fatalf("expected 422 profileless_definition, got %d: %s", rec.Code, rec.Body.String())
	}
}
