package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func getProvenance(u *auth.User, id string) *httptest.ResponseRecorder {
	router := NewRouter(Options{AuthMiddleware: injectUser(u)})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/executions/"+id+"/provenance", nil))
	return rec
}

// With no work-items store an authorised caller gets 503, never 404.
func TestExecutionProvenance_UnconfiguredStoreIs503(t *testing.T) {
	rec := getProvenance(adminUser(), "we_1")
	if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeExecutionProvenanceUnavailable {
		t.Errorf("admin: %d %s", rec.Code, rec.Body.String())
	}
	run := auth.NewAgentUser("investigator", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "r1"})
	rec = getProvenance(run, "we_1")
	if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeExecutionProvenanceUnavailable {
		t.Errorf("own run: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExecutionProvenance_OtherCallersAreForbidden(t *testing.T) {
	run := auth.NewAgentUser("investigator", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "r1"})
	if rec := getProvenance(run, "we_2"); rec.Code != http.StatusForbidden {
		t.Errorf("run for another execution: %d, want 403", rec.Code)
	}
	if rec := getProvenance(auth.NewGitHubUser("u1", []string{"labs"}), "we_1"); rec.Code != http.StatusForbidden {
		t.Errorf("tenant member: %d, want 403", rec.Code)
	}
}

func getProvenanceWith(store *workitems.Store, u *auth.User, id string) *httptest.ResponseRecorder {
	router := NewRouter(Options{AuthMiddleware: injectUser(u), WorkItems: store})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/executions/"+id+"/provenance", nil))
	return rec
}

// T10: the full read matrix against a real store. Absent is 404 and an
// unreadable store is 503; the two must never be confused.
func TestExecutionProvenance_ReadMatrix(t *testing.T) {
	env := newWorkItemsEnv(t)
	ctx := context.Background()
	store := env.h.opts.WorkItems
	mut := workitems.Mutation{Actor: "service:mctl-agent", Surface: "cli", RequestID: "req-t10"}
	item, _, err := store.Create(ctx, workitems.CreateInput{Mutation: mut, Tenant: env.tenant,
		Visibility: workitems.VisibilityTenant, OriginSurface: "cli", Title: "t10"})
	if err != nil {
		t.Fatal(err)
	}
	exec, _, err := store.AttachExecution(ctx, workitems.ExecutionInput{Mutation: mut, WorkItemID: item.ID,
		Engine: workitems.EngineTemporal, EngineRef: "t10-run", Phase: workitems.PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	want, err := store.ExecutionProvenance(ctx, exec.ID)
	if err != nil {
		t.Fatal(err)
	}
	ownRun := auth.NewAgentUser("investigator", auth.AgentRun{ExecutionID: exec.ID, WorkItemID: item.ID, RunID: "r1"})
	otherRun := auth.NewAgentUser("investigator", auth.AgentRun{ExecutionID: "we_other", WorkItemID: "wi_other", RunID: "r2"})

	decode := func(rec *httptest.ResponseRecorder) workitems.Provenance {
		var p workitems.Provenance
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("body %s: %v", rec.Body.String(), err)
		}
		return p
	}
	for name, u := range map[string]*auth.User{"admin": adminUser(), "run bound to the same execution": ownRun} {
		rec := getProvenanceWith(store, u, exec.ID)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if got := decode(rec); got.AttemptID != want.AttemptID || got.LineageRoot != want.LineageRoot || got.ExecutionID != exec.ID {
			t.Errorf("%s: served %+v, stored %+v", name, got, want)
		}
	}
	if rec := getProvenanceWith(store, otherRun, exec.ID); rec.Code != http.StatusForbidden {
		t.Errorf("run bound to another execution: %d, want 403", rec.Code)
	}
	if rec := getProvenanceWith(store, adminUser(), "we_no-such-execution"); rec.Code != http.StatusNotFound || bodyCode(rec) != codeExecutionProvenanceAbsent {
		t.Errorf("absent: %d %s, want 404 %s", rec.Code, rec.Body.String(), codeExecutionProvenanceAbsent)
	}
	closed, err := workitems.NewStore(ctx, env.connStr)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	for name, u := range map[string]*auth.User{"admin": adminUser(), "own run": ownRun} {
		rec := getProvenanceWith(closed, u, exec.ID)
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeExecutionProvenanceUnavailable {
			t.Errorf("%s on an unreadable store: %d %s, want 503 %s", name, rec.Code, rec.Body.String(), codeExecutionProvenanceUnavailable)
		}
	}
}

// Without an authenticated principal the handler answers 401 before it
// touches the store.
func TestExecutionProvenance_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	r := chi.NewRouter()
	r.Get("/api/v1/executions/{execution_id}/provenance", h.GetExecutionProvenance)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/executions/we_1/provenance", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no principal: %d, want 401", rec.Code)
	}
}
