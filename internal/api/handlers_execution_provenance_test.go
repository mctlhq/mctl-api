package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
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
