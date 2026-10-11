package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The generic execute path enforces the registry's parameter constraints
// (mctl-api#559): a value outside its Pattern is a 400 naming the parameter,
// and nothing reaches the executor.
func TestExecute_ParameterConstraintRejectedBeforeSubmit(t *testing.T) {
	exec := &fakeExecutor{}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		AuditLog:  audit.NewLogger(),
		Executor:  exec,
	})
	in := map[string]string{
		"action":         "deploy",
		"team_name":      "a",
		"component_name": "b",
		"host":           "$(id)",
	}
	w := postAs(t, router, "/api/v1/operations/deploy-service/execute", in, adminUser)
	assertStatus(t, w, http.StatusBadRequest)
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Error, "validation failed") || !strings.Contains(body.Error, "host:") {
		t.Errorf("error = %q, want the validation failed prefix naming host", body.Error)
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("an invalid host must not be submitted: %v", exec.submitted)
	}
}
