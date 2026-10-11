package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// A domain row whose team/service pair is now reserved must still be torn
// down: DeleteDomain keeps the row when teardown fails, so refusing it here
// would make the row undeletable and leave its ingress and TLS in place.
func TestTriggerRemoveCustomDomain_ReservedPairStillTearsDown(t *testing.T) {
	exec := &fakeDomainExecutor{}
	h := &Handlers{opts: Options{Executor: exec, Registry: operations.NewRegistry()}}
	d := &domains.Domain{Team: "labs", Service: "oidc-zitadel", Domain: "x.example.com", Status: domains.StatusActive}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/domains/x", nil)
	r = r.WithContext(auth.WithUser(context.Background(), auth.NewGitHubUser("u1", []string{"labs"})))
	_, outcome, err := h.triggerRemoveCustomDomain(r.Context(), r, d)
	if err != nil || outcome != cleanupSubmitted {
		t.Fatalf("outcome %q, err %v; want the teardown submitted", outcome, err)
	}
	if len(exec.submitted) != 1 {
		t.Fatalf("submitted %d, want 1", len(exec.submitted))
	}
}
