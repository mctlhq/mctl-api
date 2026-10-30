package api_test

import (
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// T14: the generic execute route enforces RequiresConfirm for every
// operation that declares it and is not HandlerOnly.
func TestExecuteOperation_RequiresConfirmParity(t *testing.T) {
	admin := auth.NewServiceUser()
	for _, op := range operations.NewRegistry().List() {
		if !op.RequiresConfirm || op.HandlerOnly {
			continue
		}
		t.Run(op.Name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := map[string]string{"tenant_name": "erpact", "team_name": "erpact", "component_name": "web", "app_name": "web"}
			path := "/api/v1/operations/" + op.Name + "/execute"

			w := postAsRaw(t, f.router, path, body, admin)
			if w.Code != http.StatusPreconditionRequired {
				t.Fatalf("without confirm: status %d, want 428; body: %s", w.Code, w.Body.String())
			}
			if got := decodeJSON(t, w)["code"]; got != "operation_confirmation_required" {
				t.Fatalf("code = %v", got)
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("a workflow was submitted without confirm: %v", f.exec.submitted)
			}
			e := f.lastAudit(t)
			if e.Operation != op.Name || e.Status != "denied" {
				t.Fatalf("audit entry = {%q, %q}", e.Operation, e.Status)
			}

			// "  YES " counts: trimmed, case-insensitive.
			body["confirm"] = "  YES "
			w = postAsRaw(t, f.router, path, body, admin)
			if w.Code == http.StatusPreconditionRequired {
				t.Fatalf("with confirm: still 428; body: %s", w.Body.String())
			}
			for _, p := range f.exec.submittedParams {
				if _, present := p["confirm"]; present {
					t.Fatalf("confirm reached the workflow parameters: %v", p)
				}
			}
		})
	}
}
