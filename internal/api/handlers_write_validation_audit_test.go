package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// mctl-api#760: an ExecuteOperation request refused by Registry.ValidateInput
// left no audit row and no typed code. These tests pin both, plus the rule
// that no secret parameter value reaches the audit Message or Parameters.

const secretSentinel = "s3cr3tsentinelvalue"

func validDeployBody() map[string]string {
	return map[string]string{
		"action":          "onboard",
		"team_name":       "tests",
		"component_name":  "my-app",
		"dockerfile_repo": "myorg/my-app",
		"git_tag":         "v1.0.0",
	}
}

func deniedEntries(f *roleFixture) []audit.Entry {
	var out []audit.Entry
	for _, e := range f.audit.List(1000) {
		if e.Status == "denied" {
			out = append(out, e)
		}
	}
	return out
}

func assertNoSentinel(t *testing.T, where string, e audit.Entry) {
	t.Helper()
	if strings.Contains(e.Message, secretSentinel) {
		t.Errorf("%s: secret value leaked into audit Message: %q", where, e.Message)
	}
	for k, v := range e.Parameters {
		if strings.Contains(v, secretSentinel) || strings.Contains(k, secretSentinel) {
			t.Errorf("%s: secret value leaked into audit Parameters[%q] = %q", where, k, v)
		}
	}
}

func TestExecuteOperation_ValidationFailureIsAuditedAndTyped(t *testing.T) {
	cases := map[string]struct {
		mutate     func(map[string]string)
		wantReason string
	}{
		"missing required": {
			mutate:     func(b map[string]string) { delete(b, "component_name") },
			wantReason: "missing required parameter: component_name",
		},
		"pattern": {
			mutate:     func(b map[string]string) { b["component_name"] = "Bad_Name!" },
			wantReason: "component_name: must match pattern",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := validDeployBody()
			tc.mutate(body)
			body["secret_env_vars"] = "API_KEY=" + secretSentinel

			w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
			assertStatus(t, w, http.StatusBadRequest)

			var resp map[string]interface{}
			mustJSON(t, w.Body.Bytes(), &resp)
			if resp["code"] != "validation_failed" {
				t.Errorf("code = %v, want validation_failed; body: %s", resp["code"], w.Body.String())
			}
			errText, _ := resp["error"].(string)
			if !strings.HasPrefix(errText, "validation failed: ") || !strings.Contains(errText, tc.wantReason) {
				t.Errorf("error = %q, want prefix %q and reason %q", errText, "validation failed: ", tc.wantReason)
			}
			if ve, _ := resp["validationErrors"].([]interface{}); len(ve) == 0 {
				t.Errorf("validationErrors missing from response: %s", w.Body.String())
			}

			if len(f.exec.submitted) != 0 {
				t.Fatalf("executor was invoked for invalid input: %v", f.exec.submitted)
			}
			denied := deniedEntries(f)
			if len(denied) != 1 {
				t.Fatalf("denied audit rows = %d, want exactly 1: %+v", len(denied), denied)
			}
			if total := len(f.audit.List(1000)); total != 1 {
				t.Fatalf("audit rows = %d, want exactly 1", total)
			}
			e := denied[0]
			if e.UserID != adminUser.ID {
				t.Errorf("actor = %q, want %q", e.UserID, adminUser.ID)
			}
			if e.Operation != "deploy-service" {
				t.Errorf("operation = %q", e.Operation)
			}
			if e.RiskLevel != "medium" {
				t.Errorf("risk level = %q, want medium", e.RiskLevel)
			}
			if !strings.Contains(e.Message, "validation_failed") || !strings.Contains(e.Message, tc.wantReason) {
				t.Errorf("message = %q, want it to carry the code and reason %q", e.Message, tc.wantReason)
			}
			if e.Parameters["code"] != "validation_failed" {
				t.Errorf("parameters code = %q, want validation_failed", e.Parameters["code"])
			}
			if e.Parameters["secret_env_vars"] != "[REDACTED]" {
				t.Errorf("secret parameter = %q, want [REDACTED]", e.Parameters["secret_env_vars"])
			}
			if e.Parameters["team_name"] != "tests" {
				t.Errorf("non-secret parameter not recorded: %v", e.Parameters)
			}
			assertNoSentinel(t, name, e)
		})
	}
}

// Adversarial: a validation reason that echoes a submitted value (the reserved
// service pair does) must not carry a secret parameter's value into the audit
// Message, even when the secret equals a field that gets echoed.
func TestExecuteOperation_ValidationReasonDoesNotLeakSecretValue(t *testing.T) {
	f := newRoleFixture(t)
	body := validDeployBody()
	body["team_name"] = "tenant" // "tenant-<x>" Applications are platform-owned
	body["component_name"] = secretSentinel
	body["secret_env_vars"] = secretSentinel

	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
	assertStatus(t, w, http.StatusBadRequest)
	var resp map[string]interface{}
	mustJSON(t, w.Body.Bytes(), &resp)
	if resp["code"] != "validation_failed" {
		t.Fatalf("code = %v; body: %s", resp["code"], w.Body.String())
	}
	denied := deniedEntries(f)
	if len(denied) != 1 {
		t.Fatalf("denied rows = %d, want 1", len(denied))
	}
	if !strings.Contains(denied[0].Message, "reserved for platform use") {
		t.Fatalf("message = %q: the echoing reason was expected so the scrub is exercised", denied[0].Message)
	}
	assertNoSentinel(t, "echoed reason", denied[0])
	if len(f.exec.submitted) != 0 {
		t.Fatalf("executor invoked: %v", f.exec.submitted)
	}
}

// Valid input and existing authorization refusals keep their own behavior:
// no extra denied row from the validation path.
func TestExecuteOperation_NoValidationDeniedRowOnSuccessOrOtherRefusals(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newRoleFixture(t)
		w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", validDeployBody(), adminUser)
		assertStatus(t, w, http.StatusAccepted)
		if d := deniedEntries(f); len(d) != 0 {
			t.Fatalf("denied rows on a valid request: %+v", d)
		}
	})
	t.Run("tenant access refused first", func(t *testing.T) {
		f := newRoleFixture(t)
		body := validDeployBody()
		body["team_name"] = "erpact"
		body["component_name"] = "Bad_Name!" // invalid too, but authorization refuses first
		w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, auth.NewGitHubUser("outsider", []string{"other-team"}))
		if w.Code == http.StatusAccepted {
			t.Fatalf("unexpected 202: %s", w.Body.String())
		}
		if d := deniedEntries(f); len(d) > 1 {
			t.Fatalf("denied rows = %d, want at most 1: %+v", len(d), d)
		}
		for _, e := range deniedEntries(f) {
			if strings.Contains(e.Message, "validation_failed") {
				t.Fatalf("authorization refusal was recorded as a validation failure: %+v", e)
			}
		}
	})
	t.Run("confirm required stays single row", func(t *testing.T) {
		f := newRoleFixture(t)
		confirmOp := ""
		for _, op := range operations.NewRegistry().List() {
			if op.RequiresConfirm && !op.HandlerOnly {
				confirmOp = op.Name
				break
			}
		}
		if confirmOp == "" {
			t.Skip("no confirm-gated operation in the registry")
		}
		body := map[string]string{"tenant_name": "erpact", "team_name": "erpact", "component_name": "web", "app_name": "web"}
		w := postAsRaw(t, f.router, "/api/v1/operations/"+confirmOp+"/execute", body, auth.NewServiceUser())
		assertStatus(t, w, http.StatusPreconditionRequired)
		if d := deniedEntries(f); len(d) != 1 || strings.Contains(d[0].Message, "validation_failed") {
			t.Fatalf("denied rows = %+v, want exactly one confirmation denial", d)
		}
	})
}
