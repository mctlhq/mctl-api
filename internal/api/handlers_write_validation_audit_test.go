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
	entries := f.audit.List(1000)
	for i := range entries {
		e := &entries[i]
		if e.Status == "denied" {
			out = append(out, *e)
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
	if !strings.HasPrefix(denied[0].Message, "validation_failed: ") || !strings.Contains(denied[0].Message, "reason withheld") {
		t.Fatalf("message = %q: the echoing reason was expected to be withheld", denied[0].Message)
	}
	if !strings.Contains(w.Body.String(), "reserved for platform use") {
		t.Errorf("response must keep the full reason: %s", w.Body.String())
	}
	assertNoSentinel(t, "echoed reason", denied[0])
	if len(f.exec.submitted) != 0 {
		t.Fatalf("executor invoked: %v", f.exec.submitted)
	}
}

// A normal secret is KEY=value (or several lines of it), not the bare value.
// The value echoed by another field and by the reserved-service reason must
// not reach the audit Message or Parameters, whatever its length.
func TestExecuteOperation_ValidationAuditScrubsKeyValueSecretFragments(t *testing.T) {
	cases := map[string]struct {
		secret   string
		fragment string
	}{
		"long KEY=value":    {"API_KEY=" + secretSentinel, secretSentinel},
		"multi-line block":  {"A=first\nAPI_KEY=" + secretSentinel + "\nZ=last", secretSentinel},
		"short value":       {"K=ab", "ab"},
		"short multi-line":  {"A=xy\nB=zq", "zq"},
		"single char value": {"K=q", "q"},
		"CRLF multi-line":   {"A=1\r\nB=" + secretSentinel, secretSentinel},
		"value with equals": {"TOKEN=abc=def", "abc=def"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := validDeployBody()
			body["team_name"] = "tenant"
			body["component_name"] = tc.fragment
			body["secret_env_vars"] = tc.secret

			w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
			assertStatus(t, w, http.StatusBadRequest)
			var resp map[string]interface{}
			mustJSON(t, w.Body.Bytes(), &resp)
			if resp["code"] != "validation_failed" {
				t.Fatalf("code = %v; body: %s", resp["code"], w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("executor invoked: %v", f.exec.submitted)
			}
			if total := len(f.audit.List(1000)); total != 1 {
				t.Fatalf("audit rows = %d, want exactly 1", total)
			}
			denied := deniedEntries(f)
			if len(denied) != 1 {
				t.Fatalf("denied rows = %d, want 1", len(denied))
			}
			e := denied[0]
			if !strings.HasPrefix(e.Message, "validation_failed: ") {
				t.Errorf("message = %q, want validation_failed prefix", e.Message)
			}
			if strings.Contains(e.Message, tc.fragment) {
				t.Errorf("secret fragment %q leaked into audit Message: %q", tc.fragment, e.Message)
			}
			for k, v := range e.Parameters {
				if k != "code" && strings.Contains(v, tc.fragment) {
					t.Errorf("secret fragment %q leaked into audit Parameters[%q] = %q", tc.fragment, k, v)
				}
			}
			if e.Parameters["code"] != "validation_failed" || e.Parameters["secret_env_vars"] != "[REDACTED]" {
				t.Errorf("parameters = %v", e.Parameters)
			}
			if e.Parameters["team_name"] != "tenant" {
				t.Errorf("unrelated parameter altered: %v", e.Parameters)
			}
		})
	}
}

// Where no secret is involved the raw reasons stay readable.
func TestExecuteOperation_ValidationAuditKeepsReasonWithoutSecretMatch(t *testing.T) {
	f := newRoleFixture(t)
	body := validDeployBody()
	body["component_name"] = "Bad_Name!"
	body["secret_env_vars"] = "K=zzqq"
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
	assertStatus(t, w, http.StatusBadRequest)
	denied := deniedEntries(f)
	if len(denied) != 1 || !strings.Contains(denied[0].Message, "component_name: must match pattern") {
		t.Fatalf("reason not preserved: %+v", denied)
	}
	if denied[0].Parameters["component_name"] != "Bad_Name!" {
		t.Errorf("parameters = %v", denied[0].Parameters)
	}
}

// A whitespace-only secret is not a secret fragment: it must not withhold the
// useful validation reason or blank unrelated audit parameters that merely
// contain a space. The secret parameter itself stays masked by name.
func TestExecuteOperation_ValidationAuditIgnoresWhitespaceOnlySecret(t *testing.T) {
	cases := map[string]string{
		"single space":         " ",
		"tabs":                 "\t\t",
		"multiline whitespace": " \n\t\r\n  ",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := validDeployBody()
			body["component_name"] = "Bad_Name!"
			body["env_vars"] = "A=b" + secret + "c"
			body["secret_env_vars"] = secret

			w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
			assertStatus(t, w, http.StatusBadRequest)
			var resp map[string]interface{}
			mustJSON(t, w.Body.Bytes(), &resp)
			if resp["code"] != "validation_failed" {
				t.Fatalf("code = %v; body: %s", resp["code"], w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("executor invoked: %v", f.exec.submitted)
			}
			if total := len(f.audit.List(1000)); total != 1 {
				t.Fatalf("audit rows = %d, want exactly 1", total)
			}
			denied := deniedEntries(f)
			if len(denied) != 1 {
				t.Fatalf("denied rows = %d, want 1", len(denied))
			}
			e := denied[0]
			if strings.Contains(e.Message, "reason withheld") || !strings.Contains(e.Message, "component_name: must match pattern") {
				t.Errorf("useful reason withheld by whitespace secret: %q", e.Message)
			}
			if e.Parameters["env_vars"] != "A=b"+secret+"c" {
				t.Errorf("unrelated whitespace parameter blanked: %v", e.Parameters)
			}
			if e.Parameters["component_name"] != "Bad_Name!" {
				t.Errorf("component_name altered: %v", e.Parameters)
			}
			if e.Parameters["secret_env_vars"] != "[REDACTED]" {
				t.Errorf("secret parameter = %q, want [REDACTED]", e.Parameters["secret_env_vars"])
			}
		})
	}
}

// A genuine KEY=<padded base64> assignment protects its whole padded value
// without inventing a universal "=" fragment: the value after the first "="
// is "YWJjZA==", not "=", so unrelated KEY=value parameters stay readable.
// (The earlier bare-token cases "YWJjZA==" / "YWJjZQ=" assumed a bare token is
// not an assignment; under the documented secret_env_vars parser, Cut yields
// key "YWJjZA" and value "=", indistinguishable from a real "K==". That
// expectation was unauthorized and is characterized below instead.)
func TestExecuteOperation_ValidationAuditPaddedBase64SecretDoesNotInventEqualsFragment(t *testing.T) {
	cases := map[string]struct {
		secret string
		leak   string // must not appear in Message or any Parameter
	}{
		"KEY=padded base64":          {"TOKEN=YWJjZA==", "YWJjZA=="},
		"KEY=single-pad base64":      {"TOKEN=YWJjZQ=", "YWJjZQ="},
		"value with internal equals": {"TOKEN=abc=def", "abc=def"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := validDeployBody()
			body["component_name"] = "Bad_Name!" // reason that never echoes a value
			body["env_vars"] = "A=b\nMODE=fast"  // unrelated, contains '='
			body["secret_env_vars"] = tc.secret

			w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
			assertStatus(t, w, http.StatusBadRequest)
			var resp map[string]interface{}
			mustJSON(t, w.Body.Bytes(), &resp)
			if resp["code"] != "validation_failed" {
				t.Fatalf("code = %v; body: %s", resp["code"], w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("executor invoked: %v", f.exec.submitted)
			}
			if total := len(f.audit.List(1000)); total != 1 {
				t.Fatalf("audit rows = %d, want exactly 1", total)
			}
			denied := deniedEntries(f)
			if len(denied) != 1 {
				t.Fatalf("denied rows = %d, want 1", len(denied))
			}
			e := denied[0]
			if strings.Contains(e.Message, "reason withheld") || !strings.Contains(e.Message, "component_name: must match pattern") {
				t.Errorf("safe reason withheld: %q", e.Message)
			}
			if e.Parameters["env_vars"] != "A=b\nMODE=fast" {
				t.Errorf("unrelated env_vars falsely redacted: %q", e.Parameters["env_vars"])
			}
			if e.Parameters["component_name"] != "Bad_Name!" {
				t.Errorf("component_name altered: %q", e.Parameters["component_name"])
			}
			if e.Parameters["secret_env_vars"] != "[REDACTED]" {
				t.Errorf("secret parameter = %q, want [REDACTED]", e.Parameters["secret_env_vars"])
			}
			if strings.Contains(e.Message, tc.leak) {
				t.Errorf("secret %q leaked into Message: %q", tc.leak, e.Message)
			}
			for k, v := range e.Parameters {
				if k != "secret_env_vars" && strings.Contains(v, tc.leak) {
					t.Errorf("secret %q leaked into Parameters[%q] = %q", tc.leak, k, v)
				}
			}
		})
	}
}

// Designed policy, not a regression (P2): a short secret value such as
// DEBUG=1 is matched as a substring, so an unrelated parameter or reason that
// merely contains it is blanked/withheld. The audit row favors no leak over
// detail, because a genuine one-character secret can be embedded anywhere. The
// declared secret stays masked, the response is unchanged, and no value leaks.
func TestExecuteOperation_ValidationAuditShortSecretSuppressionIsConservativePolicy(t *testing.T) {
	f := newRoleFixture(t)
	body := validDeployBody() // git_tag "v1.0.0" contains "1"
	body["component_name"] = "Bad_Name!"
	body["secret_env_vars"] = "DEBUG=1"

	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
	assertStatus(t, w, http.StatusBadRequest)
	if len(f.exec.submitted) != 0 {
		t.Fatalf("executor invoked: %v", f.exec.submitted)
	}
	denied := deniedEntries(f)
	if len(denied) != 1 || len(f.audit.List(1000)) != 1 {
		t.Fatalf("want exactly one denied row, got %+v", denied)
	}
	e := denied[0]
	if e.Parameters["secret_env_vars"] != "[REDACTED]" {
		t.Errorf("secret parameter = %q, want [REDACTED]", e.Parameters["secret_env_vars"])
	}
	if e.Parameters["git_tag"] != "[REDACTED]" {
		t.Errorf("git_tag = %q: the short-secret substring is expected to be suppressed", e.Parameters["git_tag"])
	}
	if e.Parameters["team_name"] != "tests" {
		t.Errorf("parameter without the fragment altered: %v", e.Parameters)
	}
	if !strings.Contains(w.Body.String(), "component_name") {
		t.Errorf("HTTP response must keep the full reason: %s", w.Body.String())
	}
}

// Genuine assignments whose value is only "=" characters (K==, K===) are real
// secrets under the KEY=value contract. Their "="/"==" value must not echo
// into declared non-secret parameters or reasons: they are blanked/withheld
// conservatively, even though that also hides unrelated values containing "=".
// A bare token such as "YWJjZA==" parses identically (value "="), and there is
// no reliable heuristic to tell it apart, so it gets the same protection.
func TestExecuteOperation_ValidationAuditEqualsOnlyValueIsProtected(t *testing.T) {
	cases := map[string]string{
		"K==":                 "K==",
		"K===":                "K===",
		"multiline real":      "A=first\nK==\nZ=last",
		"multiline triple":    "A=first\r\nK===\nZ=last",
		"bare padded (ambig)": "YWJjZA==",
		"line with padded":    "A=zq9\nYWJjZA==",
	}
	// "bare single-pad" YWJjZQ= parses to an empty value (no "=" fragment); only
	// its whole line is protected, so it is not part of this "=" value table.
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			body := validDeployBody()
			body["component_name"] = "Bad_Name!"
			body["env_vars"] = "A=b\nMODE=fast\nX==y" // declared non-secret, echoes "=" and "=="
			body["secret_env_vars"] = secret

			w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
			assertStatus(t, w, http.StatusBadRequest)
			var resp map[string]interface{}
			mustJSON(t, w.Body.Bytes(), &resp)
			if resp["code"] != "validation_failed" {
				t.Fatalf("code = %v; body: %s", resp["code"], w.Body.String())
			}
			if len(f.exec.submitted) != 0 {
				t.Fatalf("executor invoked: %v", f.exec.submitted)
			}
			if total := len(f.audit.List(1000)); total != 1 {
				t.Fatalf("audit rows = %d, want exactly 1", total)
			}
			denied := deniedEntries(f)
			if len(denied) != 1 {
				t.Fatalf("denied rows = %d, want 1", len(denied))
			}
			e := denied[0]
			if e.Parameters["secret_env_vars"] != "[REDACTED]" {
				t.Errorf("secret parameter = %q, want [REDACTED]", e.Parameters["secret_env_vars"])
			}
			if v := e.Parameters["env_vars"]; v != "[REDACTED]" {
				t.Errorf("env_vars = %q: the \"=\" value echo must be blanked", v)
			}
			if !strings.HasPrefix(e.Message, "validation_failed: ") {
				t.Errorf("message = %q", e.Message)
			}
			if !strings.Contains(w.Body.String(), "component_name") {
				t.Errorf("HTTP response must keep the full reason: %s", w.Body.String())
			}
		})
	}
}

// A declared parameter echoed in a reason: with a "==" value secret the reason
// is withheld whole. Uses the reserved-service reason, which echoes the name.
func TestExecuteOperation_ValidationAuditEqualsOnlyValueWithholdsEchoingReason(t *testing.T) {
	for _, secret := range []string{"K==", "K===", "A=1\nK=="} {
		f := newRoleFixture(t)
		body := validDeployBody()
		body["team_name"] = "tenant"
		body["component_name"] = "x=="
		body["secret_env_vars"] = secret

		w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
		assertStatus(t, w, http.StatusBadRequest)
		if len(f.exec.submitted) != 0 {
			t.Fatalf("executor invoked: %v", f.exec.submitted)
		}
		denied := deniedEntries(f)
		if len(denied) != 1 || len(f.audit.List(1000)) != 1 {
			t.Fatalf("secret %q: want exactly one denied row, got %+v", secret, denied)
		}
		e := denied[0]
		if strings.Contains(e.Message, "x==") {
			t.Errorf("secret %q: \"==\" echo leaked into Message: %q", secret, e.Message)
		}
		if v := e.Parameters["component_name"]; strings.Contains(v, "==") {
			t.Errorf("secret %q: component_name = %q leaked", secret, v)
		}
		var resp map[string]interface{}
		mustJSON(t, w.Body.Bytes(), &resp)
		if resp["code"] != "validation_failed" {
			t.Errorf("code = %v", resp["code"])
		}
	}
}

// The raw padded secret echoed by another parameter is still blanked whole.
func TestExecuteOperation_ValidationAuditPaddedBase64EchoIsBlanked(t *testing.T) {
	for _, secret := range []string{"YWJjZA==", "TOKEN=YWJjZA=="} {
		f := newRoleFixture(t)
		body := validDeployBody()
		body["component_name"] = "Bad_Name!"
		body["env_vars"] = "X=" + "YWJjZA=="
		body["secret_env_vars"] = secret
		w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, adminUser)
		assertStatus(t, w, http.StatusBadRequest)
		denied := deniedEntries(f)
		if len(denied) != 1 {
			t.Fatalf("denied rows = %d, want 1", len(denied))
		}
		if v := denied[0].Parameters["env_vars"]; v != "[REDACTED]" {
			t.Errorf("secret %q: env_vars echo = %q, want [REDACTED]", secret, v)
		}
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
