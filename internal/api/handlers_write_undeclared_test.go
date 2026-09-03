package api_test

import (
	"net/http"
	"testing"
)

// config_patch is the parameter that motivated the filter (gitops#997): it is a
// raw yq expression that tpl-git-commit evaluates against the service's
// values.yaml, it is NOT declared in the deploy-service registry entry, and
// wft-deploy-service does declare it as a workflow parameter — so before the
// filter it travelled from an arbitrary request body all the way into the yq
// call. Its only legitimate producer is handlers_openclaw.go, which builds it
// server-side and calls Executor.Submit directly, bypassing this path.
func TestExecuteOperation_UndeclaredParamNeverReachesArgo(t *testing.T) {
	router, exec := newTestRouter(t)

	w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
		"action":          "onboard",
		"team_name":       "tests",
		"component_name":  "my-app",
		"dockerfile_repo": "myorg/my-app",
		"git_tag":         "v1.0.0",
		"config_patch":    `.image.tag = "pwned"`,
	}, adminUser)

	// Dropped, not rejected: an extra field must not fail a live caller.
	assertStatus(t, w, http.StatusAccepted)

	if len(exec.submittedParams) == 0 {
		t.Fatal("expected a workflow submission")
	}
	params := exec.submittedParams[len(exec.submittedParams)-1]
	if v, present := params["config_patch"]; present {
		t.Fatalf("config_patch reached the executor as %q; an undeclared parameter must never be forwarded to Argo", v)
	}
	// The declared parameters in the same request must survive untouched —
	// otherwise this passes for the wrong reason.
	if params["component_name"] != "my-app" {
		t.Errorf("declared parameter was dropped: component_name = %q, want %q", params["component_name"], "my-app")
	}
	if params["action"] != "onboard" {
		t.Errorf("declared parameter was dropped: action = %q, want %q", params["action"], "onboard")
	}
}

// Defaults are applied after the filter, so an undeclared key must not be
// resurrected by ApplyDefaults, and a declared-but-absent one must still be.
func TestExecuteOperation_FilterRunsBeforeDefaults(t *testing.T) {
	router, exec := newTestRouter(t)

	w := postAs(t, router, "/api/v1/operations/deploy-service/execute", map[string]string{
		"action":          "onboard",
		"team_name":       "tests",
		"component_name":  "my-app",
		"dockerfile_repo": "myorg/my-app",
		"git_tag":         "v1.0.0",
		"not_a_parameter": "x",
	}, adminUser)
	assertStatus(t, w, http.StatusAccepted)

	params := exec.submittedParams[len(exec.submittedParams)-1]
	if _, present := params["not_a_parameter"]; present {
		t.Error("undeclared parameter survived into the submitted params")
	}
	if params["port"] != "8080" {
		t.Errorf("declared default was not applied: port = %q, want %q", params["port"], "8080")
	}
}
