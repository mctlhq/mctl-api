package api_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Release-pin values in the two shapes mctl-agents' registry activity builds
// (_image_ref in orchestrator/temporal/activities/registry.py): by tag when the
// published version carries no digest, by digest when it does.
const (
	pinImageByTag    = "ghcr.io/mctlhq/mctl-agents:1.54.0"
	pinImageByDigest = "ghcr.io/mctlhq/mctl-agents@sha256:6ef615deee2a2864195014760bf6c3989b26059b47435933f04c6d8f5060e9f6"
)

// devLoopSubmissions lists, per mctl-agents-* operation, every parameter set
// mctl-agents submits through POST /operations/{name}/execute. The source of
// each row is named so the table can be re-checked against that code when it
// changes; a parameter added there must be added here, and to the registry.
//
// Every row is a parameter the CWFT already declares. Parameters mctl-agents
// sends that the CWFT does NOT declare yet are listed in
// devLoopParamsPendingDeclaration below instead.
var devLoopSubmissions = []struct {
	name      string
	operation string
	params    map[string]string
}{
	{
		// dev_loop.py investigate step, dispatched loop (#461): the release pin
		// plus the bound work item and execution.
		name:      "investigate, pinned and dispatched",
		operation: "mctl-agents-investigate",
		params: map[string]string{
			"issue_url":     "https://github.com/mctlhq/mctl-api/issues/372",
			"agent_image":   pinImageByTag,
			"agent_version": "issue-investigator@1.54.0",
			"work_item_id":  "wi_5c8e1f2b-0000-0000-0000-000000000000",
			"execution_id":  "we_9a010000-0000-0000-0000-000000000000",
		},
	},
	{
		// dev_loop.py investigate step, a published version with a digest.
		name:      "investigate, pinned by digest",
		operation: "mctl-agents-investigate",
		params: map[string]string{
			"issue_url":     "https://github.com/mctlhq/mctl-api/issues/372",
			"agent_image":   pinImageByDigest,
			"agent_version": "issue-investigator@1.33.0",
		},
	},
	{
		// run_issue_directive_poller.py submit_investigate.
		name:      "investigate, directive poller",
		operation: "mctl-agents-investigate",
		params:    map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/372"},
	},
	{
		// dev_loop.py approve step, relaying the human approver.
		name:      "approve",
		operation: "mctl-agents-approve",
		params: map[string]string{
			"service":  "mctl-api",
			"slug":     "issue-372-declare-pin-params",
			"approver": "mashkovd",
		},
	},
	{
		// dev_loop.py implement step.
		name:      "implement, pinned",
		operation: "mctl-agents-implement",
		params: map[string]string{
			"service":       "mctl-api",
			"slug":          "issue-372-declare-pin-params",
			"agent_image":   pinImageByTag,
			"agent_version": "implementer@1.54.0",
		},
	},
	{
		// implement_sweep.py SweptImplementWorkflow.
		name:      "implement, sweep",
		operation: "mctl-agents-implement",
		params: map[string]string{
			"service": "mctl-api",
			"slug":    "issue-372-declare-pin-params",
		},
	},
	{
		// dev_loop.py _shepherd_tick.
		name:      "shepherd tick, pinned",
		operation: "mctl-agents-shepherd",
		params: map[string]string{
			"service":       "mctl-api",
			"slug":          "issue-372-declare-pin-params",
			"agent_image":   pinImageByTag,
			"agent_version": "shepherd@1.54.0",
		},
	},
	{
		// incidents.py IncidentResponderWorkflow.
		name:      "incident responder, pinned",
		operation: "mctl-agents-incidents",
		params: map[string]string{
			"mode":          "incident-responder",
			"agent_image":   pinImageByTag,
			"agent_version": "incident-responder@1.54.0",
		},
	},
	{
		// reconcile.py ReconcileWorkflow apply.
		name:      "reconcile apply",
		operation: "mctl-agents-reconcile",
		params:    map[string]string{"dry_run": "false"},
	},
}

// TestExecuteOperation_DevLoopParamsAreNeverDropped submits every row as the
// mctl-agent service principal, the identity the Temporal worker uses, and
// asserts each parameter reaches the executor unchanged. A parameter missing
// from the registry is stripped by StripUndeclared and fails here, which is
// how the investigator release pin went dead unnoticed (mctlhq/mctl-api#372).
func TestExecuteOperation_DevLoopParamsAreNeverDropped(t *testing.T) {
	for _, tc := range devLoopSubmissions {
		t.Run(tc.name, func(t *testing.T) {
			router, exec := newTestRouter(t)
			w := postAs(t, router, "/api/v1/operations/"+tc.operation+"/execute", tc.params, auth.NewServiceUser())
			assertStatus(t, w, http.StatusAccepted)
			if len(exec.submittedParams) == 0 {
				t.Fatal("expected a workflow submission")
			}
			got := exec.submittedParams[len(exec.submittedParams)-1]

			var dropped []string
			for k, want := range tc.params {
				v, ok := got[k]
				if !ok {
					dropped = append(dropped, k)
					continue
				}
				if v != want {
					t.Errorf("%s = %q at the executor, want %q", k, v, want)
				}
			}
			sort.Strings(dropped)
			if len(dropped) > 0 {
				t.Errorf("%s dropped %v: declare them in internal/operations/registry.go "+
					"(the CWFT declares them, so mctl-api is the only thing stripping them)",
					tc.operation, dropped)
			}
		})
	}
}

// devLoopParamsPendingDeclaration are parameters mctl-agents sends, or will
// send, that the CWFT does not declare yet. They are deliberately undeclared
// here: declaring one in mctl-api before gitops would forward it to a
// template that rejects it. When the CWFT half lands, move the parameter into
// the registry and its row into devLoopSubmissions.
var devLoopParamsPendingDeclaration = []struct {
	operation string
	param     string
	value     string
}{
	// dev_loop.py human-input continuation; not declared by
	// cwft-mctl-agents-investigate (mctlhq/mctl-api#372 item 3).
	{"mctl-agents-investigate", "human_input_responses", `[{"request_id":"hir-0000000000000000"}]`},
	// Loop identity (mctlhq/mctl-agents#461, #451). Order: gitops CWFT, then
	// the mctl-agents release that sends them, then mctl-api.
	{"mctl-agents-investigate", "temporal_workflow_id", "dev-loop-xr_0000"},
	{"mctl-agents-investigate", "temporal_run_id", "00000000-0000-0000-0000-000000000000"},
	{"mctl-agents-investigate", "execution_request_id", "xr_0000"},
}

// TestExecuteOperation_PendingDevLoopParamsAreStillStripped pins the other
// side of the table: these are dropped today, and this fails the moment one
// is declared, so the declaration is a deliberate step that also updates the
// table above.
func TestExecuteOperation_PendingDevLoopParamsAreStillStripped(t *testing.T) {
	for _, tc := range devLoopParamsPendingDeclaration {
		t.Run(tc.param, func(t *testing.T) {
			router, exec := newTestRouter(t)
			w := postAs(t, router, "/api/v1/operations/"+tc.operation+"/execute", map[string]string{
				"issue_url": "https://github.com/mctlhq/mctl-api/issues/372",
				tc.param:    tc.value,
			}, auth.NewServiceUser())
			assertStatus(t, w, http.StatusAccepted)
			got := exec.submittedParams[len(exec.submittedParams)-1]
			if _, ok := got[tc.param]; ok {
				t.Errorf("%s reached the executor; if it is now declared, move it into devLoopSubmissions", tc.param)
			}
		})
	}
}

// An unpinned caller must keep the CWFT's default image. Declaring
// agent_image with Default "" would otherwise send agent_image="" to Argo,
// which overrides the template default with an empty container image.
func TestExecuteOperation_UnpinnedCallerSendsNoAgentImage(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
	}{
		{"omitted", map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/372"}},
		{"explicitly empty", map[string]string{
			"issue_url":     "https://github.com/mctlhq/mctl-api/issues/372",
			"agent_image":   "",
			"agent_version": "",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, exec := newTestRouter(t)
			w := postAs(t, router, "/api/v1/operations/mctl-agents-investigate/execute", tc.params, auth.NewServiceUser())
			assertStatus(t, w, http.StatusAccepted)
			got := exec.submittedParams[len(exec.submittedParams)-1]
			for _, k := range []string{"agent_image", "agent_version"} {
				if v, ok := got[k]; ok {
					t.Errorf("%s = %q reached the executor for an unpinned caller; it must be absent so the CWFT default applies", k, v)
				}
			}
		})
	}
}
