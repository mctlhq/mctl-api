package api_test

import (
	"net/http"
	"sort"
	"strings"
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
		// dev_loop.py investigate step, submitted by a DevLoopWorkflow: the
		// release pin, the bound work item and execution, plus the Temporal
		// correlation identifiers (mctlhq/mctl-api#426, mctlhq/.github#50)
		// and the execution-request id the dispatcher path sets (#461).
		name:      "investigate, pinned and correlated",
		operation: "mctl-agents-investigate",
		params: map[string]string{
			"issue_url":            "https://github.com/mctlhq/mctl-api/issues/372",
			"agent_image":          pinImageByTag,
			"agent_version":        "issue-investigator@1.54.0",
			"work_item_id":         "wi_5c8e1f2b-0000-0000-0000-000000000000",
			"execution_id":         "we_9a010000-0000-0000-0000-000000000000",
			"temporal_workflow_id": "dev-loop-mctlhq-mctl-agents-494",
			"temporal_run_id":      "00000000-0000-0000-0000-000000000000",
			"execution_request_id": "xr_0000",
		},
	},
	{
		// dev_loop.py human-input continuation (mctlhq/mctl-agents#473): the
		// pinned, correlated investigate step plus the accepted answers.
		name:      "investigate, human-input continuation",
		operation: "mctl-agents-investigate",
		params: map[string]string{
			"issue_url":             "https://github.com/mctlhq/mctl-api/issues/372",
			"agent_image":           pinImageByTag,
			"agent_version":         "issue-investigator@1.54.0",
			"temporal_workflow_id":  "dev-loop-mctlhq-mctl-agents-494",
			"temporal_run_id":       "00000000-0000-0000-0000-000000000000",
			"human_input_responses": `[{"request_id":"hir-0123456789abcdef","request_hash":"sha256:` + strings.Repeat("a", 64) + `","value":"library B","received_at":"2026-10-04T10:00:00Z"}]`,
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
		// dev_loop.py implement step, submitted by a DevLoopWorkflow: the
		// release pin plus the Temporal/work-item correlation identifiers
		// (mctlhq/mctl-api#426, mctlhq/.github#50).
		name:      "implement, pinned and correlated",
		operation: "mctl-agents-implement",
		params: map[string]string{
			"service":              "mctl-api",
			"slug":                 "issue-372-declare-pin-params",
			"agent_image":          pinImageByTag,
			"agent_version":        "implementer@1.54.0",
			"temporal_workflow_id": "dev-loop-mctlhq-mctl-api-372",
			"temporal_run_id":      "00000000-0000-0000-0000-000000000000",
			"execution_request_id": "xr_0000",
			"work_item_id":         "wi_5c8e1f2b-0000-0000-0000-000000000000",
			"execution_id":         "we_9a010000-0000-0000-0000-000000000000",
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
		// dev_loop.py _shepherd_tick, submitted by a DevLoopWorkflow: the
		// release pin plus the Temporal/work-item correlation identifiers
		// (mctlhq/mctl-api#426, mctlhq/.github#50).
		name:      "shepherd tick, pinned and correlated",
		operation: "mctl-agents-shepherd",
		params: map[string]string{
			"service":              "mctl-api",
			"slug":                 "issue-372-declare-pin-params",
			"agent_image":          pinImageByTag,
			"agent_version":        "shepherd@1.54.0",
			"temporal_workflow_id": "dev-loop-mctlhq-mctl-api-372",
			"temporal_run_id":      "00000000-0000-0000-0000-000000000000",
			"execution_request_id": "xr_0000",
			"work_item_id":         "wi_5c8e1f2b-0000-0000-0000-000000000000",
			"execution_id":         "we_9a010000-0000-0000-0000-000000000000",
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
	// human_input_responses (mctl-api#372 item 3) moved to devLoopSubmissions
	// above once cwft-mctl-agents-investigate declared it
	// (mctlhq/mctl-gitops#1581).
	// Loop identity (mctlhq/mctl-agents#461, #451) moved to devLoopSubmissions
	// above: temporal_workflow_id, temporal_run_id and execution_request_id
	// are now declared on all three DevLoop operations
	// (mctlhq/mctl-api#426, mctlhq/.github#50).
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

// TestExecuteOperation_UncorrelatedCallerSendsNoCorrelationParams pins the
// byte-identical-to-today guarantee (mctlhq/mctl-api#426) for a caller that
// sends none of the new DevLoop correlation identifiers: the directive
// poller, implement_sweep.py, and a manual operator trigger. Declaring the
// parameters with OmitWhenEmpty must not start sending
// temporal_workflow_id="" (or similar) to Argo for these callers.
//
// investigate's pre-existing work_item_id / execution_id are deliberately
// excluded from its case: they are declared without OmitWhenEmpty (a latent
// inconsistency noted in the design doc) and were already sent as "" by an
// unpinned caller before this change, so that behaviour is out of scope here.
func TestExecuteOperation_UncorrelatedCallerSendsNoCorrelationParams(t *testing.T) {
	newCorrelationKeys := []string{"temporal_workflow_id", "temporal_run_id", "execution_request_id"}
	cases := []struct {
		name      string
		operation string
		params    map[string]string
		keys      []string
	}{
		{"investigate, omitted", "mctl-agents-investigate",
			map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/372"},
			newCorrelationKeys},
		{"implement, omitted", "mctl-agents-implement",
			map[string]string{"service": "mctl-api", "slug": "issue-372-declare-pin-params"},
			append(append([]string{}, newCorrelationKeys...), "work_item_id", "execution_id")},
		{"shepherd, omitted", "mctl-agents-shepherd",
			map[string]string{"service": "mctl-api", "slug": "issue-372-declare-pin-params"},
			append(append([]string{}, newCorrelationKeys...), "work_item_id", "execution_id")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, exec := newTestRouter(t)
			w := postAs(t, router, "/api/v1/operations/"+tc.operation+"/execute", tc.params, auth.NewServiceUser())
			assertStatus(t, w, http.StatusAccepted)
			got := exec.submittedParams[len(exec.submittedParams)-1]
			for _, k := range tc.keys {
				if v, ok := got[k]; ok {
					t.Errorf("%s: %s = %q reached the executor for an uncorrelated caller; it must be absent so the CWFT default applies", tc.operation, k, v)
				}
			}
		})
	}
}

// human_input_responses is opaque to mctl-api, but its shape is pinned: only
// a JSON array reaches the investigator, and an empty value is an absence,
// so a run without answers keeps the CWFT's exact argv (mctlhq/mctl-gitops#1581).
func TestExecuteOperation_HumanInputResponsesShape(t *testing.T) {
	const issue = "https://github.com/mctlhq/mctl-api/issues/372"
	t.Run("non-array rejected", func(t *testing.T) {
		router, exec := newTestRouter(t)
		w := postAs(t, router, "/api/v1/operations/mctl-agents-investigate/execute", map[string]string{
			"issue_url": issue, "human_input_responses": `{"request_id":"hir-0123456789abcdef"}`,
		}, auth.NewServiceUser())
		assertStatus(t, w, http.StatusBadRequest)
		if len(exec.submittedParams) != 0 {
			t.Fatal("a rejected submission reached the executor")
		}
	})
	t.Run("empty omitted", func(t *testing.T) {
		router, exec := newTestRouter(t)
		w := postAs(t, router, "/api/v1/operations/mctl-agents-investigate/execute", map[string]string{
			"issue_url": issue, "human_input_responses": "",
		}, auth.NewServiceUser())
		assertStatus(t, w, http.StatusAccepted)
		if _, ok := exec.submittedParams[len(exec.submittedParams)-1]["human_input_responses"]; ok {
			t.Error("an empty human_input_responses reached the executor; it must be omitted")
		}
	})
}
