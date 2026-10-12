package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
)

type fakeLookup struct {
	entry *audit.Entry
	err   error
	calls int
}

func (f *fakeLookup) LookupByWorkflow(context.Context, string) (*audit.Entry, error) {
	f.calls++
	return f.entry, f.err
}

const dae = "https://workflows.mctl.ai/workflows/argo-workflows/mctl-agents-implement-dae24112"

func argoAlert(summary string) *alerts.Alert {
	return &alerts.Alert{ID: "argo-x-1", Source: "argo-workflows", Summary: summary}
}

func TestDeriveIncidentTrace(t *testing.T) {
	tp := map[string]string{"traceparent": "00-431486061c652efb376a860d9d656f25-7a16c732dc164e9e-01"}
	allow := func(*audit.Entry) bool { return true }
	deny := func(*audit.Entry) bool { return false }

	tests := []struct {
		name       string
		a          *alerts.Alert
		lookup     *fakeLookup
		nilLookup  bool
		canRead    func(*audit.Entry) bool
		wantID     string
		wantSource string
		wantReason string
		wantCalls  int
	}{
		{"summary url", argoAlert("failed: " + dae), &fakeLookup{entry: &audit.Entry{Parameters: tp}}, false, allow, "431486061c652efb376a860d9d656f25", "workflow_audit", "", 1},
		{"stored workflow name", &alerts.Alert{Source: "argo-workflows", WorkflowName: "wf-1"}, &fakeLookup{entry: &audit.Entry{Parameters: tp}}, false, allow, "431486061c652efb376a860d9d656f25", "workflow_audit", "", 1},
		{"reported wins", &alerts.Alert{Source: "argo-workflows", TraceID: "431486061c652efb376a860d9d656f25"}, &fakeLookup{}, false, allow, "431486061c652efb376a860d9d656f25", "reported", "", 0},
		{"not found", argoAlert(dae), &fakeLookup{}, false, allow, "", "", "audit_record_not_found", 1},
		{"lookup error", argoAlert(dae), &fakeLookup{err: errors.New("db")}, false, allow, "", "", "audit_unavailable", 1},
		{"nil lookup", argoAlert(dae), nil, true, allow, "", "", "audit_unavailable", 0},
		{"no name", argoAlert("no url"), &fakeLookup{}, false, allow, "", "", "workflow_name_unknown", 0},
		{"no traceparent", argoAlert(dae), &fakeLookup{entry: &audit.Entry{}}, false, allow, "", "", "no_traceparent_in_audit_record", 1},
		{"forbidden", argoAlert(dae), &fakeLookup{entry: &audit.Entry{Parameters: tp}}, false, deny, "", "", "audit_record_forbidden", 1},
		{"non-argo", &alerts.Alert{Source: "alertmanager"}, &fakeLookup{}, false, allow, "", "", "not_reported", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var l workflowAuditLookup
			if !tc.nilLookup {
				l = tc.lookup
			}
			deriveIncidentTrace(context.Background(), tc.a, l, tc.canRead)
			if tc.a.TraceID != tc.wantID || tc.a.TraceSource != tc.wantSource || tc.a.TraceUnavailable != tc.wantReason {
				t.Fatalf("got id=%q source=%q reason=%q", tc.a.TraceID, tc.a.TraceSource, tc.a.TraceUnavailable)
			}
			if tc.lookup != nil && tc.lookup.calls != tc.wantCalls {
				t.Fatalf("lookup calls = %d, want %d", tc.lookup.calls, tc.wantCalls)
			}
		})
	}
}

func TestValidIncidentTraceInputs(t *testing.T) {
	const id = "431486061c652efb376a860d9d656f25"
	if got := validIncidentTraceID(json.RawMessage(`"` + id + `"`)); got != id {
		t.Errorf("valid: %q", got)
	}
	for _, bad := range []string{`123`, `"` + id[:31] + `"`, `"431486061C652EFB376A860D9D656F25"`, `"00000000000000000000000000000000"`, `null`} {
		if got := validIncidentTraceID(json.RawMessage(bad)); got != "" {
			t.Errorf("%s accepted: %q", bad, got)
		}
	}
	if validIncidentWorkflowName(json.RawMessage(`"Bad_Name"`)) != "" || validIncidentWorkflowName(json.RawMessage(`5`)) != "" {
		t.Error("invalid workflow name accepted")
	}
	if validIncidentWorkflowName(json.RawMessage(`"wf-1"`)) != "wf-1" {
		t.Error("valid workflow name rejected")
	}
}

func TestAlertJSONTraceKey(t *testing.T) {
	b, _ := json.Marshal(alerts.Alert{TraceID: "abc"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["trace_id"] != "abc" {
		t.Fatalf("trace_id missing: %s", b)
	}
}

// mctl-api#586: an audit row whose params could not be decoded is an
// unreadable record, not a forbidden one or one without a traceparent.
func TestDeriveIncidentTrace_UnreadableParametersIsAuditUnavailable(t *testing.T) {
	a := argoAlert("Failed — " + dae)
	lookup := &fakeLookup{entry: &audit.Entry{WorkflowName: "mctl-agents-implement-dae24112", ParametersUnreadable: true}}
	deriveIncidentTrace(context.Background(), a, lookup, func(*audit.Entry) bool { return true })
	if a.TraceID != "" || a.TraceUnavailable != traceAuditUnavailable {
		t.Fatalf("trace_id=%q trace_unavailable=%q, want \"\" / %q", a.TraceID, a.TraceUnavailable, traceAuditUnavailable)
	}
}
