package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func ownerActionHTTPRequest(body string, u *auth.User) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/"+abandonTestWorkflow+"/owner-actions", bytes.NewBufferString(body))
	req = withChiParam(req, "workflow_id", abandonTestWorkflow)
	return req.WithContext(auth.WithUser(req.Context(), u))
}

// Only a direct human admin may take an owner action; every other caller is
// refused before Temporal or the store is touched.
func TestRequestDevLoopOwnerAction_RefusesNonDirectHumans(t *testing.T) {
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"service principal": auth.NewServiceUser(),
		"surface":           surface,
		"relayed":           auth.NewRelayedUser("alice", []string{"admins"}, surface),
		"non-admin":         {ID: "bob", Groups: []string{"tenant"}},
	} {
		for _, action := range []string{"request_changes", "defer", "request_cancel"} {
			t.Run(name+"/"+action, func(t *testing.T) {
				fake := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Running", RunID: "run-1"}}
				h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger(), WorkItems: &workitems.Store{}}}
				rec := httptest.NewRecorder()
				h.RequestDevLoopOwnerAction(rec, ownerActionHTTPRequest(`{"action":"`+action+`","idempotency_key":"k1"}`, u))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
				}
				if u.IsAdmin() && !strings.Contains(rec.Body.String(), ownerActionCodeForbidden) {
					t.Fatalf("expected %s, got %s", ownerActionCodeForbidden, rec.Body.String())
				}
				if fake.abandonCalls != 0 || fake.describeExecCalls != 0 {
					t.Fatalf("a refused caller reached Temporal: %d signals, %d describes", fake.abandonCalls, fake.describeExecCalls)
				}
			})
		}
	}
}

// The body is codes only: free text, unknown fields and fields that do not
// belong to the action are refused before any lookup.
func TestRequestDevLoopOwnerAction_RefusesMalformedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"free text reason":      `{"action":"defer","idempotency_key":"k","reason":"later"}`,
		"free text comment":     `{"action":"defer","idempotency_key":"k","comment":"later"}`,
		"identity field":        `{"action":"defer","idempotency_key":"k","approved_by":"x"}`,
		"unknown action":        `{"action":"approve","idempotency_key":"k"}`,
		"missing key":           `{"action":"defer"}`,
		"long key":              `{"action":"defer","idempotency_key":"` + strings.Repeat("k", 129) + `"}`,
		"free text reason_code": `{"action":"defer","idempotency_key":"k","reason_code":"not now please"}`,
		"run id on defer":       `{"action":"defer","idempotency_key":"k","expected_run_id":"run-1"}`,
		"empty body":            ``,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeDevLoopClient{}
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: audit.NewLogger(), WorkItems: &workitems.Store{}}}
			rec := httptest.NewRecorder()
			h.RequestDevLoopOwnerAction(rec, ownerActionHTTPRequest(body, &auth.User{ID: "alice", Groups: []string{"admins"}}))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if fake.abandonCalls != 0 || fake.describeExecCalls != 0 {
				t.Fatal("a malformed body must not reach Temporal")
			}
		})
	}
}

// cancellation_pending needs proof that implement has not started: a
// pending grant, or no grant where the run could not have been approved
// without one (an open we_ was read and the legacy approver payload is
// disabled). Not seeing a grant is not that proof.
func TestOwnerCancelSignalledOutcome(t *testing.T) {
	exec := &workitems.Execution{ID: "we_1"}
	for name, tc := range map[string]struct {
		exec           *workitems.Execution
		legacyDisabled bool
		want           string
	}{
		"no grant, open execution, legacy disabled":    {exec, true, ownerOutcomeCancellationPending},
		"no grant, open execution, legacy enabled":     {exec, false, ownerOutcomeEffectsUnknown},
		"no grant, no open execution, legacy disabled": {nil, true, ownerOutcomeEffectsUnknown},
		"no grant, no open execution, legacy enabled":  {nil, false, ownerOutcomeEffectsUnknown},
	} {
		if got := ownerCancelSignalledOutcome(tc.exec, nil, tc.legacyDisabled); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
	for state, want := range map[string]string{
		workitems.ApprovalPending:  ownerOutcomeCancellationPending,
		workitems.ApprovalApproved: ownerOutcomeEffectsUnknown,
		workitems.ApprovalInFlight: ownerOutcomeEffectsUnknown,
		workitems.ApprovalConsumed: ownerOutcomeEffectsUnknown,
		workitems.ApprovalExecuted: ownerOutcomeEffectsUnknown,
		workitems.ApprovalDenied:   ownerOutcomeEffectsUnknown,
		workitems.ApprovalExpired:  ownerOutcomeEffectsUnknown,
	} {
		for _, legacyDisabled := range []bool{false, true} {
			if got := ownerCancelSignalledOutcome(exec, &workitems.ActionApprovalRequest{State: state}, legacyDisabled); got != want {
				t.Errorf("%s (legacy disabled %v): got %s, want %s", state, legacyDisabled, got, want)
			}
		}
	}
}

// The digest tells a retry from a reused key with other content.
func TestOwnerActionContentDigest(t *testing.T) {
	a := &ownerActionRequest{Action: "defer", IdempotencyKey: "k"}
	b := &ownerActionRequest{Action: "defer", IdempotencyKey: "other-key"}
	if a.contentDigest("wf") != b.contentDigest("wf") {
		t.Fatal("the key is not content")
	}
	b.ReasonCode = "later"
	if a.contentDigest("wf") == b.contentDigest("wf") {
		t.Fatal("a different reason_code must change the digest")
	}
	if a.contentDigest("wf") == a.contentDigest("wf2") {
		t.Fatal("a different workflow must change the digest")
	}
}
