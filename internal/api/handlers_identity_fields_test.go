// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
)

// T11: a body carrying on_behalf_of, subject, delegated_actor or
// acting_principal is 400 on the dev-loop approve route (mctl-api#376
// slice B3), and an empty body / {"approver": "<caller>"} still behaves
// exactly as it does today (regression-guarded by the existing
// TestApproveDevLoopWorkflow_Success and
// TestApproveDevLoopWorkflow_ApproverComesFromCredential).
func TestApproveDevLoopWorkflow_RejectsForbiddenIdentityFields(t *testing.T) {
	for _, field := range []string{"on_behalf_of", "subject", "delegated_actor", "acting_principal"} {
		t.Run(field, func(t *testing.T) {
			fake := &fakeDevLoopClient{}
			logger := audit.NewLogger()
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

			body := `{"reason":"looks good","` + field + `":"github:alice"}`
			req := httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve",
				bytes.NewBufferString(body))
			req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
			req = adminCtx(req)
			rec := httptest.NewRecorder()
			h.ApproveDevLoopWorkflow(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: code = %d %s, want 400", field, rec.Code, rec.Body.String())
			}
			if fake.lastApprovedWorkflow != "" {
				t.Fatalf("%s: SignalApprove must not be called", field)
			}
		})
	}
}

// The approve route's own tolerances are untouched by the additive check:
// an empty body and an explicit approver equal to the caller still succeed.
func TestApproveDevLoopWorkflow_UnaffectedByTheIdentityFieldCheck(t *testing.T) {
	for name, body := range map[string]string{
		"empty body":               "",
		"approver equals caller":   `{"approver":"tester"}`,
		"reason with no body keys": `{"reason":"ok"}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeDevLoopClient{}
			logger := audit.NewLogger()
			h := &Handlers{opts: Options{TemporalClient: fake, AuditLog: logger}}

			var req *http.Request
			if body == "" {
				req = httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", nil)
			} else {
				req = httptest.NewRequest("POST", "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-telegram-1/approve", bytes.NewBufferString(body))
			}
			req = withChiParam(req, "workflow_id", "dev-loop-mctlhq-mctl-telegram-1")
			req = adminCtx(req)
			rec := httptest.NewRecorder()
			h.ApproveDevLoopWorkflow(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: code = %d %s, want 200", name, rec.Code, rec.Body.String())
			}
		})
	}
}

// T11 (human-input half): the same four keys are 400 on
// POST /api/v1/human-input/{request_id}/response.
func TestRespondHumanInput_RejectsForbiddenIdentityFields(t *testing.T) {
	for _, field := range []string{"on_behalf_of", "subject", "delegated_actor", "acting_principal"} {
		t.Run(field, func(t *testing.T) {
			h, tc, _, _ := newHumanInputResponseHandlers(t)
			tc.onSignal = workflowAccepts
			body := `{"request_hash":"` + hiASCIIHash + `","value":"library A","` + field + `":"github:alice"}`
			got := respond(t, h, alice, hiASCII, body)
			if got.code != http.StatusBadRequest {
				t.Fatalf("%s: code = %d %s, want 400", field, got.code, got.raw)
			}
			if len(tc.humanInputSignals) != 0 {
				t.Fatalf("%s: signalled despite a forbidden identity field: %v", field, tc.humanInputSignals)
			}
		})
	}
}
