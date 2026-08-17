// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
)

func TestArgoComplete_FailClosedWithoutSecret(t *testing.T) {
	router := NewRouter(Options{})
	rec := postArgoComplete(router, `{"workflow_name":"wf","phase":"Succeeded"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestArgoComplete_RejectsBadHMAC(t *testing.T) {
	router := NewRouter(Options{ArgoWebhookSecret: "s3cret"})
	rec := postArgoComplete(router, `{"workflow_name":"wf","phase":"Succeeded"}`, "sha256=deadbeef")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestArgoComplete_AcceptsValidHMAC(t *testing.T) {
	const secret = "s3cret"
	body := `{"workflow_name":"wf","phase":"Succeeded"}`
	router := NewRouter(Options{ArgoWebhookSecret: secret})
	rec := postArgoComplete(router, body, argoSig(secret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
}

func TestArgoComplete_RejectsMissingWorkflowName(t *testing.T) {
	const secret = "s3cret"
	body := `{"phase":"Succeeded"}`
	router := NewRouter(Options{ArgoWebhookSecret: secret})
	rec := postArgoComplete(router, body, argoSig(secret, body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func argoSig(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postArgoComplete(router http.Handler, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/events/argo-complete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-MCTL-Signature", sig)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestArgoComplete_ClosesAuditStatus is the point of the webhook: before this,
// it verified the HMAC, logged, and returned 200 without touching anything, so
// every audit row stayed "submitted" for good.
func TestArgoComplete_ClosesAuditStatus(t *testing.T) {
	cases := []struct {
		phase string
		want  string
	}{
		{"Succeeded", "succeeded"},
		{"Failed", "failed"},
		{"Error", "error"},
	}

	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			const secret = "s3cret"
			log := audit.NewLogger()
			log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-1", Status: "submitted"})

			router := NewRouter(Options{ArgoWebhookSecret: secret, AuditLog: log})
			body := `{"workflow_name":"wf-1","phase":"` + tc.phase + `"}`
			rec := postArgoComplete(router, body, argoSig(secret, body))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
			}

			got := log.GetByWorkflow("wf-1")
			if got == nil {
				t.Fatal("audit entry disappeared")
			}
			if got.Status != tc.want {
				t.Errorf("audit status = %q, want %q", got.Status, tc.want)
			}
		})
	}
}

// TestArgoComplete_RunningPhaseLeavesStatusAlone guards the terminal-only gate:
// Argo can report Running, and treating that as an outcome would close the row
// before the workflow finished.
func TestArgoComplete_RunningPhaseLeavesStatusAlone(t *testing.T) {
	const secret = "s3cret"
	log := audit.NewLogger()
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-2", Status: "submitted"})

	router := NewRouter(Options{ArgoWebhookSecret: secret, AuditLog: log})
	body := `{"workflow_name":"wf-2","phase":"Running"}`
	rec := postArgoComplete(router, body, argoSig(secret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := log.GetByWorkflow("wf-2"); got.Status != "submitted" {
		t.Errorf("audit status = %q, want it left at \"submitted\"", got.Status)
	}
}

// TestArgoComplete_RedeliveryIsANoOp: the Argo exit hook swallows its own
// errors, so a retried or duplicated delivery is possible. The second one must
// not overwrite a terminal status.
func TestArgoComplete_RedeliveryIsANoOp(t *testing.T) {
	const secret = "s3cret"
	log := audit.NewLogger()
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-3", Status: "submitted"})
	router := NewRouter(Options{ArgoWebhookSecret: secret, AuditLog: log})

	first := `{"workflow_name":"wf-3","phase":"Succeeded"}`
	postArgoComplete(router, first, argoSig(secret, first))

	second := `{"workflow_name":"wf-3","phase":"Failed"}`
	rec := postArgoComplete(router, second, argoSig(secret, second))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (redelivery must still be acknowledged)", rec.Code)
	}
	if got := log.GetByWorkflow("wf-3"); got.Status != "succeeded" {
		t.Errorf("audit status = %q, want it to stay %q", got.Status, "succeeded")
	}
}

// TestArgoComplete_UnknownWorkflowStillAcknowledged: cron workflows have no
// audit row at all. Returning 4xx would only add noise to the exit hook, which
// cannot act on it.
func TestArgoComplete_UnknownWorkflowStillAcknowledged(t *testing.T) {
	const secret = "s3cret"
	log := audit.NewLogger()
	router := NewRouter(Options{ArgoWebhookSecret: secret, AuditLog: log})

	body := `{"workflow_name":"cron-wf-nobody-submitted","phase":"Succeeded"}`
	rec := postArgoComplete(router, body, argoSig(secret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
