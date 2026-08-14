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
