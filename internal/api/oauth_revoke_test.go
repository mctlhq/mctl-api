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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRevoke(router http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestOAuthRevoke_RejectsUnparseableRequest covers the difference RFC 7009
// draws between an invalid *token* and an invalid *request*. The former is a
// 200 — the caller wanted the token not to work, and it does not. The latter
// is an error per RFC 6749 §5.2, and answering 200 to it is actively
// dangerous: a caller revoking a compromised token is told it succeeded while
// nothing was revoked, so it stops treating a live token as live.
func TestOAuthRevoke_RejectsOversizedBody(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	huge := "token=" + strings.Repeat("x", maxOAuthFormBytes*2)
	rec := postRevoke(router, huge)
	if rec.Code == http.StatusOK {
		t.Fatal("oversized revocation answered 200 without revoking anything")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestOAuthRevoke_AcceptsWellFormedRequest(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	// An unknown token is still a 200 per RFC 7009 §2.2 — the end state the
	// caller asked for already holds.
	rec := postRevoke(router, "token=not-a-real-token&client_id=cli")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
}
