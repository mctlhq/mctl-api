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
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestHandleProtectedResourceMeta_ReturnsExpectedShape(t *testing.T) {
	h := &Handlers{opts: Options{OAuthServer: &auth.OAuthServer{BaseURL: "https://api.mctl.ai"}}}

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.handleProtectedResourceMeta(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rec.Code)
		}
		var meta ProtectedResourceMeta
		if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		if meta.Resource != "https://api.mctl.ai/mcp" {
			t.Errorf("%s: resource = %q, want https://api.mctl.ai/mcp", path, meta.Resource)
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://api.mctl.ai" {
			t.Errorf("%s: authorization_servers = %v, want [https://api.mctl.ai]", path, meta.AuthorizationServers)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", path, ct)
		}
	}
}

func TestHandleProtectedResourceMeta_NotFoundWithoutOAuthServer(t *testing.T) {
	h := &Handlers{opts: Options{}}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.handleProtectedResourceMeta(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
