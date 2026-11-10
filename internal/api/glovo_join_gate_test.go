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

	"github.com/mctlhq/mctl-api/internal/auth"
)

// T2: the join surface is confined in both directions. The facade principal
// reaches only the join prefix (every other path, /mcp included, is 401), and
// no other principal reaches the join prefix.
func TestGlovoJoinGateConfinesBothDirections(t *testing.T) {
	principals := map[string]*auth.User{
		"facade":         auth.NewGlovoFacadeUser(),
		"service":        auth.NewServiceUser(),
		"worker":         auth.NewGlovoWorkerUser(),
		"control-worker": auth.NewGlovoControlWorkerUser(),
		"human":          {ID: "dan", Groups: []string{"acme"}},
	}
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := principals[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	reached := false
	router := NewRouter(Options{AuthMiddleware: mw,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusOK) })})
	call := func(method, path, who string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+who)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	bodyCode := func(rec *httptest.ResponseRecorder) string {
		var b struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if b.Code != "" {
			return b.Code
		}
		return b.Error
	}
	join := "/api/v1/assistants/glovo/v1alpha1/connection"

	// The facade off its prefix.
	for _, rt := range [][2]string{
		{"GET", "/api/v1/whoami"}, {"GET", "/api/v1/services"}, {"POST", "/mcp"}, {"GET", "/mcp"},
		{"POST", "/api/v1/glovo/worker/check"}, {"GET", "/api/v1/assistants/glovo/v1alpha1"},
	} {
		reached = false
		rec := call(rt[0], rt[1], "facade")
		if rec.Code != http.StatusUnauthorized || bodyCode(rec) != "not_authorized" || reached {
			t.Errorf("facade on %s %s = %d %q (mcp reached %v), want 401 not_authorized", rt[0], rt[1], rec.Code, bodyCode(rec), reached)
		}
	}
	// The facade on its prefix is past the gate (the route table decides).
	if rec := call("GET", join, "facade"); rec.Code == http.StatusUnauthorized {
		t.Errorf("facade on the join prefix refused by the gate: %d %s", rec.Code, rec.Body.String())
	}
	// Everyone else on the join prefix.
	for name := range principals {
		if name == "facade" {
			continue
		}
		rec := call("GET", join, name)
		if rec.Code != http.StatusUnauthorized || bodyCode(rec) != "not_authorized" {
			t.Errorf("%s on the join prefix = %d %q, want 401 not_authorized", name, rec.Code, bodyCode(rec))
		}
	}
}
