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
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The work-item role gate (mctl-api#489) answers typed codes, decides by
// principal in principal mode, and passes the service principal.
func TestRequireWorkItemRole(t *testing.T) {
	inErpact := map[string][]string{shadowPRN: {"erpact"}, zitadelOnlyPRN: {"erpact"}}
	zitadel := func() *auth.User {
		return principalUser(t, auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "z-1", "dan@example.com", auth.KindHuman), zitadelOnlyPRN, inErpact)
	}
	roles := func(role string) PrincipalMembershipReader {
		return &stubPrincipalMembership{roles: map[string][][]string{"erpact": {{role}}}}
	}
	tests := []struct {
		name     string
		user     *auth.User
		pm       PrincipalMembershipReader
		min      operations.Role
		wantCode int
		wantType string
	}{
		{"developer passes", zitadel(), roles("developer"), workItemWriteRole, 0, ""},
		{"owner passes execution", zitadel(), roles("owner"), workItemExecutionRole, 0, ""},
		{"viewer refused", zitadel(), roles("viewer"), workItemWriteRole, http.StatusForbidden, wiCodeRoleForbidden},
		{"viewer refused execution", zitadel(), roles("viewer"), workItemExecutionRole, http.StatusForbidden, wiCodeRoleForbidden},
		{"unreadable role", zitadel(), nil, workItemWriteRole, http.StatusServiceUnavailable, wiCodeRoleUnavailable},
		{"service passes", auth.NewServiceUser(), nil, workItemExecutionRole, 0, ""},
		{"agent is refused as non-human", auth.NewAgentUser("implementer", auth.AgentRun{}), roles("owner"), workItemWriteRole, http.StatusForbidden, wiCodeRoleForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: tt.pm}}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/work-items", nil)
			ok := h.requireWorkItemRole(rec, r, tt.user, "erpact", tt.min, "test")
			if ok != (tt.wantCode == 0) {
				t.Fatalf("ok = %v, want %v (status %d)", ok, tt.wantCode == 0, rec.Code)
			}
			if tt.wantCode == 0 {
				return
			}
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			var body struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body.Code != tt.wantType {
				t.Fatalf("code = %q, want %q; body=%s", body.Code, tt.wantType, rec.Body.String())
			}
		})
	}
}

// The login is never consulted in principal mode, and legacy mode refuses a
// login-keyed viewer.
func TestRequireWorkItemRole_Modes(t *testing.T) {
	inErpact := map[string][]string{shadowPRN: {"erpact"}}
	u := principalUser(t, erpactMember("dan-dev"), shadowPRN, inErpact)
	byPrincipal := &stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"viewer"}}}}
	h := &Handlers{opts: Options{GitReader: rolesOf("erpact/dan-dev=owner"), TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: byPrincipal}}
	if h.requireWorkItemRole(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil), u, "erpact", workItemWriteRole, "test") {
		t.Fatal("principal viewer passed because the login says owner")
	}
	legacy := &Handlers{opts: Options{GitReader: rolesOf("erpact/dan-dev=viewer")}}
	if legacy.requireWorkItemRole(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil), erpactMember("dan-dev"), "erpact", workItemWriteRole, "test") {
		t.Fatal("legacy viewer passed")
	}
	legacy = &Handlers{opts: Options{GitReader: rolesOf("erpact/dan-dev=developer")}}
	if !legacy.requireWorkItemRole(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil), erpactMember("dan-dev"), "erpact", workItemWriteRole, "test") {
		t.Fatal("legacy developer refused")
	}
}

// A viewer cannot sync repos, and no upstream request is made.
func TestSyncRepos_ViewerRefused(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, GitReader: rolesOf("labs/vic=viewer")}}
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{"team":"labs"}`)), auth.NewGitHubUser("vic", []string{"labs"}))
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)
	if rec.Code != http.StatusForbidden || len(*seen) != 0 {
		t.Fatalf("status = %d, upstream calls = %d", rec.Code, len(*seen))
	}
}
