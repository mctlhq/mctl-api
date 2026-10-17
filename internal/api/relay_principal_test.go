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
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// unreadableTenants is a membership source whose read fails.
type unreadableTenants struct{}

func (unreadableTenants) PrincipalTenants(string) ([]string, []string, error) {
	return nil, nil, errors.New("checkout is stale")
}

// B5: in principal mode a surface relays a human with the tenants of the
// human's principal, never those of its login, never as admin, and a human
// whose principal or membership cannot be read is not relayed at all.
func TestSurfaceRelay_PrincipalMode(t *testing.T) {
	const prn = "prn_ALICE"
	for name, tc := range map[string]struct {
		resolveErr error
		authz      func(tenant string) *auth.PrincipalAuthz
		wantCode   int
		wantErr    string
	}{
		"member by principal": {authz: func(tenant string) *auth.PrincipalAuthz {
			return &auth.PrincipalAuthz{Members: tenantsByPrincipal{prn: {tenant}}}
		}, wantCode: http.StatusCreated},
		// alice's login is a member (sidTenants); her principal is not.
		"member by login only": {authz: func(string) *auth.PrincipalAuthz {
			return &auth.PrincipalAuthz{Members: tenantsByPrincipal{}}
		}, wantCode: http.StatusForbidden},
		"admin principal is not admin when relayed": {authz: func(string) *auth.PrincipalAuthz {
			return &auth.PrincipalAuthz{Members: tenantsByPrincipal{}, Admins: map[string]bool{prn: true}}
		}, wantCode: http.StatusForbidden},
		"membership unreadable": {authz: func(string) *auth.PrincipalAuthz {
			return &auth.PrincipalAuthz{Members: unreadableTenants{}}
		}, wantCode: http.StatusServiceUnavailable, wantErr: sidCodeUnavailable},
		"principal unresolved": {resolveErr: errors.New("store down"), authz: func(tenant string) *auth.PrincipalAuthz {
			return &auth.PrincipalAuthz{Members: tenantsByPrincipal{prn: {tenant}}}
		}, wantCode: http.StatusServiceUnavailable, wantErr: sidCodeUnavailable},
		"not configured": {authz: func(string) *auth.PrincipalAuthz { return nil },
			wantCode: http.StatusServiceUnavailable, wantErr: sidCodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			pr := &relayPrincipals{byLogin: map[string]string{"alice": prn}}
			var tenant string
			e := newSIDEnvOpts(t, pr, func(o *Options) {
				developerByPrincipal()(o)
				tenant = o.TenantResolver.(sidTenants)["carol"][0]
				o.PrincipalAuthz = tc.authz(tenant)
			})
			e.link("alice", "telegram", "4242")
			pr.err = tc.resolveErr
			code, body := e.relayCreate("telegram", "4242", nil)
			if code != tc.wantCode {
				t.Fatalf("relayed create = %d %v, want %d", code, body, tc.wantCode)
			}
			if tc.wantErr != "" && body["code"] != tc.wantErr {
				t.Fatalf("error code = %v, want %s", body["code"], tc.wantErr)
			}
		})
	}
}

// B5: in principal mode a delegated subject gets the tenants of its
// principal, never those of its login and never admin; one whose
// membership cannot be decided is refused.
func TestAgentPrincipalGate_PrincipalMode(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	for name, tc := range map[string]struct {
		authz      *auth.PrincipalAuthz
		wantCode   int
		wantGroups []string
	}{
		"tenants by principal": {authz: &auth.PrincipalAuthz{Members: tenantsByPrincipal{"prn_ALICE": {"labs"}}, Admins: map[string]bool{"prn_ALICE": true}},
			wantCode: http.StatusOK, wantGroups: []string{"labs"}},
		"membership unreadable": {authz: &auth.PrincipalAuthz{Members: unreadableTenants{}}, wantCode: http.StatusServiceUnavailable},
		"not configured":        {wantCode: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handlers{opts: Options{
				AuditLog:        audit.NewLogger(),
				TenantResolver:  sidTenants{"alice": {"acme"}},
				Principals:      &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE"}},
				Delegation:      &fakeDelegation{fn: alwaysGrant},
				TenantAuthzMode: TenantAuthzPrincipal,
				PrincipalAuthz:  tc.authz,
			}}
			rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
			if rec.Code != tc.wantCode {
				t.Fatalf("code = %d %s, want %d", rec.Code, rec.Body.String(), tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				if next.called {
					t.Fatal("an undecided subject reached the handler")
				}
				if body := decodeBody(t, rec); body["code"] != delegationCodeUnavailable {
					t.Fatalf("error code = %v", body["code"])
				}
				return
			}
			if u := next.user; !slices.Equal(u.Groups, tc.wantGroups) || u.IsAdmin() || u.HasTenantAccess("acme") {
				t.Fatalf("groups = %v admin = %v, want %v and never admin", u.Groups, u.IsAdmin(), tc.wantGroups)
			}
		})
	}
}
