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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

type signinResolver struct {
	prn string
	err error
}

func (s signinResolver) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return s.prn, s.err
}

// A sign-in mints for the principal it resolved. A disabled or refused
// principal stops it in every mode; any other failure stops it only in
// principal mode, where a token without a principal is refused anyway.
func TestSigninPrincipal(t *testing.T) {
	const prn = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	unresolved := errors.New("store down")
	tests := []struct {
		name          string
		resolver      auth.PrincipalResolver
		principalMode bool
		wantPRN       string
		wantStatus    int // 0: the sign-in goes on
	}{
		{"resolved", signinResolver{prn: prn}, false, prn, 0},
		{"resolved, principal mode", signinResolver{prn: prn}, true, prn, 0},
		{"disabled", signinResolver{err: auth.ErrPrincipalDisabled}, false, "", http.StatusForbidden},
		{"refused, principal mode", signinResolver{err: fmt.Errorf("x: %w", auth.ErrIdentityRefused)}, true, "", http.StatusForbidden},
		{"unresolved", signinResolver{err: unresolved}, false, "", 0},
		{"unresolved, principal mode", signinResolver{err: unresolved}, true, "", http.StatusServiceUnavailable},
		{"no resolver", nil, false, "", 0},
		{"no resolver, principal mode", nil, true, "", http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := TenantAuthzLegacy
			if tt.principalMode {
				mode = TenantAuthzPrincipal
			}
			h := &Handlers{opts: Options{TenantAuthzMode: mode, Principals: tt.resolver}}
			rec := httptest.NewRecorder()
			got, stopped := h.signinPrincipal(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback", nil), githubSigninIdentity("alice", 4242))
			want := map[int]string{0: "", http.StatusForbidden: "principal_refused", http.StatusServiceUnavailable: "principal_unavailable"}[tt.wantStatus]
			if got != tt.wantPRN || stopped != want {
				t.Fatalf("got %q, %q; want %q, %q", got, stopped, tt.wantPRN, want)
			}
			if tt.wantStatus != 0 && rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
