// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The route sweep for the CI principal (mctl-api#530): every authenticated
// route but the deploy route answers 403 from ciPrincipalGate.
func TestCIPrincipal_IsConfinedToTheDeployRoute(t *testing.T) {
	got := sweepRouter(t, auth.NewCIUser("mctlhq/mctl-telegram", "1001"))
	if len(got) < 100 {
		t.Fatalf("the sweep saw only %d authenticated routes; it is not walking the API", len(got))
	}
	for _, mustSee := range []string{"POST /mcp", "GET /mcp", "GET /api/v1/whoami", "POST /api/v1/agents", "GET /api/v1/tenants"} {
		if _, ok := got[mustSee]; !ok {
			t.Errorf("the sweep never reached %s", mustSee)
		}
	}
	const allowed = "POST /api/v1/operations/{name}/execute"
	for route, res := range got {
		gated := res.status == http.StatusForbidden && res.code == codeCIRouteForbidden
		switch {
		case route == allowed && res.code == codeCIRouteForbidden:
			// The sweep calls it as /operations/x/execute, which is not the
			// deploy route: refused by the gate is right.
		case route != allowed && !gated:
			t.Errorf("%s: got %d %q, want 403 %s", route, res.status, res.code, codeCIRouteForbidden)
		}
	}
}

func TestCIPrincipalGate_OnlyTheExactDeployRoute(t *testing.T) {
	router := NewRouter(Options{
		AuthMiddleware: injectUser(auth.NewCIUser("mctlhq/mctl-telegram", "1001")),
		Registry:       operations.NewRegistry(),
	})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, ciDeployRoute},
		{http.MethodPut, ciDeployRoute},
		{http.MethodPost, ciDeployRoute + "/"},
		{http.MethodPost, "/api/v1/operations/deploy%2Dservice/execute"},
		{http.MethodPost, "/api/v1/operations/rollback-service/execute"},
		{http.MethodPost, "/api/v1/operations/retire-service/execute"},
		{http.MethodPost, "/api/v1/services/labs/mctl-telegram/deploy"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeCIRouteForbidden {
			t.Errorf("%s %s: got %d %q, want 403 %s", c.method, c.path, rec.Code, bodyCode(rec), codeCIRouteForbidden)
		}
	}

	// The exact route reaches the handler, whose own CI check then answers.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ciDeployRoute, bytes.NewReader([]byte("{}"))))
	if bodyCode(rec) != codeCIDeployDenied {
		t.Fatalf("the deploy route did not reach the handler: %d %s", rec.Code, rec.Body.String())
	}
}

// Nobody else is touched by the gate.
func TestCIPrincipalGate_IgnoresOtherPrincipals(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(auth.NewGitHubUser("dan", []string{"labs"}))})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil))
	if bodyCode(rec) == codeCIRouteForbidden {
		t.Fatalf("the CI gate refused a human: %s", rec.Body.String())
	}
}
