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

package api_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// scriptedArgo answers GetAppStatus from a per-name table of apps and
// errors; a name in neither is the real client's 404.
type scriptedArgo struct {
	fakeArgoCD
	errs  map[string]error
	asked []string
}

func (s *scriptedArgo) GetAppStatus(name string) (*argocd.AppStatus, error) {
	s.asked = append(s.asked, name)
	if err, ok := s.errs[name]; ok {
		return nil, err
	}
	return s.fakeArgoCD.GetAppStatus(name)
}

func statusRouter(t *testing.T, argo *scriptedArgo) http.Handler {
	t.Helper()
	if os.Getenv("AUTH_REQUIRED") == "" {
		t.Setenv("AUTH_REQUIRED", "false")
	}
	return mctlapi.NewRouter(mctlapi.Options{
		Registry: operations.NewRegistry(),
		GitReader: &fakeGitReader{
			tenants: []gitops.Tenant{{Name: "acme"}, {Name: "acme-beta"}},
			services: []gitops.Service{
				{Team: "acme", Name: "web", ComponentType: "base-service"},
				{Team: "acme-beta", Name: "web", ComponentType: "base-service"},
			},
		},
		ArgoCD:   argo,
		AuditLog: audit.NewLogger(),
		Executor: &fakeExecutor{},
	})
}

// acmeUser can read tenant "acme" only.
var acmeUser = &auth.User{ID: "acme-dev", Groups: []string{"acme"}}

// TestServiceStatus_DoesNotReadAnotherTenantsApp is the finding: tenant
// "acme" asking for app "beta-web" builds the ArgoCD name "acme-beta-web",
// which is tenant "acme-beta"'s app "web". Its status must not come back.
func TestServiceStatus_DoesNotReadAnotherTenantsApp(t *testing.T) {
	foreign := &argocd.AppStatus{Name: "acme-beta-web", Health: "Degraded", SyncStatus: "OutOfSync",
		Revision: "beta-secret-rev", Message: "beta internal message", DestNamespace: "acme-beta"}
	foreignPreview := &argocd.AppStatus{Name: "preview-acme-beta-web", Health: "Degraded", SyncStatus: "OutOfSync",
		Revision: "beta-preview-rev", DestNamespace: "acme-beta-preview"}
	argo := &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
		"acme-beta-web":         foreign,
		"preview-acme-beta-web": foreignPreview,
	}}}

	w := getAs(t, statusRouter(t, argo), "/api/v1/status/acme/beta-web", acmeUser)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, leak := range []string{"beta-secret-rev", "beta internal message", "beta-preview-rev", "Degraded"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks another tenant's application (%q): %s", leak, body)
		}
	}
	if got := decodeJSON(t, w)["argocd"]; got != nil {
		t.Errorf("argocd = %v, want nil for an application that deploys into another tenant", got)
	}
}

func TestServiceStatus_ReturnsOwnApp(t *testing.T) {
	cases := []struct {
		name string
		app  *argocd.AppStatus
	}{
		{"production app", &argocd.AppStatus{Name: "acme-web", Health: "Healthy", SyncStatus: "Synced", DestNamespace: "acme"}},
		{"preview app in the preview namespace", &argocd.AppStatus{Name: "preview-acme-web", Health: "Healthy", SyncStatus: "Synced", DestNamespace: "acme-preview"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argo := &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{tc.app.Name: tc.app}}}
			w := getAs(t, statusRouter(t, argo), "/api/v1/status/acme/web", acmeUser)
			assertStatus(t, w, http.StatusOK)
			got, _ := decodeJSON(t, w)["argocd"].(map[string]interface{})
			if got == nil || got["name"] != tc.app.Name || got["health"] != "Healthy" {
				t.Fatalf("argocd = %v, want the tenant's own application %s", got, tc.app.Name)
			}
		})
	}
}

func TestServiceStatus_AbsentAppIsANote(t *testing.T) {
	argo := &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{}}}
	w := getAs(t, statusRouter(t, argo), "/api/v1/status/acme/web", acmeUser)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "ArgoCD application not found") {
		t.Fatalf("want the not-found note on a 404 from ArgoCD, got %s", w.Body.String())
	}
}

// TestServiceStatus_UnreadableOwnershipFailsClosed: anything that is not an
// observation of the application is an error, never "not found" and never a
// status.
func TestServiceStatus_UnreadableOwnershipFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		argo *scriptedArgo
	}{
		{"destination namespace missing", &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"acme-web": {Name: "acme-web", Health: "Healthy", SyncStatus: "Synced"},
		}}}},
		{"preview destination namespace missing", &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"preview-acme-web": {Name: "preview-acme-web", Health: "Healthy", SyncStatus: "Synced"},
		}}}},
		{"answer names another application", &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"acme-web": {Name: "acme-beta-web", Health: "Healthy", SyncStatus: "Synced", DestNamespace: "acme"},
		}}}},
		{"forbidden", &scriptedArgo{errs: map[string]error{"acme-web": fmt.Errorf("%w: denied", argocd.ErrForbidden)}}},
		{"transport failure", &scriptedArgo{errs: map[string]error{"acme-web": errors.New("argocd request failed: connection refused")}}},
		{"preview read fails after a 404", &scriptedArgo{errs: map[string]error{"preview-acme-web": errors.New("argocd returned 502")}}},
		{"unauthenticated", &scriptedArgo{errs: map[string]error{"acme-web": fmt.Errorf("%w: expired", argocd.ErrUnauthenticated)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := getAs(t, statusRouter(t, tc.argo), "/api/v1/status/acme/web", acmeUser)
			assertStatus(t, w, http.StatusServiceUnavailable)
			body := w.Body.String()
			if strings.Contains(body, "not found") || strings.Contains(body, "Healthy") {
				t.Errorf("unreadable ownership reported as absence or status: %s", body)
			}
		})
	}
}
