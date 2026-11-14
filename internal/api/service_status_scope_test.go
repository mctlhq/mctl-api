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
	"slices"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// scriptedArgo answers from a per-name table of apps and errors the way
// ArgoCD 3.3 does (argo-cd server/application getAppEnforceRBAC): without a
// project a missing application is a 403, indistinguishable from a denied
// read; with a project it is a 404, and so is an application that lives in
// another project.
type scriptedArgo struct {
	fakeArgoCD
	errs  map[string]error
	asked []string
	// ignoreProject answers as if no project had been given in the query
	// beyond the 403-for-missing rule, standing in for a server that drops
	// the parameter.
	ignoreProject bool
}

func (s *scriptedArgo) GetAppStatus(name string) (*argocd.AppStatus, error) {
	s.asked = append(s.asked, "/"+name)
	if err, ok := s.errs[name]; ok {
		return nil, err
	}
	if _, ok := s.apps[name]; !ok {
		return nil, fmt.Errorf("%w: permission denied", argocd.ErrForbidden)
	}
	return s.fakeArgoCD.GetAppStatus(name)
}

func (s *scriptedArgo) GetProjectAppStatus(project, name string) (*argocd.AppStatus, error) {
	if project == "" {
		return s.GetAppStatus(name)
	}
	s.asked = append(s.asked, project+"/"+name)
	if err, ok := s.errs[name]; ok {
		return nil, err
	}
	if s.ignoreProject {
		return s.fakeArgoCD.GetAppStatus(name)
	}
	return s.fakeArgoCD.GetProjectAppStatus(project, name)
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
		Revision: "beta-secret-rev", Message: "beta internal message", Project: "apps", DestNamespace: "acme-beta"}
	foreignPreview := &argocd.AppStatus{Name: "preview-acme-beta-web", Health: "Degraded", SyncStatus: "OutOfSync",
		Revision: "beta-preview-rev", Project: "apps", DestNamespace: "acme-beta-preview"}
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
		{"production app", &argocd.AppStatus{Name: "acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps", DestNamespace: "acme"}},
		{"preview app in the preview namespace", &argocd.AppStatus{Name: "preview-acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps", DestNamespace: "acme-preview"}},
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

// TestServiceStatus_AbsentAppIsANote: missing in both legs. ArgoCD only
// says 404 when the read names the project; unscoped it says 403 for a
// missing application, which must not be what the handler relies on.
func TestServiceStatus_AbsentAppIsANote(t *testing.T) {
	cases := map[string]map[string]*argocd.AppStatus{
		"missing in both legs": {},
		// ArgoCD hides an application of another project behind a 404 when
		// the read names the project, so it is absent for this read.
		"exists only in another project": {
			"acme-web": {Name: "acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "erpact", DestNamespace: "acme"},
		},
	}
	for name, apps := range cases {
		t.Run(name, func(t *testing.T) {
			argo := &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: apps}}
			w := getAs(t, statusRouter(t, argo), "/api/v1/status/acme/web", acmeUser)
			assertStatus(t, w, http.StatusOK)
			if !strings.Contains(w.Body.String(), "ArgoCD application not found") || strings.Contains(w.Body.String(), "Healthy") {
				t.Fatalf("want the not-found note, got %s", w.Body.String())
			}
			want := []string{"apps/acme-web", "apps/preview-acme-web"}
			if !slices.Equal(argo.asked, want) {
				t.Errorf("reads = %v, want both legs scoped to the project: %v", argo.asked, want)
			}
		})
	}
}

// TestServiceStatus_MissingProdFallsThroughToPreview: the first leg's
// absence must be a 404, or the preview leg is never reached.
func TestServiceStatus_MissingProdFallsThroughToPreview(t *testing.T) {
	argo := &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
		"preview-acme-web": {Name: "preview-acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps", DestNamespace: "acme-preview"},
	}}}
	w := getAs(t, statusRouter(t, argo), "/api/v1/status/acme/web", acmeUser)
	assertStatus(t, w, http.StatusOK)
	got, _ := decodeJSON(t, w)["argocd"].(map[string]interface{})
	if got == nil || got["name"] != "preview-acme-web" {
		t.Fatalf("argocd = %v, want the preview application after a 404 on acme-web", got)
	}
	if want := []string{"apps/acme-web", "apps/preview-acme-web"}; !slices.Equal(argo.asked, want) {
		t.Errorf("reads = %v, want %v", argo.asked, want)
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
			"acme-web": {Name: "acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps"},
		}}}},
		{"preview destination namespace missing", &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"preview-acme-web": {Name: "preview-acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps"},
		}}}},
		{"answer names another application", &scriptedArgo{fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"acme-web": {Name: "acme-beta-web", Health: "Healthy", SyncStatus: "Synced", Project: "apps", DestNamespace: "acme"},
		}}}},
		{"answer is from another project", &scriptedArgo{ignoreProject: true, fakeArgoCD: fakeArgoCD{apps: map[string]*argocd.AppStatus{
			"acme-web": {Name: "acme-web", Health: "Healthy", SyncStatus: "Synced", Project: "erpact", DestNamespace: "acme"},
		}}}},
		{"forbidden on the preview read", &scriptedArgo{errs: map[string]error{"preview-acme-web": fmt.Errorf("%w: denied", argocd.ErrForbidden)}}},
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
