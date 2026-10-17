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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
)

const workspacePID = "prn_01M39HRB7JRXZ2PHW5VVB695YZ"

type workspacePrincipal struct{ err error }

type workspaceAuthzSource struct{ err error }

func (s workspaceAuthzSource) PrincipalTenants(string) ([]string, []string, error) {
	return []string{"acme"}, nil, s.err
}

func (p workspacePrincipal) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return workspacePID, nil
}
func (p workspacePrincipal) CheckPrincipal(context.Context, string) error { return p.err }

type workspaceQuota struct {
	missing string
	failed  string
}

func (q workspaceQuota) GetNamespaceUsage(_ context.Context, ns string) (map[string]string, map[string]string, error) {
	if q.failed == ns {
		return nil, nil, errors.New("quota unavailable")
	}
	if q.missing == ns {
		return nil, nil, nil
	}
	return nil, map[string]string{"requests.cpu": "1", "limits.cpu": "2", "requests.memory": "2Gi", "limits.memory": "3Gi", "pods": "10"}, nil
}

type workspaceArgo struct{ apps map[string]*argocd.AppStatus }

func (a *workspaceArgo) GetAppStatus(name string) (*argocd.AppStatus, error) {
	app, ok := a.apps[name]
	if !ok {
		return nil, errors.New("not read")
	}
	return app, nil
}
func (a *workspaceArgo) ListApps(string) ([]argocd.AppStatus, error) {
	return nil, errors.New("unused")
}
func (a *workspaceArgo) ListWorkloads() ([]argocd.Workload, error) { return nil, errors.New("unused") }

func workspaceOptions() Options {
	return Options{
		Principals:          workspacePrincipal{},
		PrincipalMembership: &stubPrincipalMembership{namespaces: []string{"acme"}, roles: map[string][][]string{"acme": {{"owner"}}}},
		ArgoCD:              &workspaceArgo{apps: map[string]*argocd.AppStatus{"tenant-acme": {Name: "tenant-acme", Health: "Healthy", SyncStatus: "Synced"}}},
		QuotaReader:         workspaceQuota{},
		SurfaceZitadel:      &SurfaceZitadelOptions{SigninClientID: "portal", CustomersOrgID: "customers"},
		TenantAuthzMode:     TenantAuthzShadow,
	}
}

func observeWorkspace(t *testing.T, opts Options, user *auth.User, actor, tenant string) (int, WorkspaceAccess) {
	t.Helper()
	opts.AuthMiddleware = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), user)))
		})
	}
	r := httptest.NewRequest("GET", "/api/v1/surface-principals/workspace-access/"+tenant, nil)
	if actor != "" {
		r.Header.Set(SurfaceActorHeader, actor)
	}
	w := httptest.NewRecorder()
	NewRouter(opts).ServeHTTP(w, r)
	var result WorkspaceAccess
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("observation was cacheable")
		}
	}
	return w.Code, result
}

func TestWorkspaceAccessReadyDoesNotEnableCustomerMCP(t *testing.T) {
	code, got := observeWorkspace(t, workspaceOptions(), auth.NewSurfaceUser("portal"), "principal:"+workspacePID, "acme")
	if code != 200 || got.Infrastructure != "ready" || got.Role != "owner" || got.Portal != "configured" || got.MCP != "blocked" || len(got.Environments) != 2 || got.ObservedAt == "" || got.PrincipalID != workspacePID {
		t.Fatalf("observation: %d %+v", code, got)
	}
}

func TestWorkspaceAccessMCPRequiresLaunchedAndConfiguredPrincipalAuthorization(t *testing.T) {
	for _, mode := range []TenantAuthzMode{TenantAuthzLegacy, TenantAuthzShadow, TenantAuthzPrincipal} {
		t.Run(string(mode), func(t *testing.T) {
			o := workspaceOptions()
			o.TenantAuthzMode = mode
			o.PrincipalAuthz = &auth.PrincipalAuthz{Members: workspaceAuthzSource{}}
			o.OAuthServer = &auth.OAuthServer{}
			o.OAuthUpstream = OAuthUpstreamZitadel
			o.OAuthZitadel = &OAuthZitadelOptions{Issuer: "https://auth.example", ClientID: "api", CustomersOrgID: "customers"}
			code, got := observeWorkspace(t, o, auth.NewSurfaceUser("portal"), "principal:"+workspacePID, "acme")
			want := "blocked"
			if mode == TenantAuthzPrincipal {
				want = "available"
			}
			if code != 200 || got.MCP != want {
				t.Fatalf("got %d %+v, want MCP %s", code, got, want)
			}
		})
	}
}

func TestWorkspaceAccessRefusesForeignOrDisabledPrincipal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"foreign", func(o *Options) { o.PrincipalMembership = &stubPrincipalMembership{namespaces: []string{"other"}} }},
		{"disabled", func(o *Options) { o.Principals = workspacePrincipal{err: auth.ErrPrincipalDisabled} }},
		{"missing", func(o *Options) { o.Principals = workspacePrincipal{err: auth.ErrIdentityRefused} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := workspaceOptions()
			tc.mutate(&o)
			code, _ := observeWorkspace(t, o, auth.NewSurfaceUser("portal"), "principal:"+workspacePID, "acme")
			if code != 403 {
				t.Fatalf("got %d", code)
			}
		})
	}
}

func TestWorkspaceAccessFailedReadsStayUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"no membership source", func(o *Options) { o.PrincipalMembership = nil }},
		{"busy snapshot", func(o *Options) { o.PrincipalMembership = &stubPrincipalMembership{busy: true} }},
		{"partial snapshot", func(o *Options) {
			o.PrincipalMembership = &stubPrincipalMembership{namespaces: []string{"acme"}, unreadable: []string{"broken"}}
		}},
		{"failed snapshot", func(o *Options) {
			o.PrincipalMembership = &stubPrincipalMembership{namespaces: []string{"acme"}, err: errors.New("failed")}
		}},
		{"failed role", func(o *Options) { o.PrincipalMembership.(*stubPrincipalMembership).rolesErr = errors.New("failed") }},
		{"malformed role", func(o *Options) {
			o.PrincipalMembership.(*stubPrincipalMembership).roles["acme"] = [][]string{{"unknown"}}
		}},
		{"failed principal read", func(o *Options) { o.Principals = workspacePrincipal{err: errors.New("db down")} }},
		{"failed app", func(o *Options) { o.ArgoCD = &workspaceArgo{} }},
		{"nil app", func(o *Options) { o.ArgoCD.(*workspaceArgo).apps["tenant-acme"] = nil }},
		{"unknown app", func(o *Options) { o.ArgoCD.(*workspaceArgo).apps["tenant-acme"].Health = "Unknown" }},
		{"failed preview quota", func(o *Options) { o.QuotaReader = workspaceQuota{failed: "acme-preview"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := workspaceOptions()
			tc.mutate(&o)
			code, _ := observeWorkspace(t, o, auth.NewSurfaceUser("portal"), "principal:"+workspacePID, "acme")
			if code != 503 {
				t.Fatalf("got %d, want unknown", code)
			}
		})
	}
}

func TestWorkspaceAccessUnconvergedIsPending(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"missing preview quota", func(o *Options) { o.QuotaReader = workspaceQuota{missing: "acme-preview"} }},
		{"degraded app", func(o *Options) { o.ArgoCD.(*workspaceArgo).apps["tenant-acme"].Health = "Degraded" }},
		{"out of sync", func(o *Options) { o.ArgoCD.(*workspaceArgo).apps["tenant-acme"].SyncStatus = "OutOfSync" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := workspaceOptions()
			tc.mutate(&o)
			code, got := observeWorkspace(t, o, auth.NewSurfaceUser("portal"), "principal:"+workspacePID, "acme")
			if code != 200 || got.Infrastructure != "pending" {
				t.Fatalf("got %d %+v", code, got)
			}
		})
	}
}

func TestWorkspaceAccessPortalOnlyAndValidatesActor(t *testing.T) {
	for _, user := range []*auth.User{auth.NewSurfaceUser("telegram"), auth.NewServiceUser()} {
		code, _ := observeWorkspace(t, workspaceOptions(), user, "", "acme")
		if code != 403 && code != 400 {
			t.Fatalf("non-portal reached observer: %d", code)
		}
	}
	for _, actor := range []string{"", workspacePID, "principal:bad", "github:octocat"} {
		code, _ := observeWorkspace(t, workspaceOptions(), auth.NewSurfaceUser("portal"), actor, "acme")
		if code != 400 {
			t.Fatalf("actor %q: %d", actor, code)
		}
	}
}
