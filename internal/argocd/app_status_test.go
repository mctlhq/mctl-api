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

package argocd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetAppStatusReadsDestinationNamespace: the destination namespace is
// what ties an application to a tenant (GetServiceStatus refuses an answer
// without one), and it is not metadata.namespace, where the Application
// object itself lives.
func TestGetAppStatusReadsDestinationNamespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/applications/acme-web" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
		"metadata": {"name": "acme-web", "namespace": "argocd"},
		"spec": {"project": "acme", "destination": {"server": "https://kubernetes.default.svc", "namespace": "acme"}},
		"status": {"health": {"status": "Healthy"}, "sync": {"status": "Synced", "revision": "abc"}}
	}`))
	}))
	t.Cleanup(srv.Close)
	got, err := NewClient(srv.URL, "token").GetAppStatus("acme-web")
	if err != nil {
		t.Fatalf("GetAppStatus: %v", err)
	}
	if got.DestNamespace != "acme" {
		t.Errorf("DestNamespace = %q, want %q", got.DestNamespace, "acme")
	}
	if got.Namespace != "argocd" {
		t.Errorf("Namespace = %q, want the Application's own namespace %q", got.Namespace, "argocd")
	}
}

// TestGetProjectAppStatusNamesTheProject: ArgoCD answers 404 for a missing
// application only when the read names the project; without it the answer
// is 403. The project must reach the query, and the 404 must come back as
// ErrNotFound while a 403 stays ErrForbidden.
func TestGetProjectAppStatusNamesTheProject(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		switch {
		case r.URL.Query().Get("projects") == "":
			http.Error(w, `{"code":7,"message":"permission denied"}`, http.StatusForbidden)
		case r.URL.Path == "/api/v1/applications/denied":
			http.Error(w, `{"code":7,"message":"permission denied"}`, http.StatusForbidden)
		default:
			http.Error(w, `{"code":5,"message":"applications.argoproj.io \"missing\" not found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, "token")

	_, err := c.GetProjectAppStatus("apps", "missing")
	if gotQuery != "projects=apps" {
		t.Errorf("query = %q, want projects=apps", gotQuery)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("missing application in a named project: err = %v, want ErrNotFound", err)
	}
	if _, err := c.GetProjectAppStatus("apps", "denied"); !errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
		t.Errorf("denied read: err = %v, want ErrForbidden only", err)
	}
	if _, err := c.GetAppStatus("missing"); !errors.Is(err, ErrForbidden) {
		t.Errorf("unscoped read of a missing application: err = %v, want ErrForbidden (what ArgoCD answers)", err)
	}
	if gotQuery != "" {
		t.Errorf("unscoped read sent query %q", gotQuery)
	}
}
