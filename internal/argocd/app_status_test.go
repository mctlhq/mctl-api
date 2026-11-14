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
