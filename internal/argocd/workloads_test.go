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
	"reflect"
	"strings"
	"testing"
)

func workloadServer(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/applications" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("project") != "" || r.URL.Query().Get("projects") != "" {
			t.Errorf("workload listing must not be limited to a project: %s", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.Query().Get("fields"), "items.spec.destination.namespace") {
			t.Errorf("fields=%q does not ask for the destination namespace", r.URL.Query().Get("fields"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "token")
}

func TestListWorkloads(t *testing.T) {
	c := workloadServer(t, http.StatusOK, `{"items":[
	  {"metadata":{"name":"acme-shared"},
	   "spec":{"project":"acme","destination":{"namespace":"acme"},"source":{"repoURL":"https://git.example.test/acme/apps","path":"shared"}},
	   "status":{"health":{"status":"Healthy"},"sync":{"status":"Synced"},
	     "summary":{"externalURLs":["http://b.example.test/","https://a.example.test/x","http://b.example.test/hooks","::bad::","c.example.test","d.example.test/path","e.example.test:8443/x"],"images":["bench:15"]}}},
	  {"metadata":{"name":"multi"},
	   "spec":{"project":"platform","destination":{"namespace":"acme"},"sources":[{"repoURL":"https://charts.example.test","path":""},{"repoURL":"https://git.example.test/values"}]},
	   "status":{}}
	]}`)

	got, err := c.ListWorkloads()
	if err != nil {
		t.Fatalf("ListWorkloads: %v", err)
	}
	want := []Workload{
		{Name: "acme-shared", Project: "acme", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced",
			Hosts: []string{"a.example.test", "b.example.test", "c.example.test", "d.example.test", "e.example.test"}, Images: []string{"bench:15"},
			SourceRepo: "https://git.example.test/acme/apps", SourcePath: "shared"},
		{Name: "multi", Project: "platform", DestNamespace: "acme", SourceRepo: "https://charts.example.test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestListWorkloads_EmptyListIsNotAnError(t *testing.T) {
	got, err := workloadServer(t, http.StatusOK, `{"items":[]}`).ListWorkloads()
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v; want an empty list and no error", got, err)
	}
}

// Every way of not observing the list is an error, never a shorter list.
func TestListWorkloads_FailedReadIsAnError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		is     error
	}{
		{"unauthenticated", http.StatusUnauthorized, `{}`, ErrUnauthenticated},
		{"forbidden", http.StatusForbidden, `{}`, ErrForbidden},
		{"server error", http.StatusBadGateway, `upstream`, nil},
		{"malformed body", http.StatusOK, `{"items":[`, nil},
		{"nameless item", http.StatusOK, `{"items":[{"metadata":{"name":"ok"}},{"spec":{"project":"acme"}}]}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := workloadServer(t, tc.status, tc.body).ListWorkloads()
			if err == nil {
				t.Fatalf("got %v and no error", got)
			}
			if got != nil {
				t.Errorf("got a partial list %v alongside the error", got)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err=%v, want it to wrap %v", err, tc.is)
			}
		})
	}
}
