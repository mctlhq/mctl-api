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

func swServer(t *testing.T, status int, body string, gotPath, gotQuery *string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotPath != nil {
			*gotPath = r.URL.Path
		}
		if gotQuery != nil {
			*gotQuery = r.URL.RawQuery
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "token")
}

func TestGetProjectSyncWindowsReadsWindows(t *testing.T) {
	var path string
	c := swServer(t, 200, `{"windows":[{"kind":"deny","schedule":"0 22 * * *","duration":"8h","timeZone":"UTC","applications":["admins-*"],"manualSync":true}]}`, &path, nil)
	got, err := c.GetProjectSyncWindows("default")
	if err != nil {
		t.Fatalf("GetProjectSyncWindows: %v", err)
	}
	if path != "/api/v1/projects/default/syncwindows" {
		t.Errorf("path = %q", path)
	}
	if got.Project != "default" || len(got.Windows) != 1 {
		t.Fatalf("got %+v", got)
	}
	w := got.Windows[0]
	if w.Kind != "deny" || w.Schedule != "0 22 * * *" || w.Duration != "8h" || !w.ManualSync || w.Applications[0] != "admins-*" {
		t.Errorf("window = %+v", w)
	}
}

// A project with no windows answers 200 with the key absent (omitempty) or
// null: that is empty, and must come back as [] rather than nil.
func TestGetProjectSyncWindowsEmptyIsEmptyList(t *testing.T) {
	for _, body := range []string{`{}`, `{"windows":null}`, `{"windows":[]}`} {
		got, err := swServer(t, 200, body, nil, nil).GetProjectSyncWindows("default")
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got.Windows == nil || len(got.Windows) != 0 {
			t.Errorf("%s: Windows = %#v, want empty non-nil", body, got.Windows)
		}
	}
}

// Could not observe is never observed absent: a body that is not the
// expected object, or a windows value that is not a list, is an error.
func TestGetProjectSyncWindowsBadBodyIsError(t *testing.T) {
	for _, body := range []string{``, `<html>502</html>`, `[]`, `{"windows":"none"}`, `{"windows":{"a":1}}`} {
		if _, err := swServer(t, 200, body, nil, nil).GetProjectSyncWindows("default"); err == nil {
			t.Errorf("body %q: want an error, got none", body)
		}
	}
}

func TestGetProjectSyncWindowsErrorsKeepTheirKind(t *testing.T) {
	if _, err := swServer(t, 403, `{"error":"permission denied"}`, nil, nil).GetProjectSyncWindows("default"); !errors.Is(err, ErrForbidden) {
		t.Errorf("403: err = %v, want ErrForbidden", err)
	}
	if _, err := swServer(t, 404, `{"error":"not found"}`, nil, nil).GetProjectSyncWindows("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: err = %v, want ErrNotFound", err)
	}
	if _, err := NewClient("http://x", "t").GetProjectSyncWindows(""); err == nil {
		t.Error("empty project: want an error")
	}
}

func TestGetAppSyncWindowsReadsState(t *testing.T) {
	var path, query string
	c := swServer(t, 200, `{"activeWindows":[{"kind":"deny","schedule":"0 22 * * *","duration":"8h","manualSync":false}],"assignedWindows":[{"kind":"deny","schedule":"0 22 * * *","duration":"8h","manualSync":false}],"canSync":false}`, &path, &query)
	got, err := c.GetAppSyncWindows("admins", "admins-mctl-api")
	if err != nil {
		t.Fatalf("GetAppSyncWindows: %v", err)
	}
	if path != "/api/v1/applications/admins-mctl-api/syncwindows" || query != "projects=admins" {
		t.Errorf("path=%q query=%q", path, query)
	}
	if got.CanSync || len(got.ActiveWindows) != 1 || len(got.AssignedWindows) != 1 {
		t.Errorf("got %+v", got)
	}
}

// canSync is a required proto field the server always sends. Absent is a
// failed read: defaulting it to false would claim "blocked" (or, flipped,
// "allowed") that nobody observed.
func TestGetAppSyncWindowsMissingCanSyncIsError(t *testing.T) {
	for _, body := range []string{`{}`, `{"activeWindows":[],"assignedWindows":[]}`, `<html/>`, ``} {
		if _, err := swServer(t, 200, body, nil, nil).GetAppSyncWindows("p", "a"); err == nil {
			t.Errorf("body %q: want an error, got none", body)
		}
	}
	got, err := swServer(t, 200, `{"canSync":true}`, nil, nil).GetAppSyncWindows("p", "a")
	if err != nil {
		t.Fatalf("canSync only: %v", err)
	}
	if !got.CanSync || got.ActiveWindows == nil || got.AssignedWindows == nil {
		t.Errorf("got %+v, want canSync true and non-nil empty lists", got)
	}
}
