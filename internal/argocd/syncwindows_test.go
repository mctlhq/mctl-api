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

func projectBody(name, spec string) string {
	return `{"metadata":{"name":"` + name + `"},"spec":` + spec + `}`
}

// The windows come from the project's spec.syncWindows, not from the
// /syncwindows endpoint, which answers only the windows in effect right now.
func TestGetProjectSyncWindowsReadsConfiguredWindows(t *testing.T) {
	var path string
	c := swServer(t, 200, projectBody("default", `{"sourceRepos":["*"],"syncWindows":[{"kind":"deny","schedule":"0 22 * * *","duration":"8h","timeZone":"UTC","applications":["admins-*"],"manualSync":true}]}`), &path, nil)
	got, err := c.GetProjectSyncWindows("default")
	if err != nil {
		t.Fatalf("GetProjectSyncWindows: %v", err)
	}
	if path != "/api/v1/projects/default" {
		t.Errorf("path = %q, want the project itself, not its /syncwindows", path)
	}
	if got.Project != "default" || len(got.Windows) != 1 {
		t.Fatalf("got %+v", got)
	}
	w := got.Windows[0]
	if w.Kind != "deny" || w.Schedule != "0 22 * * *" || w.Duration != "8h" || !w.ManualSync || w.Applications[0] != "admins-*" {
		t.Errorf("window = %+v", w)
	}
}

// The case that was wrong: a window configured and closed right now. The old
// endpoint answered `[]`; the project holds it.
func TestGetProjectSyncWindowsSeesAClosedWindow(t *testing.T) {
	got, err := swServer(t, 200, projectBody("apps", `{"syncWindows":[{"kind":"deny","schedule":"0 3 * * 0","duration":"1h","applications":["labs-portfolio"]}]}`), nil, nil).GetProjectSyncWindows("apps")
	if err != nil || len(got.Windows) != 1 || got.Windows[0].Applications[0] != "labs-portfolio" || got.Windows[0].Schedule != "0 3 * * 0" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// A project whose spec carries no syncWindows (key absent or null, as Argo CD
// omits it) has none configured: [] rather than nil.
func TestGetProjectSyncWindowsEmptyIsEmptyList(t *testing.T) {
	for _, spec := range []string{`{}`, `{"sourceRepos":["*"]}`, `{"syncWindows":null}`, `{"syncWindows":[]}`} {
		got, err := swServer(t, 200, projectBody("default", spec), nil, nil).GetProjectSyncWindows("default")
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if got.Windows == nil || len(got.Windows) != 0 {
			t.Errorf("%s: Windows = %#v, want empty non-nil", spec, got.Windows)
		}
	}
}

// Could not observe is never observed absent: a body that is not the project
// asked for, has no spec, or has syncWindows that is not a list is an error.
func TestGetProjectSyncWindowsBadBodyIsError(t *testing.T) {
	for name, body := range map[string]string{
		"empty":                ``,
		"html":                 `<html>502</html>`,
		"a list":               `[]`,
		"no metadata":          `{"spec":{}}`,
		"another project":      projectBody("platform", `{}`),
		"no spec":              `{"metadata":{"name":"default"}}`,
		"null spec":            `{"metadata":{"name":"default"},"spec":null}`,
		"windows is a string":  projectBody("default", `{"syncWindows":"none"}`),
		"windows is an object": projectBody("default", `{"syncWindows":{"a":1}}`),
		"the old answer shape": `{"windows":[]}`,
	} {
		if _, err := swServer(t, 200, body, nil, nil).GetProjectSyncWindows("default"); err == nil {
			t.Errorf("%s (%q): want an error, got none", name, body)
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
	if path != "/api/v1/applications/admins-mctl-api/syncwindows" || query != "project=admins" {
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
