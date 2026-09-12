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

package ghactions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestDispatcher(t *testing.T, handler http.HandlerFunc) (*Dispatcher, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	return &Dispatcher{Token: "t0ken", BaseURL: srv.URL, HTTP: srv.Client()}, srv.Close
}

func TestDispatch_SendsTheDocumentedRequest(t *testing.T) {
	var gotPath, gotAuth, gotAPIVersion string
	var gotBody map[string]interface{}
	d, closeSrv := newTestDispatcher(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAPIVersion = r.Header.Get("X-GitHub-Api-Version")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeSrv()

	if err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "cloudflare-apply.yml", "main", nil); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if want := "/repos/mctlhq/mctl-gitops/actions/workflows/cloudflare-apply.yml/dispatches"; gotPath != want {
		t.Errorf("path %q, want %q", gotPath, want)
	}
	if gotAuth != "Bearer t0ken" {
		t.Errorf("authorization header %q", gotAuth)
	}
	if gotAPIVersion != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version %q", gotAPIVersion)
	}
	if gotBody["ref"] != "main" {
		t.Errorf("body ref %v, want main", gotBody["ref"])
	}
	// Absent, not an empty object: GitHub rejects `inputs` naming anything
	// the workflow does not declare, and this workflow declares none.
	if _, ok := gotBody["inputs"]; ok {
		t.Errorf("body carries an inputs key for a call that passed none: %v", gotBody)
	}
}

// The handler's own test asserts inputs against a FAKE dispatcher, so it
// passes even if Dispatch silently dropped them. This is the same claim
// against the real HTTP body -- and it is not a formality: the root is what
// tells cloudflare-apply.yml which OpenTofu root to apply. A dropped input on
// a workflow that defaulted `root` would start an apply against a different
// Cloudflare root and still answer 202.
func TestDispatch_InputsReachTheRequestBody(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d := &Dispatcher{Token: "t0ken", BaseURL: srv.URL}
	err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "cloudflare-apply.yml", "main",
		map[string]string{"root": "infrastructure/cloudflare/portal"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	inputs, ok := gotBody["inputs"].(map[string]interface{})
	if !ok {
		t.Fatalf("body carries no inputs object: %v", gotBody)
	}
	if got := inputs["root"]; got != "infrastructure/cloudflare/portal" {
		t.Errorf("inputs.root = %v, want infrastructure/cloudflare/portal", got)
	}
}

// The guard is an allowlist because the denylist it replaced ("/?#%") let
// through exactly the two values a traversal needs.
func TestDispatch_RejectsRelativePathSegments(t *testing.T) {
	// BaseURL points at a closed port, so anything that gets PAST the guard
	// fails with a connection error. Asserting "some error" would therefore
	// pass even with the guard removed -- caught by mutation: restoring the
	// old denylist left this test green. The assertion is on the validation
	// error specifically.
	d := &Dispatcher{Token: "t0ken", BaseURL: "http://127.0.0.1:1"}
	for _, bad := range []string{"..", ".", "", "a/b", "a?b", "a#b", "a%2e", "a b", "a..b/../c"} {
		err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", bad, "main", nil)
		if err == nil {
			t.Errorf("workflow %q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "invalid workflow") {
			t.Errorf("workflow %q reached the network instead of the guard: %v", bad, err)
		}
	}
	// A ref with a slash is ordinary -- it rides in the JSON body, not the
	// path -- and rejecting it would break the dispatcher for most branch
	// names. Asserted against the guard, not against the network.
	for _, ref := range []string{"feature/some-branch", "refs/heads/main", "v1.2.3"} {
		err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "w.yml", ref, nil)
		if err != nil && strings.Contains(err.Error(), "invalid ref") {
			t.Errorf("ref %q was rejected by the guard: %v", ref, err)
		}
	}
	if err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "w.yml", "", nil); err == nil ||
		!strings.Contains(err.Error(), "invalid ref") {
		t.Errorf("an empty ref was not refused: %v", err)
	}

	// A dot INSIDE a segment is ordinary and must stay legal, or no workflow
	// file name and no semver ref would pass.
	for _, good := range []string{"cloudflare-apply.yml", "v1.2.3", "release-please--branches--main"} {
		err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", good, "main", nil)
		if err != nil && strings.Contains(err.Error(), "invalid") {
			t.Errorf("workflow %q was rejected by the guard: %v", good, err)
		}
	}
}

func TestDispatch_NoTokenIsErrNotConfigured(t *testing.T) {
	d := &Dispatcher{BaseURL: "http://127.0.0.1:1"}
	err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "w.yml", "main", nil)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
	// And a nil receiver, which is what an unconfigured optional dependency
	// degrades to at the call site.
	var nilD *Dispatcher
	if err := nilD.Dispatch(context.Background(), "o", "r", "w.yml", "main", nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil dispatcher: want ErrNotConfigured, got %v", err)
	}
}

// Every value in this table is interpolated into the URL path. Nothing
// reaches them from a request today, but the check is here rather than at
// the one caller so a later caller that does forward input cannot walk out
// of the path. `ref` is deliberately absent: it travels in the JSON body,
// so "main#frag" is a ref GitHub will reject, not a path escape -- and
// path-validating it would refuse every branch name with a slash in it.
func TestDispatch_RejectsSegmentsThatWouldEscapeThePath(t *testing.T) {
	reached := false
	d, closeSrv := newTestDispatcher(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	defer closeSrv()

	for _, bad := range []struct{ owner, repo, wf, ref string }{
		{"../admin", "mctl-gitops", "w.yml", "main"},
		{"mctlhq", "mctl-gitops/../other", "w.yml", "main"},
		{"mctlhq", "mctl-gitops", "w.yml?x=1", "main"},
		{"mctlhq", "mctl-gitops", "w.yml#frag", "main"},
		{"", "mctl-gitops", "w.yml", "main"},
	} {
		if err := d.Dispatch(context.Background(), bad.owner, bad.repo, bad.wf, bad.ref, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if reached {
		t.Error("a rejected segment still produced a request")
	}
}

// A token without actions:write gets 404, not 403 — the same answer as a
// workflow file that is not there. An operator reading only the status would
// chase the wrong one, so the error says both.
func TestDispatch_404NamesBothCauses(t *testing.T) {
	d, closeSrv := newTestDispatcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	defer closeSrv()

	err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "cloudflare-apply.yml", "main", nil)
	if err == nil {
		t.Fatal("expected an error for 404")
	}
	if !strings.Contains(err.Error(), "actions:write") {
		t.Errorf("404 error does not mention the permission cause: %v", err)
	}
}

func TestDispatch_OtherStatusIsAnError(t *testing.T) {
	d, closeSrv := newTestDispatcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Workflow does not have 'workflow_dispatch' trigger"}`))
	})
	defer closeSrv()

	err := d.Dispatch(context.Background(), "mctlhq", "mctl-gitops", "cloudflare-apply.yml", "main", nil)
	if err == nil || !strings.Contains(err.Error(), "422") {
		t.Fatalf("want an error naming 422, got %v", err)
	}
	// The token must not travel in the message. It is only ever a header, so
	// this is a regression guard on that staying true.
	if strings.Contains(err.Error(), "t0ken") {
		t.Errorf("error text carries the token: %v", err)
	}
}
