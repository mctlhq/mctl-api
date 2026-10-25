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

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
)

// The build workflow's binding check (GET /api/v1/ci/build-repo-binding).

const (
	buildBindingPath  = "/api/v1/ci/build-repo-binding"
	buildImageWfRef   = "mctlhq/mctl-gitops/.github/workflows/build-image.yaml@refs/heads/main"
	buildBindingQuery = "?team=acme&repo=Acme/private-app"
)

type bindingPortal struct {
	handler http.HandlerFunc
	calls   atomic.Int32
	auth    atomic.Value
	query   atomic.Value
}

func newBindingRouter(t *testing.T, handler http.HandlerFunc) (http.Handler, *bindingPortal) {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	p := &bindingPortal{handler: handler}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		p.auth.Store(r.Header.Get("Authorization"))
		p.query.Store(r.URL.Path + "?" + r.URL.RawQuery)
		p.handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return mctlapi.NewRouter(mctlapi.Options{
		BackstageInternalURL:           srv.URL,
		BackstageGithubAppConnectToken: "gac-token",
		GitReader:                      &fakeGitReader{},
	}), p
}

func buildWorkflowUser() *auth.User {
	return auth.NewCIJobUser("mctlhq/mctl-gitops", "3003", buildImageWfRef)
}

func TestCIBuildBinding_AnswersTheBindingToTheBuildWorkflow(t *testing.T) {
	for _, bound := range []bool{true, false} {
		router, portal := newBindingRouter(t, bindingAnswer(bound))
		w := getAs(t, router, buildBindingPath+buildBindingQuery, buildWorkflowUser())
		if w.Code != http.StatusOK {
			t.Fatalf("bound=%v: status %d: %s", bound, w.Code, w.Body.String())
		}
		var got struct {
			Team  string `json:"team"`
			Repo  string `json:"repo"`
			Bound *bool  `json:"bound"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Team != "acme" || got.Repo != "Acme/private-app" || got.Bound == nil || *got.Bound != bound {
			t.Fatalf("bound=%v: got %+v", bound, got)
		}
		if portal.auth.Load() != "Bearer gac-token" {
			t.Fatalf("portal saw Authorization %q", portal.auth.Load())
		}
		want := "/api/github-app-connect/repo-binding?" + url.Values{"team": {"acme"}, "repo": {"Acme/private-app"}}.Encode()
		if portal.query.Load() != want {
			t.Fatalf("portal asked %q, want %q", portal.query.Load(), want)
		}
	}
}

func TestCIBuildBinding_OnlyTheBuildWorkflowMayAsk(t *testing.T) {
	admin := &auth.User{ID: "admin", Groups: []string{"admins"}}
	cases := map[string]*auth.User{
		"no workflow ref":                       auth.NewCIUser("mctlhq/mctl-gitops", "3003"),
		"another gitops workflow":               auth.NewCIJobUser("mctlhq/mctl-gitops", "3003", "mctlhq/mctl-gitops/.github/workflows/gitops-bump.yaml@refs/heads/main"),
		"build-image off main":                  auth.NewCIJobUser("mctlhq/mctl-gitops", "3003", "mctlhq/mctl-gitops/.github/workflows/build-image.yaml@refs/heads/feature"),
		"same file elsewhere":                   auth.NewCIJobUser("mctlhq/mctl-telegram", "1001", "mctlhq/mctl-telegram/.github/workflows/build-image.yaml@refs/heads/main"),
		"reusable call from another repository": auth.NewCIJobUser("mctlhq/mctl-telegram", "1001", buildImageWfRef),
		"a platform admin":                      admin,
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			router, portal := newBindingRouter(t, bindingAnswer(true))
			w := getAs(t, router, buildBindingPath+buildBindingQuery, u)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
			}
			if portal.calls.Load() != 0 {
				t.Fatal("the portal was asked for a refused caller")
			}
		})
	}
}

func TestCIBuildBinding_LookupFailureIsNotUnbound(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"portal 500": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"no verdict": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"team":"acme","repo":"Acme/private-app"}`))
		},
		"other team": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"team":"labs","repo":"Acme/private-app","bound":true}`))
		},
		"not json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newBindingRouter(t, h)
			w := getAs(t, router, buildBindingPath+buildBindingQuery, buildWorkflowUser())
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCIBuildBinding_RefusesMalformedQueries(t *testing.T) {
	for _, q := range []string{
		"",
		"?team=acme",
		"?repo=Acme/private-app",
		"?team=Acme&repo=Acme/private-app",
		"?team=acme&repo=private-app",
		"?team=acme&repo=Acme/..",
		"?team=acme&repo=a/b&repo=c/d",
		"?team=acme&team=labs&repo=a/b",
	} {
		router, portal := newBindingRouter(t, bindingAnswer(true))
		w := getAs(t, router, buildBindingPath+q, buildWorkflowUser())
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d, want 400: %s", q, w.Code, w.Body.String())
		}
		if portal.calls.Load() != 0 {
			t.Fatalf("%q: the portal was asked", q)
		}
	}
}

func TestCIBuildBinding_GateStillConfinesTheWorkflow(t *testing.T) {
	router, _ := newBindingRouter(t, bindingAnswer(true))
	u := buildWorkflowUser()
	for _, w := range []*httptest.ResponseRecorder{
		getAs(t, router, "/api/v1/whoami", u),
		getAs(t, router, "/api/v1/tenants", u),
		postAs(t, router, buildBindingPath+buildBindingQuery, nil, u),
	} {
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
		}
	}
}
