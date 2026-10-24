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
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/k8s"
)

type stubPreviewLister struct {
	items []k8s.PreviewRelease
	err   error
}

func (s stubPreviewLister) ListPreviewReleases(context.Context, string, string) ([]k8s.PreviewRelease, error) {
	return s.items, s.err
}

func callListPreviews(l PreviewLister, url string, user *auth.User) *httptest.ResponseRecorder {
	h := &Handlers{opts: Options{}}
	if l != nil {
		h.opts.PreviewLister = l
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if user != nil {
		req = req.WithContext(auth.WithUser(req.Context(), user))
	}
	rec := httptest.NewRecorder()
	h.ListPreviews(rec, req)
	return rec
}

func TestListPreviewsFailClosed(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"labs"})
	for name, l := range map[string]PreviewLister{
		"nil":    nil,
		"failed": stubPreviewLister{err: errors.New("forbidden")},
	} {
		rec := callListPreviews(l, "/api/v1/previews?team=labs", u)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: code %d", name, rec.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if _, ok := body["count"]; ok {
			t.Fatalf("%s: count present", name)
		}
		if _, ok := body["items"]; ok {
			t.Fatalf("%s: items present", name)
		}
	}
}

func TestListPreviewsFailureHidesTheKubernetesError(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"labs"})
	k8sErr := errors.New(`deployments.apps is forbidden: User "system:serviceaccount:mctl-api:mctl-api" cannot list resource "deployments"`)
	rec := callListPreviews(stubPreviewLister{err: k8sErr}, "/api/v1/previews?team=labs", u)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"serviceaccount", "forbidden", "deployments"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "could not list previews in labs-preview") {
		t.Fatalf("response lost the namespace: %s", body)
	}
}

func TestListPreviewsResults(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"labs"})
	rec := callListPreviews(stubPreviewLister{err: k8s.ErrNamespaceAbsent}, "/api/v1/previews?team=labs", u)
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["count"] != float64(0) || body["preview_namespace"] != "absent" {
		t.Fatalf("absent: %d %v", rec.Code, body)
	}
	rec = callListPreviews(stubPreviewLister{items: []k8s.PreviewRelease{{Release: "preview-a-b1"}}}, "/api/v1/previews?team=labs", u)
	body = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["count"] != float64(1) || body["preview_namespace"] != "present" {
		t.Fatalf("ok: %d %v", rec.Code, body)
	}
}

func TestListPreviewsGuards(t *testing.T) {
	l := stubPreviewLister{}
	if c := callListPreviews(l, "/api/v1/previews?team=labs", nil).Code; c != 401 {
		t.Fatalf("401: %d", c)
	}
	u := auth.NewGitHubUser("u1", []string{"labs"})
	if c := callListPreviews(l, "/api/v1/previews", u).Code; c != 400 {
		t.Fatalf("400: %d", c)
	}
	if c := callListPreviews(l, "/api/v1/previews?team=other", u).Code; c != 403 {
		t.Fatalf("403: %d", c)
	}
}
