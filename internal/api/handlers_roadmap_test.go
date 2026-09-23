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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/roadmap"
)

type roadmapDirSource struct{ dir string }

func (s roadmapDirSource) Revision() (string, error) { return "0123abc", nil }
func (s roadmapDirSource) ReadFiles(names ...string) (map[string][]byte, string, error) {
	out := map[string][]byte{}
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(s.dir, n)) //nolint:gosec // test fixture directory
		if err != nil {
			return nil, "", err
		}
		out[n] = data
	}
	return out, "0123abc", nil
}

func roadmapRouter(h *Handlers) chi.Router {
	r := chi.NewRouter()
	r.Get("/api/v1/roadmap/epics", h.ListRoadmapEpics)
	r.Get("/api/v1/roadmap/epic-status", h.GetRoadmapEpicStatus)
	r.Get("/api/v1/roadmap/ready", h.GetRoadmapReadyWorkItems)
	return r
}

func roadmapGet(t *testing.T, h *Handlers, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(auth.WithUser(req.Context(), auth.NewGitHubUser("alice", []string{"acme"})))
	rec := httptest.NewRecorder()
	roadmapRouter(h).ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func liveRoadmapHandlers() *Handlers {
	src := roadmapDirSource{dir: filepath.Join("..", "roadmap", "testdata", "live")}
	return &Handlers{opts: Options{Roadmap: roadmap.NewReader(src)}}
}

func TestRoadmap_UnconfiguredOrBrokenAnswers503(t *testing.T) {
	for name, h := range map[string]*Handlers{
		"unconfigured": {},
		"broken":       {opts: Options{Roadmap: roadmap.NewReader(roadmapDirSource{dir: t.TempDir()})}},
	} {
		for _, path := range []string{"/api/v1/roadmap/epics", "/api/v1/roadmap/ready", "/api/v1/roadmap/epic-status?epic=x"} {
			code, body := roadmapGet(t, h, path)
			if code != http.StatusServiceUnavailable || body["code"] != "roadmap_unavailable" {
				t.Errorf("%s %s = %d %v", name, path, code, body)
			}
			if msg, _ := body["error"].(string); strings.Contains(msg, "/") {
				t.Errorf("%s %s leaks local detail: %q", name, path, msg)
			}
		}
	}
}

func TestRoadmap_EpicStatusAndReady(t *testing.T) {
	h := liveRoadmapHandlers()
	code, body := roadmapGet(t, h, "/api/v1/roadmap/epic-status?epic=mctlhq%2F.github%2357")
	if code != http.StatusOK {
		t.Fatalf("epic-status = %d %v", code, body)
	}
	epic := body["epic"].(map[string]any)
	if epic["name"] == "" || epic["lifecycle"] == "" || body["readiness"] == nil || body["health"] == nil {
		t.Fatalf("epic-status body = %v", body)
	}
	prov := body["provenance"].(map[string]any)
	if prov["state_revision"] != "0123abc" || prov["age_seconds"] == nil {
		t.Fatalf("provenance = %v", prov)
	}

	code, list := roadmapGet(t, h, "/api/v1/roadmap/epics")
	if epics, _ := list["epics"].([]any); code != http.StatusOK || len(epics) == 0 || list["provenance"] == nil {
		t.Fatalf("epics = %d %v", code, list)
	}
	if code, _ := roadmapGet(t, h, "/api/v1/roadmap/epic-status"); code != http.StatusBadRequest {
		t.Errorf("missing epic = %d", code)
	}
	if code, body := roadmapGet(t, h, "/api/v1/roadmap/epic-status?epic=nope"); code != http.StatusNotFound || body["code"] != "epic_not_found" {
		t.Errorf("unknown epic = %d %v", code, body)
	}
	if code, _ := roadmapGet(t, h, "/api/v1/roadmap/ready?required_only=maybe"); code != http.StatusBadRequest {
		t.Errorf("bad required_only = %d", code)
	}

	count := func(body map[string]any) int {
		n := 0
		for _, e := range body["epics"].([]any) {
			n += len(e.(map[string]any)["items"].([]any))
		}
		return n
	}
	_, def := roadmapGet(t, h, "/api/v1/roadmap/ready")
	_, req := roadmapGet(t, h, "/api/v1/roadmap/ready?required_only=true")
	_, all := roadmapGet(t, h, "/api/v1/roadmap/ready?required_only=false")
	if def["required_only"] != true || count(def) != count(req) || count(all) <= count(req) {
		t.Fatalf("required_only default/true/false = %d/%d/%d", count(def), count(req), count(all))
	}
}
