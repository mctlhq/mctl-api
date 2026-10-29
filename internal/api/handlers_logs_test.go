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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/loki"
)

type stubLogQuerier struct {
	lines    []loki.LogLine
	err      error
	calls    int
	gotLines int
	gotSince time.Duration
}

func (s *stubLogQuerier) QueryRange(_ context.Context, _, _ string, lines int, since time.Duration) ([]loki.LogLine, error) {
	s.calls++
	s.gotLines, s.gotSince = lines, since
	return s.lines, s.err
}

func logsRouter(q LogQuerier, git GitReader) http.Handler {
	h := &Handlers{opts: Options{LogQuerier: q, GitReader: git, ArgoCD: &workloadArgo{}}}
	r := chi.NewRouter()
	r.Get("/api/v1/logs/{team}/{app}", h.GetServiceLogs)
	return r
}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

func TestGetServiceLogs_Failures(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"generic", errors.New("loki: HTTP 500: secret-body http://loki.internal"), 503},
		{"deadline", fmt.Errorf("loki: request failed: %w", context.DeadlineExceeded), 504},
		{"url timeout", &url.Error{Op: "Get", URL: "http://loki.internal/q", Err: timeoutNetErr{}}, 504},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLogQuerier{err: c.err}
			rec := serveUser(logsRouter(stub, workloadTenants{}), u, "GET", "/api/v1/logs/acme/web")
			if rec.Code != c.want {
				t.Fatalf("code = %d, want %d", rec.Code, c.want)
			}
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if _, ok := body["error"]; !ok {
				t.Errorf("no error key: %s", rec.Body.String())
			}
			if _, ok := body["lines"]; ok {
				t.Errorf("failure carries lines: %s", rec.Body.String())
			}
			if _, ok := body["count"]; ok {
				t.Errorf("failure carries count: %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "loki.internal") || strings.Contains(rec.Body.String(), "secret-body") {
				t.Errorf("body leaks upstream detail: %s", rec.Body.String())
			}
		})
	}
}

func TestGetServiceLogs_NilQuerier(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})
	rec := serveUser(logsRouter(nil, workloadTenants{}), u, "GET", "/api/v1/logs/acme/web")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "log querying not configured") {
		t.Errorf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestGetServiceLogs_Success(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})

	stub := &stubLogQuerier{}
	rec := serveUser(logsRouter(stub, workloadTenants{}), u, "GET", "/api/v1/logs/acme/web")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"lines":[]`) {
		t.Errorf("empty result not []: %s", rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["count"] != float64(0) || body["limit"] != float64(100) || body["since"] != "1h0m0s" {
		t.Errorf("body = %v", body)
	}

	stub = &stubLogQuerier{lines: []loki.LogLine{{}, {}}}
	rec = serveUser(logsRouter(stub, workloadTenants{}), u, "GET", "/api/v1/logs/acme/web?lines=10&since=15m")
	body = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["count"] != float64(2) || body["limit"] != float64(10) || body["since"] != "15m0s" {
		t.Errorf("got %d %v", rec.Code, body)
	}
	if stub.gotLines != 10 || stub.gotSince != 15*time.Minute {
		t.Errorf("stub got %d %v", stub.gotLines, stub.gotSince)
	}
}

func TestGetServiceLogs_RejectsBeforeLoki(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme", "broken", "ghost"})
	cases := []struct {
		path string
		git  GitReader
		want int
	}{
		{"/api/v1/logs/acme/web?lines=0", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?lines=1001", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?lines=abc", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?since=7d", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?since=-1h", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?since=30s", workloadTenants{}, 400},
		{"/api/v1/logs/acme/web?since=721h", workloadTenants{}, 400},
		{"/api/v1/logs/acme/typo", workloadTenants{}, 404},
		{"/api/v1/logs/acme/web", workloadTenants{svcErr: errors.New("boom")}, 503},
		{"/api/v1/logs/ghost/web", workloadTenants{}, 404},
		{"/api/v1/logs/broken/web", workloadTenants{}, 503},
		{"/api/v1/logs/Acme_x/web", workloadTenants{}, 400},
		{"/api/v1/logs/acme/Web_", workloadTenants{}, 400},
	}
	for _, c := range cases {
		stub := &stubLogQuerier{}
		rec := serveUser(logsRouter(stub, c.git), u, "GET", c.path)
		if rec.Code != c.want {
			t.Errorf("%s = %d, want %d", c.path, rec.Code, c.want)
		}
		if stub.calls != 0 {
			t.Errorf("%s reached Loki", c.path)
		}
	}
}

func TestGetServiceLogs_Canceled(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})
	cases := []struct {
		name   string
		err    error
		cancel bool
	}{
		{"wrapped canceled", fmt.Errorf("loki: request failed: %w", context.Canceled), false},
		// The caller went away: the request context is canceled even though
		// the client error reads as a timeout. It must not become a 504.
		{"request context canceled", &url.Error{Op: "Get", URL: "http://loki.internal/q", Err: timeoutNetErr{}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/logs/acme/web", nil)
			ctx, cancel := context.WithCancel(auth.WithUser(req.Context(), u))
			if c.cancel {
				cancel()
			} else {
				defer cancel()
			}
			rec := httptest.NewRecorder()
			logsRouter(&stubLogQuerier{err: c.err}, workloadTenants{}).ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "request canceled") {
				t.Errorf("got %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// A failed Loki read through the support scope gate is audited as failed.
func TestGetServiceLogs_SupportAuditFailed(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{
		AuditLog:   log,
		LogQuerier: &stubLogQuerier{err: errors.New("loki: HTTP 500: body")},
		GitReader:  workloadTenants{},
		ArgoCD:     &workloadArgo{},
	}}
	r := chi.NewRouter()
	r.Use(h.agentScopeGate)
	r.Get("/api/v1/logs/{team}/{app}", h.GetServiceLogs)
	if rec := serveUser(r, auditedSupportRun(t, "acme"), "GET", "/api/v1/logs/acme/web"); rec.Code != 503 {
		t.Fatalf("code = %d: %s", rec.Code, rec.Body.String())
	}
	rows, _ := log.ListSupport(context.Background(), audit.SupportFilter{Tenant: "acme"})
	if len(rows) != 1 || rows[0].Status != "failed" || rows[0].Parameters["http_status"] != "503" {
		t.Fatalf("rows = %+v", rows)
	}
}

// The request deadline expired while the querier returned an error that
// wraps nothing (e.g. formatted with %v): still a timeout, not "unavailable".
func TestGetServiceLogs_RequestDeadlineIsTimeout(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})
	req := httptest.NewRequest("GET", "/api/v1/logs/acme/web", nil)
	ctx, cancel := context.WithDeadline(auth.WithUser(req.Context(), u), time.Now().Add(-time.Second))
	defer cancel()
	rec := httptest.NewRecorder()
	stub := &stubLogQuerier{err: errors.New("loki: request failed: context deadline exceeded")}
	logsRouter(stub, workloadTenants{}).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("got %d %s", rec.Code, rec.Body.String())
	}
}
