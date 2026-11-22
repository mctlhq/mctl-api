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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// seriesCount returns how many series the named metric family currently has.
func seriesCount(t *testing.T, name string) int {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return len(f.GetMetric())
		}
	}
	return 0
}

// Unmatched paths and invented methods must not grow the metric series set
// (mctl-api#241). Fails if the raw URL path or raw method is used as a label.
func TestMetricsMiddlewareBoundsLabelCardinality(t *testing.T) {
	r := chi.NewRouter()
	r.Use(metricsMiddleware())
	r.Get("/known/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}

	// Prime the "unmatched" series and one matched series.
	if code := do(http.MethodGet, "/nope-prime"); code != http.StatusNotFound {
		t.Fatalf("prime = %d, want 404", code)
	}
	do(http.MethodGet, "/known/1")
	do("BREW", "/nope-prime")
	baseReq, baseDur := seriesCount(t, "http_requests_total"), seriesCount(t, "http_request_duration_seconds")

	for i := 0; i < 200; i++ {
		if code := do(http.MethodGet, fmt.Sprintf("/api/v1/x-%d", i)); code != http.StatusNotFound {
			t.Fatalf("path %d = %d, want 404", i, code)
		}
		do(fmt.Sprintf("M%d", i), fmt.Sprintf("/nope-%d", i))
		do(http.MethodGet, fmt.Sprintf("/known/%d", i))
	}

	if got := seriesCount(t, "http_requests_total"); got != baseReq {
		t.Errorf("http_requests_total series = %d, want constant %d", got, baseReq)
	}
	if got := seriesCount(t, "http_request_duration_seconds"); got != baseDur {
		t.Errorf("http_request_duration_seconds series = %d, want constant %d", got, baseDur)
	}
}

func TestMetricsMethodLabel(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"} {
		if got := metricsMethodLabel(m); got != m {
			t.Errorf("metricsMethodLabel(%q) = %q, want unchanged", m, got)
		}
	}
	for _, m := range []string{"", "get", "BREW", "PROPFIND", "X\n"} {
		if got := metricsMethodLabel(m); got != "other" {
			t.Errorf("metricsMethodLabel(%q) = %q, want other", m, got)
		}
	}
}
