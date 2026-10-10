// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/LICENSE-2.0
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadyz_NoProbesConfiguredIsReady(t *testing.T) {
	h := &Handlers{opts: Options{}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeReady(t, rec)
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	for _, name := range []string{"gitops", "postgres", "dex", "vault"} {
		if body.Checks[name] != "not_configured" {
			t.Errorf("checks[%s] = %q, want not_configured", name, body.Checks[name])
		}
	}
}

func TestReadyz_AllProbesOK(t *testing.T) {
	ok := func(context.Context) error { return nil }
	h := &Handlers{opts: Options{
		GitopsReady:   ok,
		PostgresReady: ok,
		DexReady:      ok,
		VaultReady:    ok,
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	for _, name := range []string{"gitops", "postgres", "dex", "vault"} {
		if body.Checks[name] != "ok" {
			t.Errorf("checks[%s] = %q, want ok", name, body.Checks[name])
		}
	}
}

// mctl-api#536: every replica probes the same shared dependencies, so a
// dependency outage must not fail readiness, or all replicas go not-Ready at
// once and the Service loses every endpoint.
func TestReadyz_AllDependenciesFailingStaysReady(t *testing.T) {
	fail := func(context.Context) error { return fmt.Errorf("down") }
	h := &Handlers{opts: Options{
		GitopsReady:       fail,
		PostgresReady:     fail,
		DexReady:          fail,
		VaultReady:        fail,
		StoreInitFailures: func() []string { return nil },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	for _, name := range []string{"gitops", "postgres", "dex", "vault"} {
		if body.Checks[name] != "unavailable" {
			t.Errorf("checks[%s] = %q, want unavailable (still observable)", name, body.Checks[name])
		}
	}
	if got := fmt.Sprint(body.DegradedDependencies); got != "[gitops postgres dex vault]" {
		t.Errorf("degraded_dependencies = %s, want all four named", got)
	}
	if body.Checks["stores"] != "ok" {
		t.Errorf("checks[stores] = %q, want ok", body.Checks["stores"])
	}
}

func TestReadyz_OneFailedDependencyIsReportedAndStaysReady(t *testing.T) {
	h := &Handlers{opts: Options{
		GitopsReady:   func(context.Context) error { return fmt.Errorf("never synced") },
		PostgresReady: func(context.Context) error { return nil },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeReady(t, rec)
	if body.Checks["gitops"] != "unavailable" {
		t.Errorf("gitops = %q, want unavailable", body.Checks["gitops"])
	}
	if body.Checks["postgres"] != "ok" {
		t.Errorf("postgres = %q, want ok", body.Checks["postgres"])
	}
	if got := fmt.Sprint(body.DegradedDependencies); got != "[gitops]" {
		t.Errorf("degraded_dependencies = %s, want [gitops]", got)
	}
}

// A hanging dependency must not slow the response beyond the per-check
// timeout, and must not make a sibling probe inherit its deadline.
func TestReadyz_HangingProbeIsBoundedAndDoesNotStarveOthers(t *testing.T) {
	h := &Handlers{opts: Options{
		GitopsReady: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		PostgresReady: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return nil
		},
	}}
	rec := httptest.NewRecorder()
	start := time.Now()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if elapsed := time.Since(start); elapsed > readyCheckTimeout+time.Second {
		t.Errorf("handler took %s, want about readyCheckTimeout (%s)", elapsed, readyCheckTimeout)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeReady(t, rec)
	if body.Checks["gitops"] != "unavailable" {
		t.Errorf("gitops = %q, want unavailable", body.Checks["gitops"])
	}
	if body.Checks["postgres"] != "ok" {
		t.Errorf("postgres = %q, want ok (own timeout; must not inherit a sibling's deadline)", body.Checks["postgres"])
	}
}

func TestHTTPReady_SuccessAndFailure(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	if err := HTTPReady(okSrv.URL)(context.Background()); err != nil {
		t.Fatalf("ok probe: %v", err)
	}
	if err := HTTPReady(failSrv.URL)(context.Background()); err == nil {
		t.Fatal("fail probe: expected error")
	}
}

type readyBody struct {
	Status       string            `json:"status"`
	Checks       map[string]string `json:"checks"`
	FailedStores []string          `json:"failed_stores"`

	DegradedDependencies []string `json:"degraded_dependencies"`
}

func decodeReady(t *testing.T, rec *httptest.ResponseRecorder) readyBody {
	t.Helper()
	var body readyBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return body
}

// mctl-api#387: a configured store that failed its one startup init stays nil
// for the life of the pod. /readyz must say so and name it, even when every
// live dependency probe is healthy, so a rolling update keeps the old pod.
func TestReadyz_FailedStoreInitIsNotReady(t *testing.T) {
	ok := func(context.Context) error { return nil }
	h := &Handlers{opts: Options{
		GitopsReady:   ok,
		PostgresReady: ok,
		StoreInitFailures: func() []string {
			return []string{"surface identities", "agent registry"}
		},
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	if body.Status != "not ready" {
		t.Errorf("status = %q, want not ready", body.Status)
	}
	if body.Checks["stores"] != "init_failed" {
		t.Errorf("checks[stores] = %q, want init_failed", body.Checks["stores"])
	}
	if got := fmt.Sprint(body.FailedStores); got != "[surface identities agent registry]" {
		t.Errorf("failed_stores = %s, want both stores named", got)
	}
}

// Both at once: the store init failure alone decides the 503, and the failing
// dependency is still reported.
func TestReadyz_StoreInitFailureWithFailingDependencyIsNotReady(t *testing.T) {
	h := &Handlers{opts: Options{
		VaultReady:        func(context.Context) error { return fmt.Errorf("hang") },
		StoreInitFailures: func() []string { return []string{"agent registry"} },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	if body.Checks["vault"] != "unavailable" || body.Checks["stores"] != "init_failed" {
		t.Errorf("checks = %v, want vault unavailable and stores init_failed", body.Checks)
	}
}

func TestReadyz_StoresAllInitialisedIsReady(t *testing.T) {
	h := &Handlers{opts: Options{StoreInitFailures: func() []string { return nil }}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	if body.Checks["stores"] != "ok" || body.FailedStores != nil {
		t.Errorf("checks[stores] = %q failed_stores = %v, want ok and none", body.Checks["stores"], body.FailedStores)
	}
}

func TestReadyz_StoresNotWiredIsNotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := decodeReady(t, rec).Checks["stores"]; got != "not_configured" {
		t.Errorf("checks[stores] = %q, want not_configured", got)
	}
}
