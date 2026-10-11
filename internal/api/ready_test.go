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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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

func TestReadyz_FailedProbeStaysReady(t *testing.T) {
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
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.Checks["gitops"] != "unavailable" {
		t.Errorf("gitops = %q, want unavailable", body.Checks["gitops"])
	}
	if body.Checks["postgres"] != "ok" {
		t.Errorf("postgres = %q, want ok", body.Checks["postgres"])
	}
}

func TestReadyz_SlowProbeDoesNotStarveOthers(t *testing.T) {
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
		t.Errorf("elapsed = %s, hanging probe slowed the response", elapsed)
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
	Dependencies string            `json:"dependencies"`
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

func TestReadyz_AllDependenciesFailingStoresOKIsReady(t *testing.T) {
	bad := func(context.Context) error { return fmt.Errorf("down") }
	h := &Handlers{opts: Options{
		GitopsReady: bad, PostgresReady: bad, DexReady: bad, VaultReady: bad,
		StoreInitFailures: func() []string { return nil },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeReady(t, rec)
	if body.Status != "ready" || body.Checks["stores"] != "ok" || body.Dependencies != "degraded" {
		t.Errorf("body = %+v", body)
	}
	for _, name := range []string{"gitops", "postgres", "dex", "vault"} {
		if body.Checks[name] != "unavailable" {
			t.Errorf("checks[%s] = %q, want unavailable", name, body.Checks[name])
		}
	}
}

func TestReadyz_StoreInitFailureWithFailingDepsIs503(t *testing.T) {
	bad := func(context.Context) error { return fmt.Errorf("down") }
	h := &Handlers{opts: Options{
		GitopsReady: bad, PostgresReady: bad, DexReady: bad, VaultReady: bad,
		StoreInitFailures: func() []string { return []string{"agent registry"} },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := decodeReady(t, rec); fmt.Sprint(body.FailedStores) != "[agent registry]" {
		t.Errorf("failed_stores = %v", body.FailedStores)
	}
}

func TestReadyz_DrainingIs503(t *testing.T) {
	ok := func(context.Context) error { return nil }
	h := &Handlers{opts: Options{GitopsReady: ok, Draining: func() bool { return true }}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := decodeReady(t, rec).Checks["shutdown"]; got != "draining" {
		t.Errorf("checks[shutdown] = %q, want draining", got)
	}
}

// A pod whose own gitops checkout has never synced would serve an empty
// catalogue. That is pod-local, so it must keep /readyz at 503 even though the
// shared gitops dependency probe no longer gates readiness.
func TestReadyz_GitopsNeverSyncedIs503(t *testing.T) {
	ok := func(context.Context) error { return nil }
	h := &Handlers{opts: Options{GitopsReady: ok, GitopsSynced: func() bool { return false }}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body := decodeReady(t, rec)
	if got := body.Checks["gitops_sync"]; got != "never_synced" {
		t.Errorf("checks[gitops_sync] = %q, want never_synced", got)
	}
	if body.Status != "not ready" {
		t.Errorf("status = %q, want not ready", body.Status)
	}
}

// Once synced, a failing shared gitops probe (e.g. ListTenants erroring during a
// GitHub outage) is reported but does not fail readiness.
func TestReadyz_GitopsSyncedWithFailingProbeIsReady(t *testing.T) {
	fail := func(context.Context) error { return errors.New("list tenants failed") }
	h := &Handlers{opts: Options{GitopsReady: fail, GitopsSynced: func() bool { return true }}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeReady(t, rec)
	if body.Checks["gitops_sync"] != "ok" || body.Checks["gitops"] != "unavailable" {
		t.Errorf("checks = %v, want gitops_sync=ok gitops=unavailable", body.Checks)
	}
}

func TestReadyz_DependencyGauge(t *testing.T) {
	dependencyUp.Reset()
	h := &Handlers{opts: Options{
		GitopsReady:   func(context.Context) error { return fmt.Errorf("down") },
		PostgresReady: func(context.Context) error { return nil },
	}}
	h.handleReadyz(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if got := testutil.ToFloat64(dependencyUp.WithLabelValues("gitops")); got != 0 {
		t.Errorf("gitops gauge = %v, want 0", got)
	}
	if got := testutil.ToFloat64(dependencyUp.WithLabelValues("postgres")); got != 1 {
		t.Errorf("postgres gauge = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(dependencyUp); n != 2 {
		t.Errorf("series = %d, want 2 (unconfigured probes have none)", n)
	}
}

func TestReadyz_DependenciesAggregate(t *testing.T) {
	ok := func(context.Context) error { return nil }
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{GitopsReady: ok, VaultReady: ok}, "ok"},
		{Options{}, "not_configured"},
	} {
		h := &Handlers{opts: tc.opts}
		rec := httptest.NewRecorder()
		h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if got := decodeReady(t, rec).Dependencies; got != tc.want {
			t.Errorf("dependencies = %q, want %q", got, tc.want)
		}
	}
}
