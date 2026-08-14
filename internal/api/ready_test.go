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

func TestReadyz_FailedProbeReturns503(t *testing.T) {
	h := &Handlers{opts: Options{
		GitopsReady:   func(context.Context) error { return fmt.Errorf("never synced") },
		PostgresReady: func(context.Context) error { return nil },
	}}
	rec := httptest.NewRecorder()
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body := decodeReady(t, rec)
	if body.Status != "not ready" {
		t.Errorf("status = %q, want not ready", body.Status)
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
	h.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
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
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func decodeReady(t *testing.T, rec *httptest.ResponseRecorder) readyBody {
	t.Helper()
	var body readyBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return body
}
