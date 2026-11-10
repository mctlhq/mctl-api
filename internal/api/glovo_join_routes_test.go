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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

func joinRouter(opts *GlovoJoinRoutes) http.Handler {
	facade := auth.NewGlovoFacadeUser()
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), facade)))
		})
	}
	return NewRouter(Options{AuthMiddleware: mw, GlovoJoin: opts})
}

func joinCall(h http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.RemoteAddr = "203.0.113.9:4444"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// T9: with the flag off the join prefix does not exist, for the facade too.
func TestGlovoJoinRoutesAreUnmountedUnlessEnabled(t *testing.T) {
	for name, o := range map[string]*GlovoJoinRoutes{"nil": nil, "disabled": {Enabled: false}} {
		h := joinRouter(o)
		for _, rt := range contract.MustLoad().Routes {
			path := strings.Replace(contract.BasePath+rt.Path, "{order_id}", "x", 1)
			if rec := joinCall(h, rt.Method, path); rec.Code != http.StatusNotFound {
				t.Errorf("%s: %s %s = %d, want 404", name, rt.Method, path, rec.Code)
			}
		}
	}
}

// The flag alone mounts the routes but wires nothing: every dependent route
// is 503 not_ready and /compatibility is never deploy_ready.
func TestGlovoJoinEnabledWithoutDependenciesIsNotReady(t *testing.T) {
	h := joinRouter(&GlovoJoinRoutes{Enabled: true})
	rec := joinCall(h, "GET", contract.BasePath+"/compatibility")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deploy_ready":false`) {
		t.Fatalf("compatibility = %d %s", rec.Code, rec.Body.String())
	}
	rec = joinCall(h, "GET", contract.BasePath+"/connection")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"not_ready"`) {
		t.Fatalf("connection = %d %s", rec.Code, rec.Body.String())
	}
}

// T8: the facade is exempt from the global 300/min per-principal limiter (one
// principal id stands for every end user), and the join routes enforce their
// own aggregate instead.
func TestGlovoJoinFacadeSkipsTheGlobalLimiterAndHasItsOwn(t *testing.T) {
	rt := &glovojoin.Routes{Aggregate: 400}
	h := joinRouter(&GlovoJoinRoutes{Enabled: true, Routes: rt})
	got429At := 0
	for i := 1; i <= 450; i++ {
		rec := joinCall(h, "GET", contract.BasePath+"/compatibility")
		if rec.Code == http.StatusTooManyRequests {
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			got429At = i
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	if got429At != 401 {
		t.Fatalf("first 429 at request %d, want 401 (the aggregate of 400, not the global 300)", got429At)
	}
}
