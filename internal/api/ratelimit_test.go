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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

func TestIsLoopbackRemote(t *testing.T) {
	cases := []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"192.0.2.1:1234", false},
		{"10.42.4.181:443", false},
		{"127.0.0.1", true},
		{"::1", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.remote
		if got := isLoopbackRemote(req); got != tc.want {
			t.Errorf("RemoteAddr %q: isLoopbackRemote = %v, want %v", tc.remote, got, tc.want)
		}
	}
}

func TestIsLoopbackRemote_IgnoresSpoofedXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:443"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	if isLoopbackRemote(req) {
		t.Fatal("X-Forwarded-For must not make a public peer look like loopback")
	}
}

func injectRateLimitUser(next http.Handler) http.Handler {
	u := &auth.User{ID: "rate-limit-user", Groups: []string{"admins"}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
	})
}

func getWithAddr(h http.Handler, path, remote string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// Loopback peers must not consume the global authenticated bucket; a
// non-loopback peer on the same user still does. Local Limit(2) keeps this
// fast — production uses 300 with the same skipLoopbackRateLimit wrapper.
func TestGlobalRateLimit_LoopbackNotCounted(t *testing.T) {
	r := chi.NewRouter()
	r.Use(injectRateLimitUser)
	r.Use(skipLoopbackRateLimit(httprate.Limit(2, time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
		if user := auth.UserFromContext(r.Context()); user != nil {
			return "user:" + user.ID, nil
		}
		return keyByTrustedIP(r)
	}))))
	r.Get("/probe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 5; i++ {
		if c := getWithAddr(r, "/probe", "127.0.0.1:9"); c != http.StatusOK {
			t.Fatalf("loopback request %d: got %d, want 200 (must not consume the bucket)", i, c)
		}
	}
	for i := 0; i < 3; i++ {
		if c := getWithAddr(r, "/probe", "[::1]:9"); c != http.StatusOK {
			t.Fatalf("::1 request %d: got %d, want 200", i, c)
		}
	}

	if c := getWithAddr(r, "/probe", "192.0.2.1:1234"); c != http.StatusOK {
		t.Fatalf("first non-loopback: got %d, want 200", c)
	}
	if c := getWithAddr(r, "/probe", "192.0.2.1:1234"); c != http.StatusOK {
		t.Fatalf("second non-loopback: got %d, want 200", c)
	}
	if c := getWithAddr(r, "/probe", "192.0.2.1:1234"); c != http.StatusTooManyRequests {
		t.Fatalf("third non-loopback should hit Limit(2): got %d", c)
	}
}

// httptest default RemoteAddr is 192.0.2.1, so these count against the global
// 300/min cap. 101 used to 429 at the old 100/min limit.
func TestGlobalRateLimit_AllowsBurstOver100(t *testing.T) {
	h := NewRouter(Options{AuthMiddleware: injectRateLimitUser})
	for i := 0; i < 101; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200 (authenticated cap is 300/min)", i+1, w.Code)
		}
	}
}

// Write 20/min must still apply to loopback so MCP deploys cannot bypass it.
func TestWriteRateLimit_LoopbackStillCounted(t *testing.T) {
	h := NewRouter(Options{
		AuthMiddleware: injectRateLimitUser,
		Registry:       operations.NewRegistry(),
	})
	var last int
	for i := 0; i < 21; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operations/does-not-exist/execute", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:9"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		last = w.Code
		if i < 20 && w.Code == http.StatusTooManyRequests {
			t.Fatalf("write request %d hit 429 too early (loopback must still use the 20/min write cap, not skip it)", i+1)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("21st loopback write: got %d, want 429", last)
	}
}
