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

package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestGitHubTokenKind(t *testing.T) {
	for raw, want := range map[string]string{
		"github_pat_11ABCDEF0123": "fine_grained_pat",
		"ghp_abcdef":              "classic_pat",
		"gho_abcdef":              "oauth_app",
		"ghu_abcdef":              "app_user",
		"ghs_abcdef":              "app_installation",
		"ghr_abcdef":              "other",
		"0123456789abcdef":        "other",
		"":                        "other",
	} {
		if got := githubTokenKind(raw); got != want {
			t.Errorf("githubTokenKind(%q) = %q, want %q", raw, got, want)
		}
	}
}

// captureLog routes slog to a buffer for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestGitHubProviderCountsAndLogsOK(t *testing.T) {
	buf := captureLog(t)
	v := NewGitHubValidator(nil)
	const token = "gho_cachedtokenvalue" // #nosec G101 -- fake test token
	v.cache[token] = &githubUserInfo{Login: "octocat", ID: 42, CachedAt: time.Now()}
	p := newGitHubProvider(v, nil)

	okBefore := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("oauth_app", "ok"))
	ctx := withUserAgent(context.Background(), "mctl-cli/1.2.3")
	for i := 0; i < 3; i++ {
		if _, err := p.Verify(ctx, token); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	if got := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("oauth_app", "ok")) - okBefore; got != 3 {
		t.Fatalf("ok counter delta = %v, want 3 (every call counts)", got)
	}
	out := buf.String()
	if n := strings.Count(out, "github token verified"); n != 1 {
		t.Fatalf("log lines = %d, want 1 (deduped per caller):\n%s", n, out)
	}
	for _, want := range []string{"login=octocat", "kind=oauth_app", "mctl-cli/1.2.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
	if strings.Contains(out, "cachedtokenvalue") {
		t.Fatalf("log leaks the token: %s", out)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubProviderCountsFailuresWithoutLogging(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		status int // 0: the lookup never gets a response
		header http.Header
		want   string
	}{
		{"rejected by GitHub", context.Background(), http.StatusUnauthorized, nil, "invalid"},
		{"forbidden", context.Background(), http.StatusForbidden, nil, "invalid"},
		{"rate limited", context.Background(), http.StatusForbidden, http.Header{"X-Ratelimit-Remaining": {"0"}}, "unavailable"},
		{"GitHub error", context.Background(), http.StatusBadGateway, nil, "unavailable"},
		{"lookup failed", cancelled, 0, nil, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			v := NewGitHubValidator(nil)
			v.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if err := r.Context().Err(); err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: tc.status, Header: tc.header, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
			})}
			p := newGitHubProvider(v, nil)

			counter := func(result string) float64 {
				return testutil.ToFloat64(githubTokenVerifications.WithLabelValues("classic_pat", result))
			}
			before := map[string]float64{}
			for _, r := range []string{"ok", "invalid", "unavailable"} {
				before[r] = counter(r)
			}
			if _, err := p.Verify(tc.ctx, "ghp_notavalidtoken"); err == nil {
				t.Fatal("Verify succeeded on a failed lookup")
			}
			for r, b := range before {
				want := 0.0
				if r == tc.want {
					want = 1
				}
				if got := counter(r) - b; got != want {
					t.Errorf("result=%s delta = %v, want %v", r, got, want)
				}
			}
			if strings.Contains(buf.String(), "github token verified") {
				t.Fatalf("a failed verification was logged as verified: %s", buf.String())
			}
		})
	}
}

func TestSightingLogRelogsAfterInterval(t *testing.T) {
	buf := captureLog(t)
	now := time.Unix(0, 0)
	s := sightingLog{now: func() time.Time { return now }}
	s.log("octocat", "classic_pat", "curl/8")
	s.log("octocat", "classic_pat", "curl/8")
	s.log("octocat", "classic_pat", "python-requests/2") // another client
	now = now.Add(sightingInterval)
	s.log("octocat", "classic_pat", "curl/8")
	if n := strings.Count(buf.String(), "github token verified"); n != 3 {
		t.Fatalf("log lines = %d, want 3:\n%s", n, buf.String())
	}
}

func TestSightingLogCapsAgentsPerCaller(t *testing.T) {
	buf := captureLog(t)
	s := sightingLog{}
	for i := 0; i < 50; i++ {
		s.log("octocat", "classic_pat", fmt.Sprintf("bot/%d", i)) // a nonce per request
	}
	if n := strings.Count(buf.String(), "github token verified"); n != maxAgentsPerCaller {
		t.Fatalf("log lines = %d, want %d", n, maxAgentsPerCaller)
	}
}

func TestSightingLogSweepsFinishedWindowsAtCap(t *testing.T) {
	now := time.Unix(0, 0)
	s := sightingLog{now: func() time.Time { return now }}
	s.log("live", "classic_pat", "curl/8")
	now = now.Add(sightingInterval / 2)
	for i := 0; i < maxSightings-1; i++ {
		s.log(fmt.Sprintf("old-%d", i), "classic_pat", "curl/8")
	}
	now = now.Add(sightingInterval / 2) // the first window ended, the rest are live
	s.log("new", "classic_pat", "curl/8")
	if _, ok := s.seen["old-0\x00classic_pat"]; !ok {
		t.Fatal("a live window was dropped at the cap; only finished ones should be swept")
	}
	if _, ok := s.seen["live\x00classic_pat"]; ok {
		t.Fatal("a finished window survived the sweep")
	}
}

// The middleware is what puts the User-Agent into the context; without it
// every logged user_agent is empty.
func TestMiddlewareLogsGitHubTokenUserAgent(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_FEDERATION_DISABLED", "")
	buf := captureLog(t)
	v := NewGitHubValidator(nil)
	v.cache["gho_uatoken"] = &githubUserInfo{Login: "ua-tester", ID: 7, CachedAt: time.Now()}
	h := Middleware(v, nil, nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer gho_uatoken")
	req.Header.Set("User-Agent", "mctl-cli/9.9.9")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, "login=ua-tester") || !strings.Contains(out, "user_agent=mctl-cli/9.9.9") {
		t.Fatalf("sighting line lacks the request User-Agent:\n%s", out)
	}
}

func TestUserAgentFromContextTruncates(t *testing.T) {
	if got := userAgentFromContext(context.Background()); got != "" {
		t.Fatalf("no user agent = %q, want empty", got)
	}
	long := strings.Repeat("a", maxLoggedUserAgent+50)
	if got := userAgentFromContext(withUserAgent(context.Background(), long)); len(got) != maxLoggedUserAgent {
		t.Fatalf("len = %d, want %d", len(got), maxLoggedUserAgent)
	}
	if got := userAgentFromContext(withUserAgent(context.Background(), "bad\xffagent")); got != "badagent" {
		t.Fatalf("invalid UTF-8 user agent = %q, want %q", got, "badagent")
	}
	// A cut through a multi-byte rune must not leave invalid UTF-8.
	split := strings.Repeat("a", maxLoggedUserAgent-1) + "étail"
	if got := userAgentFromContext(withUserAgent(context.Background(), split)); !utf8.ValidString(got) {
		t.Fatalf("truncated user agent is not valid UTF-8: %q", got)
	}
}
