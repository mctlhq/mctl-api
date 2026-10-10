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
	"log/slog"
	"strings"
	"testing"
	"time"

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

func TestGitHubProviderCountsInvalidWithoutLogging(t *testing.T) {
	buf := captureLog(t)
	p := newGitHubProvider(NewGitHubValidator(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // fails the GitHub lookup without reaching the network

	okBefore := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("classic_pat", "ok"))
	invalidBefore := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("classic_pat", "invalid"))
	if _, err := p.Verify(ctx, "ghp_notavalidtoken"); err == nil {
		t.Fatal("Verify succeeded on a failed lookup")
	}
	if got := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("classic_pat", "invalid")) - invalidBefore; got != 1 {
		t.Fatalf("invalid counter delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(githubTokenVerifications.WithLabelValues("classic_pat", "ok")) - okBefore; got != 0 {
		t.Fatalf("ok counter delta = %v, want 0", got)
	}
	if strings.Contains(buf.String(), "github token verified") {
		t.Fatalf("a failed verification was logged as verified: %s", buf.String())
	}
}

func TestSightingLogRelogsAfterInterval(t *testing.T) {
	buf := captureLog(t)
	now := time.Unix(0, 0)
	s := sightingLog{now: func() time.Time { return now }}
	s.log("octocat", "classic_pat", "curl/8")
	s.log("octocat", "classic_pat", "curl/8")
	s.log("octocat", "classic_pat", "python-requests/2") // another caller
	now = now.Add(sightingInterval)
	s.log("octocat", "classic_pat", "curl/8")
	if n := strings.Count(buf.String(), "github token verified"); n != 3 {
		t.Fatalf("log lines = %d, want 3:\n%s", n, buf.String())
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
}
