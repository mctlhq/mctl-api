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
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// NewRouter must log exactly one startup warning when
// BackstageGithubAppConnectToken is unset, so a missing credential is
// greppable in mctl_get_service_logs instead of silently degrading every
// repos proxy call to an anonymous (and now-401ing) request. The token
// value itself must never appear in the log.
func TestNewRouterWarnsWhenGithubAppConnectTokenUnset(t *testing.T) {
	var buf bytes.Buffer
	restore := swapDefaultLogger(&buf)
	defer restore()

	NewRouter(Options{})

	out := buf.String()
	if strings.Count(out, "BACKSTAGE_GITHUB_APP_CONNECT_TOKEN") != 1 {
		t.Fatalf("expected exactly one startup warning naming BACKSTAGE_GITHUB_APP_CONNECT_TOKEN, got log:\n%s", out)
	}
}

func TestNewRouterSilentWhenGithubAppConnectTokenSet(t *testing.T) {
	var buf bytes.Buffer
	restore := swapDefaultLogger(&buf)
	defer restore()

	NewRouter(Options{BackstageGithubAppConnectToken: "secret-token"})

	out := buf.String()
	if strings.Contains(out, "BACKSTAGE_GITHUB_APP_CONNECT_TOKEN") {
		t.Fatalf("expected no startup warning when the token is configured, got log:\n%s", out)
	}
	if strings.Contains(out, "secret-token") {
		t.Fatal("token value must never be logged")
	}
}

// swapDefaultLogger installs a JSON slog logger writing to buf as the
// package-level default (what slog.Warn/slog.Error use) and returns a func
// that restores the previous default.
func swapDefaultLogger(buf *bytes.Buffer) func() {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	return func() { slog.SetDefault(prev) }
}
