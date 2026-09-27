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
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// T13: secretMatches behavioural table. Every case must produce the same
// accept/reject outcome the pre-change staticServiceUser (token ==
// serviceToken) produced -- only the timing signal changes.
func TestSecretMatchesBehaviourTable(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		presented  string
		want       bool
	}{
		{"empty configured secret never matches", "", "anything", false},
		{"empty configured, empty presented still refuses", "", "", false},
		{"equal secrets match", "svc-token-0123456789", "svc-token-0123456789", true},
		{"same length, differs in first byte", "svc-token-0123456789", "Xvc-token-0123456789", false},
		{"same length, differs in last byte", "svc-token-0123456789", "svc-token-012345678X", false},
		{"different length, presented shorter", "svc-token-0123456789", "svc-token-0123456", false},
		{"different length, presented longer", "svc-token-0123456789", "svc-token-0123456789-extra", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := secretMatches(c.configured, c.presented); got != c.want {
				t.Errorf("secretMatches(%q, %q) = %v, want %v", c.configured, c.presented, got, c.want)
			}
			// The old plain-== outcome must agree exactly: only the timing
			// signal is a deliberate, stated behaviour change.
			if oldOutcome := c.configured != "" && c.configured == c.presented; oldOutcome != c.want {
				t.Errorf("outcome diverges from the pre-change == compare: old=%v new=%v", oldOutcome, c.want)
			}
		})
	}
}

// T14: source-scanning pin. A behavioural test cannot observe
// constant-timeness, so this reads the source of the static-secret path and
// asserts it references subtle.ConstantTimeCompare and contains no ==/!=
// comparison against a presented token. Precedent for source-scanning tests
// in this repo: TestMainWiresEveryStoreIntoReadiness (cmd/api/main_test.go)
// and TestPortalAllowlist_CoversEveryRegisteredTool
// (internal/mcp/portal_allowlist_test.go).
//
// This only scans provider_static.go, the new static-secret path every
// provider (and therefore every non-kill-switch request) routes through.
// oidc.go's staticServiceUser keeps its original plain == deliberately: it
// is the pre-registry fallback restored wholesale by
// MCTL_FEDERATION_DISABLED, and design.md's rollback notes says as much
// ("the kill switch also restores the plain == service-token compare").
// surfaceUserFor and usageWriterUserFor in oidc.go, which provider_static.go
// itself calls into, already used subtle.ConstantTimeCompare before this
// proposal; this test pins that they still do.
func TestStaticSecretPathUsesConstantTimeCompareOnly(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	staticSrc := readSourceFile(t, filepath.Join(dir, "provider_static.go"))
	if !strings.Contains(staticSrc, "subtle.ConstantTimeCompare") {
		t.Fatal("provider_static.go no longer references subtle.ConstantTimeCompare")
	}
	assertNoTokenEqualityCompare(t, "provider_static.go", staticSrc)

	oidcSrc := readSourceFile(t, filepath.Join(dir, "oidc.go"))
	if !strings.Contains(oidcSrc, "subtle.ConstantTimeCompare") {
		t.Fatal("oidc.go no longer references subtle.ConstantTimeCompare (surfaceUserFor/usageWriterUserFor)")
	}
}

func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- path is this package's own source file, derived from runtime.Caller, not user input
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// tokenEqualityPattern matches an == or != comparison where one side is an
// identifier that plausibly names a presented bearer token or secret
// (token, raw, presented, candidate, serviceToken and similar), in either
// operand position. It intentionally does not flag comparisons against a
// literal ("" or a constant), which are shape checks, not secret compares.
var tokenEqualityPattern = regexp.MustCompile(`(?i)\b(token|raw|presented|candidate\w*|servicetoken)\b\s*(==|!=)\s*\w|\w\s*(==|!=)\s*\b(token|raw|presented|candidate\w*|servicetoken)\b`)

func assertNoTokenEqualityCompare(t *testing.T, file, src string) {
	t.Helper()
	for _, m := range tokenEqualityPattern.FindAllString(src, -1) {
		// "configured == \"\"" style empty-secret guards are shape checks,
		// not a comparison against the presented token; only flag matches
		// that are not that specific guard.
		if strings.Contains(m, `""`) {
			continue
		}
		t.Errorf("%s: found a plain equality compare against what looks like a presented token: %q", file, m)
	}
}
