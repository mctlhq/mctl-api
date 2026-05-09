// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package audit

import (
	"strings"
	"testing"
)

func TestIsLikelySensitive(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"empty", "", false},
		{"short_plain", "info", false},
		{"short_path", "/var/log", false},
		{"short_int", "8080", false},
		{"long_random", strings.Repeat("a", 150), true},
		{"oauth_marker", "76d3c64b.oauth2v2_int_bf24d6", true},
		{"jwt_prefix", "eyJhbGciOiJIUzI1NiIs", true},
		{"github_pat", "ghp_abc123", true},
		{"github_fine_pat", "github_pat_11ABC", true},
		{"slack_bot", "xoxb-abc-123", true},
		{"bearer", "Bearer ABC123", true},
		{"cookie_blob_with_marker", "cf_clearance=xyz", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsLikelySensitive(c.val); got != c.want {
				t.Errorf("IsLikelySensitive(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestRedactEntry_EnvVarsBlock(t *testing.T) {
	e := Entry{
		Operation: "deploy-service",
		Parameters: map[string]string{
			"team_name":      "labs",
			"component_name": "kuptsi-app",
			// Mix of plain key=value (kept) and sensitive blob (masked).
			"env_vars": strings.Join([]string{
				"LOG_LEVEL=info",
				"PORT=8080",
				"UPWORK_COOKIES=W3sibmFtZSI6InZpc2l0b3JfaWQ" + strings.Repeat("X", 200),
				"GITHUB_TOKEN=ghp_abc",
				"WEB_CONCURRENCY=2",
			}, "\n"),
		},
	}
	got := RedactEntry(e)

	envOut := got.Parameters["env_vars"]
	if !strings.Contains(envOut, "LOG_LEVEL=info") {
		t.Errorf("expected LOG_LEVEL=info to pass through, got %q", envOut)
	}
	if !strings.Contains(envOut, "PORT=8080") {
		t.Errorf("expected PORT=8080 to pass through, got %q", envOut)
	}
	if !strings.Contains(envOut, "UPWORK_COOKIES=[REDACTED]") {
		t.Errorf("expected UPWORK_COOKIES to be redacted, got %q", envOut)
	}
	if !strings.Contains(envOut, "GITHUB_TOKEN=[REDACTED]") {
		t.Errorf("expected GITHUB_TOKEN to be redacted, got %q", envOut)
	}
	if !strings.Contains(envOut, "WEB_CONCURRENCY=2") {
		t.Errorf("expected WEB_CONCURRENCY=2 to pass through, got %q", envOut)
	}
	// Non-env_vars short fields untouched.
	if got.Parameters["team_name"] != "labs" {
		t.Errorf("team_name should not be mutated, got %q", got.Parameters["team_name"])
	}
}

func TestRedactEntry_StandaloneSensitiveField(t *testing.T) {
	e := Entry{
		Parameters: map[string]string{
			"safe_short":   "labs",
			"long_blob":    strings.Repeat("z", 200),
			"oauth_marker": "76d3c64b.oauth2v2_int_xyz",
		},
	}
	got := RedactEntry(e)
	if got.Parameters["safe_short"] != "labs" {
		t.Errorf("safe_short mutated: %q", got.Parameters["safe_short"])
	}
	if got.Parameters["long_blob"] != "[REDACTED]" {
		t.Errorf("long_blob not redacted: %q", got.Parameters["long_blob"])
	}
	if got.Parameters["oauth_marker"] != "[REDACTED]" {
		t.Errorf("oauth_marker not redacted: %q", got.Parameters["oauth_marker"])
	}
}

func TestRedactEntry_NilParameters(t *testing.T) {
	e := Entry{Operation: "noop"}
	got := RedactEntry(e)
	if got.Operation != "noop" {
		t.Errorf("Operation lost: %q", got.Operation)
	}
	if got.Parameters != nil {
		t.Errorf("expected nil Parameters, got %v", got.Parameters)
	}
}

func TestRedactEntry_NoMutationOfInput(t *testing.T) {
	original := Entry{
		Parameters: map[string]string{
			"env_vars": "FOO=" + strings.Repeat("a", 200),
		},
	}
	originalEnv := original.Parameters["env_vars"]
	_ = RedactEntry(original)
	if original.Parameters["env_vars"] != originalEnv {
		t.Errorf("RedactEntry mutated input map; before=%q after=%q",
			originalEnv, original.Parameters["env_vars"])
	}
}

func TestRedactEntries_Empty(t *testing.T) {
	if got := RedactEntries(nil); got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}
	if got := RedactEntries([]Entry{}); len(got) != 0 {
		t.Errorf("expected empty slice for empty input, got %v", got)
	}
}
