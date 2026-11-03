package api

import "testing"

func TestCanonicalIssueURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/mctlhq/mctl-api/issues/42":   "https://github.com/mctlhq/mctl-api/issues/42",
		"https://github.com/Mctlhq/Mctl-API/issues/0042": "https://github.com/mctlhq/mctl-api/issues/42",
		"https://github.com/mctlhq/.github/issues/7":     "https://github.com/mctlhq/.github/issues/7",
	} {
		got, _, ok := canonicalIssueURL(in)
		if !ok || got != want {
			t.Errorf("canonicalIssueURL(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "https://github.com/mctlhq/x/pull/1", "http://github.com/mctlhq/x/issues/1", "https://github.com/mctlhq/x/issues/99999999999999999999"} {
		if _, _, ok := canonicalIssueURL(bad); ok {
			t.Errorf("canonicalIssueURL(%q) accepted", bad)
		}
	}
}
