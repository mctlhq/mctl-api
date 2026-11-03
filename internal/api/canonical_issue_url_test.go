package api

import "testing"

func TestCanonicalIssueURL(t *testing.T) {
	for _, tc := range []struct{ in, key, title string }{
		{"https://github.com/mctlhq/mctl-api/issues/42", "https://github.com/mctlhq/mctl-api/issues/42", "Investigate mctlhq/mctl-api#42"},
		{"https://github.com/Mctlhq/Mctl-API/issues/0042", "https://github.com/mctlhq/mctl-api/issues/42", "Investigate mctlhq/mctl-api#42"},
		{"https://github.com/mctlhq/.github/issues/7", "https://github.com/mctlhq/.github/issues/7", "Investigate mctlhq/.github#7"},
	} {
		key, title, ok := canonicalIssueURL(tc.in)
		if !ok || key != tc.key || title != tc.title {
			t.Errorf("canonicalIssueURL(%q) = %q, %q, %v; want %q, %q", tc.in, key, title, ok, tc.key, tc.title)
		}
	}
	for _, bad := range []string{"", "https://github.com/mctlhq/x/pull/1", "http://github.com/mctlhq/x/issues/1", "https://github.com/mctlhq/x/issues/99999999999999999999"} {
		if _, _, ok := canonicalIssueURL(bad); ok {
			t.Errorf("canonicalIssueURL(%q) accepted", bad)
		}
	}
}
