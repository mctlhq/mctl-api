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

import "testing"

// Native apps bind an ephemeral loopback port (RFC 8252 §7.3), so no static
// allowlist entry can name it and the in-memory client registry forgets it on
// every pod restart. These tests pin the port-independent acceptance, and the
// boundaries that keep it from becoming an open redirect.
func TestIsRedirectURIAllowedLoopback(t *testing.T) {
	// No static entries at all: acceptance must come from the loopback rule.
	s := &OAuthServer{}

	allowed := []string{
		"http://localhost:3118/callback",  // the port Claude Code happened to pick
		"http://localhost:52341/callback", // a different one on the next run
		"http://127.0.0.1:8080/callback",
		"http://[::1]:9000/callback",
		"http://127.0.0.1/callback", // no explicit port
		"http://localhost:3118/some/other/path",
		"http://LOCALHOST:3118/callback", // host names are case-insensitive
		"http://LocalHost:3118/callback",
	}
	for _, uri := range allowed {
		if !s.IsRedirectURIAllowed(uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = false, want true — loopback redirects are port-independent", uri)
		}
	}

	rejected := []string{
		"http://evil.com/callback",           // plainly remote
		"http://localhost.evil.com/callback", // suffix trick against a naive prefix match
		"http://notlocalhost/callback",       // substring trick
		"http://127.0.0.1.evil.com/callback", // IP-looking prefix, remote host
		"https://localhost:3118/callback",    // loopback listeners are plain http
		"http://192.168.1.10:3118/callback",  // private, but not loopback
		"http://[::2]:9000/callback",         // adjacent to ::1
		"://malformed",                       // unparseable
		"http://evil.com@localhost/callback", // userinfo: Go host is localhost
		"http://user:pass@127.0.0.1/callback",
		"http://evil.com%5C@localhost/callback", // encoded backslash as userinfo
		`http://evil.com\@localhost/callback`,   // parser/browser split on '\'
	}
	for _, uri := range rejected {
		if s.IsRedirectURIAllowed(uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = true, want false", uri)
		}
	}
}

// The loopback rule is additive — it must not disturb the existing allowlist
// semantics, including the "/*" prefix form.
func TestIsRedirectURIAllowedStaticStillApplies(t *testing.T) {
	s := &OAuthServer{AllowedRedirectURIs: []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/*",
	}}

	for _, uri := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/anything/deeper",
	} {
		if !s.IsRedirectURIAllowed(uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = false, want true", uri)
		}
	}

	if s.IsRedirectURIAllowed("https://claude.ai/somewhere/else") {
		t.Error("exact-match allowlist entry matched a different path")
	}
}
