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
		if !s.IsRedirectURIAllowed("any-client", uri) {
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
		if s.IsRedirectURIAllowed("any-client", uri) {
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
		if !s.IsRedirectURIAllowed("any-client", uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = false, want true", uri)
		}
	}

	if s.IsRedirectURIAllowed("any-client", "https://claude.ai/somewhere/else") {
		t.Error("exact-match allowlist entry matched a different path")
	}
}

// A registration must only vouch for the client that made it. Dynamic
// registration is open, so when any registration counted for every client an
// attacker could register their own callback and then run the flow under a
// privileged client's ID to have the code delivered to them. PKCE does not
// close that — the party starting the flow picks the challenge.
func TestIsRedirectURIAllowedScopesRegistrationToItsClient(t *testing.T) {
	s := NewOAuthServer("https://api.mctl.ai", "gh", "sec", []byte("k"), nil, nil)

	victim := s.RegisterClient("mctl-cli", []string{"https://cli.example.com/cb"})
	attacker := s.RegisterClient("attacker", []string{"https://attacker.example.com/cb"})

	if !s.IsRedirectURIAllowed(victim.ClientID, "https://cli.example.com/cb") {
		t.Error("a client's own registered URI was rejected")
	}
	if !s.IsRedirectURIAllowed(attacker.ClientID, "https://attacker.example.com/cb") {
		t.Error("a client's own registered URI was rejected")
	}

	if s.IsRedirectURIAllowed(victim.ClientID, "https://attacker.example.com/cb") {
		t.Error("attacker's registered URI was accepted under the victim's client_id — cross-client redirect")
	}
	if s.IsRedirectURIAllowed("never-registered", "https://attacker.example.com/cb") {
		t.Error("a registered URI was accepted under an unknown client_id")
	}
}

func TestIsRedirectURIAllowedWildcardPrefixes(t *testing.T) {
	s := &OAuthServer{AllowedRedirectURIs: []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/*",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-*",
		"https://oauth-redirect-sandbox.googleusercontent.com/r/user_bound_custom-mcp-*",
		"https://app.example.com*", // malformed entry ending inside host, must never match subdomains or paths
	}}

	// Legitimate matching URIs.
	accepted := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/", // empty remainder on "/*" preserved
		"https://chatgpt.com/connector/oauth/callback",
		"https://chatgpt.com/connector/oauth/v2/cb",
		"https://chatgpt.com/connector/oauth/cb?state=a%2eb&other=foo.bar", // query string with dots / %2e allowed
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-281712b859b6752b580bc9da",
		"https://oauth-redirect-sandbox.googleusercontent.com/r/user_bound_custom-mcp-abc123",
	}
	for _, uri := range accepted {
		if !s.IsRedirectURIAllowed("any-client", uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = false, want true", uri)
		}
	}

	// Rejected URIs: host suffix evasion, empty remainder on delimiter-terminated prefix, dot-traversals, fragments, userinfo, non-matching hosts.
	rejected := []string{
		"https://claude.ai/somewhere/else",
		"https://app.example.com.evil.net/cb",                                   // host-suffix evasion rejected
		"https://app.example.com/cb",                                            // entry had no path prefix, rejected
		"https://chatgpt.com:8080/connector/oauth/cb",                           // port mismatch rejected
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-", // empty remainder on "-" rejected
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-../evil",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-%2e%2e/evil",
		"https://oauth-redirect.googleusercontent.com/r/other_project_id",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123#frag",
		"https://user@oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123",
		"https://evil.com/r/user_bound_custom-mcp-123",
	}
	for _, uri := range rejected {
		if s.IsRedirectURIAllowed("any-client", uri) {
			t.Errorf("IsRedirectURIAllowed(%q) = true, want false", uri)
		}
	}
}

func TestValidateRedirectPrefix(t *testing.T) {
	valid := []string{
		"https://chatgpt.com/connector/oauth/*",
		"https://antigravity.google/*",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-*",
	}
	for _, e := range valid {
		if err := ValidateRedirectPrefix(e); err != nil {
			t.Errorf("ValidateRedirectPrefix(%q) = %v, want nil", e, err)
		}
	}
	invalid := []string{
		"https://app.example.com*", // prefix ends inside the host
		"http://example.com/cb/*",  // not https
		"https://x.com/cb?a=*",     // query would be ignored by the matcher
		"https://x.com/cb#f*",      // fragment
		"https://u@x.com/cb/*",     // userinfo
		"https://x.com/*/cb/*",     // inner *
		"https://x.com/a\\b/*",     // backslash
		"https://x.com/cb",         // no trailing *
	}
	for _, e := range invalid {
		if err := ValidateRedirectPrefix(e); err == nil {
			t.Errorf("ValidateRedirectPrefix(%q) = nil, want an error", e)
		}
	}
}

func TestIsRedirectURIAllowedIgnoresMalformedWildcardEntries(t *testing.T) {
	s := &OAuthServer{AllowedRedirectURIs: []string{"https://x.com/cb?a=*"}}
	if s.IsRedirectURIAllowed("any-client", "https://x.com/cbevil") {
		t.Error("a wildcard entry with a query admitted a path it does not name")
	}
	s = &OAuthServer{AllowedRedirectURIs: []string{"https://x.com/cb/*"}}
	if s.IsRedirectURIAllowed("any-client", "https://x.com/cb/a%5Cb") {
		t.Error("a backslash in the path was accepted on a prefix match")
	}
}
