package auth

import (
	"strings"
	"testing"
	"time"
)

func newPreregServer(t *testing.T) *OAuthServer {
	t.Helper()
	return NewOAuthServer("https://api.test", "gh-id", "gh-secret", []byte("0123456789abcdef0123456789abcdef"), nil, nil)
}

// TestPreregisteredClient_SurvivesEvictionAndTTL is the property the portal
// needs: the id it stored keeps resolving no matter what the dynamic registry
// does around it.
func TestPreregisteredClient_SurvivesEvictionAndTTL(t *testing.T) {
	s := newPreregServer(t)
	s.MaxRegisteredClients = 1
	s.ClientRegistrationTTL = time.Nanosecond
	if err := s.AddPreregisteredClient("cloudflare-portal-mcp", "Portal", []string{"https://mcp.mctl.ai/servers-callback"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Churn the dynamic registry past its cap and past its TTL.
	s.RegisterClient("a", []string{"https://a.example/cb"})
	s.RegisterClient("b", []string{"https://b.example/cb"})
	time.Sleep(2 * time.Millisecond)
	c, ok := s.GetClient("cloudflare-portal-mcp")
	if !ok {
		t.Fatal("pre-registered client vanished under eviction/TTL")
	}
	if c.ClientName != "Portal" || len(c.RedirectURIs) != 1 {
		t.Fatalf("unexpected record: %+v", c)
	}
	if s.PreregisteredClientCount() != 1 {
		t.Fatalf("count = %d", s.PreregisteredClientCount())
	}
}

// TestPreregisteredClient_RedirectIsExact: the registered callback and only
// the registered callback. Near-misses that a lenient comparison would let
// through are refused, and neither the global allowlist nor the loopback
// rule can lend a static client a callback it never registered -- that is
// the isolation the documentation promises, so it is pinned with both rules
// deliberately switched on.
func TestPreregisteredClient_RedirectIsExact(t *testing.T) {
	s := newPreregServer(t)
	s.AllowedRedirectURIs = []string{"https://elsewhere.example/cb", "https://chatgpt.com/connector/oauth/*"}
	const cb = "https://mcp.mctl.ai/servers-callback"
	if err := s.AddPreregisteredClient("cloudflare-portal-mcp", "", []string{cb}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !s.IsRedirectURIAllowed("cloudflare-portal-mcp", cb) {
		t.Fatal("exact callback refused")
	}
	for _, bad := range []string{
		cb + "/", cb + "?x=1", "https://mcp.mctl.ai:8443/servers-callback",
		"http://mcp.mctl.ai/servers-callback", "https://mcp.mctl.ai/servers-callback/x",
	} {
		if s.IsRedirectURIAllowed("cloudflare-portal-mcp", bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if s.IsRedirectURIAllowed("someone-else", cb) {
		t.Error("another client_id borrowed the registration")
	}
	for _, borrowed := range []string{
		"https://elsewhere.example/cb",          // exact global entry
		"https://chatgpt.com/connector/oauth/x", // global prefix entry
		"http://127.0.0.1:43123/callback",       // loopback rule
		"http://localhost:6274/oauth/callback",  // loopback rule, named host
	} {
		if s.IsRedirectURIAllowed("cloudflare-portal-mcp", borrowed) {
			t.Errorf("static client borrowed %q from a rule that must not apply to it", borrowed)
		}
	}
	// The general rules still hold for everyone else.
	if !s.IsRedirectURIAllowed("some-dynamic-client", "https://elsewhere.example/cb") {
		t.Error("global allowlist stopped applying to non-static clients")
	}
}

// TestPreregisteredClient_RefusesAnIdADynamicClientHolds: GetClient prefers
// the static registry, so seeding over a live dynamic id would re-point that
// client at another redirect set. The method is exported and must refuse it
// rather than rely on being called first.
func TestPreregisteredClient_RefusesAnIdADynamicClientHolds(t *testing.T) {
	s := newPreregServer(t)
	dyn := s.RegisterClient("dyn", []string{"https://dyn.example/cb"})
	err := s.AddPreregisteredClient(dyn.ClientID, "", []string{"https://mcp.mctl.ai/servers-callback"})
	if err == nil || !strings.Contains(err.Error(), "dynamic registration") {
		t.Fatalf("err = %v, want refusal naming the dynamic registration", err)
	}
	if c, _ := s.GetClient(dyn.ClientID); len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://dyn.example/cb" {
		t.Fatalf("dynamic registration was altered: %+v", c)
	}
}

// TestPreregisteredClient_ShapeRules pins what a startup refuses.
func TestPreregisteredClient_ShapeRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
		uris []string
		want string
	}{
		{"empty id", "", []string{"https://x.test/cb"}, "client_id is required"},
		{"no redirect", "c", nil, "at least one redirect_uri"},
		{"relative", "c", []string{"/cb"}, "not an absolute URL"},
		{"http non-loopback", "c", []string{"http://x.test/cb"}, "scheme"},
		{"fragment", "c", []string{"https://x.test/cb#f"}, "fragment"},
		{"userinfo", "c", []string{"https://evil@x.test/cb"}, "userinfo"},
		{"backslash", "c", []string{"https://x.test\\cb"}, "backslash"},
		{"duplicate uri", "c", []string{"https://x.test/cb", "https://x.test/cb"}, "listed twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newPreregServer(t).AddPreregisteredClient(tc.id, "", tc.uris)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
	s := newPreregServer(t)
	if err := s.AddPreregisteredClient("loop", "", []string{"http://127.0.0.1:8080/cb"}); err != nil {
		t.Fatalf("loopback http must be accepted: %v", err)
	}
	if err := s.AddPreregisteredClient("loop", "", []string{"https://y.test/cb"}); err == nil || !strings.Contains(err.Error(), "duplicate client_id") {
		t.Fatalf("duplicate id accepted: %v", err)
	}
}

// TestPreregisteredClient_DynamicRegistrationCannotShadow forces the
// collision that 128 random bits would never produce on their own: the id
// source hands out the static id first, and the registry must skip it. A
// version of RegisterClient without the retry loop assigns "static" to the
// dynamic client and fails here.
func TestPreregisteredClient_DynamicRegistrationCannotShadow(t *testing.T) {
	s := newPreregServer(t)
	if err := s.AddPreregisteredClient("static", "Portal", []string{"https://mcp.mctl.ai/servers-callback"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ids := []string{"static", "static", "fresh"}
	s.newClientID = func() string { id := ids[0]; ids = ids[1:]; return id }
	c := s.RegisterClient("dyn", []string{"https://d.test/cb"})
	if c.ClientID != "fresh" {
		t.Fatalf("dynamic registration got id %q, want the first id that is not static", c.ClientID)
	}
	if len(ids) != 0 {
		t.Fatalf("id source was consulted %d times fewer than the collisions required", len(ids))
	}
	got, _ := s.GetClient("static")
	if got.ClientName != "Portal" {
		t.Fatalf("static client was shadowed: %+v", got)
	}
}
