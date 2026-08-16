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
	"testing"
	"time"
)

func newExpiryTestServer(ttl time.Duration) *OAuthServer {
	s := NewOAuthServer(
		"https://api.mctl.ai", "gh-id", "gh-secret", []byte("jwt-secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil,
	)
	s.ClientRegistrationTTL = ttl
	return s
}

// age rewrites a registration's CreatedAt so expiry can be tested without
// sleeping.
func (s *OAuthServer) age(t *testing.T, clientID string, by time.Duration) {
	t.Helper()
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		t.Fatalf("client %q not in registry", clientID)
	}
	c.CreatedAt = c.CreatedAt.Add(-by)
	s.clients[clientID] = c
}

func TestGetClient_ExpiredRegistrationReadsAsAbsent(t *testing.T) {
	s := newExpiryTestServer(time.Hour)
	c := s.RegisterClient("cli", []string{"http://127.0.0.1:1/cb"})

	if _, ok := s.GetClient(c.ClientID); !ok {
		t.Fatal("fresh registration not found")
	}
	s.age(t, c.ClientID, 2*time.Hour)
	if _, ok := s.GetClient(c.ClientID); ok {
		t.Error("expired registration still readable")
	}
	// Expiry must not depend on unrelated traffic: a quiet server has to drop
	// it on read, not wait for the next RegisterClient to sweep.
	if got := s.RegisteredClientCount(); got != 0 {
		t.Errorf("client count = %d, want the expired entry dropped on read", got)
	}
}

// The cap alone cannot bound staleness: a client that registers once per
// process on every start fills the map with dead entries, and eviction then
// discards live registrations to make room for them.
func TestRegisterClient_ExpiredEvictedBeforeLiveOnes(t *testing.T) {
	s := newExpiryTestServer(time.Hour)
	s.MaxRegisteredClients = 3

	stale := s.RegisterClient("stale", []string{"http://127.0.0.1:1/cb"})
	s.age(t, stale.ClientID, 2*time.Hour)
	live := s.RegisterClient("live", []string{"http://127.0.0.1:2/cb"})

	// Registering again must reclaim the stale slot, not the live one.
	s.RegisterClient("new", []string{"http://127.0.0.1:3/cb"})

	if _, ok := s.GetClient(stale.ClientID); ok {
		t.Error("stale registration survived")
	}
	if _, ok := s.GetClient(live.ClientID); !ok {
		t.Error("live registration was evicted while a stale one remained")
	}
}

func TestClientRegistrationTTL_NegativeDisablesExpiry(t *testing.T) {
	s := newExpiryTestServer(-1)
	c := s.RegisterClient("forever", []string{"http://127.0.0.1:1/cb"})
	s.age(t, c.ClientID, 100*24*time.Hour)
	if _, ok := s.GetClient(c.ClientID); !ok {
		t.Error("negative TTL should disable expiry entirely")
	}
}

func TestClientRegistrationTTL_ZeroSelectsDefault(t *testing.T) {
	s := newExpiryTestServer(0)
	if got := s.clientRegistrationTTL(); got != defaultClientRegistrationTTL {
		t.Errorf("clientRegistrationTTL() = %v, want %v", got, defaultClientRegistrationTTL)
	}
}

// Expiring a registration must not change what redirect URIs are acceptable.
// It only drops the per-client scoping; the static allowlist and RFC 8252
// loopback still stand on their own, and an arbitrary host still does not.
func TestExpiry_DoesNotWidenRedirectAllowlist(t *testing.T) {
	s := newExpiryTestServer(time.Hour)
	c := s.RegisterClient("cli", []string{"http://127.0.0.1:9999/cb"})
	s.age(t, c.ClientID, 2*time.Hour)

	if !s.IsRedirectURIAllowed(c.ClientID, "http://127.0.0.1:9999/cb") {
		t.Error("loopback refused after registration expiry")
	}
	if !s.IsRedirectURIAllowed(c.ClientID, "https://claude.ai/api/mcp/auth_callback") {
		t.Error("static allowlist entry refused after registration expiry")
	}
	if s.IsRedirectURIAllowed(c.ClientID, "https://evil.com/cb") {
		t.Error("expiry widened the allowlist to an arbitrary host")
	}
}

// The constructor used to claim a 7-day access token while main.go and
// IssueJWT both used 1h, so any caller that did not know to override got a
// week.
func TestNewOAuthServer_AccessTokenTTLDefault(t *testing.T) {
	s := NewOAuthServer("https://api.mctl.ai", "id", "secret", []byte("k"), nil, nil)
	if s.AccessTokenTTL != time.Hour {
		t.Errorf("AccessTokenTTL default = %v, want 1h", s.AccessTokenTTL)
	}
	if s.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("RefreshTokenTTL default = %v, want 720h", s.RefreshTokenTTL)
	}
}
