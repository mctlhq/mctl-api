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
	"fmt"
	"sync"
	"testing"
)

func newRegistryTestServer(max int) *OAuthServer {
	s := NewOAuthServer(
		"https://api.mctl.ai", "gh-id", "gh-secret", []byte("jwt-secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil,
	)
	s.MaxRegisteredClients = max
	return s
}

// TestRegisterClient_CapEvictsOldest pins the memory bound on an
// unauthenticated endpoint. Before the cap the map grew for the process
// lifetime, and it grew during ordinary use: an MCP client that fans out
// across processes registers one client per process on every start.
func TestRegisterClient_CapEvictsOldest(t *testing.T) {
	s := newRegistryTestServer(3)

	first := s.RegisterClient("first", []string{"http://127.0.0.1:1/cb"})
	for i := 0; i < 5; i++ {
		s.RegisterClient(fmt.Sprintf("c%d", i), []string{"http://127.0.0.1:2/cb"})
	}

	if got := s.RegisteredClientCount(); got != 3 {
		t.Errorf("client count = %d, want it held at the cap of 3", got)
	}
	if _, ok := s.GetClient(first.ClientID); ok {
		t.Error("oldest registration survived past the cap")
	}
}

func TestRegisterClient_DefaultCapApplies(t *testing.T) {
	s := newRegistryTestServer(0) // 0 selects the default
	for i := 0; i < defaultMaxRegisteredClients+20; i++ {
		s.RegisterClient("c", []string{"http://127.0.0.1:1/cb"})
	}
	if got := s.RegisteredClientCount(); got != defaultMaxRegisteredClients {
		t.Errorf("client count = %d, want %d", got, defaultMaxRegisteredClients)
	}
}

// Eviction must not widen what redirects are accepted. A client evicted from
// the registry falls back to the static allowlist, never to "anything goes".
func TestRegisterClient_EvictionDoesNotWidenRedirectAllowlist(t *testing.T) {
	s := newRegistryTestServer(2)

	evicted := s.RegisterClient("loopback-cli", []string{"http://127.0.0.1:9999/cb"})
	for i := 0; i < 4; i++ {
		s.RegisterClient("filler", []string{"http://127.0.0.1:1/cb"})
	}
	if _, ok := s.GetClient(evicted.ClientID); ok {
		t.Fatal("test setup: client was not evicted")
	}

	// Loopback stays allowed on its own merits (RFC 8252), the static
	// allowlist still applies, and an off-allowlist host is still refused.
	if !s.IsRedirectURIAllowed(evicted.ClientID, "http://127.0.0.1:9999/cb") {
		t.Error("loopback redirect refused after eviction")
	}
	if !s.IsRedirectURIAllowed(evicted.ClientID, "https://claude.ai/api/mcp/auth_callback") {
		t.Error("static allowlist entry refused after eviction")
	}
	if s.IsRedirectURIAllowed(evicted.ClientID, "https://evil.com/cb") {
		t.Error("eviction widened the allowlist to an arbitrary host")
	}
}

// The map is written from concurrent HTTP handlers; the cap logic must not
// race. Run with -race.
func TestRegisterClient_ConcurrentRegistrationRespectsCap(t *testing.T) {
	s := newRegistryTestServer(50)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := s.RegisterClient("concurrent", []string{"http://127.0.0.1:1/cb"})
			s.GetClient(c.ClientID)
		}()
	}
	wg.Wait()
	if got := s.RegisteredClientCount(); got > 50 {
		t.Errorf("client count = %d, want it never above the cap of 50", got)
	}
}
