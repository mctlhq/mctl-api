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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/clientstore"
	"github.com/mctlhq/mctl-api/internal/auth/clientstore/clientstoretest"
)

// The two callbacks the Cloudflare MCP portal's DCR registration carries
// (mctlhq/mctl-api#395): user sign-in, and the dashboard's "Authenticate
// server" for the `api` upstream.
const (
	portalCallback = "https://mcp.mctl.ai/servers-callback"
	dashCallback   = "https://dash.cloudflare.com/6a09f637d20e1f66a8e9d45ebe778058/one/access-controls/ai-controls/mcp-server/oauth-callback/api"
)

// newPersistedServer builds a server the way main.go does once a database is
// configured: a fresh process, pointed at store. Two calls over the same store
// are a pod before and after a rollout.
func newPersistedServer(store *clientstoretest.MemoryStore) *OAuthServer {
	s := newPortalAllowlistServer()
	s.ClientStore = store
	return s
}

// newPortalAllowlistServer is the same server with no store: the in-memory
// registry.
func newPortalAllowlistServer() *OAuthServer {
	return NewOAuthServer(
		"https://api.mctl.ai", "gh-id", "gh-secret", []byte("jwt-secret"),
		[]string{portalCallback, dashCallback}, nil,
	)
}

// TestPersistedRegistration_SurvivesRestart is the acceptance of #395: a
// client that registered before a rollout still resolves after it. The
// in-memory registry fails this by construction -- see the contrast below.
func TestPersistedRegistration_SurvivesRestart(t *testing.T) {
	store := clientstoretest.New()
	before := newPersistedServer(store)
	c, err := before.RegisterDynamicClient("Cloudflare MCP Portal", []string{portalCallback, dashCallback})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	after := newPersistedServer(store) // new process, same database
	got, ok := after.GetClient(c.ClientID)
	if !ok {
		t.Fatal("registration made before the restart does not resolve after it")
	}
	if got.ClientName != "Cloudflare MCP Portal" || len(got.RedirectURIs) != 2 {
		t.Errorf("resolved client = %+v, want the registered name and both callbacks", got)
	}
	for _, uri := range []string{portalCallback, dashCallback} {
		if !after.IsRedirectURIAllowed(c.ClientID, uri) {
			t.Errorf("redirect %q refused for the restored client", uri)
		}
	}
}

// The contrast that makes the test above meaningful: without a store a
// restart forgets the client, which is the bug #395 describes.
func TestInMemoryRegistration_LostOnRestart(t *testing.T) {
	before := newPortalAllowlistServer()
	c, err := before.RegisterDynamicClient("cli", []string{portalCallback})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	after := newPortalAllowlistServer()
	if _, ok := after.GetClient(c.ClientID); ok {
		t.Fatal("in-memory registration unexpectedly survived a new server instance")
	}
}

// TestPersistedRegistration_Idempotent bounds the rows an ordinary client can
// create: the portal (or anything else) registering again with the same
// metadata gets the same client back, not another row.
func TestPersistedRegistration_Idempotent(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)

	first, err := s.RegisterDynamicClient("portal", []string{portalCallback, dashCallback})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.HasPrefix(first.ClientID, dynamicClientIDPrefix) {
		t.Errorf("client_id = %q, want the %q prefix", first.ClientID, dynamicClientIDPrefix)
	}
	// Same set in another order, with a duplicate: still the same client.
	again, err := s.RegisterDynamicClient("portal", []string{dashCallback, portalCallback, dashCallback})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again.ClientID != first.ClientID {
		t.Errorf("re-registration got %q, want the original %q", again.ClientID, first.ClientID)
	}
	if !again.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("re-registration moved client_id_issued_at from %v to %v", first.CreatedAt, again.CreatedAt)
	}
	if store.Len() != 1 {
		t.Errorf("stored clients = %d, want 1 after an idempotent re-registration", store.Len())
	}

	// A different callback set or a different name is a different client.
	other, _ := s.RegisterDynamicClient("portal", []string{portalCallback})
	named, _ := s.RegisterDynamicClient("someone else", []string{portalCallback, dashCallback})
	if other.ClientID == first.ClientID || named.ClientID == first.ClientID || other.ClientID == named.ClientID {
		t.Errorf("distinct registrations share an id: %q %q %q", first.ClientID, other.ClientID, named.ClientID)
	}
	if store.Len() != 3 {
		t.Errorf("stored clients = %d, want 3", store.Len())
	}
}

// The cap in MaxRegisteredClients is handed to the store, which trims by
// least recent use.
func TestPersistedRegistration_PassesCap(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	if _, err := s.RegisterDynamicClient("a", []string{portalCallback}); err != nil {
		t.Fatal(err)
	}
	if store.LastMax != defaultMaxRegisteredClients {
		t.Errorf("cap passed = %d, want default %d", store.LastMax, defaultMaxRegisteredClients)
	}
	s.MaxRegisteredClients = 2
	for _, name := range []string{"b", "c", "d"} {
		if _, err := s.RegisterDynamicClient(name, []string{portalCallback}); err != nil {
			t.Fatal(err)
		}
	}
	if store.Len() != 2 {
		t.Errorf("stored clients = %d, want the cap of 2", store.Len())
	}
}

// Retention runs from last use, not registration, and reads as absent before
// the GC ticker gets to it.
func TestPersistedRegistration_Retention(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	s.PersistedClientRetention = time.Hour
	c, err := s.RegisterDynamicClient("cli", []string{portalCallback})
	if err != nil {
		t.Fatal(err)
	}
	store.Age(c.ClientID, 30*time.Minute)
	if _, ok := s.GetClient(c.ClientID); !ok {
		t.Fatal("client inside retention reads as absent")
	}
	store.Age(c.ClientID, time.Hour)
	if _, ok := s.GetClient(c.ClientID); ok {
		t.Error("client past retention still resolves")
	}
	if err := s.GCPersistedClients(); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 0 {
		t.Errorf("stored clients after GC = %d, want 0", store.Len())
	}
}

// A client that registered once and only ever exchanges and refreshes -- the
// portal -- must count as live, or the cap and retention would evict exactly
// the registration #395 exists to keep.
func TestPersistedRegistration_TokenUseTouchesClient(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	c, err := s.RegisterDynamicClient("portal", []string{portalCallback})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-verifier-verifier-verifier-verifier"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code, err := s.IssueCode("alice", c.ClientID, portalCallback, challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, refresh, err := s.ExchangeCode(code, verifier, c.ClientID, portalCallback)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if store.Touches[c.ClientID] != 1 {
		t.Errorf("touches after exchange = %d, want 1", store.Touches[c.ClientID])
	}
	if _, _, err := s.RefreshAccessToken(refresh, c.ClientID); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if store.Touches[c.ClientID] != 2 {
		t.Errorf("touches after refresh = %d, want 2", store.Touches[c.ClientID])
	}
}

// A store outage is a server error, never a silently unpersisted client.
func TestPersistedRegistration_StoreErrorIsServerError(t *testing.T) {
	store := clientstoretest.New()
	store.Err = errors.New("db down")
	s := newPersistedServer(store)
	_, err := s.RegisterDynamicClient("cli", []string{portalCallback})
	if !errors.Is(err, ErrServerError) {
		t.Fatalf("err = %v, want ErrServerError", err)
	}
	if _, ok := s.GetClient(derivedClientID("cli", []string{portalCallback})); ok {
		t.Error("lookup during a store outage resolved a client")
	}
}

// A derived id must never answer for a pre-registered client.
func TestPersistedRegistration_CannotShadowStatic(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	id := derivedClientID("dyn", canonicalRedirectURIs([]string{portalCallback}))
	if err := s.AddPreregisteredClient(id, "Static", []string{portalCallback}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.RegisterDynamicClient("dyn", []string{portalCallback}); !errors.Is(err, ErrClientIDTaken) {
		t.Fatalf("err = %v, want ErrClientIDTaken", err)
	}
	if store.Len() != 0 {
		t.Errorf("stored clients = %d, want nothing written", store.Len())
	}
	if got, _ := s.GetClient(id); got.ClientName != "Static" {
		t.Errorf("static client shadowed: %+v", got)
	}
}

// Ids that cannot be in the store -- empty, or not of the derived shape --
// are answered without a query: /oauth/authorize and /oauth/register reach
// GetClient with caller-chosen values.
func TestGetClient_OnlyQueriesStoreForDerivedIDs(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	for _, id := range []string{"", "anything", "dcr_", "dcr_xyz", "dcr_" + strings.Repeat("A", 32), "dcr_" + strings.Repeat("0", 31)} {
		if _, ok := s.GetClient(id); ok {
			t.Errorf("GetClient(%q) resolved", id)
		}
	}
	if n := store.GetCount(); n != 0 {
		t.Errorf("store queried %d times for ids that cannot be stored", n)
	}
	if _, ok := s.GetClient(derivedClientID("x", []string{portalCallback})); ok {
		t.Error("unregistered derived id resolved")
	}
	if n := store.GetCount(); n != 1 {
		t.Errorf("store queried %d times for one derived id, want 1", n)
	}
}

// ClientForLog serves the failure branch of /oauth/token and must never
// reach the store.
func TestClientForLog_NeverQueriesStore(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	c, err := s.RegisterDynamicClient("portal", []string{portalCallback})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, consulted := s.ClientForLog(c.ClientID); consulted {
		t.Error("ClientForLog claims to have consulted the registry for a persisted id")
	}
	if _, found, consulted := s.ClientForLog("random"); found || !consulted {
		t.Errorf("unknown non-derived id: found=%v consulted=%v, want false/true", found, consulted)
	}
	if n := store.GetCount(); n != 0 {
		t.Errorf("ClientForLog queried the store %d times", n)
	}
	// Without a store, the in-memory answer is authoritative as before.
	mem := newPortalAllowlistServer()
	mc := mem.RegisterClient("cli", []string{portalCallback})
	if got, found, consulted := mem.ClientForLog(mc.ClientID); !found || !consulted || got.ClientName != "cli" {
		t.Errorf("in-memory ClientForLog = %+v found=%v consulted=%v", got, found, consulted)
	}
}

// blockingStore's Get blocks until its context is done, like a lookup
// against a database that has stopped answering.
type blockingStore struct{ *clientstoretest.MemoryStore }

func (b blockingStore) Get(ctx context.Context, _ string) (clientstore.Client, error) {
	<-ctx.Done()
	return clientstore.Client{}, ctx.Err()
}

// A hung database costs a GetClient caller clientLookupTimeout, not the
// store's 5s budget.
func TestGetClient_StoreLookupIsBounded(t *testing.T) {
	s := newPortalAllowlistServer()
	s.ClientStore = blockingStore{clientstoretest.New()}
	start := time.Now()
	if _, ok := s.GetClient(derivedClientID("x", []string{portalCallback})); ok {
		t.Fatal("hung lookup resolved a client")
	}
	if d := time.Since(start); d > 2*clientLookupTimeout {
		t.Errorf("GetClient took %v with a hung store, want about %v", d, clientLookupTimeout)
	}
	// The authorize-path check degrades to the allowlist, not to an error.
	if !s.IsRedirectURIAllowed(derivedClientID("x", []string{portalCallback}), portalCallback) {
		t.Error("allowlisted callback refused while the store hangs")
	}
}

// A client that completed a grant is never evicted by registration churn.
func TestPersistedRegistration_UsedClientSurvivesChurn(t *testing.T) {
	store := clientstoretest.New()
	s := newPersistedServer(store)
	s.MaxRegisteredClients = 1
	portal, err := s.RegisterDynamicClient("portal", []string{portalCallback})
	if err != nil {
		t.Fatal(err)
	}
	s.touchClient(portal.ClientID)
	for i := range 5 {
		if _, err := s.RegisterDynamicClient(strings.Repeat("n", i+1), []string{portalCallback}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.GetClient(portal.ClientID); !ok {
		t.Error("used client evicted by registration churn")
	}
	if store.Len() != 2 {
		t.Errorf("stored clients = %d, want the used one plus the cap of 1", store.Len())
	}
}
