package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
)

// memFlowStore is a shared in-memory flowstore.Store: two OAuthServers
// holding the same instance behave like two replicas on one database.
type memFlowStore struct {
	mu      sync.Mutex
	entries map[string][]byte
	exp     map[string]time.Time
	putErr  error
	takeErr error
}

func newMemFlowStore() *memFlowStore {
	return &memFlowStore{entries: map[string][]byte{}, exp: map[string]time.Time{}}
}

func (m *memFlowStore) Put(_ context.Context, kind, key string, payload []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	k := kind + "\x00" + key
	if _, dup := m.entries[k]; dup {
		return errors.New("duplicate key")
	}
	m.entries[k], m.exp[k] = payload, time.Now().Add(ttl)
	return nil
}

func (m *memFlowStore) Take(_ context.Context, kind, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.takeErr != nil {
		return nil, false, m.takeErr
	}
	k := kind + "\x00" + key
	p, ok := m.entries[k]
	exp := m.exp[k]
	delete(m.entries, k)
	delete(m.exp, k)
	if !ok || !time.Now().Before(exp) {
		return nil, false, nil
	}
	return p, true, nil
}

func (m *memFlowStore) GC(context.Context) error { return nil }

var _ flowstore.Store = (*memFlowStore)(nil)

func twoReplicas(t *testing.T) (a, b *OAuthServer, st *memFlowStore) {
	t.Helper()
	st = newMemFlowStore()
	a, b = newTestOAuthServer(t), newTestOAuthServer(t)
	a.FlowStore, b.FlowStore = st, st
	return a, b, st
}

func TestFlowStorePendingAuthCrossesReplicas(t *testing.T) {
	a, b, _ := twoReplicas(t)
	ctx := context.Background()
	if err := a.StorePendingOIDCAuth(ctx, "z-state", PendingOIDCAuth{
		Upstream: UpstreamZitadel, ClientID: "client-1", RedirectURI: "https://client.example/callback",
		CodeChallenge: "ch", ClientState: "cs", Nonce: "n", Verifier: "v",
	}); err != nil {
		t.Fatalf("StorePendingOIDCAuth: %v", err)
	}
	p, ok, err := b.LoadPendingAuth(ctx, "z-state")
	if err != nil || !ok {
		t.Fatalf("LoadPendingAuth on the other replica = %v, %v; want found", ok, err)
	}
	if p.Upstream != UpstreamZitadel || p.ClientID != "client-1" || p.Nonce != "n" || p.Verifier != "v" || p.ClientState != "cs" {
		t.Fatalf("pending = %+v; fields lost in the round trip", p)
	}
	if _, ok, err := a.LoadPendingAuth(ctx, "z-state"); ok || err != nil {
		t.Fatalf("second load = %v, %v; a state must be consumed once across replicas", ok, err)
	}
}

func TestFlowStoreCodeCrossesReplicas(t *testing.T) {
	a, b, _ := twoReplicas(t)
	code, err := a.IssueCode(context.Background(), "dmitrii", "client-1", "https://client.example/callback",
		testPKCEChallenge(t, "verifier-1"), []string{"my-team"})
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	access, _, err := b.ExchangeCode(context.Background(), code, "verifier-1", "client-1", "https://client.example/callback")
	if err != nil {
		t.Fatalf("ExchangeCode on the other replica: %v", err)
	}
	if got := mustIssuedGroups(t, b, access); len(got) != 1 || got[0] != "my-team" {
		t.Fatalf("groups = %v, want [my-team]", got)
	}
	if _, _, err := a.ExchangeCode(context.Background(), code, "verifier-1", "client-1", "https://client.example/callback"); err == nil ||
		!strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("replayed code = %v; want invalid or expired", err)
	}
}

// A store that cannot be read is a server error, never "invalid state" or
// "invalid code": the client must not be told its grant is bad when it was
// the database that failed.
func TestFlowStoreFailuresAreServerErrors(t *testing.T) {
	ctx := context.Background()

	a, _, st := twoReplicas(t)
	st.putErr = errors.New("db down")
	if err := a.StorePendingAuth(ctx, "s", "c", "https://client.example/callback", "ch"); !errors.Is(err, ErrServerError) {
		t.Fatalf("StorePendingAuth on put failure = %v; want ErrServerError", err)
	}
	if _, err := a.IssueCode(context.Background(), "u", "c", "https://client.example/callback", "ch", nil); !errors.Is(err, ErrServerError) {
		t.Fatalf("IssueCode on put failure = %v; want ErrServerError", err)
	}

	a, _, st = twoReplicas(t)
	st.takeErr = errors.New("db down")
	if _, ok, err := a.LoadPendingAuth(ctx, "s"); ok || !errors.Is(err, ErrServerError) {
		t.Fatalf("LoadPendingAuth on take failure = %v, %v; want ErrServerError", ok, err)
	}
	if _, _, err := a.ExchangeCode(context.Background(), "code", "v", "c", "https://client.example/callback"); !errors.Is(err, ErrServerError) {
		t.Fatalf("ExchangeCode on take failure = %v; want ErrServerError", err)
	}
}

func TestFlowStoreUndecodablePayloadIsServerError(t *testing.T) {
	a, _, st := twoReplicas(t)
	_ = st.Put(context.Background(), flowstore.KindCode, "code", []byte("not json"), time.Minute)
	if _, _, err := a.ExchangeCode(context.Background(), "code", "v", "c", "https://client.example/callback"); !errors.Is(err, ErrServerError) {
		t.Fatalf("ExchangeCode on corrupt payload = %v; want ErrServerError", err)
	}
}

func TestFlowStoreKeepsCodeAndStateApart(t *testing.T) {
	a, _, _ := twoReplicas(t)
	ctx := context.Background()
	code, err := a.IssueCode(context.Background(), "u", "c", "https://client.example/callback", "ch", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.LoadPendingAuth(ctx, code); ok || err != nil {
		t.Fatalf("a code redeemed as a state = %v, %v; want not found", ok, err)
	}
}

// The client's state is returned byte for byte, even when it is not UTF-8,
// which encoding/json would otherwise rewrite.
func TestFlowStoreClientStateRoundTripsBytes(t *testing.T) {
	a, b, _ := twoReplicas(t)
	ctx := context.Background()
	raw := "st\xff\xfe-\x00ok"
	if err := a.StorePendingOIDCAuth(ctx, "z", PendingOIDCAuth{Upstream: UpstreamZitadel, ClientState: raw}); err != nil {
		t.Fatal(err)
	}
	p, ok, err := b.LoadPendingAuth(ctx, "z")
	if err != nil || !ok || p.ClientState != raw {
		t.Fatalf("ClientState = %q, %v, %v; want %q", p.ClientState, ok, err, raw)
	}
}

// deadlineStore records whether each call's context carried a deadline.
type deadlineStore struct {
	*memFlowStore
	calls   int
	missing []string
}

func (d *deadlineStore) Put(ctx context.Context, kind, key string, p []byte, ttl time.Duration) error {
	d.calls++
	if _, ok := ctx.Deadline(); !ok {
		d.missing = append(d.missing, "put "+kind)
	}
	return d.memFlowStore.Put(ctx, kind, key, p, ttl)
}

func (d *deadlineStore) Take(ctx context.Context, kind, key string) ([]byte, bool, error) {
	d.calls++
	if _, ok := ctx.Deadline(); !ok {
		d.missing = append(d.missing, "take "+kind)
	}
	return d.memFlowStore.Take(ctx, kind, key)
}

// Every shared-store round trip is bounded, even when the caller's context
// has no deadline: a hung database must not hold a sign-in open forever.
func TestFlowStoreCallsAreBounded(t *testing.T) {
	s := newTestOAuthServer(t)
	st := &deadlineStore{memFlowStore: newMemFlowStore()}
	s.FlowStore = st
	ctx := context.Background()
	_ = s.StorePendingAuth(ctx, "s", "client-1", "https://client.example/callback", "ch")
	_, _, _ = s.LoadPendingAuth(ctx, "s")
	code, _ := s.IssueCode(ctx, "u", "client-1", "https://client.example/callback", testPKCEChallenge(t, "v"), nil)
	if _, _, err := s.ExchangeCode(ctx, code, "v", "client-1", "https://client.example/callback"); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	// Both directions: every call is checked, and all four reached the store.
	if st.calls != 4 {
		t.Fatalf("store calls = %d, want 4 (two puts, two takes)", st.calls)
	}
	if len(st.missing) != 0 {
		t.Fatalf("store calls without a deadline: %v", st.missing)
	}
}
