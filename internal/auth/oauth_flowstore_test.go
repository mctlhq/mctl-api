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

func (m *memFlowStore) Put(_ context.Context, kind, key string, payload []byte, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	k := kind + "\x00" + key
	if _, dup := m.entries[k]; dup {
		return errors.New("duplicate key")
	}
	m.entries[k], m.exp[k] = payload, expiresAt
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
	code, err := a.IssueCode("dmitrii", "client-1", "https://client.example/callback",
		testPKCEChallenge(t, "verifier-1"), []string{"my-team"})
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	access, _, err := b.ExchangeCode(code, "verifier-1", "client-1", "https://client.example/callback")
	if err != nil {
		t.Fatalf("ExchangeCode on the other replica: %v", err)
	}
	if got := mustIssuedGroups(t, b, access); len(got) != 1 || got[0] != "my-team" {
		t.Fatalf("groups = %v, want [my-team]", got)
	}
	if _, _, err := a.ExchangeCode(code, "verifier-1", "client-1", "https://client.example/callback"); err == nil ||
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
	if _, err := a.IssueCode("u", "c", "https://client.example/callback", "ch", nil); !errors.Is(err, ErrServerError) {
		t.Fatalf("IssueCode on put failure = %v; want ErrServerError", err)
	}

	a, _, st = twoReplicas(t)
	st.takeErr = errors.New("db down")
	if _, ok, err := a.LoadPendingAuth(ctx, "s"); ok || !errors.Is(err, ErrServerError) {
		t.Fatalf("LoadPendingAuth on take failure = %v, %v; want ErrServerError", ok, err)
	}
	if _, _, err := a.ExchangeCode("code", "v", "c", "https://client.example/callback"); !errors.Is(err, ErrServerError) {
		t.Fatalf("ExchangeCode on take failure = %v; want ErrServerError", err)
	}
}

func TestFlowStoreUndecodablePayloadIsServerError(t *testing.T) {
	a, _, st := twoReplicas(t)
	_ = st.Put(context.Background(), flowstore.KindCode, "code", []byte("not json"), time.Now().Add(time.Minute))
	if _, _, err := a.ExchangeCode("code", "v", "c", "https://client.example/callback"); !errors.Is(err, ErrServerError) {
		t.Fatalf("ExchangeCode on corrupt payload = %v; want ErrServerError", err)
	}
}

func TestFlowStoreKeepsCodeAndStateApart(t *testing.T) {
	a, _, _ := twoReplicas(t)
	ctx := context.Background()
	code, err := a.IssueCode("u", "c", "https://client.example/callback", "ch", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.LoadPendingAuth(ctx, code); ok || err != nil {
		t.Fatalf("a code redeemed as a state = %v, %v; want not found", ok, err)
	}
}
