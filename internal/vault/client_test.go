package vault

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type recordingProvider struct {
	tokens      []string // tokens returned by successive GetToken calls
	idx         int32
	invalidated []string
}

func (p *recordingProvider) GetToken(context.Context) (string, error) {
	i := atomic.AddInt32(&p.idx, 1) - 1
	if int(i) >= len(p.tokens) {
		return p.tokens[len(p.tokens)-1], nil
	}
	return p.tokens[i], nil
}

func (p *recordingProvider) Invalidate(rejected string) {
	p.invalidated = append(p.invalidated, rejected)
}

func vaultKVOK(data map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": data},
		})
	}
}

func TestClient_ReadKV_SendsTokenNoRetryOnSuccess(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		vaultKVOK(map[string]string{"key": "value"})(w, r)
	}))
	defer srv.Close()

	tokens := &recordingProvider{tokens: []string{"s.tok"}}
	c := NewClientWithTokenProvider(srv.URL, tokens)

	data, err := c.ReadKV(context.Background(), "teams/nfc/quirestack-api/database")
	if err != nil {
		t.Fatal(err)
	}
	if data["key"] != "value" {
		t.Fatalf("data = %+v; want key=value", data)
	}
	if gotToken != "s.tok" {
		t.Fatalf("token sent = %q; want s.tok", gotToken)
	}
	if len(tokens.invalidated) != 0 {
		t.Fatalf("invalidated = %v; want none", tokens.invalidated)
	}
}

func TestClient_ReadKV_InvalidatesAndRetriesOn403(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		tok := r.Header.Get("X-Vault-Token")
		if n == 1 {
			if tok != "s.stale" {
				t.Errorf("first request token = %q; want s.stale", tok)
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if tok != "s.fresh" {
			t.Errorf("retry token = %q; want s.fresh", tok)
		}
		vaultKVOK(map[string]string{"key": "value"})(w, r)
	}))
	defer srv.Close()

	tokens := &recordingProvider{tokens: []string{"s.stale", "s.fresh"}}
	c := NewClientWithTokenProvider(srv.URL, tokens)

	data, err := c.ReadKV(context.Background(), "teams/nfc/quirestack-api/database")
	if err != nil {
		t.Fatal(err)
	}
	if data["key"] != "value" {
		t.Fatalf("data = %+v; want key=value", data)
	}
	if len(tokens.invalidated) != 1 || tokens.invalidated[0] != "s.stale" {
		t.Fatalf("invalidated = %v; want [s.stale]", tokens.invalidated)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("requests made = %d; want 2", got)
	}
}

func TestClient_ReadKV_InvalidatesAndRetriesOn401(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		vaultKVOK(map[string]string{"key": "value"})(w, r)
	}))
	defer srv.Close()

	tokens := &recordingProvider{tokens: []string{"s.stale", "s.fresh"}}
	c := NewClientWithTokenProvider(srv.URL, tokens)

	if _, err := c.ReadKV(context.Background(), "teams/nfc/quirestack-api/database"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("requests made = %d; want 2", got)
	}
}

func TestClient_ReadKV_NoRetryOn404(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tokens := &recordingProvider{tokens: []string{"s.tok"}}
	c := NewClientWithTokenProvider(srv.URL, tokens)

	data, err := c.ReadKV(context.Background(), "teams/nfc/quirestack-api/database")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if data != nil {
		t.Fatalf("data = %+v; want nil", data)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("requests made = %d; want 1 (no retry on 404)", got)
	}
	if len(tokens.invalidated) != 0 {
		t.Fatalf("invalidated = %v; want none", tokens.invalidated)
	}
}

// A login failure raised while retrying after a 403 must propagate, not be
// swallowed.
func TestClient_ReadKV_PropagatesLoginFailureWhileRetrying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	tokens := &failingRetryProvider{first: "s.stale"}
	c := NewClientWithTokenProvider(srv.URL, tokens)

	_, err := c.ReadKV(context.Background(), "teams/nfc/quirestack-api/database")
	if err == nil {
		t.Fatal("expected an error when the retry login itself fails")
	}
}

type failingRetryProvider struct {
	first  string
	served bool
}

func (p *failingRetryProvider) GetToken(context.Context) (string, error) {
	if !p.served {
		p.served = true
		return p.first, nil
	}
	return "", context.DeadlineExceeded
}

func (p *failingRetryProvider) Invalidate(string) {}

func TestClient_Health_AcceptsStandby(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			t.Errorf("path = %s, want /v1/sys/health", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "" {
			t.Error("health probe must not send a vault token")
		}
		w.WriteHeader(http.StatusTooManyRequests) // 429 standby
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "s.unused")
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("standby health: %v", err)
	}
}

func TestClient_Health_FailsSealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "s.unused")
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("expected sealed vault to fail health")
	}
}

// A hung Vault must fail the probe within the client's own cap, not hang on
// until the kubelet gives up.
func TestClient_Health_HungServerFailsFast(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := NewClient(srv.URL, "s.unused")
	c.health.Timeout = 100 * time.Millisecond

	start := time.Now()
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("expected a hung vault to fail health")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("probe took %v, want it bounded by the client timeout", d)
	}
	if healthTimeout >= 5*time.Second {
		t.Fatalf("healthTimeout %v must stay below the kubelet's 5s probe timeout", healthTimeout)
	}
}

// Every probe must dial its own connection. A pooled connection that has gone
// bad (prod 2026-10-09) otherwise fails every later probe, and a cancelled
// request does not evict it.
func TestClient_Health_NeverReusesAConnection(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := NewClient(srv.URL, "s.unused")
	for i := 0; i < 3; i++ {
		if err := c.Health(context.Background()); err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	if got := conns.Load(); got != 3 {
		t.Fatalf("3 probes used %d connections, want 3 (one each)", got)
	}
}

// A probe that timed out must not affect the next one.
func TestClient_Health_RecoversAfterHungProbe(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	c := NewClient(srv.URL, "s.unused")
	c.health.Timeout = 100 * time.Millisecond
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("first probe should time out")
	}
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("second probe must succeed after a hung one: %v", err)
	}
}

type wrappedTransport struct{ http.RoundTripper }

// A wrapped http.DefaultTransport must not make the client constructor panic,
// and the probe client must keep its one-connection-per-probe and time cap.
func TestNewHealthClient_NonStandardDefaultTransport(t *testing.T) {
	orig := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = orig })
	http.DefaultTransport = wrappedTransport{orig}

	c := newHealthClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("health transport is %T, want *http.Transport", c.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatal("health transport must disable keep-alives")
	}
	if c.Timeout != healthTimeout {
		t.Fatalf("timeout = %v, want %v", c.Timeout, healthTimeout)
	}
}
