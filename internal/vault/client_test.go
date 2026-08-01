package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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
