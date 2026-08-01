package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(0, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func loginOK(token string, leaseSeconds int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   token,
				"lease_duration": leaseSeconds,
			},
		})
	}
}

func staticJWT(jwt string) func(string) (string, error) {
	return func(string) (string, error) { return jwt, nil }
}

func TestStaticTokenProvider(t *testing.T) {
	p := NewStaticTokenProvider("s.static")
	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.static" {
		t.Fatalf("GetToken() = %q, %v; want s.static, nil", tok, err)
	}
	p.Invalidate("s.static")
	// Nothing to re-issue — a static token is all we have, so it must keep
	// being handed out rather than becoming empty.
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.static" {
		t.Fatalf("GetToken() after invalidate = %q, %v; want s.static, nil", tok, err)
	}
}

func TestKubernetesTokenProvider_LogsInAndReturnsToken(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/v1/auth/kubernetes/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role"] != "backstage" || body["jwt"] != "jwt-1" {
			t.Errorf("unexpected login body: %+v", body)
		}
		loginOK("s.k8s", 3600)(w, r)
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.k8s" {
		t.Fatalf("GetToken() = %q, %v; want s.k8s, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("login calls = %d; want 1", got)
	}
}

func TestKubernetesTokenProvider_HonoursCustomAuthPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		loginOK("s.k8s", 3600)(w, r)
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		AuthPath:  "kubernetes-preprod",
		ReadJWT:   staticJWT("jwt-1"),
	})
	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/auth/kubernetes-preprod/login" {
		t.Fatalf("path = %q; want /v1/auth/kubernetes-preprod/login", gotPath)
	}
}

func TestKubernetesTokenProvider_CachesInsteadOfLoginPerRequest(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		loginOK("s.k8s", 3600)(w, r)
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	for i := 0; i < 3; i++ {
		if _, err := p.GetToken(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("login calls = %d; want 1", got)
	}
}

func TestKubernetesTokenProvider_RelogsInAt80PercentOfLease(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.first", 100)(w, r)
		} else {
			loginOK("s.second", 100)(w, r)
		}
	}))
	defer srv.Close()

	clock := newFakeClock()
	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
		Now:       clock.Now,
	})

	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.first" {
		t.Fatalf("GetToken() = %q, %v; want s.first, nil", tok, err)
	}

	clock.Advance(79 * time.Second) // just inside the renew threshold
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.first" {
		t.Fatalf("GetToken() at +79s = %q, %v; want s.first, nil", tok, err)
	}

	clock.Advance(2 * time.Second) // now at +81s, past the 80s threshold
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.second" {
		t.Fatalf("GetToken() at +81s = %q, %v; want s.second, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls = %d; want 2", got)
	}
}

func TestKubernetesTokenProvider_ReReadsJWTOnEveryLogin(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if n == 1 {
			if body["jwt"] != "jwt-old" {
				t.Errorf("first login jwt = %q; want jwt-old", body["jwt"])
			}
			loginOK("s.first", 100)(w, r)
		} else {
			if body["jwt"] != "jwt-rotated" {
				t.Errorf("second login jwt = %q; want jwt-rotated", body["jwt"])
			}
			loginOK("s.second", 100)(w, r)
		}
	}))
	defer srv.Close()

	var jwtCalls int32
	readJWT := func(string) (string, error) {
		n := atomic.AddInt32(&jwtCalls, 1)
		if n == 1 {
			return "jwt-old", nil
		}
		return "jwt-rotated", nil
	}

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   readJWT,
		Now:       time.Now,
	})

	first, err := p.GetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.Invalidate(first)
	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&jwtCalls); got != 2 {
		t.Fatalf("readJWT calls = %d; want 2", got)
	}
}

func TestKubernetesTokenProvider_LogsInAgainAfterInvalidate(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.first", 3600)(w, r)
		} else {
			loginOK("s.second", 3600)(w, r)
		}
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	first, err := p.GetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.Invalidate(first)
	second, err := p.GetToken(context.Background())
	if err != nil || second != "s.second" {
		t.Fatalf("GetToken() after invalidate = %q, %v; want s.second, nil", second, err)
	}
}

// Several requests can each get a 403 for the same dead token. The first to
// notice refreshes; the rest must not undo that, or one revocation turns
// into a cascade of logins.
func TestKubernetesTokenProvider_IgnoresInvalidateForAlreadyReplacedToken(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.stale", 3600)(w, r)
		} else {
			loginOK("s.fresh", 3600)(w, r)
		}
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	stale, err := p.GetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.Invalidate(stale) // first straggler: this one is real
	fresh, err := p.GetToken(context.Background())
	if err != nil || fresh != "s.fresh" {
		t.Fatalf("GetToken() = %q, %v; want s.fresh, nil", fresh, err)
	}

	// Two more late 403s arriving with the old token.
	p.Invalidate(stale)
	p.Invalidate(stale)

	again, err := p.GetToken(context.Background())
	if err != nil || again != "s.fresh" {
		t.Fatalf("GetToken() after late invalidates = %q, %v; want s.fresh, nil", again, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls = %d; want 2", got)
	}
}

// Codex P2 (mctl-portal#53, 2026-08-01): a transient renewal failure — the
// Kubernetes TokenReview API blipping while Vault's KV endpoint stays up —
// must not clear the cached token if it's still valid for the rest of its
// lease, or a blip becomes an outage for every route that reads secrets.
func TestKubernetesTokenProvider_KeepsServingOldTokenWhenRenewalFailsWithinLease(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			loginOK("s.first", 100)(w, r)
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			loginOK("s.third", 100)(w, r)
		}
	}))
	defer srv.Close()

	clock := newFakeClock()
	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
		Now:       clock.Now,
	})

	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.first" {
		t.Fatalf("initial GetToken() = %q, %v; want s.first, nil", tok, err)
	}

	clock.Advance(90 * time.Second) // past the 80s renew threshold, inside the 100s lease
	tok, err = p.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() during transient renewal failure returned error: %v", err)
	}
	if tok != "s.first" {
		t.Fatalf("GetToken() during transient renewal failure = %q; want s.first (fallback)", tok)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls = %d; want 2 (renewal attempted and failed)", got)
	}

	clock.Advance(5 * time.Second)
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.third" {
		t.Fatalf("GetToken() next call = %q, %v; want s.third, nil (retry succeeds)", tok, err)
	}
}

// Once the old token's lease has actually run out, a failing renewal must
// surface the error rather than pretend a dead token is still good.
func TestKubernetesTokenProvider_ErrorsOnceLeaseTrulyExpiredAndRenewalFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.first", 100)(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	clock := newFakeClock()
	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
		Now:       clock.Now,
	})

	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(101 * time.Second) // past the token's actual 100s lease
	_, err := p.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected an error once the lease has truly expired, got nil")
	}
}

func TestKubernetesTokenProvider_IncludesVaultErrorDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{"role 'backstage' could not be found"},
		})
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})
	_, err := p.GetToken(context.Background())
	want := `vault k8s auth failed for role "backstage": HTTP 400 — role 'backstage' could not be found`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v; want %q", err, want)
	}
}

func TestKubernetesTokenProvider_ReportsStatusWhenErrorBodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})
	_, err := p.GetToken(context.Background())
	want := `vault k8s auth failed for role "backstage": HTTP 502`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v; want %q", err, want)
	}
}

func TestKubernetesTokenProvider_DoesNotStartSecondLoginWhileOneInFlight(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-release
		loginOK("s.k8s", 3600)(w, r)
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	var wg sync.WaitGroup
	results := make([]string, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = p.GetToken(context.Background())
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let both goroutines reach the in-flight wait
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil || results[i] != "s.k8s" {
			t.Fatalf("goroutine %d: got %q, %v; want s.k8s, nil", i, results[i], err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("login calls = %d; want 1", got)
	}
}

func TestKubernetesTokenProvider_AllowsFreshLoginAfterFailedOne(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		} else {
			loginOK("s.k8s", 3600)(w, r)
		}
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})

	if _, err := p.GetToken(context.Background()); err == nil {
		t.Fatal("expected the first login to fail")
	}
	// The in-flight attempt must be cleared on rejection, or the provider
	// would replay the same failure forever.
	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.k8s" {
		t.Fatalf("GetToken() after failed login = %q, %v; want s.k8s, nil", tok, err)
	}
}

func TestKubernetesTokenProvider_RejectsEmptyServiceAccountToken(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("  \n"),
	})
	_, err := p.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected an error for an empty ServiceAccount token")
	}
	if called {
		t.Fatal("expected Vault not to be called with an empty JWT")
	}
}

func TestKubernetesTokenProvider_RejectsLoginWithNoClientToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{}})
	}))
	defer srv.Close()

	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
	})
	_, err := p.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected an error when Vault returns no client_token")
	}
}

func TestKubernetesTokenProvider_FallsBackToHourlyRenewalWhenNoLease(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		loginOK("s.k8s", 0)(w, r)
	}))
	defer srv.Close()

	clock := newFakeClock()
	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
		Now:       clock.Now,
	})

	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2880*time.Second - time.Second) // 3600s * 0.8 = 2880s
	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("login calls = %d; want 1", got)
	}
	clock.Advance(2 * time.Second)
	if _, err := p.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls = %d; want 2", got)
	}
}
