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

	// Past both the backoff window applied after a fallback and the lease's
	// actual hard expiry — unambiguously time for a fresh, unconstrained
	// login attempt.
	clock.Advance(15 * time.Second)
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.third" {
		t.Fatalf("GetToken() next call = %q, %v; want s.third, nil (retry succeeds)", tok, err)
	}
}

// Claude P3 (mctl-api#125, 2026-08-01): a fallback must not itself trigger a
// login on every subsequent call while Vault keeps flaking — that turns a
// blip into sustained request pressure against the endpoint that's already
// unhealthy. Uses a long lease so the backoff window isn't coincidentally
// capped by hardExpiry (that interaction is exercised separately above).
func TestKubernetesTokenProvider_BacksOffAfterFallbackInsteadOfRetryingEveryCall(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			loginOK("s.first", 1000)(w, r)
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			loginOK("s.third", 1000)(w, r)
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

	clock.Advance(850 * time.Second) // past the 800s renew threshold, well inside the 1000s lease
	tok, err := p.GetToken(context.Background())
	if err != nil || tok != "s.first" {
		t.Fatalf("GetToken() during fallback = %q, %v; want s.first, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls after fallback = %d; want 2", got)
	}

	clock.Advance(10 * time.Second) // +860s: inside the backoff window
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.first" {
		t.Fatalf("GetToken() inside backoff window = %q, %v; want s.first, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("login calls inside backoff window = %d; want 2 (no re-login storm)", got)
	}

	clock.Advance(21 * time.Second) // +881s: past the backoff window, still inside the lease
	tok, err = p.GetToken(context.Background())
	if err != nil || tok != "s.third" {
		t.Fatalf("GetToken() after backoff window = %q, %v; want s.third, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("login calls after backoff window = %d; want 3", got)
	}
}

// Claude P3 (mctl-api#125, 2026-08-01): fallback must re-check that the
// cache still holds the exact token it snapshotted before serving it — a
// concurrent Invalidate() for that same token means Vault has already
// rejected it, and handing it back out defeats the point of invalidating.
func TestKubernetesTokenProvider_DoesNotResurrectATokenInvalidatedDuringRenewal(t *testing.T) {
	var calls int32
	var loginStartedOnce sync.Once
	loginStarted := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.first", 100)(w, r)
			return
		}
		if n == 2 {
			loginStartedOnce.Do(func() { close(loginStarted) })
			<-release
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	clock := newFakeClock()
	p := NewKubernetesTokenProvider(KubernetesAuthOptions{
		VaultAddr: srv.URL,
		Role:      "backstage",
		ReadJWT:   staticJWT("jwt-1"),
		Now:       clock.Now,
	})

	first, err := p.GetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	clock.Advance(90 * time.Second) // past renewAfter, inside the 100s lease

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = p.GetToken(context.Background())
	}()

	<-loginStarted
	// The in-flight renewal's request already carried `first`; a straggler
	// 403 from an earlier request arrives now and invalidates it mid-flight.
	p.Invalidate(first)
	close(release)
	wg.Wait()

	// The renewal failed, and the token it would have fallen back to was
	// invalidated while it was in flight — there is nothing left to trust,
	// so the next call must attempt a fresh login (and error, since the mock
	// keeps failing) rather than replay `first`.
	tok, err := p.GetToken(context.Background())
	if tok == "s.first" {
		t.Fatal("GetToken() resurrected a token that was invalidated during renewal")
	}
	if err == nil {
		t.Fatal("expected an error from the fresh login attempt, got nil")
	}
}

// Codex P2 (mctl-api#125, 2026-08-01): one caller's context must not cancel
// a login/renewal that other concurrent callers are waiting on, and a
// canceled caller must not block on a login it no longer cares about.
func TestKubernetesTokenProvider_OneCallersCancellationDoesNotAffectOthers(t *testing.T) {
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

	cancelCtx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	var cancelledErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, cancelledErr = p.GetToken(cancelCtx)
	}()

	var okTok string
	var okErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		okTok, okErr = p.GetToken(context.Background())
	}()

	time.Sleep(50 * time.Millisecond) // let both goroutines reach the wait
	cancel()                          // cancel only the first caller
	time.Sleep(50 * time.Millisecond) // let the cancellation actually propagate
	close(release)                    // let the shared login complete
	wg.Wait()

	if cancelledErr == nil {
		t.Fatal("expected the canceled caller to receive an error")
	}
	if okErr != nil || okTok != "s.k8s" {
		t.Fatalf("uncancelled caller got %q, %v; want s.k8s, nil", okTok, okErr)
	}

	// The background login must have completed and cached its result
	// despite the leader-or-follower cancellation — a later call should not
	// need to hit the server again.
	if tok, err := p.GetToken(context.Background()); err != nil || tok != "s.k8s" {
		t.Fatalf("GetToken() after both calls settled = %q, %v; want s.k8s, nil", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("login calls = %d; want 1 (cancellation must not trigger a duplicate login)", got)
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

// Codex P2 (mctl-api#125, 2026-08-01): a non-expiring token (lease_duration
// 0, e.g. a root-ish token) must not get an artificial hard expiry tied to
// the hourly re-login cadence. If Vault's own auth path has been flaking for
// longer than an hour, the token itself is still genuinely valid — GetToken
// should keep falling back to it, not discard it just because our own
// preferred renewal cadence has elapsed many times over.
func TestKubernetesTokenProvider_NonExpiringTokenHasNoArtificialHardExpiry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			loginOK("s.first", 0)(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{})
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

	// Advance well past the hourly renewal cadence — many hours, not just
	// past the 2880s (80% of the assumed 3600s) renew threshold — with
	// every renewal attempt failing the whole time.
	clock.Advance(10 * time.Hour)
	tok, err := p.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() after 10h of failed renewals = %v; want nil error (token is still genuinely valid)", err)
	}
	if tok != "s.first" {
		t.Fatalf("GetToken() = %q; want s.first (fallback to the still-valid non-expiring token)", tok)
	}
}
