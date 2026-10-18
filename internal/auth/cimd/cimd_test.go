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

package cimd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsCIMDURL(t *testing.T) {
	ok := []string{"https://app.example.com/client.json", "https://app.example.com:443/a/b", "https://a.b/x"}
	bad := []string{
		"", "http://app.example.com/c", "https://app.example.com", "https://app.example.com/",
		"https://127.0.0.1/c", "https://[::1]/c", "https://app.example.com:8443/c",
		"https://u:p@app.example.com/c", "https://app.example.com/c?x=1", "https://app.example.com/c#f",
		"https://app.example.com/a/../c", "https://app.example.com/./c", "https://app.example.com/%2e%2e/c",
		"https://app.example.com/" + strings.Repeat("a", 512), "https://app.example.com/c?",
		"https://app.example.com\\@evil/c",
	}
	for _, s := range ok {
		if !IsCIMDURL(s) {
			t.Errorf("%q must be a CIMD URL", s)
		}
	}
	for _, s := range bad {
		if IsCIMDURL(s) {
			t.Errorf("%q must not be a CIMD URL", s)
		}
	}
}

func TestParseAllowedHosts(t *testing.T) {
	if h, err := ParseAllowedHosts("a.example.com, .Example.org"); err != nil || len(h) != 2 || h[1] != ".example.org" {
		t.Fatalf("%v %v", h, err)
	}
	for _, s := range []string{"", "  ", "a.com,,b.com", "1.2.3.4", "a.com/x", "*.a.com", "a.com:443"} {
		if _, err := ParseAllowedHosts(s); err == nil {
			t.Errorf("%q must be refused", s)
		}
	}
}

func TestRedirectAllowed(t *testing.T) {
	entries := []string{
		"https://app.example.com/cb",
		"http://127.0.0.1:8000/callback",
		"http://[::1]:9/cb?x=1",
		"http://localhost:8000/cb",
	}
	yes := []string{
		"https://app.example.com/cb",
		"http://127.0.0.1:8000/callback", "http://127.0.0.1:54321/callback", "http://127.0.0.1/callback",
		"http://[::1]:5555/cb?x=1",
		"http://localhost:8000/cb",
	}
	no := []string{
		"https://app.example.com:444/cb", "https://app.example.com/other",
		"https://127.0.0.1:5000/callback",       // scheme
		"http://127.0.0.1:5000/other",           // path
		"http://127.0.0.1:5000/callback?y=2",    // query
		"http://[::1]:5555/cb",                  // query missing
		"http://[::1]:5555/cb?x=2",              // query differs
		"http://localhost:9999/cb",              // no port exemption for localhost
		"http://[::1]:5/callback",               // other host's path
		"http://u@127.0.0.1:5000/callback",      // userinfo
		"http://127.0.0.1:5000/callback#frag",   // fragment
		"http://127.0.0.1:5000\\@evil/callback", // backslash
		"http://127.0.0.2:5000/callback",
		"",
	}
	for _, u := range yes {
		if !RedirectAllowed(entries, u) {
			t.Errorf("%q must be allowed", u)
		}
	}
	for _, u := range no {
		if RedirectAllowed(entries, u) {
			t.Errorf("%q must be refused", u)
		}
	}
	// The exemption never applies to an entry the document does not list.
	if RedirectAllowed([]string{"https://app.example.com/cb"}, "http://127.0.0.1:5000/cb") {
		t.Error("loopback not listed must be refused")
	}
}

// fixture serves a document over TLS and a client that trusts it and
// reaches it (bypassing the public-address rule, which netsafe tests cover).
type fixture struct {
	srv   *httptest.Server
	hits  atomic.Int32
	h     http.HandlerFunc
	cl    *http.Client
	url   string
	mu    sync.Mutex
	clock time.Time
}

func newFixture(t *testing.T, h http.HandlerFunc) *fixture {
	f := &fixture{h: h, clock: time.Unix(1_700_000_000, 0)}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	f.cl = &http.Client{
		Timeout: 300 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return dialTo(ctx, n, f.srv.Listener.Addr().String())
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	f.url = "https://app.example.com/client.json"
	return f
}

func (f *fixture) resolver(hosts ...string) *Resolver {
	if len(hosts) == 0 {
		hosts = []string{"app.example.com"}
	}
	return NewResolver(Options{AllowedHosts: hosts, HTTPClient: f.cl, Now: func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.clock
	}})
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

func doc(id string, extra string) string {
	return fmt.Sprintf(`{"client_id":%q,"client_name":"Demo","redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"none"%s}`, id, extra)
}

func serve(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = fmt.Fprint(w, body)
	}
}

func TestResolveOK(t *testing.T) {
	f := newFixture(t, nil)
	f.h = serve(doc(f.url, ""))
	d, err := f.resolver().Resolve(context.Background(), f.url)
	if err != nil || d.ClientName != "Demo" || len(d.RedirectURIs) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestAllowlistBeforeAnyNetwork(t *testing.T) {
	f := newFixture(t, serve("{}"))
	for _, hosts := range [][]string{nil, {"other.example.com"}, {".example.org"}, {".app.example.com"}} {
		r := f.resolver(hosts...)
		if len(hosts) == 0 {
			r = NewResolver(Options{HTTPClient: f.cl})
		}
		if _, err := r.Resolve(context.Background(), f.url); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%v: %v", hosts, err)
		}
	}
	if f.hits.Load() != 0 {
		t.Fatal("no network access before the allowlist")
	}
	if _, err := f.resolver(".example.com").Resolve(context.Background(), f.url); errors.Is(err, ErrNotAllowed) {
		t.Fatal("suffix entry must match a subdomain")
	}
}

func TestFetchFailuresFailClosed(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/x", http.StatusFound)
		},
		"media type": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, "{}")
		},
		"oversize": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"x":"`+strings.Repeat("a", 70<<10)+`"}`)
		},
		"slow": func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(600 * time.Millisecond)
		},
		"not json": serve("nope"),
		"array":    serve("[]"),
	}
	for name, h := range cases {
		f := newFixture(t, h)
		if _, err := f.resolver().Resolve(context.Background(), f.url); !errors.Is(err, ErrFetch) && !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDocumentValidation(t *testing.T) {
	f0 := newFixture(t, nil)
	id := f0.url
	cases := map[string]string{
		"other client_id":   `{"client_id":"https://evil.example.com/x","redirect_uris":["https://a/cb"],"token_endpoint_auth_method":"none"}`,
		"no redirect_uris":  fmt.Sprintf(`{"client_id":%q,"token_endpoint_auth_method":"none"}`, id),
		"empty uris":        fmt.Sprintf(`{"client_id":%q,"redirect_uris":[],"token_endpoint_auth_method":"none"}`, id),
		"relative uri":      fmt.Sprintf(`{"client_id":%q,"redirect_uris":["/cb"],"token_endpoint_auth_method":"none"}`, id),
		"not a list":        fmt.Sprintf(`{"client_id":%q,"redirect_uris":"https://a/cb","token_endpoint_auth_method":"none"}`, id),
		"wrong auth method": fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://a/cb"],"token_endpoint_auth_method":"private_key_jwt"}`, id),
		"missing method":    fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://a/cb"]}`, id),
		"client_secret":     doc(id, `,"client_secret":"s"`),
		"secret expiry":     doc(id, `,"client_secret_expires_at":0`),
		"fragment uri":      fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example.com/cb#f"],"token_endpoint_auth_method":"none"}`, id),
		"userinfo uri":      fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://u:p@app.example.com/cb"],"token_endpoint_auth_method":"none"}`, id),
		"javascript uri":    fmt.Sprintf(`{"client_id":%q,"redirect_uris":["javascript:alert(1)"],"token_endpoint_auth_method":"none"}`, id),
		"data uri":          fmt.Sprintf(`{"client_id":%q,"redirect_uris":["data:text/html,x"],"token_endpoint_auth_method":"none"}`, id),
	}
	// The scheme is an allowlist: everything but https and loopback http is
	// refused, including schemes no denylist named.
	for _, u := range []string{
		"about:blank", "filesystem:https://a/x", "jar:https://a/x!/", "intent://cb#Intent;end", "ftp://app.example.com/cb",
		"ws://app.example.com/cb", "wss://app.example.com/cb", "view-source:https://a/", "com.example.app:/cb",
		"http://app.example.com/cb", "http://localhost:8000/cb", "http://127.0.0.2/cb", "https:///cb", "HTTP://app.example.com/cb",
	} {
		cases["scheme "+u] = fmt.Sprintf(`{"client_id":%q,"redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, id, u)
	}
	for name, body := range cases {
		f := newFixture(t, serve(body))
		f.url = id
		if _, err := f.resolver().Resolve(context.Background(), id); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAllowedRedirectSchemes(t *testing.T) {
	f := newFixture(t, nil)
	uris := []string{"https://app.example.com/cb", "http://127.0.0.1:8000/cb", "http://[::1]/cb"}
	f.h = serve(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["%s"],"token_endpoint_auth_method":"none"}`, f.url, strings.Join(uris, `","`)))
	d, err := f.resolver().Resolve(context.Background(), f.url)
	if err != nil || len(d.RedirectURIs) != len(uris) {
		t.Fatalf("%v %v", d, err)
	}
}

// The two halves of the cancellation fix are pinned separately: this test
// fails without context.WithoutCancel, the next one without the ctx.Err guard.
func TestCancelledCallerStillWarmsTheCache(t *testing.T) {
	f := newFixture(t, nil)
	f.h = serve(doc(f.url, ""))
	r := f.resolver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = r.Resolve(ctx, f.url) // may succeed or fail; must not poison the cache
	if f.hits.Load() != 1 {
		t.Fatalf("the detached fetch must still run for a cancelled caller: hits = %d", f.hits.Load())
	}
	if _, err := r.Resolve(context.Background(), f.url); err != nil {
		t.Fatalf("a cancelled caller must not poison the cache: %v", err)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("the detached fetch must warm the cache for the callers behind it: hits = %d", f.hits.Load())
	}
}

func TestFailureSeenByDepartedCallerIsNotCached(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	f := newFixture(t, nil)
	f.h = func(w http.ResponseWriter, r *http.Request) {
		if f.hits.Load() == 1 {
			close(started)
			<-proceed
			w.WriteHeader(500)
			return
		}
		serve(doc(f.url, ""))(w, r)
	}
	f.cl.Timeout = 5 * time.Second
	r := f.resolver()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Resolve(ctx, f.url); done <- err }()
	<-started
	cancel()
	close(proceed)
	if err := <-done; !errors.Is(err, ErrFetch) {
		t.Fatalf("the leader must see the failure: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.url); err != nil {
		t.Fatalf("a failure seen only by a departed caller must not be cached: %v", err)
	}
	if f.hits.Load() != 2 {
		t.Fatalf("hits = %d", f.hits.Load())
	}
}

func TestDetachedFetchHasItsOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	t.Cleanup(func() { close(release) }) // runs before the server's Close
	f.cl.Timeout = 0                     // an injected client with no timeout
	r := NewResolver(Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: f.cl, FetchTimeout: 100 * time.Millisecond})
	done := make(chan error, 1)
	go func() { _, err := r.Resolve(context.Background(), f.url); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrFetch) {
			t.Fatalf("want ErrFetch, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the detached fetch is not bounded by its own deadline")
	}
}

func TestCaching(t *testing.T) {
	f := newFixture(t, nil)
	f.h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=1")
		_, _ = fmt.Fprint(w, doc(f.url, ""))
	}
	r := f.resolver()
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), f.url); err != nil {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 1 {
		t.Fatalf("hits = %d", f.hits.Load())
	}
	f.advance(2 * time.Second) // max-age is honoured, with no floor
	_, _ = r.Resolve(context.Background(), f.url)
	if f.hits.Load() != 2 {
		t.Fatalf("max-age=1 must expire after a second: hits = %d", f.hits.Load())
	}
}

func TestCacheTTL(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"":                        defaultTTL,
		"public":                  defaultTTL,
		"max-age=600":             10 * time.Minute,
		"max-age=60":              time.Minute,
		"max-age=0":               0,
		"no-store":                0,
		"No-Cache":                0,
		`no-cache="set-cookie"`:   0,
		"max-age=600, no-store":   0,
		"max-age=abc":             0,
		"max-age=-1":              0,
		"max-age=600, max-age=60": time.Minute,
		"max-age=60, max-age=600": time.Minute,
		"max-age=999999":          maxTTL,
		`max-age="120"`:           2 * time.Minute,
	} {
		if got := cacheTTL(cc); got != want {
			t.Errorf("%q: %v, want %v", cc, got, want)
		}
	}
}

func TestNoStoreDocumentIsNotCached(t *testing.T) {
	f := newFixture(t, nil)
	f.h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, doc(f.url, ""))
	}
	r := f.resolver()
	for i := 0; i < 2; i++ {
		if _, err := r.Resolve(context.Background(), f.url); err != nil {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 2 {
		t.Fatalf("a no-store document must be refetched: hits = %d", f.hits.Load())
	}
}

func TestNegativeCache(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	r := f.resolver()
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), f.url); !errors.Is(err, ErrFetch) {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 1 {
		t.Fatalf("a cached failure must not refetch: %d", f.hits.Load())
	}
	f.advance(6 * time.Minute)
	_, _ = r.Resolve(context.Background(), f.url)
	if f.hits.Load() != 2 {
		t.Fatal("failure must expire after 5 minutes")
	}
}

func TestSingleflight(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, nil)
	f.h = func(w http.ResponseWriter, r *http.Request) {
		<-release
		serve(doc(f.url, ""))(w, r)
	}
	f.cl.Timeout = 5 * time.Second
	r := f.resolver()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Resolve(context.Background(), f.url); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if f.hits.Load() != 1 {
		t.Fatalf("hits = %d", f.hits.Load())
	}
}

func TestRateLimitAndSemaphore(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	r := NewResolver(Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: f.cl, HostPerMinute: 2, Now: func() time.Time { return f.clock }})
	var limited int
	for i := 0; i < 5; i++ {
		_, err := r.Resolve(context.Background(), fmt.Sprintf("https://app.example.com/c%d", i))
		if errors.Is(err, ErrRateLimited) {
			limited++
		}
	}
	if limited != 3 || f.hits.Load() != 2 {
		t.Fatalf("limited=%d hits=%d", limited, f.hits.Load())
	}
	r2 := NewResolver(Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: f.cl, MaxConcurrent: 1})
	r2.sem <- struct{}{}
	if _, err := r2.Resolve(context.Background(), f.url); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("full semaphore must refuse: %v", err)
	}
}

func TestRateStateIsHardBounded(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	r := NewResolver(Options{AllowedHosts: []string{".example.com"}, HTTPClient: f.cl, Now: func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.clock
	}})
	// Fill the map with hosts all seen within the minute, as a .suffix entry
	// lets a caller do.
	r.mu.Lock()
	for i := 0; i < maxRateHosts; i++ {
		r.rate[fmt.Sprintf("h%d.example.com", i)] = []time.Time{f.clock}
	}
	r.mu.Unlock()
	if _, err := r.Resolve(context.Background(), "https://new.example.com/c.json"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a new host must be refused while the map is full: %v", err)
	}
	r.mu.Lock()
	n := len(r.rate)
	r.mu.Unlock()
	if n != maxRateHosts || f.hits.Load() != 0 {
		t.Fatalf("len(rate) = %d, hits = %d", n, f.hits.Load())
	}
	// A host already tracked is still served.
	if _, err := r.Resolve(context.Background(), "https://h1.example.com/c.json"); !errors.Is(err, ErrFetch) {
		t.Fatalf("a known host must be fetched: %v", err)
	}
	// Once the entries are stale they are swept and the new host gets a slot.
	f.advance(2 * time.Minute)
	if _, err := r.Resolve(context.Background(), "https://new.example.com/c.json"); !errors.Is(err, ErrFetch) {
		t.Fatalf("after the sweep the new host must be fetched: %v", err)
	}
}

func dialTo(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
