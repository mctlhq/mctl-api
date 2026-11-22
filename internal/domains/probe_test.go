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

package domains

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/netsafe"
)

type ipResolver struct {
	addrs []string
	err   error
	calls atomic.Int32
}

func (s *ipResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	var out []netip.Addr
	for _, a := range s.addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func probeAgainst(srv *httptest.Server, res *ipResolver, onClient func([]netip.Addr)) *HTTPSProber {
	return &HTTPSProber{
		Resolver: res, Attempts: 1, Delay: time.Millisecond,
		client: func(pinned []netip.Addr) *http.Client {
			if onClient != nil {
				onClient(pinned)
			}
			c := srv.Client()
			// Reach the loopback test server whatever the name is.
			c.Transport.(*http.Transport).DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, srv.Listener.Addr().String())
			}
			return c
		},
	}
}

func TestProbe_RefusesNonPublicWithoutConnecting(t *testing.T) {
	for _, bad := range []string{
		"127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "0.0.0.0",
	} {
		t.Run(bad, func(t *testing.T) {
			res := &ipResolver{addrs: []string{"93.184.216.34", bad}} // mixed: one public, one not
			dialed := false
			p := &HTTPSProber{Resolver: res, Attempts: 3, Delay: time.Millisecond,
				client: func([]netip.Addr) *http.Client { dialed = true; return &http.Client{} }}
			err := p.Probe(context.Background(), "tenant.example.com")
			var pe *ProbeError
			if !errors.As(err, &pe) || pe.Hint != hintNonPublic {
				t.Fatalf("err = %v, want non-public refusal", err)
			}
			if dialed {
				t.Fatal("a client was built and a connection could be made to a refused answer")
			}
			if res.calls.Load() != 1 {
				t.Errorf("lookups = %d, a permanent refusal must not be retried", res.calls.Load())
			}
			if strings.Contains(pe.Hint, bad) {
				t.Errorf("hint leaks the resolved address: %q", pe.Hint)
			}
		})
	}
}

func TestProbe_UnobservableIsNotVerified(t *testing.T) {
	cases := map[string]*HTTPSProber{
		"lookup error":    {Resolver: &ipResolver{err: errors.New("servfail")}, Attempts: 1},
		"no answers":      {Resolver: &ipResolver{}, Attempts: 1},
		"ip literal host": {Resolver: &ipResolver{addrs: []string{"93.184.216.34"}}, Attempts: 1},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			host := "tenant.example.com"
			if name == "ip literal host" {
				host = "93.184.216.34"
			}
			if err := p.Probe(context.Background(), host); err == nil {
				t.Fatal("probe passed without observing the domain")
			}
		})
	}
}

func TestProbe_StatusVerdicts(t *testing.T) {
	for code, ok := range map[int]bool{200: true, 204: true, 302: true, 401: true, 403: true,
		404: false, 500: false, 502: false, 520: false, 522: false, 526: false} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		err := probeAgainst(srv, &ipResolver{addrs: []string{"93.184.216.34"}}, nil).Probe(context.Background(), "tenant.example.com")
		srv.Close()
		if (err == nil) != ok {
			t.Errorf("HTTP %d: err = %v, want pass=%v", code, err, ok)
		}
	}
}

func TestProbe_ConnectsToTheValidatedAddressesOnly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	res := &ipResolver{addrs: []string{"93.184.216.34", "2606:2800:220:1::1"}}
	var pinned []netip.Addr
	if err := probeAgainst(srv, res, func(a []netip.Addr) { pinned = a }).Probe(context.Background(), "tenant.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 2 || pinned[0].String() != "93.184.216.34" {
		t.Errorf("pinned = %v, want the validated answers", pinned)
	}
	if res.calls.Load() != 1 {
		t.Errorf("lookups = %d, want exactly 1 (no second resolution between check and connect)", res.calls.Load())
	}
}

// TestProbe_RealClientDialsPinnedAddressOnly: the production client answers
// the dialer's lookup from the validated set. A pinned loopback address (which
// Probe itself would have refused earlier) is refused by the dialer, proving
// the name is not looked up again.
func TestProbe_RealClientDialsPinnedAddressOnly(t *testing.T) {
	c := pinnedClient([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	_, err := c.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "pin-test.invalid:443")
	if !errors.Is(err, netsafe.ErrNonPublic) {
		t.Fatalf("err = %v, want ErrNonPublic from the pinned set", err)
	}
	_, err = c.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "pin-test.invalid:8080")
	if err == nil {
		t.Fatal("non-443 port dialed")
	}
}

func TestProbe_DoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/internal", http.StatusFound)
	}))
	defer srv.Close()
	if err := probeAgainst(srv, &ipResolver{addrs: []string{"93.184.216.34"}}, nil).Probe(context.Background(), "tenant.example.com"); err != nil {
		t.Fatalf("a redirect is an answer: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect target was fetched %d times", hits.Load())
	}
}

func TestProbe_BodyIsCappedAndTimeoutIsNotVerified(t *testing.T) {
	// An endless body: only the read cap lets the probe return.
	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 32<<10))
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer big.Close()
	start := time.Now()
	if err := probeAgainst(big, &ipResolver{addrs: []string{"93.184.216.34"}}, nil).Probe(context.Background(), "tenant.example.com"); err != nil {
		t.Fatalf("oversized body must be truncated, not fail the verdict: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("probe read past the body cap")
	}

	release := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer slow.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := probeAgainst(slow, &ipResolver{addrs: []string{"93.184.216.34"}}, nil).Probe(ctx, "tenant.example.com"); err == nil {
		t.Fatal("a hanging origin was reported reachable")
	}
}

func TestProbe_RetriesTransientFailure(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(520)
		}
	}))
	defer srv.Close()
	p := probeAgainst(srv, &ipResolver{addrs: []string{"93.184.216.34"}}, nil)
	p.Attempts = 3
	if err := p.Probe(context.Background(), "tenant.example.com"); err != nil {
		t.Fatalf("err = %v, want success on the third attempt", err)
	}
	if n.Load() != 3 {
		t.Errorf("attempts = %d, want 3", n.Load())
	}
	p.Attempts = 2
	n.Store(-5)
	if err := p.Probe(context.Background(), "tenant.example.com"); err == nil {
		t.Fatal("window exhausted must be not verified")
	}
}
