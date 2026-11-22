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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/mctlhq/mctl-api/internal/netsafe"
)

// Prober proves that a custom domain answers over HTTPS. The hostname is
// tenant-controlled, so an implementation must be SSRF-safe; Probe returns
// nil only for a domain it actually fetched.
type Prober interface {
	Probe(ctx context.Context, host string) error
}

// ProbeError is a failed probe. Hint is safe to store on the domain row and
// show to the tenant: it never carries a resolved address or a raw
// transport error, which could describe the network around mctl-api.
type ProbeError struct{ Hint string }

func (e *ProbeError) Error() string { return "https probe: " + e.Hint }

const (
	probeBodyCap  = 64 << 10
	probeTimeout  = 5 * time.Second
	probeAttempts = 3
	probeDelay    = 3 * time.Second
)

// HTTPSProber fetches https://<host>/ once per attempt. Per attempt it
// resolves the name itself, refuses the domain if ANY answer is not a public
// address, and pins the connection to those validated addresses (no second
// resolution, so no DNS rebinding window). It follows no redirect, uses
// short timeouts, reads at most probeBodyCap bytes and only ever dials
// port 443. A domain that cannot be probed is never reported reachable.
type HTTPSProber struct {
	// Resolver defaults to the system resolver.
	Resolver netsafe.Resolver
	// Attempts and Delay bound the retry window for cert issuance and edge
	// propagation. Defaults: 3 attempts, 3s apart.
	Attempts int
	Delay    time.Duration
	// client, when set, replaces the pinned netsafe client (tests only).
	client func(pinned []netip.Addr) *http.Client
}

// pinnedClient connects only to addrs: the dialer's lookup is answered from
// the validated set, so the name is never resolved a second time.
func pinnedClient(addrs []netip.Addr) *http.Client {
	return netsafe.Client(netsafe.Options{Timeout: probeTimeout, Resolver: pinnedResolver{addrs: addrs}})
}

type pinnedResolver struct{ addrs []netip.Addr }

func (p pinnedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return p.addrs, nil
}

// Probe implements Prober.
func (p *HTTPSProber) Probe(ctx context.Context, host string) error {
	attempts, delay := p.Attempts, p.Delay
	if attempts <= 0 {
		attempts = probeAttempts
	}
	if delay <= 0 {
		delay = probeDelay
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return &ProbeError{Hint: "probe cancelled before the domain could be verified"}
			case <-time.After(delay):
			}
		}
		err = p.probeOnce(ctx, host)
		var pe *ProbeError
		if err == nil || (errors.As(err, &pe) && pe.permanent()) {
			return err
		}
	}
	return err
}

// permanent reports a refusal retrying cannot change.
func (e *ProbeError) permanent() bool { return e.Hint == hintNonPublic || e.Hint == hintBadHost }

const (
	hintNonPublic = "domain resolves to a non-public address; refusing to probe it"
	hintBadHost   = "not a probeable hostname"
)

func (p *HTTPSProber) probeOnce(ctx context.Context, host string) error {
	if _, perr := netip.ParseAddr(host); perr == nil || host == "" {
		return &ProbeError{Hint: hintBadHost}
	}
	res := p.Resolver
	if res == nil {
		res = netResolver{}
	}
	lctx, cancel := context.WithTimeout(ctx, probeTimeout)
	addrs, err := res.LookupNetIP(lctx, "ip", host)
	cancel()
	if err != nil || len(addrs) == 0 {
		return &ProbeError{Hint: "DNS lookup failed or returned no address"}
	}
	for _, a := range addrs {
		if !netsafe.PublicAddr(a) {
			return &ProbeError{Hint: hintNonPublic}
		}
	}
	var client *http.Client
	if p.client != nil {
		client = p.client(addrs)
	} else {
		client = pinnedClient(addrs)
	}
	// A redirect is judged as the answer it is, never followed.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	rctx, rcancel := context.WithTimeout(ctx, probeTimeout)
	defer rcancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return &ProbeError{Hint: hintBadHost}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &ProbeError{Hint: "no HTTPS answer: TLS handshake or connection failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyCap))
	return judgeStatus(resp.StatusCode)
}

// judgeStatus accepts what shows the origin served the host: success,
// redirects, and 401/403 from an auth-gated app. Everything else, including
// a 404 (ingress did not match the host) and any 5xx, is not verified.
func judgeStatus(code int) error {
	switch {
	case code >= 200 && code < 400, code == http.StatusUnauthorized, code == http.StatusForbidden:
		return nil
	case code == 520 || code == 526:
		return &ProbeError{Hint: fmt.Sprintf("HTTP %d: origin TLS handshake problem", code)}
	case code == 522:
		return &ProbeError{Hint: "HTTP 522: origin not reachable"}
	case code == http.StatusNotFound:
		return &ProbeError{Hint: "HTTP 404: ingress did not match the host"}
	}
	return &ProbeError{Hint: fmt.Sprintf("HTTP %d", code)}
}

type netResolver struct{}

func (netResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
