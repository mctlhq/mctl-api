// Copyright 2026 MCTL Authors
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

package live

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// core is the HTTP layer shared by Reader and Writer. It has no write
// method of its own: writes go through doWrite, which only Writer calls.
type core struct {
	cfg  Config
	base *url.URL
	hc   *http.Client
	ts   TokenSource
	now  func() time.Time

	mu         sync.Mutex
	customerID string
}

func newCore(cfg Config, ts TokenSource) (*core, error) {
	n, base, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if ts == nil {
		return nil, errors.New("glovolive: invalid config: token source")
	}
	rt := n.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	c := &core{cfg: n, base: base, ts: ts, now: time.Now}
	c.hc = &http.Client{
		Transport: &hostGuard{host: base.Host, next: rt},
		// A redirect is never followed: a 3xx is surfaced as unavailable, so
		// the bearer token cannot be carried to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// hostGuard refuses any request whose host is not the configured API host.
type hostGuard struct {
	host string
	next http.RoundTripper
}

func (g *hostGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != g.host {
		return nil, ErrHostNotAllowed
	}
	return g.next.RoundTrip(r)
}

type reqSpec struct {
	method   string
	path     string
	query    url.Values
	body     any
	allow404 bool
}

type result struct {
	status int
	body   []byte
}

// sendOnce performs one HTTP exchange. A non-nil error is a transport-level
// failure (no usable status); the error text never includes the URL.
func (c *core) sendOnce(ctx context.Context, rs reqSpec, token string) (result, error) {
	u := *c.base
	u.Path = rs.path
	if len(rs.query) > 0 {
		u.RawQuery = rs.query.Encode()
	}
	var rd io.Reader
	if rs.body != nil {
		raw, err := json.Marshal(rs.body)
		if err != nil {
			return result{}, ErrSchemaDrift
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, rs.method, u.String(), rd)
	if err != nil {
		return result{}, ErrUnavailable
	}
	c.setHeaders(req, token, rs.body != nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		if errors.Is(err, ErrHostNotAllowed) {
			return result{}, ErrHostNotAllowed
		}
		if ctx.Err() != nil {
			return result{}, ctx.Err()
		}
		return result{}, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return result{status: resp.StatusCode}, ctx.Err()
		}
		return result{status: resp.StatusCode}, ErrUnavailable
	}
	if int64(len(buf)) > c.cfg.MaxResponseBytes {
		return result{status: resp.StatusCode}, ErrResponseTooLarge
	}
	return result{status: resp.StatusCode, body: buf}, nil
}

func (c *core) setHeaders(req *http.Request, token string, hasBody bool) {
	h := req.Header
	h.Set("Accept", "application/json")
	if hasBody {
		h.Set("Content-Type", "application/json")
	}
	h.Set("Glovo-Api-Version", "14")
	h.Set("Glovo-App-Context", "web")
	h.Set("Glovo-App-Development-State", "prod")
	h.Set("Glovo-App-Platform", "web")
	h.Set("Glovo-App-Type", "customer")
	h.Set("Glovo-Language-Code", c.cfg.Language)
	h.Set("Glovo-Location-Country-Code", c.cfg.Delivery.CountryCode)
	h.Set("Glovo-Location-City-Code", c.cfg.Delivery.CityCode)
	h.Set("Glovo-Delivery-Location-Latitude", c.cfg.Delivery.Latitude)
	h.Set("Glovo-Delivery-Location-Longitude", c.cfg.Delivery.Longitude)
	h.Set("Glovo-Delivery-Location-Timestamp", strconv.FormatInt(c.now().UnixMilli(), 10))
	h.Set("Glovo-Delivery-Location-Accuracy", "0")
	h.Set("Glovo-Request-Id", requestID())
	h.Set("Glovo-Request-TTL", "7500")
	// No Glovo-Perseus-Consent header: the adapter never asserts marketing
	// consent on the owner's behalf (upstream sends essential_functional_marketing).
	for k, v := range c.cfg.ExtraHeaders {
		h.Set(k, v)
	}
	if token != "" {
		h.Set("Authorization", c.cfg.AuthScheme+token)
	}
}

func requestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0"
	}
	return hex.EncodeToString(b[:])
}

// classify maps a transport error to a typed cause.
func classify(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, ErrHostNotAllowed), errors.Is(err, ErrResponseTooLarge):
		return err
	default:
		return ErrUnavailable
	}
}

// statusCause maps a non-2xx status to a typed cause.
func statusCause(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrAuth
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return ErrUnavailable
	}
}

// do performs one read. On 401 it asks the TokenSource for one refresh and
// repeats the request once; a second 401 is ErrAuth. There is no other retry.
func (c *core) do(ctx context.Context, op string, rs reqSpec) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()
	tok, err := c.ts.Token(ctx)
	if err != nil || tok == "" {
		return nil, 0, unobserved(op, ErrAuth)
	}
	res, err := c.sendOnce(ctx, rs, tok)
	if err != nil {
		return nil, 0, unobserved(op, classify(err))
	}
	if res.status == http.StatusUnauthorized {
		tok, err = c.ts.Refresh(ctx)
		if err != nil || tok == "" {
			return nil, 0, unobserved(op, ErrAuth)
		}
		res, err = c.sendOnce(ctx, rs, tok)
		if err != nil {
			return nil, 0, unobserved(op, classify(err))
		}
	}
	if rs.allow404 && res.status == http.StatusNotFound {
		return nil, res.status, nil
	}
	if res.status < 200 || res.status > 299 {
		return nil, res.status, unobserved(op, statusCause(res.status))
	}
	return res.body, res.status, nil
}

// getJSON performs a read and decodes the body into v. A body that is not
// valid JSON, or has trailing data, is schema drift.
func (c *core) getJSON(ctx context.Context, op string, rs reqSpec, v any) error {
	body, _, err := c.do(ctx, op, rs)
	if err != nil {
		return err
	}
	return decode(op, body, v)
}

func decode(op string, body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return unobserved(op, ErrSchemaDrift)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return unobserved(op, ErrSchemaDrift)
	}
	return nil
}

// doWrite performs one write exactly once: no refresh, no retry. It returns
// definite=true when the provider answered with a status that proves the
// write was not applied (any 4xx) or applied (2xx); everything else
// (transport error, timeout, truncated body, 5xx, 3xx) is ambiguous.
func (c *core) doWrite(ctx context.Context, op string, rs reqSpec) (status int, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()
	tok, terr := c.ts.Token(ctx)
	if terr != nil || tok == "" {
		return 0, kindErr(op, ErrWriteRejected) // nothing was sent
	}
	res, serr := c.sendOnce(ctx, rs, tok)
	switch {
	case res.status >= 200 && res.status <= 299:
		// The body is irrelevant: the caller rereads the cart. A body read
		// failure after a 2xx status does not make the write unknown.
		return res.status, nil
	case res.status >= 400 && res.status <= 499:
		return res.status, &rejectedError{op: op, status: res.status}
	case serr != nil && res.status == 0 && errors.Is(serr, ErrHostNotAllowed):
		return 0, kindErr(op, ErrWriteRejected) // refused before sending
	default:
		return res.status, unobserved(op, ErrWriteUnknown)
	}
}

// rejectedError is a definite 4xx refusal of a write.
type rejectedError struct {
	op     string
	status int
}

func (e *rejectedError) Error() string { return "glovolive: write rejected: " + e.op }
func (e *rejectedError) Unwrap() []error {
	return []error{ErrWriteRejected, statusCause(e.status)}
}

// customer returns the numeric customer id from /v3/me, cached in memory.
func (c *core) customer(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.customerID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var me struct {
		ID flexString `json:"id"`
	}
	if err := c.getJSON(ctx, "me", reqSpec{method: http.MethodGet, path: "/v3/me"}, &me); err != nil {
		return "", err
	}
	if !validID(string(me.ID)) {
		return "", unobserved("me", ErrSchemaDrift)
	}
	c.mu.Lock()
	c.customerID = string(me.ID)
	c.mu.Unlock()
	return string(me.ID), nil
}

func pathEsc(s string) string { return url.PathEscape(s) }

func joinPath(parts ...string) string { return "/" + strings.Join(parts, "/") }
