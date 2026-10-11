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

// Package erpactsites is a stopgap, not a generic abstraction (mctl-api#486,
// owner decision 2026-10-06). It lets mctl-api call the tenant `erpact`'s own
// site-deployer HTTP API with a fixed, narrow allowlist of operations: list
// sites and create one. It exists only so the feature does not wait for
// Option B (an MCP endpoint in the deployer itself, signing in through
// ZITADEL), which remains the target (tracked in mctl-api#499); this package
// is removed once that ships. No other tenant's operations belong here — a
// second tenant with its own deployer needs its own package, not an extension
// of this one.
package erpactsites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"
)

// ErrSiteExists is returned when the deployer already has a site under the
// requested name.
var ErrSiteExists = errors.New("erpact site already exists")

// ErrBusy is returned when the deployer is already running another
// deployment and refuses a concurrent one.
var ErrBusy = errors.New("erpact deployer is busy")

// ErrUnauthenticated is returned when the deployer rejects the configured
// token.
var ErrUnauthenticated = errors.New("erpact deployer token invalid or expired")

// ErrOutcomeUnknown is returned when a create request was sent but no answer
// came back in time. The deployer does its git commit and push before it
// answers, so a slow answer is not a failed create: the site may well be on
// its way (seen in prod 2026-10-09, where a "failed" create came up ACTIVE).
// Callers must report this as unknown and point at the site listing, never
// as a failure.
var ErrOutcomeUnknown = errors.New("erpact deployer did not answer in time; the outcome is unknown")

// Site is one entry of the deployer's shared-sites list. The list also holds
// the shared namespace's own base host, which carries no lifecycle status;
// callers identify it by name, not by an empty Status, because a real site
// can be reported without a status too.
type Site struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Status  string `json:"status,omitempty"`
}

// Client calls one tenant's site-deployer. baseURL is the deployer's
// in-cluster address; token is the long-lived bearer token issued by the
// deployer's own JWT scheme (see its app/auth.py — the token has no exp
// claim the deployer checks, so there is nothing to refresh).
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	// createClient has a longer timeout than httpClient: POST /site/new
	// commits and pushes to the tenant's gitops repository before it
	// answers, which took longer than 15s in prod. It stays under
	// mctl-api's own 30s request timeout.
	createClient *http.Client
}

// NewClient creates a deployer client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		createClient: &http.Client{
			Timeout: 25 * time.Second,
		},
	}
}

// ListSites lists every site the deployer knows about, tenant sites and the
// shared namespace's own base host together. An error means the listing
// could not be observed; callers must not treat it as an empty list.
func (c *Client) ListSites(ctx context.Context) ([]Site, error) {
	body, _, err := c.do(ctx, c.httpClient, http.MethodGet, "/sites/shared", nil)
	if err != nil {
		return nil, err
	}
	var sites []Site
	if err := json.Unmarshal(body, &sites); err != nil {
		return nil, fmt.Errorf("parsing erpact deployer sites response: %w", err)
	}
	return sites, nil
}

// CreateSite asks the deployer to create a new shared site under label and
// returns the host it will be served at. label is the deployer's own name
// argument, which it prefixes with its SITE_HOST_PREFIX to form the host
// (the callers' "erpact-" prefix must already be stripped). This only starts the creation: the
// deployer commits to its gitops checkout and triggers an ArgoCD sync, then
// returns — it does not wait for the site to come up. Poll ListSites for the
// matching entry's Status to follow progress.
func (c *Client) CreateSite(ctx context.Context, label string) (host string, err error) {
	reqBody := map[string]any{
		"name":   label,
		"shared": true,
	}
	body, status, err := c.do(ctx, c.createClient, http.MethodPost, "/site/new", reqBody)
	if err != nil {
		if errors.Is(err, ErrOutcomeUnknown) {
			return "", err
		}
		// Checked against the body regardless of status: the deployer's
		// own "already exists"/"busy" wording has only been observed on
		// 400, but nothing guarantees it stays there, and misclassifying a
		// real conflict as a generic 503 would make a caller retry a
		// create that will only ever fail the same way.
		var detail struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &detail)
		switch {
		case strings.Contains(detail.Detail, "already exists"):
			return "", fmt.Errorf("%w: %s", ErrSiteExists, detail.Detail)
		case strings.Contains(detail.Detail, "busy"):
			return "", fmt.Errorf("%w: %s", ErrBusy, detail.Detail)
		case status == http.StatusBadRequest:
			return "", fmt.Errorf("erpact deployer refused site %q: %s", label, detail.Detail)
		}
		return "", err
	}
	var resp struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing erpact deployer create response: %w", err)
	}
	return resp.Host, nil
}

func (c *Client) do(ctx context.Context, httpClient *http.Client, method, path string, jsonBody any) ([]byte, int, error) {
	var reqReader io.Reader
	if jsonBody != nil {
		data, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, 0, fmt.Errorf("encoding erpact deployer request: %w", err)
		}
		reqReader = strings.NewReader(string(data))
	}
	// Records whether any request bytes left this process. A timeout before
	// that point (dial, DNS, TLS) cannot have started anything on the
	// deployer, so it is a plain failure and not an unknown outcome.
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, c.baseURL+path, reqReader)
	if err != nil {
		return nil, 0, fmt.Errorf("creating erpact deployer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// A write that timed out or was cancelled AFTER the request went out
		// may have reached the deployer and be in progress; a read, or a
		// write that never left this process, is safe to call failed.
		if method != http.MethodGet && sent.Load() && isTimeoutOrCancel(err) {
			return nil, 0, fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
		}
		return nil, 0, fmt.Errorf("erpact deployer request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Bounded: this is the tenant's own deployer, not an attacker-controlled
	// endpoint, but nothing stops an unbounded read on a misbehaving
	// response from growing without limit either.
	const maxResponseBytes = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading erpact deployer response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return body, resp.StatusCode, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return body, resp.StatusCode, fmt.Errorf("%w: %s", ErrUnauthenticated, string(body))
	case http.StatusBadRequest:
		return body, resp.StatusCode, fmt.Errorf("erpact deployer rejected the request: %s", string(body))
	default:
		return body, resp.StatusCode, fmt.Errorf("erpact deployer returned %d: %s", resp.StatusCode, string(body))
	}
}

func isTimeoutOrCancel(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
