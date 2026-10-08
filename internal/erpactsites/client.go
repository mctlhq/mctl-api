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
// ZITADEL), which remains the target; this package is removed once that
// ships. No other tenant's operations belong here — a second tenant with its
// own deployer needs its own package, not an extension of this one.
package erpactsites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// Site is one entry of the deployer's shared-sites list. Status is empty for
// the shared namespace's own base host, which the deployer lists alongside
// real tenant sites but never assigns a lifecycle status to (see
// filterBaseHost).
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
}

// NewClient creates a deployer client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ListSites lists every site the deployer knows about, tenant sites and the
// shared namespace's own base host together. An error means the listing
// could not be observed; callers must not treat it as an empty list.
func (c *Client) ListSites(ctx context.Context) ([]Site, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/sites/shared", nil)
	if err != nil {
		return nil, err
	}
	var sites []Site
	if err := json.Unmarshal(body, &sites); err != nil {
		return nil, fmt.Errorf("parsing erpact deployer sites response: %w", err)
	}
	return sites, nil
}

// CreateSite asks the deployer to create a new shared site under name and
// returns the host it will be served at. This only starts the creation: the
// deployer commits to its gitops checkout and triggers an ArgoCD sync, then
// returns — it does not wait for the site to come up. Poll ListSites for the
// matching entry's Status to follow progress.
func (c *Client) CreateSite(ctx context.Context, name string) (host string, err error) {
	reqBody := map[string]any{
		"name":   name,
		"shared": true,
	}
	body, status, err := c.do(ctx, http.MethodPost, "/site/new", reqBody)
	if err != nil {
		if status == http.StatusBadRequest {
			var detail struct {
				Detail string `json:"detail"`
			}
			_ = json.Unmarshal(body, &detail)
			if strings.Contains(detail.Detail, "already exists") {
				return "", fmt.Errorf("%w: %s", ErrSiteExists, detail.Detail)
			}
			if strings.Contains(detail.Detail, "busy") {
				return "", fmt.Errorf("%w: %s", ErrBusy, detail.Detail)
			}
			return "", fmt.Errorf("erpact deployer refused site %q: %s", name, detail.Detail)
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

func (c *Client) do(ctx context.Context, method, path string, jsonBody any) ([]byte, int, error) {
	var reqReader io.Reader
	if jsonBody != nil {
		data, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, 0, fmt.Errorf("encoding erpact deployer request: %w", err)
		}
		reqReader = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqReader)
	if err != nil {
		return nil, 0, fmt.Errorf("creating erpact deployer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("erpact deployer request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
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
