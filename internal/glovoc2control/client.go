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

// Package glovoc2control is the mctl-api client for the mctl-glovo runtime
// kill switch (mctl-glovo epic #11, slice 5). The switch state lives in
// mctl-glovo's own glovo_control row; this client only asks mctl-glovo to set
// it, over an authenticated service call, and refuses to report success
// unless mctl-glovo confirms the exact state that was requested.
package glovoc2control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Path is the mctl-glovo control endpoint, relative to the base URL.
const Path = "/internal/v1/control/kill-switch"

// ErrUnknown means the switch state could not be observed or confirmed. It is
// never the same as "switched on" or "switched off".
var ErrUnknown = errors.New("glovo kill switch state unknown")

// State is the confirmed state returned by mctl-glovo.
type State struct {
	Killed bool `json:"killed"`
}

// Client calls mctl-glovo. The zero value is unusable; use New.
type Client struct {
	endpoint string
	// tokenFile holds a short-lived ZITADEL machine-user access token. It is
	// re-read on every call so a refresher sidecar can rotate it in place.
	tokenFile string
	http      *http.Client
}

// New validates the base URL and the token file path. The token itself is read
// per call (never cached, logged or echoed); an unreadable or malformed file is
// ErrUnknown at call time, not a boot failure, so a refresher that has not
// written its first token yet cannot crash-loop the API.
func New(baseURL, tokenFile string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("glovoc2control: invalid base URL")
	}
	if strings.TrimSpace(tokenFile) == "" || !filepath.IsAbs(tokenFile) {
		return nil, errors.New("glovoc2control: token file must be an absolute path")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	// Never follow redirects: the bearer token must go to the configured host only.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: u.String() + Path, tokenFile: tokenFile, http: &c}, nil
}

// SetKilled sets the switch (idempotent PUT, not a toggle) and returns the
// state mctl-glovo confirms. Any transport error, non-200 status, malformed
// body or confirmed state different from the requested one is ErrUnknown.
func (c *Client) SetKilled(ctx context.Context, killed bool) (State, error) {
	token, err := c.readToken()
	if err != nil {
		return State{}, err
	}
	body, _ := json.Marshal(State{Killed: killed})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return State{}, fmt.Errorf("%w: build request", ErrUnknown)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// Only a coarse, token-free class is kept; err itself can embed the URL.
		return State{}, fmt.Errorf("%w: transport failure (%s)", ErrUnknown, transportClass(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return State{}, fmt.Errorf("%w: upstream status %d", ErrUnknown, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return State{}, fmt.Errorf("%w: unreadable response", ErrUnknown)
	}
	var got struct {
		Killed *bool `json:"killed"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.Killed == nil {
		return State{}, fmt.Errorf("%w: malformed response", ErrUnknown)
	}
	if *got.Killed != killed {
		return State{}, fmt.Errorf("%w: confirmed state differs from request", ErrUnknown)
	}
	return State{Killed: *got.Killed}, nil
}

// readToken re-reads the machine-user token. Empty, oversized or whitespace-
// bearing content is refused: the request is never sent unauthenticated.
func (c *Client) readToken() (string, error) {
	raw, err := os.ReadFile(c.tokenFile)
	if err != nil || len(raw) > 16*1024 {
		return "", fmt.Errorf("%w: service token unreadable", ErrUnknown)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" || strings.ContainsAny(tok, "\r\n\t ") {
		return "", fmt.Errorf("%w: service token invalid", ErrUnknown)
	}
	return tok, nil
}

// transportClass names why a call failed without echoing the error text.
func transportClass(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.As(err, new(*net.OpError)):
		return "connect"
	default:
		return "other"
	}
}
