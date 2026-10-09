package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Vault KV v2 reader.
type Client struct {
	addr   string
	tokens TokenProvider
	http   *http.Client
	// health is separate from http on purpose: a probe that reuses the
	// pooled connection of the read client inherits whatever is wrong with
	// it. Production 2026-10-09: one half-dead connection to Cloudflare kept
	// every /readyz Vault probe timing out for hours (the pod sat 0/1, so
	// api.mctl.ai answered 503) while a fresh wget from the same pod
	// succeeded. A cancelled request does not evict such a connection.
	health *http.Client
}

// healthTimeout is a hard cap on one health probe, below the kubelet's 5s
// readiness probe timeout so the answer is ours, not a kubelet timeout.
const healthTimeout = 3 * time.Second

func newHealthClient() *http.Client {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		// Something (an instrumentation wrapper, a test) replaced the default
		// transport. Build an equivalent one instead of panicking at startup.
		tr = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: healthTimeout}).DialContext,
			TLSHandshakeTimeout: healthTimeout,
		}
	}
	// A new connection per probe: one probe per 10s is cheap, and it means a
	// probe can only fail because Vault is unreachable now, never because a
	// previous connection went bad.
	tr.DisableKeepAlives = true
	return &http.Client{Transport: tr, Timeout: healthTimeout}
}

// NewClient constructs a Vault client for KV v2 reads, authenticating with a
// pre-issued static token.
func NewClient(addr, token string) *Client {
	return NewClientWithTokenProvider(addr, NewStaticTokenProvider(token))
}

// NewClientWithTokenProvider constructs a Vault client for KV v2 reads,
// authenticating via the given TokenProvider (static or Kubernetes auth).
func NewClientWithTokenProvider(addr string, tokens TokenProvider) *Client {
	return &Client{
		addr:   strings.TrimRight(addr, "/"),
		tokens: tokens,
		http:   &http.Client{Timeout: 15 * time.Second},
		health: newHealthClient(),
	}
}

// ReadKV reads secret/data/<path> and returns its key/value data.
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]string, error) {
	url := c.addr + "/v1/secret/data/" + strings.TrimLeft(path, "/")

	used, err := c.tokens.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault auth: %w", err)
	}

	resp, err := c.doRead(ctx, url, used)
	if err != nil {
		return nil, err
	}

	// A rejected token might just be lagging a rotation the caller hasn't
	// noticed yet — invalidate the exact token that was rejected and retry
	// once with a fresh one before giving up.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close() //nolint:errcheck
		c.tokens.Invalidate(used)

		var retryToken string
		if retryToken, err = c.tokens.GetToken(ctx); err != nil {
			return nil, fmt.Errorf("vault auth: %w", err)
		}
		if resp, err = c.doRead(ctx, url, retryToken); err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("vault returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode vault response: %w", err)
	}
	return payload.Data.Data, nil
}

// Health probes Vault's unauthenticated /v1/sys/health. 200 (active), 429
// (standby), 472 (DR secondary), and 473 (performance standby) all mean the
// cluster can serve traffic. 501 (uninitialized) and 503 (sealed) fail.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.health.Do(req)
	if err != nil {
		return fmt.Errorf("vault health: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests, 472, 473:
		return nil
	default:
		return fmt.Errorf("vault health: HTTP %d", resp.StatusCode)
	}
}

func (c *Client) doRead(ctx context.Context, url, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	return resp, nil
}
