package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Vault KV v2 reader.
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// NewClient constructs a Vault client for KV v2 reads.
func NewClient(addr, token string) *Client {
	return &Client{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// ReadKV reads secret/data/<path> and returns its key/value data.
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/secret/data/"+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
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
