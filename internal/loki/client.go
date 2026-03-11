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

package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// LogLine represents a single log entry with its timestamp.
type LogLine struct {
	Timestamp time.Time `json:"timestamp"`
	Line      string    `json:"line"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Client queries the Loki HTTP API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Loki client pointing at baseURL (e.g. "http://loki-stack.monitoring.svc.cluster.local:3100").
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// QueryRange fetches log lines for a namespace/app in the given time window.
// namespace corresponds to the team name; app is the service name.
func (c *Client) QueryRange(ctx context.Context, namespace, app string, lines int, since time.Duration) ([]LogLine, error) {
	query := fmt.Sprintf(`{namespace=%q, app=%q}`, namespace, app)
	// Fallback: also try kubernetes_pod_name label pattern if app label absent.
	return c.query(ctx, query, lines, since)
}

// QueryNamespace fetches all logs for a namespace (any app).
func (c *Client) QueryNamespace(ctx context.Context, namespace string, lines int, since time.Duration) ([]LogLine, error) {
	query := fmt.Sprintf(`{namespace=%q}`, namespace)
	return c.query(ctx, query, lines, since)
}

func (c *Client) query(ctx context.Context, logQL string, limit int, since time.Duration) ([]LogLine, error) {
	if limit <= 0 {
		limit = 100
	}
	end := time.Now()
	start := end.Add(-since)

	params := url.Values{}
	params.Set("query", logQL)
	params.Set("limit", strconv.Itoa(limit))
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	params.Set("direction", "backward")

	reqURL := c.baseURL + "/loki/api/v1/query_range?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("loki: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("loki: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki: HTTP %d: %s", resp.StatusCode, string(body))
	}

	return parseLokiResponse(body)
}

// lokiResponse is the shape of a Loki query_range response.
type lokiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"` // [nanosecond_ts, log_line]
		} `json:"result"`
	} `json:"data"`
}

func parseLokiResponse(body []byte) ([]LogLine, error) {
	var r lokiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("loki: parse response: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("loki: response status %q", r.Status)
	}

	var lines []LogLine
	for _, stream := range r.Data.Result {
		for _, v := range stream.Values {
			if len(v) < 2 {
				continue
			}
			ns, _ := strconv.ParseInt(v[0], 10, 64)
			ts := time.Unix(0, ns).UTC()
			lines = append(lines, LogLine{
				Timestamp: ts,
				Line:      v[1],
				Labels:    stream.Stream,
			})
		}
	}

	// Sort by timestamp descending (most recent first).
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].Timestamp.After(lines[j].Timestamp)
	})

	return lines, nil
}
