package vmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/api"
)

// Client queries VictoriaMetrics query_range endpoints.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient constructs a VictoriaMetrics client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// GetContainerUsage returns historical CPU and memory stats for a service container.
func (c *Client) GetContainerUsage(ctx context.Context, namespace, app, container string, lookback time.Duration) (api.ContainerUsageStats, error) {
	memExpr := fmt.Sprintf(`container_memory_working_set_bytes{namespace=%q,pod=~%q,container=%q}`, namespace, app+"-base-service-.*", container)
	cpuExpr := fmt.Sprintf(`sum(rate(container_cpu_usage_seconds_total{namespace=%q,pod=~%q,container=%q}[5m]))`, namespace, app+"-base-service-.*", container)

	memSamples, err := c.queryRange(ctx, memExpr, lookback, 15*time.Minute)
	if err != nil {
		return api.ContainerUsageStats{}, err
	}
	cpuSamples, err := c.queryRange(ctx, cpuExpr, lookback, 15*time.Minute)
	if err != nil {
		return api.ContainerUsageStats{}, err
	}

	stats := api.ContainerUsageStats{
		MemoryMaxBytes: maxFloat(memSamples),
		MemoryP95Bytes: p95(memSamples),
		CPUMaxCores:    maxFloat(cpuSamples),
		CPUP95Cores:    p95(cpuSamples),
		SampleCount:    maxInt(len(memSamples), len(cpuSamples)),
	}
	return stats, nil
}

func (c *Client) queryRange(ctx context.Context, expr string, lookback, step time.Duration) ([]float64, error) {
	end := time.Now().UTC()
	start := end.Add(-lookback)

	q := url.Values{}
	q.Set("query", expr)
	q.Set("start", fmt.Sprintf("%d", start.Unix()))
	q.Set("end", fmt.Sprintf("%d", end.Unix()))
	q.Set("step", fmt.Sprintf("%.0f", step.Seconds()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/query_range?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("victoriametrics request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("victoriametrics returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Values [][]interface{} `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode victoriametrics response: %w", err)
	}

	var samples []float64
	for _, series := range payload.Data.Result {
		for _, pair := range series.Values {
			if len(pair) < 2 {
				continue
			}
			text, ok := pair[1].(string)
			if !ok || text == "" {
				continue
			}
			var value float64
			if _, err := fmt.Sscanf(text, "%f", &value); err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
				samples = append(samples, value)
			}
		}
	}
	return samples, nil
}

func maxFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

func p95(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := int(math.Ceil(float64(len(sorted))*0.95)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
