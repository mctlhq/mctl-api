// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const readyCheckTimeout = 2 * time.Second

// ReadyCheck is a named dependency probe for /readyz. A nil Check means the
// dependency is not configured and is reported as not_configured.
//
// Dependency probes are informational: their outcome is reported in the
// /readyz body but never changes the status code (mctl-api#536). Every replica
// probes the same shared dependencies, so letting a probe fail readiness would
// turn one dependency outage into a simultaneous not-Ready on all replicas and
// a total outage, including of endpoints that do not need that dependency.
type ReadyCheck func(ctx context.Context) error

// HTTPReady returns a probe that GETs url and succeeds on 2xx/3xx.
func HTTPReady(url string) ReadyCheck {
	return HTTPReadyWithClient(url, nil)
}

// HTTPReadyWithClient is HTTPReady with an injectable client (tests).
func HTTPReadyWithClient(url string, client *http.Client) ReadyCheck {
	if client == nil {
		client = &http.Client{Timeout: readyCheckTimeout}
	}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close() //nolint:errcheck
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode >= 400 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
}

// handleReadyz answers the kubelet readiness probe.
//
// The status code reflects only conditions local to this pod that a restart or
// reschedule could plausibly fix: a store whose one startup init failed
// (mctl-api#387). A pod that is shutting down needs no flag here: the HTTP
// server closes its listener first, so the probe is refused.
//
// The state of shared dependencies (gitops, postgres, dex, vault) is reported
// in the body under "checks", with the names of unavailable ones in
// "degraded_dependencies", so monitoring can still see it, but it does not
// affect the status code.
func (h *Handlers) handleReadyz(w http.ResponseWriter, r *http.Request) {
	type named struct {
		name  string
		check ReadyCheck
	}
	probes := []named{
		{"gitops", h.opts.GitopsReady},
		{"postgres", h.opts.PostgresReady},
		{"dex", h.opts.DexReady},
		{"vault", h.opts.VaultReady},
	}

	results := make([]string, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.check == nil {
				results[i] = "not_configured"
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
			defer cancel()
			if err := p.check(ctx); err != nil {
				slog.Warn("readyz dependency probe failed", "check", p.name, "error", err)
				results[i] = "unavailable"
				return
			}
			results[i] = "ok"
		}()
	}
	wg.Wait()

	checks := make(map[string]string, len(probes)+1)
	degraded := []string{}
	for i, p := range probes {
		checks[p.name] = results[i]
		if results[i] == "unavailable" {
			degraded = append(degraded, p.name)
		}
	}

	// ready is decided only by local conditions below.
	ready := true

	// Stores are not probed live: a store that failed its one startup init
	// stays nil until the pod restarts (mctl-api#387), so the only honest
	// readiness answer while any did is "not ready". Checked without a
	// network call, so it cannot slow the probe down.
	body := map[string]any{}
	if h.opts.StoreInitFailures == nil {
		checks["stores"] = "not_configured"
	} else if failed := h.opts.StoreInitFailures(); len(failed) > 0 {
		checks["stores"] = "init_failed"
		body["failed_stores"] = failed
		ready = false
	} else {
		checks["stores"] = "ok"
	}

	status := "ready"
	code := http.StatusOK
	if !ready {
		status = "not ready"
		code = http.StatusServiceUnavailable
	}
	body["status"] = status
	body["checks"] = checks
	body["degraded_dependencies"] = degraded
	writeJSON(w, code, body)
}
