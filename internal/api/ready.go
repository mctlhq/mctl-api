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
	"net/http"
	"time"
)

const readyCheckTimeout = 2 * time.Second

// ReadyCheck is a named dependency probe for /readyz. A nil Check means the
// dependency is not configured and is omitted from the fail-the-pod decision.
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

func (h *Handlers) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
	defer cancel()

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

	checks := make(map[string]string, len(probes))
	ready := true
	for _, p := range probes {
		if p.check == nil {
			checks[p.name] = "not_configured"
			continue
		}
		if err := p.check(ctx); err != nil {
			checks[p.name] = err.Error()
			ready = false
			continue
		}
		checks[p.name] = "ok"
	}

	status := "ready"
	code := http.StatusOK
	if !ready {
		status = "not ready"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status": status,
		"checks": checks,
	})
}
