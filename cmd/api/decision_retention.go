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

package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/mctlhq/mctl-api/internal/decisions"
)

// startDecisionRetentionSweep deletes whole decisions (attempts cascade)
// recorded more than DECISIONS_RETENTION_DAYS ago, on the evidence sweep's
// interval. Unset or zero (the default) retains decisions indefinitely and
// starts no goroutine; a malformed value disables the sweep rather than
// guessing.
func startDecisionRetentionSweep(ctx context.Context, store *decisions.Store) {
	days, err := parseRetentionDays("DECISIONS_RETENTION_DAYS", os.Getenv("DECISIONS_RETENTION_DAYS"))
	if err != nil {
		slog.Error("invalid DECISIONS_RETENTION_DAYS; decisions will be retained indefinitely", "error", err)
		return
	}
	if days == 0 {
		return
	}
	maxAge := time.Duration(days) * 24 * time.Hour
	go func() {
		ticker := time.NewTicker(evidenceRetentionSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.PurgeOlderThan(ctx, maxAge)
				if err != nil {
					slog.Error("decision retention sweep failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("decision retention sweep purged decisions", "count", n, "max_age_days", days)
				}
			}
		}
	}()
}
