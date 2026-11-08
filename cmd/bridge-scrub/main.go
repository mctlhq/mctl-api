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

// bridge-scrub is a manual, one-shot, bounded maintenance operation.
// It is never started by the API server or its schema bootstrap.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-api/internal/bridge"
)

func run(ctx context.Context, args []string, getenv func(string) string, output io.Writer) error {
	flags := flag.NewFlagSet("bridge-scrub", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	confirm := flags.String("confirm", "", "must equal scrub-legacy-results")
	limit := flags.Int("batch-size", 100, "maximum token-bearing results updated per transaction (1..1000)")
	maxBatches := flags.Int("max-batches", 100, "maximum transactions attempted in one invocation (1..10000)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("bridge-scrub: invalid flags: %w", err)
	}
	if flags.NArg() != 0 || *confirm != "scrub-legacy-results" {
		return errors.New("bridge-scrub: explicit --confirm=scrub-legacy-results is required")
	}
	if *limit < 1 || *limit > 1000 || *maxBatches < 1 || *maxBatches > 10000 {
		return errors.New("bridge-scrub: batch-size must be 1..1000 and max-batches 1..10000")
	}
	dbURL := getenv("MCTL_BRIDGE_SCRUB_DATABASE_URL")
	if dbURL == "" {
		return errors.New("bridge-scrub: MCTL_BRIDGE_SCRUB_DATABASE_URL is required")
	}
	store, err := bridge.NewStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("bridge-scrub: open store: %w", err)
	}
	defer store.Close()

	total := 0
	var remaining int64
	for i := 1; i <= *maxBatches; i++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("bridge-scrub: cancelled after %d rows: %w", total, err)
		}
		n, left, err := store.ScrubLegacyResultBatch(ctx, *limit)
		if err != nil {
			return fmt.Errorf("bridge-scrub: batch %d failed (processed %d rows): %w", i, total, err)
		}
		total += n
		remaining = left
		fmt.Fprintf(output, "batch=%d scrubbed=%d total_scrubbed=%d remaining=%d\n", i, n, total, remaining)
		if remaining == 0 {
			fmt.Fprintln(output, "bridge-scrub: remaining=0; verify no old writers remain before activation")
			return nil
		}
		if n == 0 {
			return fmt.Errorf("bridge-scrub: no progress with %d token-bearing rows (possibly locked); retry after inspecting contention", remaining)
		}
	}
	return fmt.Errorf("bridge-scrub: stopped at batch cap with %d token-bearing rows remaining; repeat the authorized operation", remaining)
}

func runCLI() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return run(ctx, os.Args[1:], os.Getenv, os.Stdout)
}

func main() {
	if err := runCLI(); err != nil {
		slog.Error("bridge legacy-result scrub incomplete", "error", err)
		os.Exit(1)
	}
}
