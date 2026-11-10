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

package bridge

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	defaultExpiryInterval  = 30 * time.Second
	defaultExpiryMaxBatch  = 10
	overdueWarnSeconds     = 300.0
	consecutiveErrorsAlert = 3
)

// ExpirySweeper is the store view the Expirer needs.
type ExpirySweeper interface {
	ExpireDue(ctx context.Context, limit int) (int, error)
	ExpiryBacklog(ctx context.Context) (int64, float64, error)
}

// ReadEraser is optionally implemented by the ExpirySweeper: it erases the
// stored bytes of expired read results and deletes the rows 24 h later.
type ReadEraser interface {
	EraseExpiredReads(ctx context.Context, limit int) (erased, deleted int, err error)
}

// Expirer expires due commands in the background, independent of any provider
// poll. Each tick runs at most MaxBatches batches of Batch rows; a larger
// backlog continues on later ticks. There is no one-interval guarantee under
// large backlog, row locks, replica contention or database failures: progress
// is observable through Stats and the logs, which carry counts only.
type Expirer struct {
	Store      ExpirySweeper
	Interval   time.Duration
	Batch      int
	MaxBatches int

	processed    atomic.Int64
	errCount     atomic.Int64
	consecErrs   atomic.Int64
	lastSuccess  atomic.Int64 // unix seconds
	backlog      atomic.Int64
	oldestOverdu atomic.Int64 // seconds
}

// ExpiryStats is a point-in-time view of the sweep progress metrics.
type ExpiryStats struct {
	Processed         int64
	Errors            int64
	ConsecutiveErrors int64
	LastSuccess       time.Time
	Backlog           int64
	OldestOverdueSecs int64
}

// Stats returns the current progress counters.
func (e *Expirer) Stats() ExpiryStats {
	var ls time.Time
	if v := e.lastSuccess.Load(); v > 0 {
		ls = time.Unix(v, 0).UTC()
	}
	return ExpiryStats{
		Processed: e.processed.Load(), Errors: e.errCount.Load(), ConsecutiveErrors: e.consecErrs.Load(),
		LastSuccess: ls, Backlog: e.backlog.Load(), OldestOverdueSecs: e.oldestOverdu.Load(),
	}
}

// RunOnce runs one tick and returns how many commands it expired.
func (e *Expirer) RunOnce(ctx context.Context) (int, error) {
	batch := e.Batch
	if batch <= 0 {
		batch = DefaultExpiryBatch
	}
	maxBatches := e.MaxBatches
	if maxBatches <= 0 {
		maxBatches = defaultExpiryMaxBatch
	}
	total := 0
	recordError := func(err error) (int, error) {
		// Shutdown cancellation is expected, not a failed expiry sweep.
		if ctx.Err() == nil {
			e.errCount.Add(1)
			if c := e.consecErrs.Add(1); c >= consecutiveErrorsAlert {
				slog.Error("bridge expiry sweep failing persistently", "consecutive_errors", c, "error", err)
			}
		}
		return total, err
	}
	for i := 0; i < maxBatches; i++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := e.Store.ExpireDue(ctx, batch)
		if err != nil {
			return recordError(err)
		}
		total += n
		e.processed.Add(int64(n))
		if n < batch {
			break
		}
	}
	if er, ok := e.Store.(ReadEraser); ok {
		if _, _, err := er.EraseExpiredReads(ctx, batch); err != nil {
			return recordError(err)
		}
	}
	// A failed backlog query must not quietly overwrite the previous healthy
	// snapshot, clear consecutive errors, or claim this sweep succeeded.
	cnt, oldest, err := e.Store.ExpiryBacklog(ctx)
	if err != nil {
		return recordError(err)
	}
	e.backlog.Store(cnt)
	e.oldestOverdu.Store(int64(oldest))
	e.consecErrs.Store(0)
	e.lastSuccess.Store(time.Now().Unix())
	if oldest > overdueWarnSeconds {
		slog.Warn("bridge expiry backlog overdue", "backlog", cnt, "oldest_overdue_seconds", int64(oldest))
	}
	if total > 0 {
		slog.Info("bridge expiry sweep", "expired", total)
	}
	return total, nil
}

// Run loops until ctx ends.
func (e *Expirer) Run(ctx context.Context) {
	interval := e.Interval
	if interval <= 0 {
		interval = defaultExpiryInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if _, err := e.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("bridge expiry sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
