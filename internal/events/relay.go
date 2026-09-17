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

package events

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	streamMaxLen       = 10000
	auditMaxLen        = 10000
	batchSize          = 100
	safetyInterval     = 30 * time.Second
	maxBackoff         = time.Minute
	publishedRetention = 7 * 24 * time.Hour
)

// Store is the slice of *db.Store the relay needs.
type Store interface {
	PendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error)
	MarkOutboxPublished(ctx context.Context, id int64, at time.Time) error
	MarkOutboxFailed(ctx context.Context, id int64, reason string) error
	PurgePublishedOutbox(ctx context.Context, before time.Time) (int64, error)
	OutboxBacklog(ctx context.Context) (int64, error)
}

// Publisher is the transport the relay writes to.
type Publisher interface {
	XAdd(ctx context.Context, stream string, maxLen int, fields ...string) (string, error)
	Close()
}

// Relay publishes committed outbox rows to Valkey. It is woken by Notify right
// after an ingest commits and, as a safety net, every 30s -- that timer only
// drains this service's own table after a Valkey outage, it is not how events
// are discovered.
type Relay struct {
	store Store
	pub   Publisher
	now   func() time.Time
	wake  chan struct{}
	mu    sync.Mutex // one drain at a time

	published prometheus.Counter
	failures  prometheus.Counter
	backlog   prometheus.Gauge
}

// Metrics are the relay's collectors.
var (
	publishedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_api_events_published_total",
		Help: "Event envelopes published to Valkey Streams.",
	})
	publishFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_api_events_publish_failures_total",
		Help: "Failed attempts to publish an event envelope; the row stays in the outbox.",
	})
	outboxBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_api_events_outbox_backlog",
		Help: "Event envelopes accepted but not yet published.",
	})
	registerOnce sync.Once
)

// NewRelay builds a relay. register=true reports into the process-wide
// collectors on the default registry; false gives the relay its own
// unregistered collectors, so tests stay hermetic under -count and -shuffle.
func NewRelay(store Store, pub Publisher, register bool) *Relay {
	r := &Relay{
		store: store,
		pub:   pub,
		now:   time.Now,
		wake:  make(chan struct{}, 1),
	}
	if register {
		registerOnce.Do(func() {
			prometheus.MustRegister(publishedTotal, publishFailuresTotal, outboxBacklog)
		})
		r.published, r.failures, r.backlog = publishedTotal, publishFailuresTotal, outboxBacklog
		return r
	}
	r.published = prometheus.NewCounter(prometheus.CounterOpts{Name: "events_published_total"})
	r.failures = prometheus.NewCounter(prometheus.CounterOpts{Name: "events_publish_failures_total"})
	r.backlog = prometheus.NewGauge(prometheus.GaugeOpts{Name: "events_outbox_backlog"})
	return r
}

// Notify asks the relay to drain now. Never blocks.
func (r *Relay) Notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run drains until ctx is done.
func (r *Relay) Run(ctx context.Context) {
	defer r.pub.Close()
	backoff := time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()
	lastPurge := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-timer.C:
		}
		err := r.Drain(ctx)
		if n, berr := r.store.OutboxBacklog(ctx); berr == nil {
			r.backlog.Set(float64(n))
		}
		wait := safetyInterval
		if err != nil {
			slog.Warn("event relay drain failed", "err", err, "retry_in", backoff)
			wait = backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = time.Second
		}
		if now := r.now(); now.Sub(lastPurge) > time.Hour {
			if n, perr := r.store.PurgePublishedOutbox(ctx, now.Add(-publishedRetention)); perr == nil {
				lastPurge = now
				if n > 0 {
					slog.Info("event outbox purged", "rows", n)
				}
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// Drain publishes every pending row in order and stops at the first transport
// failure, so a Valkey outage costs one failed attempt per pass, not one per row.
func (r *Relay) Drain(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		rows, err := r.store.PendingOutbox(ctx, batchSize)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if _, err := r.pub.XAdd(ctx, row.Stream, streamMaxLen, "envelope", row.Envelope); err != nil {
				r.failures.Inc()
				if merr := r.store.MarkOutboxFailed(ctx, row.ID, err.Error()); merr != nil {
					slog.Warn("event outbox failure not recorded", "err", merr)
				}
				return err
			}
			published := r.now()
			if err := r.store.MarkOutboxPublished(ctx, row.ID, published); err != nil {
				// Published but not marked: the next pass publishes it again,
				// and the consumer deduplicates by envelope id.
				return err
			}
			r.published.Inc()
			r.audit(ctx, row, published)
		}
		if len(rows) < batchSize {
			return nil
		}
	}
}

func (r *Relay) audit(ctx context.Context, row OutboxRow, at time.Time) {
	id := row.EventID
	_, err := r.pub.XAdd(ctx, AuditStream, auditMaxLen,
		"stage", "published",
		"component", Source,
		"event_id", id,
		"correlation_id", id,
		"stream", row.Stream,
		"attempt", strconv.Itoa(row.Attempts+1),
		"latency_ms", strconv.FormatInt(at.Sub(row.CreatedAt).Milliseconds(), 10),
	)
	if err != nil {
		// Best effort: the audit trail must never hold delivery back.
		slog.Warn("event audit write failed", "err", err)
	}
}
