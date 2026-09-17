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
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const outboxSchema = `
CREATE TABLE IF NOT EXISTS event_outbox (
    id           BIGSERIAL PRIMARY KEY,
    event_id     TEXT NOT NULL,
    stream       TEXT NOT NULL,
    envelope     TEXT NOT NULL,
    attempts     INT NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS event_outbox_event_id ON event_outbox (event_id);
CREATE INDEX IF NOT EXISTS event_outbox_unpublished ON event_outbox (id) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS event_outbox_published_at ON event_outbox (published_at) WHERE published_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS event_outbox_lease (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
`

// OutboxRow is one envelope awaiting publication.
type OutboxRow struct {
	ID        int64
	EventID   string
	Stream    string
	Envelope  string
	Attempts  int
	CreatedAt time.Time
}

// Outbox is the durable record between accepting a webhook and publishing it.
// GitHub does not retry a failed delivery on its own, so answering 202 is only
// safe once the envelope is committed here.
type Outbox struct {
	pool *pgxpool.Pool
}

// NewOutbox connects and creates the schema.
func NewOutbox(ctx context.Context, connStr string) (*Outbox, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("event outbox: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, outboxSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("event outbox: create schema: %w", err)
	}
	return &Outbox{pool: pool}, nil
}

// Close releases the pool.
func (o *Outbox) Close() { o.pool.Close() }

// Enqueue stores an envelope once per event id. inserted=false means the same
// delivery was already accepted (a GitHub redelivery).
func (o *Outbox) Enqueue(ctx context.Context, env Envelope, stream string) (inserted bool, err error) {
	body, err := env.Marshal()
	if err != nil {
		return false, err
	}
	tag, err := o.pool.Exec(ctx,
		`INSERT INTO event_outbox (event_id, stream, envelope) VALUES ($1, $2, $3)
		 ON CONFLICT (event_id) DO NOTHING`, env.ID, stream, body)
	if err != nil {
		return false, fmt.Errorf("event outbox: insert: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

const outboxLeaseName = "relay"

// AcquireOutboxLease takes or renews the relay lease for holder. It succeeds
// when the lease is free, expired or already held by holder, and reports false
// while another replica holds it.
func (o *Outbox) AcquireOutboxLease(ctx context.Context, holder string, now time.Time, ttl time.Duration) (bool, error) {
	if holder == "" || ttl <= 0 {
		return false, errors.New("lease needs a holder and a positive ttl")
	}
	tag, err := o.pool.Exec(ctx,
		`INSERT INTO event_outbox_lease (name, holder, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
		 WHERE event_outbox_lease.holder = excluded.holder OR event_outbox_lease.expires_at < $4`,
		outboxLeaseName, holder, now.Add(ttl), now)
	if err != nil {
		return false, fmt.Errorf("event outbox: acquire lease: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReleaseOutboxLease gives the lease up if holder still owns it.
func (o *Outbox) ReleaseOutboxLease(ctx context.Context, holder string) error {
	if _, err := o.pool.Exec(ctx,
		`DELETE FROM event_outbox_lease WHERE name = $1 AND holder = $2`, outboxLeaseName, holder); err != nil {
		return fmt.Errorf("event outbox: release lease: %w", err)
	}
	return nil
}

// PendingOutbox returns unpublished rows, oldest first.
func (o *Outbox) PendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := o.pool.Query(ctx,
		`SELECT id, event_id, stream, envelope, attempts, created_at
		   FROM event_outbox WHERE published_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("event outbox: query: %w", err)
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(&r.ID, &r.EventID, &r.Stream, &r.Envelope, &r.Attempts, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("event outbox: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkOutboxPublished records a successful XADD.
func (o *Outbox) MarkOutboxPublished(ctx context.Context, id int64, at time.Time) error {
	_, err := o.pool.Exec(ctx,
		`UPDATE event_outbox SET published_at = $1, attempts = attempts + 1, last_error = '' WHERE id = $2`, at, id)
	if err != nil {
		return fmt.Errorf("event outbox: mark published: %w", err)
	}
	return nil
}

// MarkOutboxFailed records a failed attempt; the row stays pending.
func (o *Outbox) MarkOutboxFailed(ctx context.Context, id int64, reason string) error {
	reason = truncateUTF8(reason, 500)
	_, err := o.pool.Exec(ctx,
		`UPDATE event_outbox SET attempts = attempts + 1, last_error = $1
		  WHERE id = $2 AND published_at IS NULL`, reason, id)
	if err != nil {
		return fmt.Errorf("event outbox: mark failed: %w", err)
	}
	return nil
}

// PurgePublishedOutbox deletes rows published before the cutoff.
func (o *Outbox) PurgePublishedOutbox(ctx context.Context, before time.Time) (int64, error) {
	tag, err := o.pool.Exec(ctx,
		`DELETE FROM event_outbox WHERE published_at IS NOT NULL AND published_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("event outbox: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}

// OutboxBacklog counts unpublished rows.
func (o *Outbox) OutboxBacklog(ctx context.Context) (int64, error) {
	var n int64
	if err := o.pool.QueryRow(ctx, `SELECT COUNT(*) FROM event_outbox WHERE published_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("event outbox: backlog: %w", err)
	}
	return n, nil
}
