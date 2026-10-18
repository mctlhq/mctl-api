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

package flowstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS oauth_flow_entries (
    kind       TEXT        NOT NULL,
    key_hash   BYTEA       NOT NULL,
    payload    BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (kind, key_hash)
);
CREATE INDEX IF NOT EXISTS oauth_flow_entries_expires
    ON oauth_flow_entries (expires_at);
`

// PostgresStore is a Postgres-backed implementation of Store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a PostgresStore and auto-creates the schema.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("oauth flow store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("oauth flow store: create schema: %w", err)
	}
	slog.Info("oauth flow store initialized")
	return &PostgresStore{pool: pool}, nil
}

func keyHash(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// Put stores a new entry. Keys are random, so a conflict means a reused key,
// which is refused rather than overwritten.
func (s *PostgresStore) Put(ctx context.Context, kind, key string, payload []byte, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_flow_entries (kind, key_hash, payload, expires_at)
		 VALUES ($1, $2, $3, now() + $4::bigint * interval '1 microsecond')`,
		kind, keyHash(key), payload, ttl.Microseconds())
	if err != nil {
		return fmt.Errorf("oauth flow store: put %s: %w", kind, err)
	}
	return nil
}

// PutOnce inserts the entry, or replaces one that has expired but not yet
// been collected, in one statement. A live row leaves the conflict update's
// WHERE false, so no row is returned and the key is reported as taken.
func (s *PostgresStore) PutOnce(ctx context.Context, kind, key string, payload []byte, ttl time.Duration) (bool, error) {
	var fresh bool
	err := s.pool.QueryRow(ctx,
		`INSERT INTO oauth_flow_entries (kind, key_hash, payload, expires_at)
		 VALUES ($1, $2, $3, now() + $4::bigint * interval '1 microsecond')
		 ON CONFLICT (kind, key_hash) DO UPDATE
		     SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
		     WHERE oauth_flow_entries.expires_at <= now()
		 RETURNING true`,
		kind, keyHash(key), payload, ttl.Microseconds()).Scan(&fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("oauth flow store: put once %s: %w", kind, err)
	}
	return fresh, nil
}

// Take deletes the entry and returns it in one statement, so two replicas
// racing on the same key cannot both receive it. An expired row is deleted
// too and reported as not found.
func (s *PostgresStore) Take(ctx context.Context, kind, key string) ([]byte, bool, error) {
	var (
		payload []byte
		live    bool
	)
	err := s.pool.QueryRow(ctx,
		`DELETE FROM oauth_flow_entries
		 WHERE kind = $1 AND key_hash = $2
		 RETURNING payload, expires_at > now()`,
		kind, keyHash(key)).Scan(&payload, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("oauth flow store: take %s: %w", kind, err)
	}
	if !live {
		return nil, false, nil
	}
	return payload, true, nil
}

// GC deletes expired entries.
func (s *PostgresStore) GC(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM oauth_flow_entries WHERE expires_at <= now()`); err != nil {
		return fmt.Errorf("oauth flow store: gc: %w", err)
	}
	return nil
}
