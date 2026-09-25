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

package clientstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS oauth_registered_clients (
    client_id     TEXT        PRIMARY KEY,
    client_name   TEXT        NOT NULL DEFAULT '',
    redirect_uris JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_registered_clients_last_seen
    ON oauth_registered_clients (last_seen_at);
`

// touchInterval throttles Touch: last_seen_at only has to be accurate to
// within the retention window (days), so rewriting it on every refresh would
// be a write per token call for no information.
const touchInterval = time.Hour

// PostgresStore is a Postgres-backed implementation of Store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a PostgresStore and auto-creates the schema.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("oauth client store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("oauth client store: create schema: %w", err)
	}
	slog.Info("oauth client registration store initialized")
	return &PostgresStore{pool: pool}, nil
}

// Register implements Store.
func (s *PostgresStore) Register(c Client, maxClients int) (Client, error) {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return Client{}, fmt.Errorf("oauth client store: marshal redirect_uris: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Client{}, fmt.Errorf("oauth client store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// ON CONFLICT ... DO UPDATE rather than DO NOTHING so RETURNING always
	// yields the row, and so a repeated registration counts as a sign of life.
	// Only last_seen_at moves: the stored name, redirect set and created_at are
	// the record of the first registration, and a racing duplicate cannot
	// rewrite them.
	var out Client
	var storedURIs []byte
	err = tx.QueryRow(ctx,
		`INSERT INTO oauth_registered_clients
		   (client_id, client_name, redirect_uris, created_at, last_seen_at)
		 VALUES ($1, $2, $3, NOW(), NOW())
		 ON CONFLICT (client_id) DO UPDATE SET last_seen_at = NOW()
		 RETURNING client_id, client_name, redirect_uris, created_at, last_seen_at`,
		c.ClientID, c.ClientName, uris,
	).Scan(&out.ClientID, &out.ClientName, &storedURIs, &out.CreatedAt, &out.LastSeenAt)
	if err != nil {
		return Client{}, fmt.Errorf("oauth client store: upsert: %w", err)
	}
	if err := json.Unmarshal(storedURIs, &out.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("oauth client store: unmarshal redirect_uris: %w", err)
	}

	if maxClients > 0 {
		// Keep the maxClients most recently seen rows. The row just written
		// has last_seen_at = NOW() and is excluded explicitly as well, so ties
		// cannot make a registration evict itself.
		if _, err := tx.Exec(ctx,
			`DELETE FROM oauth_registered_clients
			 WHERE client_id <> $1
			   AND client_id NOT IN (
			     SELECT client_id FROM oauth_registered_clients
			     ORDER BY last_seen_at DESC, client_id
			     LIMIT $2)`,
			out.ClientID, maxClients,
		); err != nil {
			return Client{}, fmt.Errorf("oauth client store: trim: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Client{}, fmt.Errorf("oauth client store: commit: %w", err)
	}
	return out, nil
}

// Get implements Store.
func (s *PostgresStore) Get(clientID string) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out Client
	var uris []byte
	err := s.pool.QueryRow(ctx,
		`SELECT client_id, client_name, redirect_uris, created_at, last_seen_at
		 FROM oauth_registered_clients WHERE client_id = $1`,
		clientID,
	).Scan(&out.ClientID, &out.ClientName, &uris, &out.CreatedAt, &out.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("oauth client store: get: %w", err)
	}
	if err := json.Unmarshal(uris, &out.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("oauth client store: unmarshal redirect_uris: %w", err)
	}
	return out, nil
}

// Touch implements Store.
func (s *PostgresStore) Touch(clientID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE oauth_registered_clients SET last_seen_at = NOW()
		 WHERE client_id = $1 AND last_seen_at < NOW() - make_interval(secs => $2)`,
		clientID, touchInterval.Seconds(),
	)
	if err != nil {
		return fmt.Errorf("oauth client store: touch: %w", err)
	}
	return nil
}

// GC implements Store.
func (s *PostgresStore) GC(cutoff time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_registered_clients WHERE last_seen_at < $1`,
		cutoff.UTC(),
	); err != nil {
		return fmt.Errorf("oauth client store: gc: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}
