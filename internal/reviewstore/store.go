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

// Package reviewstore is the durable half of the Tier B review-receipt
// adapter (mctl-api#897): Postgres tables for sealed review requests, review
// receipts and nonce consumptions around the pure internal/reviewreceipts
// contract. Every read fails closed: a pool is complete or it is an error.
package reviewstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// schema is three append-only tables. A BEFORE UPDATE trigger refuses every
// UPDATE; DELETE stays permitted as the retention mechanism. Request closure
// is computed on read and never written back.
const schema = `
CREATE TABLE IF NOT EXISTS review_requests (
    ingest_seq               BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    request_id               TEXT PRIMARY KEY CHECK (request_id ~ '^rr_[0-9a-f]{16}$'),
    content_hash             TEXT NOT NULL,
    document                 BYTEA NOT NULL,
    subject_kind             TEXT NOT NULL,
    identity_key             TEXT NOT NULL,
    binding_key              TEXT NOT NULL,
    mode                     TEXT NOT NULL CHECK (mode IN ('worker', 'manual')),
    nonce_sha256             TEXT NOT NULL,
    authoring_execution_id   TEXT NOT NULL,
    tenant                   TEXT NOT NULL CHECK (tenant <> ''),
    ingested_by              TEXT NOT NULL,
    ingested_by_principal_id TEXT NOT NULL DEFAULT '',
    ingested_at              TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS review_requests_nonce ON review_requests (nonce_sha256);
CREATE INDEX IF NOT EXISTS review_requests_identity ON review_requests (identity_key, ingest_seq);
CREATE INDEX IF NOT EXISTS review_requests_binding ON review_requests (binding_key, ingest_seq);

CREATE TABLE IF NOT EXISTS review_receipts (
    ingest_seq                BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    receipt_id                TEXT PRIMARY KEY CHECK (receipt_id ~ '^rc_[0-9a-f]{16}$'),
    request_id                TEXT NOT NULL REFERENCES review_requests (request_id),
    content_hash              TEXT NOT NULL,
    document                  BYTEA NOT NULL,
    mode                      TEXT NOT NULL CHECK (mode IN ('worker', 'manual')),
    assurance                 TEXT NOT NULL CHECK (assurance IN ('independent', 'advisory')),
    tenant                    TEXT NOT NULL,
    submitted_by              TEXT NOT NULL,
    submitted_by_principal_id TEXT NOT NULL DEFAULT '',
    submitted_at              TIMESTAMPTZ NOT NULL,
    CONSTRAINT review_receipts_manual_advisory CHECK (mode <> 'manual' OR assurance = 'advisory')
);

CREATE TABLE IF NOT EXISTS review_nonce_consumptions (
    nonce_sha256 TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL REFERENCES review_requests (request_id),
    receipt_id   TEXT NOT NULL,
    consumed_at  TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION review_rows_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'review_requests_no_update') THEN
        CREATE TRIGGER review_requests_no_update
            BEFORE UPDATE ON review_requests
            FOR EACH ROW EXECUTE FUNCTION review_rows_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'review_receipts_no_update') THEN
        CREATE TRIGGER review_receipts_no_update
            BEFORE UPDATE ON review_receipts
            FOR EACH ROW EXECUTE FUNCTION review_rows_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'review_nonce_consumptions_no_update') THEN
        CREATE TRIGGER review_nonce_consumptions_no_update
            BEFORE UPDATE ON review_nonce_consumptions
            FOR EACH ROW EXECUTE FUNCTION review_rows_immutable();
    END IF;
END;
$$;
`

// Defaults for Config.
const (
	DefaultTTL     = 24 * time.Hour
	DefaultPoolMax = 10000
)

// Typed refusals. The HTTP layer maps each to a status and code.
var (
	ErrUnsealed             = errors.New("review request is not sealed: content_hash and request_id are required")
	ErrAuthoringUnresolved  = errors.New("authoring_execution_id resolves to no evidence record")
	ErrTenantUnresolved     = errors.New("the authoring evidence names no tenant")
	ErrEvidenceUnavailable  = errors.New("evidence could not be read")
	ErrIdempotencyConflict  = errors.New("a different document is already stored under this request_id")
	ErrNonceReused          = errors.New("the nonce is already used by another review request")
	ErrRequestNotFound      = errors.New("review request not found")
	ErrRequestClosed        = errors.New("review request is closed")
	ErrRequestModeWorker    = errors.New("review request is worker mode; a manual receipt cannot answer it")
	ErrBindingMismatch      = errors.New("the subject binding differs from the request's")
	ErrPoolTooLarge         = errors.New("the receipt pool exceeds the complete-read bound")
	ErrStoreCorrupt         = errors.New("a stored review document no longer parses")
	ErrManualNotAdvisory    = errors.New("a manual receipt must be advisory")
	errEvidenceStoreMissing = fmt.Errorf("%w: no evidence store", ErrEvidenceUnavailable)
)

// Closure reasons.
const (
	ClosedTTL        = "ttl"
	ClosedSuperseded = "superseded"
)

// EvidenceLookup lists evidence records (evidence.Store).
type EvidenceLookup interface {
	List(ctx context.Context, f evidence.Filter) (*evidence.ListResult, error)
}

// Config tunes a Store. Zero values take the defaults.
type Config struct {
	TTL     time.Duration
	PoolMax int
}

// Actor is the authenticated caller recorded on a write.
type Actor struct {
	Name        string
	PrincipalID string
}

// Store persists review requests and receipts.
type Store struct {
	pool        *pgxpool.Pool
	releaseOnce sync.Once
	now         func() time.Time
	ttl         time.Duration
	poolMax     int
	evidence    EvidenceLookup
}

// NewStore connects, applies the schema and returns a ready store.
func NewStore(ctx context.Context, connStr string, cfg Config) (*Store, error) {
	if cfg.TTL < 0 || cfg.PoolMax < 0 {
		return nil, errors.New("reviewstore: TTL and PoolMax must not be negative")
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.PoolMax == 0 {
		cfg.PoolMax = DefaultPoolMax
	}
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("reviewstore: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("reviewstore: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("reviewstore: schema: %w", err)
	}
	slog.Info("review receipt store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }, ttl: cfg.TTL, poolMax: cfg.PoolMax}, nil
}

// SetEvidence wires the authoring-execution resolver. Call once, before
// serving. Left unset, ingestion fails with ErrEvidenceUnavailable.
func (s *Store) SetEvidence(ev EvidenceLookup) { s.evidence = ev }

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.releaseOnce.Do(func() { pgshared.Release(s.pool) })
	}
}
