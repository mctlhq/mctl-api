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

package refreshstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash        BYTEA       PRIMARY KEY,
    client_id         TEXT        NOT NULL,
    login             TEXT        NOT NULL,
    groups            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    family_id         UUID        NOT NULL,
    parent_token_hash BYTEA,
    issued_at         TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    rotated_at        TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revoked_reason    TEXT
);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family
    ON oauth_refresh_tokens (family_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expires
    ON oauth_refresh_tokens (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_login
    ON oauth_refresh_tokens (login);
`

// PostgresStore is a Postgres-backed implementation of Store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a PostgresStore and auto-creates the schema.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("oauth refresh store: create schema: %w", err)
	}
	slog.Info("oauth refresh token store initialized")
	return &PostgresStore{pool: pool}, nil
}

func tokenHash(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// isSerializationFailure reports whether err is a Postgres serialization or
// deadlock error (codes 40001 / 40P01). These are safe to retry.
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01"
	}
	return false
}

// Insert stores a brand-new refresh token (new token family).
func (s *PostgresStore) Insert(rawToken, login, clientID string, groups []string, expiresAt time.Time) error {
	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("oauth refresh store: marshal groups: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, groups, family_id, parent_token_hash, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, NULL, NOW(), $6)`,
		tokenHash(rawToken), clientID, login, groupsJSON, uuid.New(), expiresAt,
	)
	if err != nil {
		return fmt.Errorf("oauth refresh store: insert: %w", err)
	}
	return nil
}

// Rotate atomically invalidates oldRawToken and inserts newRawToken in the same
// family. It retries on Postgres serialization failures (up to 3 attempts);
// if all retries fail it returns ErrServerError (transient DB failure, not a
// bad token) so callers map it to HTTP 500 rather than invalid_grant.
func (s *PostgresStore) Rotate(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time) (string, []string, error) {
	backoff := []time.Duration{5 * time.Millisecond, 15 * time.Millisecond}
	for attempt := range 3 {
		login, groups, err := s.rotateTx(oldRawToken, newRawToken, clientID, newExpiresAt)
		if err == nil || !isSerializationFailure(err) {
			return login, groups, err
		}
		slog.Warn("oauth refresh store: serialization failure, retrying",
			"attempt", attempt+1, "error", err)
		if attempt < len(backoff) {
			time.Sleep(backoff[attempt])
		}
	}
	return "", nil, ErrServerError
}

func (s *PostgresStore) rotateTx(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time) (string, []string, error) {
	oldHash := tokenHash(oldRawToken)
	newHash := tokenHash(newRawToken)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return "", nil, fmt.Errorf("oauth refresh store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var storedClientID, login string
	var groupsJSON []byte
	var familyID uuid.UUID
	var expiresAt time.Time
	var rotatedAt *time.Time
	var revokedAt *time.Time

	err = tx.QueryRow(ctx,
		`SELECT client_id, login, groups, family_id, expires_at, rotated_at, revoked_at
		 FROM oauth_refresh_tokens
		 WHERE token_hash = $1
		 FOR UPDATE`,
		oldHash,
	).Scan(&storedClientID, &login, &groupsJSON, &familyID, &expiresAt, &rotatedAt, &revokedAt)
	if err == pgx.ErrNoRows {
		return "", nil, ErrInvalidToken
	}
	if err != nil {
		return "", nil, fmt.Errorf("oauth refresh store: lookup: %w", err)
	}

	if time.Now().After(expiresAt) {
		return "", nil, ErrInvalidToken
	}

	// Reuse detection: token was already rotated → attacker replayed an old token.
	// Grace window (30s): if the rotation was very recent the client may be
	// retrying after a lost response — treat as invalid rather than revoking.
	// Revoke the whole family to protect the legitimate session. Fail closed:
	// if the revocation write fails, return an error rather than silently
	// reporting successful revocation.
	if rotatedAt != nil {
		if time.Since(*rotatedAt) < 30*time.Second {
			return "", nil, ErrInvalidToken
		}
		now := time.Now().UTC()
		if _, execErr := tx.Exec(ctx,
			`UPDATE oauth_refresh_tokens
			 SET revoked_at = $1, revoked_reason = 'reuse_detected'
			 WHERE family_id = $2 AND revoked_at IS NULL`,
			now, familyID,
		); execErr != nil {
			slog.Error("oauth refresh token reuse: failed to revoke family",
				"family_id", familyID, "error", execErr)
			return "", nil, fmt.Errorf("oauth refresh store: reuse revocation failed: %w", execErr)
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			slog.Error("oauth refresh token reuse: failed to commit family revocation",
				"family_id", familyID, "error", commitErr)
			return "", nil, fmt.Errorf("oauth refresh store: reuse revocation commit failed: %w", commitErr)
		}
		slog.Warn("oauth refresh token reuse detected; family revoked",
			"family_id", familyID, "login", login, "client_id", storedClientID)
		return "", nil, ErrReuseDetected
	}

	if revokedAt != nil {
		return "", nil, ErrInvalidToken
	}
	if storedClientID != clientID {
		return "", nil, ErrClientMismatch
	}

	var groups []string
	if err := json.Unmarshal(groupsJSON, &groups); err != nil {
		groups = nil
	}

	now := time.Now().UTC()

	// Mark old token as rotated.
	_, err = tx.Exec(ctx,
		`UPDATE oauth_refresh_tokens SET rotated_at = $1 WHERE token_hash = $2`,
		now, oldHash,
	)
	if err != nil {
		return "", nil, fmt.Errorf("oauth refresh store: mark rotated: %w", err)
	}

	// Insert new token inheriting the same family.
	newGroupsJSON, _ := json.Marshal(groups)
	_, err = tx.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, groups, family_id, parent_token_hash, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		newHash, clientID, login, newGroupsJSON, familyID, oldHash, now, newExpiresAt,
	)
	if err != nil {
		return "", nil, fmt.Errorf("oauth refresh store: insert rotated: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", nil, fmt.Errorf("oauth refresh store: commit: %w", err)
	}
	return login, groups, nil
}

// RevokeFamily revokes all non-revoked tokens in the same family as rawToken.
// If clientID is non-empty, only tokens belonging to that client are affected.
func (s *PostgresStore) RevokeFamily(rawToken, clientID, reason string) error {
	hash := tokenHash(rawToken)
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if clientID != "" {
		_, err = s.pool.Exec(ctx,
			`UPDATE oauth_refresh_tokens
			 SET revoked_at = $1, revoked_reason = $2
			 WHERE family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $3)
			   AND client_id = $4
			   AND revoked_at IS NULL`,
			now, reason, hash, clientID,
		)
	} else {
		_, err = s.pool.Exec(ctx,
			`UPDATE oauth_refresh_tokens
			 SET revoked_at = $1, revoked_reason = $2
			 WHERE family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $3)
			   AND revoked_at IS NULL`,
			now, reason, hash,
		)
	}
	if err != nil {
		return fmt.Errorf("oauth refresh store: revoke family: %w", err)
	}
	return nil
}

// GC hard-deletes rows that expired more than 7 days ago (regardless of revocation
// state). The 7-day grace window ensures any in-flight refresh that completed just
// before the token expired is not caught by a race with the GC ticker.
func (s *PostgresStore) GC() error {
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < $1`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("oauth refresh store: gc: %w", err)
	}
	return nil
}
