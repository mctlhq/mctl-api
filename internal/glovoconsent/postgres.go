// Copyright 2026 MCTL Authors
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

package glovoconsent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// prnPattern is auth.ValidPrincipalID's pattern. Repeated here so the store
// refuses a malformed id on its own, whoever calls it.
var prnPattern = regexp.MustCompile(`^prn_[0-9A-HJKMNP-TV-Z]{26}$`)

// schema is idempotent and run by NewStore, the repository's migration
// convention. The partial unique index is the "one active consent per
// principal" invariant; the CHECKs keep a row from naming anything but a
// canonical principal and a non-empty version.
const schema = `
CREATE TABLE IF NOT EXISTS glovo_link_consents (
	consent_id      TEXT PRIMARY KEY,
	principal_id    TEXT NOT NULL CHECK (principal_id ~ '^prn_[0-9A-HJKMNP-TV-Z]{26}$'),
	consent_version TEXT NOT NULL CHECK (consent_version <> ''),
	recorded_at     TIMESTAMPTZ NOT NULL,
	recorded_by     TEXT NOT NULL,
	revoked_at      TIMESTAMPTZ,
	revoked_by      TEXT NOT NULL DEFAULT '',
	revoke_reason   TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS glovo_link_consents_one_active
	ON glovo_link_consents (principal_id) WHERE revoked_at IS NULL;
` + accessSchema

// Revoke reasons.
const (
	ReasonWithdrawn  = "withdrawn"
	ReasonSuperseded = "superseded"
)

const dbTimeout = 5 * time.Second

// PostgresStore is the Postgres-backed Store.
type PostgresStore struct {
	pool        *pgxpool.Pool
	releaseOnce sync.Once
	now         func() time.Time
	// timeout bounds every call, the lock waits inside a transaction
	// included; dbTimeout unless a test shortens it.
	timeout time.Duration
	// accessRequired switches slot accounting to approved access; see the
	// package comment in access.go. False is the original behaviour.
	accessRequired bool
}

// Option configures a PostgresStore.
type Option func(*PostgresStore)

// WithAccessRequired sets AccessRequired: slots are held by approved access
// instead of active consents. Default false.
func WithAccessRequired(v bool) Option { return func(s *PostgresStore) { s.accessRequired = v } }

// NewStore connects and creates the schema.
func NewStore(ctx context.Context, connStr string, opts ...Option) (*PostgresStore, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("glovoconsent: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("glovoconsent: create schema: %w", err)
	}
	st := &PostgresStore{pool: pool, now: func() time.Time { return time.Now().UTC() }, timeout: dbTimeout}
	for _, o := range opts {
		o(st)
	}
	if err := st.backfillAccess(ctx); err != nil {
		pgshared.Release(pool)
		return nil, err
	}
	return st, nil
}

// Close releases the pool.
func (s *PostgresStore) Close() { s.releaseOnce.Do(func() { pgshared.Release(s.pool) }) }

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("glovoconsent: id: %w", err)
	}
	return "gcn_" + hex.EncodeToString(b[:]), nil
}

func validate(principalID, actor string) error {
	if !prnPattern.MatchString(principalID) || actor == "" {
		return ErrInvalid
	}
	return nil
}

const selectActive = `SELECT consent_id, principal_id, consent_version, recorded_at, revoked_at
	FROM glovo_link_consents WHERE principal_id = $1 AND revoked_at IS NULL`

func scan(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.ID, &r.PrincipalID, &r.Version, &r.RecordedAt, &r.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNoConsent
	}
	if err != nil {
		return Record{}, fmt.Errorf("glovoconsent: read: %w", err)
	}
	r.RecordedAt = r.RecordedAt.UTC()
	return r, nil
}

// Active implements Store. Only pgx.ErrNoRows is "no consent"; any other
// failure is returned as an error.
func (s *PostgresStore) Active(ctx context.Context, principalID string) (Record, error) {
	if !prnPattern.MatchString(principalID) {
		return Record{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return scan(s.pool.QueryRow(ctx, selectActive, principalID))
}

// withPrincipalTx runs fn in a transaction holding a per-principal advisory
// lock, so two concurrent records or revokes for one principal serialize.
func (s *PostgresStore) withPrincipalTx(ctx context.Context, principalID string, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovoconsent: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-link-consent:' || $1))`, principalID); err != nil {
		return fmt.Errorf("glovoconsent: lock: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovoconsent: commit: %w", err)
	}
	return nil
}

func revokeTx(ctx context.Context, tx pgx.Tx, id, actor, reason string, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE glovo_link_consents SET revoked_at = $2, revoked_by = $3, revoke_reason = $4
		WHERE consent_id = $1 AND revoked_at IS NULL`, id, at, actor, reason)
	if err != nil {
		return fmt.Errorf("glovoconsent: revoke: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("glovoconsent: revoke: %d rows changed, want 1", tag.RowsAffected())
	}
	return nil
}

// Record implements Store. The version is always Version.
func (s *PostgresStore) Record(ctx context.Context, principalID, actor string, capacity int) (Record, bool, error) {
	if err := validate(principalID, actor); err != nil {
		return Record{}, false, err
	}
	var out Record
	created := false
	err := s.withPrincipalTx(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		// The capacity lock serialises every slot claim, so the count
		// below and the insert after it are one atomic claim: two claims
		// for the last slot cannot both see it free. Lock order is always
		// principal, then capacity; Revoke takes only the principal lock.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-link-consent:capacity'))`); err != nil {
			return fmt.Errorf("glovoconsent: capacity lock: %w", err)
		}
		cur, err := scan(tx.QueryRow(ctx, selectActive, principalID))
		switch {
		case err == nil && cur.Version == Version:
			// Already holds a slot: idempotent, no second slot.
			out = cur
			return nil
		case err == nil:
			// Holds a slot under an older version: keeps it.
			if err := revokeTx(ctx, tx, cur.ID, actor, ReasonSuperseded, s.now()); err != nil {
				return err
			}
		case !errors.Is(err, ErrNoConsent):
			return err
		default:
			// With AccessRequired a consent holds no slot: the person
			// consents before asking, and approval claims the slot.
			if !s.accessRequired {
				if capacity <= 0 {
					return ErrCapacityReached
				}
				var taken int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM glovo_link_consents WHERE revoked_at IS NULL`).Scan(&taken); err != nil {
					return fmt.Errorf("glovoconsent: count slots: %w", err)
				}
				if taken >= capacity {
					return ErrCapacityReached
				}
			}
		}
		id, err := newID()
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(ctx, `INSERT INTO glovo_link_consents (consent_id, principal_id, consent_version, recorded_at, recorded_by)
			VALUES ($1, $2, $3, $4, $5)`, id, principalID, Version, now, actor); err != nil {
			return fmt.Errorf("glovoconsent: insert: %w", err)
		}
		out = Record{ID: id, PrincipalID: principalID, Version: Version, RecordedAt: now}
		created = true
		return nil
	})
	if err != nil {
		return Record{}, false, err
	}
	return out, created, nil
}

// Revoke implements Store.
func (s *PostgresStore) Revoke(ctx context.Context, principalID, actor string) (Record, error) {
	if err := validate(principalID, actor); err != nil {
		return Record{}, err
	}
	var out Record
	err := s.withPrincipalTx(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := scan(tx.QueryRow(ctx, selectActive, principalID))
		if err != nil {
			return err
		}
		now := s.now()
		if err := revokeTx(ctx, tx, cur.ID, actor, ReasonWithdrawn, now); err != nil {
			return err
		}
		cur.RevokedAt = &now
		out = cur
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return out, nil
}
