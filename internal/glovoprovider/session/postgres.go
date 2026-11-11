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

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema is the idempotent DDL of the session table. It is meant to be run by
// the migration role (ApplySchema), never by the runtime role; the runtime
// role needs SELECT, INSERT and UPDATE only, and no DELETE: ending a session
// wipes its ciphertext and keeps the row as an audit anchor.
//
// There is deliberately no foreign key to glovo.glovo_connections: this
// package is unwired, and the wiring slice owns the rule "a session row may
// exist only for a connection that is live for the same tenant and principal"
// and the rule "ending a connection calls Revoke".
const Schema = `
CREATE TABLE IF NOT EXISTS glovo.glovo_provider_sessions (
  connection_id     TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL,
  principal_id      TEXT NOT NULL,
  state             TEXT NOT NULL CHECK (state IN ('active','relogin_required','revoked')),
  key_id            TEXT,
  ciphertext        BYTEA,
  generation        BIGINT NOT NULL CHECK (generation >= 1),
  access_expires_at TIMESTAMPTZ,
  from_refresh      BOOLEAN NOT NULL DEFAULT FALSE,
  refresh_intent    BOOLEAN NOT NULL DEFAULT FALSE,
  relogin_reason    TEXT NOT NULL DEFAULT '',
  lease_holder      TEXT,
  lease_until       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((state = 'active') = (ciphertext IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS glovo_provider_sessions_owner
  ON glovo.glovo_provider_sessions (tenant_id, principal_id);
`

// ApplySchema runs Schema.
func ApplySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, Schema)
	return err
}

// Postgres is the Store backed by glovo.glovo_provider_sessions. Tokens are
// sealed with AES-256-GCM before they reach the database, so a database dump,
// a backup or a SQL console shows ciphertext only; the key lives outside the
// database (see Keyring).
//
// The lease and the compare-and-swap are single SQL statements on the one
// row, timed by the database clock, so replicas with skewed clocks agree.
type Postgres struct {
	pool *pgxpool.Pool
	ring *Keyring
}

// NewPostgres wires a pool and a keyring.
func NewPostgres(pool *pgxpool.Pool, ring *Keyring) *Postgres {
	return &Postgres{pool: pool, ring: ring}
}

const cols = `connection_id, tenant_id, principal_id, state, key_id, ciphertext, generation,
  from_refresh, refresh_intent, relogin_reason, lease_holder, lease_until, access_expires_at, updated_at`

func qcols(alias string) string {
	return alias + ".connection_id, " + alias + ".tenant_id, " + alias + ".principal_id, " + alias + ".state, " +
		alias + ".key_id, " + alias + ".ciphertext, " + alias + ".generation, " + alias + ".from_refresh, " +
		alias + ".refresh_intent, " + alias + ".relogin_reason, " + alias + ".lease_holder, " + alias + ".lease_until, " +
		alias + ".access_expires_at, " + alias + ".updated_at"
}

type scanned struct {
	rec     Record
	keyID   *string
	blob    []byte
	holder  *string
	until   *time.Time
	expires *time.Time
	state   string
}

func (p *Postgres) scan(row pgx.Row, key Key, extra ...any) (Record, error) {
	var s scanned
	var connID, tenant, principal string
	dest := append([]any{&connID, &tenant, &principal, &s.state, &s.keyID, &s.blob, &s.rec.Generation,
		&s.rec.FromRefresh, &s.rec.RefreshIntent, &s.rec.ReloginReason, &s.holder, &s.until, &s.expires, &s.rec.UpdatedAt}, extra...)
	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("%w: read", ErrUnavailable)
	}
	s.rec.Key = Key{TenantID: tenant, PrincipalID: principal, ConnectionID: connID}
	s.rec.State = State(s.state)
	if s.holder != nil {
		s.rec.LeaseHolder = *s.holder
	}
	if s.until != nil {
		s.rec.LeaseUntil = *s.until
	}
	if s.rec.State == StateActive {
		if s.keyID == nil || s.blob == nil {
			return Record{}, ErrCorrupt
		}
		t, err := p.ring.open(key, s.rec.Generation, *s.keyID, s.blob)
		if err != nil {
			return Record{}, err
		}
		s.rec.Tokens = t
	}
	return s.rec, nil
}

func (p *Postgres) Put(ctx context.Context, key Key, t Tokens) (Record, error) {
	if err := key.validate(); err != nil {
		return Record{}, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("%w: begin", ErrUnavailable)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var gen int64
	var tenant, principal string
	err = tx.QueryRow(ctx, `SELECT generation, tenant_id, principal_id FROM glovo.glovo_provider_sessions
	  WHERE connection_id = $1 FOR UPDATE`, key.ConnectionID).Scan(&gen, &tenant, &principal)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		gen = 0
	case err != nil:
		return Record{}, fmt.Errorf("%w: read", ErrUnavailable)
	case tenant != key.TenantID || principal != key.PrincipalID:
		// The connection id belongs to another owner: never overwrite it.
		return Record{}, ErrNotFound
	}
	gen++
	keyID, blob, err := p.ring.seal(key, gen, t)
	if err != nil {
		return Record{}, fmt.Errorf("%w: seal", ErrUnavailable)
	}
	_, err = tx.Exec(ctx, `INSERT INTO glovo.glovo_provider_sessions
	  (connection_id, tenant_id, principal_id, state, key_id, ciphertext, generation, access_expires_at)
	  VALUES ($1,$2,$3,'active',$4,$5,$6,$7)
	  ON CONFLICT (connection_id) DO UPDATE SET state='active', key_id=EXCLUDED.key_id,
	    ciphertext=EXCLUDED.ciphertext, generation=EXCLUDED.generation,
	    access_expires_at=EXCLUDED.access_expires_at, from_refresh=FALSE, refresh_intent=FALSE,
	    relogin_reason='', lease_holder=NULL, lease_until=NULL, updated_at=clock_timestamp()`,
		key.ConnectionID, key.TenantID, key.PrincipalID, keyID, blob, gen, t.AccessExpiresAt)
	if err != nil {
		return Record{}, fmt.Errorf("%w: write", ErrUnavailable)
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, fmt.Errorf("%w: commit", ErrUnavailable)
	}
	return p.Get(ctx, key)
}

func (p *Postgres) Get(ctx context.Context, key Key) (Record, error) {
	if err := key.validate(); err != nil {
		return Record{}, err
	}
	return p.scan(p.pool.QueryRow(ctx, `SELECT `+cols+` FROM glovo.glovo_provider_sessions
	  WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3`,
		key.ConnectionID, key.TenantID, key.PrincipalID), key)
}

func (p *Postgres) AcquireLease(ctx context.Context, key Key, holder string, ttl time.Duration) (Record, error) {
	if err := key.validate(); err != nil || holder == "" || ttl <= 0 {
		return Record{}, ErrInvalid
	}
	// The sub-select locks the row and reads the intent as it was BEFORE this
	// acquisition: a set intent means an earlier holder sent a refresh whose
	// outcome was never recorded.
	var prior bool
	row := p.pool.QueryRow(ctx, `UPDATE glovo.glovo_provider_sessions AS t
	  SET lease_holder=$4, lease_until=clock_timestamp() + make_interval(secs => $5),
	      refresh_intent=TRUE, updated_at=clock_timestamp()
	  FROM (SELECT connection_id AS pid, refresh_intent AS prior FROM glovo.glovo_provider_sessions
	        WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3 FOR UPDATE) p
	  WHERE t.connection_id=p.pid AND t.tenant_id=$2 AND t.principal_id=$3 AND t.state='active'
	    AND (t.lease_holder IS NULL OR t.lease_holder=$4 OR t.lease_until <= clock_timestamp())
	  RETURNING `+qcols("t")+`, p.prior`, key.ConnectionID, key.TenantID, key.PrincipalID, holder, ttl.Seconds())
	rec, err := p.scan(row, key, &prior)
	if err == nil {
		rec.RefreshIntent = prior
		return rec, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return rec, err
	}
	// Zero rows: no such session, not active, or the lease is held. Tell them apart.
	cur, gerr := p.Get(ctx, key)
	switch {
	case gerr != nil:
		return Record{}, gerr
	case cur.State != StateActive:
		return cur, nil
	default:
		return Record{}, ErrLeaseHeld
	}
}

func (p *Postgres) Commit(ctx context.Context, key Key, holder string, expected int64, t Tokens) (Record, error) {
	if err := key.validate(); err != nil || holder == "" {
		return Record{}, ErrInvalid
	}
	keyID, blob, err := p.ring.seal(key, expected+1, t)
	if err != nil {
		return Record{}, fmt.Errorf("%w: seal", ErrUnavailable)
	}
	var gen int64
	err = p.pool.QueryRow(ctx, `UPDATE glovo.glovo_provider_sessions
	  SET key_id=$6, ciphertext=$7, generation=generation+1, access_expires_at=$8, from_refresh=TRUE,
	      refresh_intent=FALSE, lease_holder=NULL, lease_until=NULL, updated_at=clock_timestamp()
	  WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3 AND state='active'
	    AND generation=$4 AND lease_holder=$5
	  RETURNING generation`,
		key.ConnectionID, key.TenantID, key.PrincipalID, expected, holder, keyID, blob, t.AccessExpiresAt).Scan(&gen)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, gerr := p.Get(ctx, key)
		if gerr != nil {
			return Record{}, gerr
		}
		if cur.State == StateActive && cur.Generation == expected {
			return Record{}, ErrLeaseLost
		}
		return Record{}, ErrStale
	}
	if err != nil {
		return Record{}, fmt.Errorf("%w: write", ErrUnavailable)
	}
	return p.Get(ctx, key)
}

func (p *Postgres) Release(ctx context.Context, key Key, holder string, outcomeKnown bool) error {
	if err := key.validate(); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions
	  SET lease_holder=NULL, lease_until=NULL, refresh_intent = refresh_intent AND NOT $5, updated_at=clock_timestamp()
	  WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3 AND lease_holder=$4`,
		key.ConnectionID, key.TenantID, key.PrincipalID, holder, outcomeKnown)
	if err != nil {
		return fmt.Errorf("%w: release", ErrUnavailable)
	}
	return nil
}

func (p *Postgres) MarkRelogin(ctx context.Context, key Key, expected int64, reason string) error {
	if err := key.validate(); err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions
	  SET state='relogin_required', key_id=NULL, ciphertext=NULL, access_expires_at=NULL, generation=generation+1,
	      relogin_reason=$5, refresh_intent=FALSE, lease_holder=NULL, lease_until=NULL, updated_at=clock_timestamp()
	  WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3 AND state='active' AND generation=$4`,
		key.ConnectionID, key.TenantID, key.PrincipalID, expected, reason)
	if err != nil {
		return fmt.Errorf("%w: write", ErrUnavailable)
	}
	if tag.RowsAffected() == 0 {
		return ErrStale
	}
	return nil
}

func (p *Postgres) Revoke(ctx context.Context, key Key) error {
	if err := key.validate(); err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions
	  SET state='revoked', key_id=NULL, ciphertext=NULL, access_expires_at=NULL, generation=generation+1,
	      refresh_intent=FALSE, lease_holder=NULL, lease_until=NULL, updated_at=clock_timestamp()
	  WHERE connection_id=$1 AND tenant_id=$2 AND principal_id=$3`,
		key.ConnectionID, key.TenantID, key.PrincipalID)
	if err != nil {
		return fmt.Errorf("%w: write", ErrUnavailable)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) Status(ctx context.Context, key Key) (Status, error) {
	r, err := p.Get(ctx, key)
	if err != nil {
		return Status{}, err
	}
	return Status{State: r.State, Generation: r.Generation, AccessExpiresAt: r.Tokens.AccessExpiresAt,
		ReloginReason: r.ReloginReason, UpdatedAt: r.UpdatedAt}, nil
}
