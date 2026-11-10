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

package glovo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The handoff and quota tables of the synthetic connection slice (mctl-api#961):
// glovo.glovo_handoff_refs holds only the SHA-256 of a single-use handoff
// reference, glovo.glovo_rate_counters holds the cross-replica quota counters.
// Both are synthetic-only, additive and created by ApplySchema under the
// migration role, never by the runtime role.

const (
	prefixHandoff = "ghr_"

	// HandoffTTL is how long an issued handoff reference can be consumed.
	HandoffTTL = 10 * time.Minute
	// MaxConnectsPerHour is the connect and reconnect budget of one owner.
	MaxConnectsPerHour = 10
	// MaxLiveConnectionsPerTenant caps the non-terminal, unlapsed connections
	// of one tenant.
	MaxLiveConnectionsPerTenant = 50

	defaultLockTimeout = 5 * time.Second
	counterScopeOwner  = "owner_hour"
	counterScopeMutex  = "tenant_mutex"
)

// handoffSchema is idempotent DDL appended to glovoSchema by ApplySchema.
const handoffSchema = `
CREATE TABLE IF NOT EXISTS glovo.glovo_handoff_refs (
  ref_hash      BYTEA PRIMARY KEY CHECK (octet_length(ref_hash) = 32),
  connection_id TEXT NOT NULL REFERENCES glovo.glovo_connections (connection_id),
  tenant_id     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS glovo_handoff_refs_connection
  ON glovo.glovo_handoff_refs (connection_id) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS glovo_handoff_refs_expires
  ON glovo.glovo_handoff_refs (expires_at);
CREATE TABLE IF NOT EXISTS glovo.glovo_rate_counters (
  scope        TEXT NOT NULL CHECK (scope IN ('owner_hour','tenant_mutex')),
  tenant_id    TEXT NOT NULL,
  principal_id TEXT NOT NULL DEFAULT '',
  window_start TIMESTAMPTZ NOT NULL,
  count        INTEGER NOT NULL CHECK (count >= 0),
  updated_at   TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (scope, tenant_id, principal_id, window_start)
);
CREATE INDEX IF NOT EXISTS glovo_rate_counters_window
  ON glovo.glovo_rate_counters (window_start) WHERE scope = 'owner_hour';
`

// slice961Tables are the tables of this slice, granted after slice959Tables.
var slice961Tables = []string{"glovo_handoff_refs", "glovo_rate_counters"}

func init() {
	RegisterGrants(
		GrantRow{Table: "glovo_handoff_refs", Privileges: []string{"SELECT", "INSERT", "DELETE"}, UpdateColumns: []string{"consumed_at"},
			Description: "hash-only single-use handoff references; TTL purge and the purge of unconsumed rows of an ended connection"},
		GrantRow{Table: "glovo_rate_counters", Privileges: []string{"SELECT", "INSERT", "DELETE"}, UpdateColumns: []string{"count", "updated_at"},
			Description: "hourly owner counters and the tenant mutex rows; stale owner windows are deleted, never the mutex rows"},
	)
}

// HandoffRefHash returns the SHA-256 stored for a raw handoff reference.
func HandoffRefHash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func newHandoffRef() (string, []byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, fmt.Errorf("glovo: crypto/rand: %w", err)
	}
	raw := prefixHandoff + hex.EncodeToString(b[:])
	return raw, HandoffRefHash(raw), nil
}

// WithLockTimeout sets the lock_timeout applied to the L2a, L2b and handoff
// locks of this file (default 5 s). A lock that times out is tenant_busy.
func WithLockTimeout(d time.Duration) Option {
	return func(s *Store) { s.lockTimeout = d }
}

func (s *Store) setLockTimeout(ctx context.Context, tx pgx.Tx) error {
	d := s.lockTimeout
	if d <= 0 {
		d = defaultLockTimeout
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(d.Milliseconds(), 10)+"ms"); err != nil {
		return fmt.Errorf("glovo: set lock timeout: %w", err)
	}
	return nil
}

// AsError maps any error of this package to the closed refusal enum: a typed
// refusal as is, a failed readiness check as not_ready, a lock timeout
// (SQLSTATE 55P03) as tenant_busy, and everything else, including a failed
// read, as unavailable, never a refusal that could read as "no".
func AsError(err error) *Error {
	var ge *Error
	if errors.As(err, &ge) && Registered(ge.Code) {
		return ge
	}
	if errors.Is(err, &Error{Code: CodeNotReady}) {
		return refuse(CodeNotReady)
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return refuse(CodeTenantBusy)
	}
	return refuse(CodeUnavailable)
}

// ConnectionView is a connection with the database clock's verdict on its
// expires_at.
type ConnectionView struct {
	*Connection
	Lapsed bool
}

// EffectiveState is the state a reader sees: a live connection whose
// expires_at has passed is expired.
func (v ConnectionView) EffectiveState() ConnectionState {
	if v.State.Live() && v.Lapsed {
		return Expired
	}
	return v.State
}

const lapsedExpr = `(expires_at IS NOT NULL AND expires_at <= clock_timestamp())`

// GetConnectionView is GetConnection with the lapsed verdict, owner-scoped.
func (s *Store) GetConnectionView(ctx context.Context, owner Owner, id string) (*ConnectionView, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	var lapsed bool
	c, err := scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+`, `+lapsedExpr+` FROM glovo.glovo_connections
 WHERE connection_id = $1 AND tenant_id = $2 AND principal_id = $3`, id, owner.TenantID, owner.PrincipalID), &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read connection: %w", err)
	}
	return &ConnectionView{Connection: c, Lapsed: lapsed}, nil
}

// ListOwnerConnections returns the owner's most recent connections, newest
// first, at most limit.
func (s *Store) ListOwnerConnections(ctx context.Context, owner Owner, limit int) ([]ConnectionView, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 50 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `SELECT `+connCols+`, `+lapsedExpr+` FROM glovo.glovo_connections
 WHERE tenant_id = $1 AND principal_id = $2 ORDER BY created_at DESC, connection_id DESC LIMIT $3`,
		owner.TenantID, owner.PrincipalID, limit)
	if err != nil {
		return nil, fmt.Errorf("glovo: list connections: %w", err)
	}
	defer rows.Close()
	var out []ConnectionView
	for rows.Next() {
		var lapsed bool
		c, err := scanConn(rows, &lapsed)
		if err != nil {
			return nil, fmt.Errorf("glovo: scan connection: %w", err)
		}
		out = append(out, ConnectionView{Connection: c, Lapsed: lapsed})
	}
	return out, rows.Err()
}

// WorkerConnectionView is GetConnectionForWorker with the lapsed verdict. Like
// it, it has no owner predicate and is for the worker routes only.
func (s *Store) WorkerConnectionView(ctx context.Context, id string) (*ConnectionView, error) {
	var lapsed bool
	c, err := scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+`, `+lapsedExpr+` FROM glovo.glovo_connections
 WHERE connection_id = $1`, id), &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read connection: %w", err)
	}
	return &ConnectionView{Connection: c, Lapsed: lapsed}, nil
}

// InstallRow returns the tenant's install in any state; nil when none exists.
func (s *Store) InstallRow(ctx context.Context, tenantID string) (*Install, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	i, err := scanInstall(s.pool.QueryRow(ctx, `SELECT `+installCols+` FROM glovo.glovo_installs WHERE tenant_id = $1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read install: %w", err)
	}
	return i, nil
}

// notIssuable is the refusal of handoff and activate for a connection that is
// not pending_handoff; nil when it is.
func notIssuable(c *Connection, lapsed bool) *Error {
	switch c.State {
	case PendingHandoff:
		return nil
	case PendingProvider:
		return refuse(CodeInvalidTransition)
	case Active:
		if lapsed {
			return refuse(CodeConnectionExpired)
		}
		return refuse(CodeInvalidTransition)
	case Revoked:
		return refuse(CodeConnectionRevoked)
	case Expired:
		return refuse(CodeConnectionExpired)
	default:
		return refuse(CodeNoConnection)
	}
}

// HandoffIssue is the one value that carries a raw handoff reference.
type HandoffIssue struct {
	Ref       string
	ExpiresAt time.Time
}

// IssueHandoff issues a fresh single-use reference for the owner's
// pending_handoff connection and deletes the connection's older unconsumed
// ones. Only the SHA-256 is stored. The connection stays pending_handoff: the
// state moves only in ActivateWithHandoff. Lock order: L1 shared, L2
// exclusive. A connection that is not the owner's is ErrNotFound.
func (s *Store) IssueHandoff(ctx context.Context, owner Owner, connectionID string, actor Actor) (*HandoffIssue, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, err
	}
	raw, hash, err := newHandoffRef()
	if err != nil {
		return nil, err
	}
	var out *HandoffIssue
	err = s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.setLockTimeout(ctx, tx); err != nil {
			return err
		}
		if err := s.withLocks(ctx, tx, owner.TenantID, owner.PrincipalID, lockShared); err != nil {
			return err
		}
		c, lapsed, err := lockOwnedConnection(ctx, tx, owner, connectionID)
		if err != nil {
			return err
		}
		if e := notIssuable(c, lapsed); e != nil {
			return e
		}
		if _, err := tx.Exec(ctx, `DELETE FROM glovo.glovo_handoff_refs WHERE connection_id = $1 AND consumed_at IS NULL`, c.ConnectionID); err != nil {
			return fmt.Errorf("glovo: delete older handoff references: %w", err)
		}
		var exp time.Time
		if err := tx.QueryRow(ctx, `INSERT INTO glovo.glovo_handoff_refs (ref_hash, connection_id, tenant_id, principal_id, created_at, expires_at)
 SELECT $1, $2, $3, $4, t.n, t.n + ($5::bigint * interval '1 microsecond') FROM (SELECT clock_timestamp() AS n) t
 RETURNING expires_at`, hash, c.ConnectionID, owner.TenantID, owner.PrincipalID, HandoffTTL.Microseconds()).Scan(&exp); err != nil {
			return fmt.Errorf("glovo: insert handoff reference: %w", err)
		}
		if err := s.appendAudit(ctx, tx, connAudit(c, actor, "handoff_issued", string(c.State), "")); err != nil {
			return err
		}
		out = &HandoffIssue{Ref: raw, ExpiresAt: exp.UTC()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ActivateWithHandoff consumes the raw handoff reference and activates the
// connection in one transaction: ActivateTx (L1 shared, L2 exclusive) with an
// AfterLocks that takes the reference row FOR UPDATE (L2b) and consumes it.
// The state, install revision and version checks of ActivateTx run first, so
// a revoked or expired connection reports its own code; an unknown, foreign,
// expired or already consumed reference is the one not_found, decided after
// them, and commits nothing. in.AfterLocks is replaced.
func (s *Store) ActivateWithHandoff(ctx context.Context, in ActivateInput, rawRef string) (*Connection, error) {
	hash := HandoffRefHash(rawRef)
	var out *Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.setLockTimeout(ctx, tx); err != nil {
			return err
		}
		refOK := false
		in.AfterLocks = func(ctx context.Context, tx pgx.Tx) error {
			var consumed, expired bool
			err := tx.QueryRow(ctx, `SELECT consumed_at IS NOT NULL, expires_at <= clock_timestamp()
 FROM glovo.glovo_handoff_refs
 WHERE ref_hash = $1 AND connection_id = $2 AND tenant_id = $3 AND principal_id = $4 FOR UPDATE`,
				hash, in.ConnectionID, in.Owner.TenantID, in.Owner.PrincipalID).Scan(&consumed, &expired)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("glovo: read handoff reference: %w", err)
			}
			if consumed || expired {
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE glovo.glovo_handoff_refs SET consumed_at = clock_timestamp() WHERE ref_hash = $1`, hash); err != nil {
				return fmt.Errorf("glovo: consume handoff reference: %w", err)
			}
			refOK = true
			return nil
		}
		c, err := s.ActivateTx(ctx, tx, in)
		if err != nil {
			return err
		}
		if !refOK {
			return ErrNotFound
		}
		out = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConnectLimits returns the AfterLocks hook of connect and reconnect: the
// tenant limit of MaxLiveConnectionsPerTenant under the L2a mutex row, then
// the hourly budget of the owner. It runs on the mutation's own transaction
// after L1 and L2, so a refusal rolls the whole connect back and no counter
// moves. The mutex row is created here (INSERT ... ON CONFLICT DO NOTHING with
// the fixed window_start 'epoch') and then locked FOR UPDATE, so the first
// connect of a tenant, and one right after a Sweep, still find a row to lock.
func (s *Store) ConnectLimits(owner Owner) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		if err := s.setLockTimeout(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo.glovo_rate_counters (scope, tenant_id, principal_id, window_start, count, updated_at)
 VALUES ('tenant_mutex', $1, '', 'epoch'::timestamptz, 0, clock_timestamp()) ON CONFLICT DO NOTHING`, owner.TenantID); err != nil {
			return fmt.Errorf("glovo: create tenant mutex: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM glovo.glovo_rate_counters
 WHERE scope = 'tenant_mutex' AND tenant_id = $1 AND principal_id = '' AND window_start = 'epoch'::timestamptz FOR UPDATE`, owner.TenantID); err != nil {
			return fmt.Errorf("glovo: lock tenant mutex: %w", err)
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM glovo.glovo_connections
 WHERE tenant_id = $1 AND state IN ('pending_handoff','pending_provider','active')
   AND (expires_at IS NULL OR expires_at > clock_timestamp())`, owner.TenantID).Scan(&live); err != nil {
			return fmt.Errorf("glovo: count live connections: %w", err)
		}
		if live >= MaxLiveConnectionsPerTenant {
			return refuse(CodeRateLimited)
		}
		var n int
		err := tx.QueryRow(ctx, `INSERT INTO glovo.glovo_rate_counters AS rc (scope, tenant_id, principal_id, window_start, count, updated_at)
 VALUES ('owner_hour', $1, $2, date_trunc('hour', clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', 1, clock_timestamp())
 ON CONFLICT (scope, tenant_id, principal_id, window_start)
 DO UPDATE SET count = rc.count + 1, updated_at = clock_timestamp() WHERE rc.count < $3
 RETURNING count`, owner.TenantID, owner.PrincipalID, MaxConnectsPerHour).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return refuse(CodeRateLimited)
		}
		if err != nil {
			return fmt.Errorf("glovo: owner counter: %w", err)
		}
		return nil
	}
}

// PurgeHandoffRefs is the EndPurger of this slice: it deletes the unconsumed
// handoff references of the ended connections on the ending path's own
// transaction, so a revoked connection can never be activated.
func PurgeHandoffRefs(ctx context.Context, tx pgx.Tx, ended []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.glovo_handoff_refs WHERE connection_id = ANY($1) AND consumed_at IS NULL`, ended); err != nil {
		return fmt.Errorf("glovo: purge handoff references: %w", err)
	}
	return nil
}

// SweepResult counts the rows one Sweep deleted.
type SweepResult struct{ HandoffRefs, Counters, ConnectRequests int64 }

// Sweep deletes, at most limit rows per table: handoff references that
// expired or were consumed over an hour ago, owner_hour counter windows over
// two hours old, and connect_requests rows over 24 hours old. It never
// deletes tenant_mutex rows.
func (s *Store) Sweep(ctx context.Context, limit int) (SweepResult, error) {
	if limit < 1 {
		return SweepResult{}, refuse(CodeInvalidRequest)
	}
	var r SweepResult
	steps := []struct {
		dst *int64
		sql string
	}{
		{&r.HandoffRefs, `DELETE FROM glovo.glovo_handoff_refs WHERE ref_hash IN (
 SELECT ref_hash FROM glovo.glovo_handoff_refs
  WHERE expires_at < clock_timestamp() - interval '1 hour' OR consumed_at < clock_timestamp() - interval '1 hour' LIMIT $1)`},
		{&r.Counters, `DELETE FROM glovo.glovo_rate_counters WHERE ctid IN (
 SELECT ctid FROM glovo.glovo_rate_counters
  WHERE scope = 'owner_hour' AND window_start < clock_timestamp() - interval '2 hours' LIMIT $1)`},
		{&r.ConnectRequests, `DELETE FROM glovo.glovo_connect_requests WHERE ctid IN (
 SELECT ctid FROM glovo.glovo_connect_requests WHERE created_at < clock_timestamp() - interval '24 hours' LIMIT $1)`},
	}
	for _, st := range steps {
		tag, err := s.pool.Exec(ctx, st.sql, limit)
		if err != nil {
			return r, fmt.Errorf("glovo: sweep: %w", err)
		}
		*st.dst = tag.RowsAffected()
	}
	return r, nil
}
