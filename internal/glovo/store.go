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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// roleNameRE is the shape every role name given to this package must have.
var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ApplySchema creates or upgrades schema glovo and the tables of this slice,
// then issues the runtime grants (the #959 rows of mctl-api#957 design 6d.1,
// read from the grant registry) and records the schema version. It runs only
// under the migration role, which becomes the owner of every object, in one
// transaction under a schema advisory lock. It creates objects only in schema
// glovo and never alters or drops any other object. It refuses a schema or an
// object in schema glovo that another role owns, a recorded schema version
// above the compiled one, and a runtimeRole that does not match
// ^[a-z_][a-z0-9_]{0,62}$.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string) error {
	if !roleNameRE.MatchString(runtimeRole) {
		return fmt.Errorf("glovo: invalid runtime role name")
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("glovo: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovo: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-schema'))`); err != nil {
		return fmt.Errorf("glovo: schema lock: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS glovo`); err != nil {
		return fmt.Errorf("glovo: create schema: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('glovo.glovo_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("glovo: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM glovo.glovo_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("glovo: read schema version: %w", err)
		}
		if recorded != nil && *recorded > schemaVersion {
			return fmt.Errorf("glovo: recorded schema version %d is above the compiled version %d", *recorded, schemaVersion)
		}
	}
	if _, err := tx.Exec(ctx, glovoSchema); err != nil {
		return fmt.Errorf("glovo: apply schema: %w", err)
	}
	if _, err := tx.Exec(ctx, handoffSchema); err != nil {
		return fmt.Errorf("glovo: apply handoff schema: %w", err)
	}
	// Ownership again: IF NOT EXISTS must not have adopted a foreign object.
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}

	role := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SCHEMA glovo TO `+role); err != nil {
		return fmt.Errorf("glovo: grant schema usage: %w", err)
	}
	for _, t := range append(append([]string(nil), slice959Tables...), slice961Tables...) {
		row, ok := grantFor(t)
		if !ok {
			return fmt.Errorf("glovo: no grant row registered for %s", t)
		}
		tbl := pgx.Identifier{"glovo", t}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
			return fmt.Errorf("glovo: revoke on %s: %w", t, err)
		}
		if len(row.Privileges) > 0 {
			if _, err := tx.Exec(ctx, `GRANT `+strings.Join(row.Privileges, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo: grant on %s: %w", t, err)
			}
		}
		if len(row.UpdateColumns) > 0 {
			cols := make([]string, len(row.UpdateColumns))
			for i, c := range row.UpdateColumns {
				cols[i] = pgx.Identifier{c}.Sanitize()
			}
			if _, err := tx.Exec(ctx, `GRANT UPDATE (`+strings.Join(cols, ", ")+`) ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo: grant column update on %s: %w", t, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.glovo_schema_version`); err != nil {
		return fmt.Errorf("glovo: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.glovo_schema_version (version) VALUES ($1)`, schemaVersion); err != nil {
		return fmt.Errorf("glovo: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovo: commit schema: %w", err)
	}
	return nil
}

// checkOwnership refuses schema glovo, or any relation or function in it, that
// current_user (the migration role) does not own.
func checkOwnership(ctx context.Context, q dbq.Querier) error {
	var n int
	err := q.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo' AND nspowner <> r.oid)
     + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'glovo' AND c.relowner <> r.oid)
     + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'glovo' AND p.proowner <> r.oid)
FROM pg_roles r WHERE r.rolname = current_user`).Scan(&n)
	if err != nil {
		return fmt.Errorf("glovo: ownership check: %w", err)
	}
	if n != 0 {
		return fmt.Errorf("glovo: schema glovo holds %d object(s) owned by another role; refusing to adopt them", n)
	}
	return nil
}

// RevocationHook is called by every path that ends a connection, on that
// path's transaction, after the rows are ended, with the ended ids. actor is
// Actor.PrincipalID of the call that ended them. An error rolls the ending
// back.
type RevocationHook func(ctx context.Context, tx pgx.Tx, ended []string, actor string) error

// EndPurger runs on the ending path's transaction, after the rows are ended
// and before the RevocationHook, with the ended ids. An error rolls the ending
// back. This package names no table of another slice; the handoff slice
// installs the purge of its own rows here.
type EndPurger func(ctx context.Context, tx pgx.Tx, ended []string) error

// Option configures a Store.
type Option func(*Store)

// WithClock sets the Go clock used for ids and for the timestamps the store
// writes from Go. Expiry is always judged by the database clock.
func WithClock(f func() time.Time) Option { return func(s *Store) { s.clock = f } }

// WithExplicitURL records whether the wiring slice opened the pool from an
// explicit GLOVO_DB_URL (never AUDIT_DB_URL). false makes Ready not_ready.
func WithExplicitURL(explicit bool) Option { return func(s *Store) { s.explicitURL = explicit } }

// WithRevocationHook installs the hook called by every ending path.
func WithRevocationHook(h RevocationHook) Option { return func(s *Store) { s.hook = h } }

// WithEndPurger installs the purge called by every ending path.
func WithEndPurger(p EndPurger) Option { return func(s *Store) { s.purger = p } }

// WithEndPurgerRequired makes Ready report end_purger_missing while no
// purger is installed.
func WithEndPurgerRequired(required bool) Option {
	return func(s *Store) { s.purgerRequired = required }
}

// WithMembershipRevoker registers the slice that detects membership removal
// and calls RevokeForMembership.
func WithMembershipRevoker(name string) Option { return func(s *Store) { s.membershipRevoker = name } }

// Store is the tenant/principal connection store. Every connection read and
// write takes an Owner.
type Store struct {
	pool                       *pgxpool.Pool
	runtimeRole, migrationRole string
	clock                      func() time.Time
	explicitURL                bool
	hook                       RevocationHook
	purger                     EndPurger
	purgerRequired             bool
	lockTimeout                time.Duration
	membershipRevoker          string

	// test hooks
	beforeL2       func()
	failAfterWrite func() error
}

// NewStore wraps the shared GLOVO_DB_URL pool. It opens no pool of its own,
// runs no DDL, and fails closed when the recorded schema version is missing or
// differs from the compiled one. It does not close the pool on failure: the
// wiring slice owns it.
func NewStore(ctx context.Context, pool *pgxpool.Pool, runtimeRole, migrationRole string, opts ...Option) (*Store, error) {
	if pool == nil {
		return nil, errors.New("glovo: nil pool")
	}
	if !roleNameRE.MatchString(runtimeRole) || !roleNameRE.MatchString(migrationRole) {
		return nil, errors.New("glovo: invalid role name")
	}
	s := &Store{pool: pool, runtimeRole: runtimeRole, migrationRole: migrationRole, clock: time.Now}
	for _, o := range opts {
		o(s)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("glovo: ping: %w", err)
	}
	if err := s.checkVersion(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) checkVersion(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT version FROM glovo.glovo_schema_version`)
	if err != nil {
		return fmt.Errorf("glovo: read schema version (was ApplySchema run?): %w", err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("glovo: scan schema version: %w", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("glovo: read schema version: %w", err)
	}
	if len(got) != 1 || got[0] != schemaVersion {
		return fmt.Errorf("glovo: schema version %v does not match the compiled version %d", got, schemaVersion)
	}
	return nil
}

// Pool returns the pool NewStore was given.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases nothing it does not own: the shared pool is closed by the
// wiring slice.
func (s *Store) Close() {}

// MembershipRevocationWired reports whether a membership revoker was named.
func (s *Store) MembershipRevocationWired() bool { return s.membershipRevoker != "" }

// EndPurgerInstalled reports whether an EndPurger is installed.
func (s *Store) EndPurgerInstalled() bool { return s.purger != nil }

func (s *Store) now() time.Time { return s.clock().UTC() }

// withTx runs fn in one transaction and rolls back on any error.
func (s *Store) withTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovo: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovo: commit: %w", err)
	}
	return nil
}

// Lock keys. L1 is the tenant install key, L2 the owner key, levels L1 and L2
// of the canonical order of mctl-api#957 design 6b. Keys are length-prefixed
// so a tenant name containing a separator cannot collide.
func installLockKey(tenant string) string {
	return lengthPrefixed("glovo-install/v1", [][2]string{{"tenant", tenant}})
}

func ownerLockKey(tenant, principal string) string {
	return lengthPrefixed("glovo-owner/v1", [][2]string{{"tenant", tenant}, {"principal", principal}})
}

type lockMode int

const (
	lockShared lockMode = iota
	lockExclusive
)

func advisory(ctx context.Context, q dbq.Querier, key string, mode lockMode) error {
	fn := "pg_advisory_xact_lock_shared"
	if mode == lockExclusive {
		fn = "pg_advisory_xact_lock"
	}
	if _, err := q.Exec(ctx, "SELECT "+fn+"(hashtextextended($1, 0))", key); err != nil {
		return fmt.Errorf("glovo: advisory lock: %w", err)
	}
	return nil
}

// withLocks takes L1 (install key) in installMode, then, when principal is
// non-empty, L2 (owner key) exclusive. Install-level changes pass an empty
// principal.
func (s *Store) withLocks(ctx context.Context, q dbq.Querier, tenant, principal string, installMode lockMode) error {
	if err := advisory(ctx, q, installLockKey(tenant), installMode); err != nil {
		return err
	}
	if principal != "" {
		return advisory(ctx, q, ownerLockKey(tenant, principal), lockExclusive)
	}
	return nil
}

// LockOwnerShared takes L1 shared, then L2 shared, on the caller's
// transaction. It begins and commits nothing.
func (s *Store) LockOwnerShared(ctx context.Context, tx pgx.Tx, tenant, principal string) error {
	if err := (Owner{TenantID: tenant, PrincipalID: principal}).validate(); err != nil {
		return err
	}
	if err := advisory(ctx, tx, installLockKey(tenant), lockShared); err != nil {
		return err
	}
	return advisory(ctx, tx, ownerLockKey(tenant, principal), lockShared)
}

var connColumns = []string{"connection_id", "tenant_id", "principal_id", "install_id", "install_revision", "state",
	"COALESCE(secret_ref, '')", "supersedes_id", "end_reason", "version", "created_at", "updated_at", "ended_at", "expires_at"}

var connCols = strings.Join(connColumns, ", ")

// connColsAs is connCols with every column qualified by alias.
func connColsAs(alias string) string {
	out := make([]string, len(connColumns))
	for i, c := range connColumns {
		if c == "COALESCE(secret_ref, '')" {
			out[i] = "COALESCE(" + alias + ".secret_ref, '')"
		} else {
			out[i] = alias + "." + c
		}
	}
	return strings.Join(out, ", ")
}

type scanner interface{ Scan(dest ...any) error }

func scanConn(r scanner, extra ...any) (*Connection, error) {
	var c Connection
	var state string
	dest := []any{&c.ConnectionID, &c.Owner.TenantID, &c.Owner.PrincipalID, &c.InstallID, &c.InstallRevision,
		&state, &c.SecretRef, &c.SupersedesID, &c.EndReason, &c.Version, &c.CreatedAt, &c.UpdatedAt, &c.EndedAt, &c.ExpiresAt}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	c.State = ConnectionState(state)
	return &c, nil
}

// appendAudit writes one audit event on q. The id and timestamp are minted
// here; callers never choose them.
func (s *Store) appendAudit(ctx context.Context, q dbq.Querier, ev AuditEvent) error {
	now := s.now()
	id, err := newPrefixedID(prefixAudit, now)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO glovo.glovo_audit_events
  (event_id, tenant_id, subject_principal_id, actor_principal_id, actor_kind, entity_kind, entity_id,
   event, from_state, to_state, install_revision, reason_code, recorded_at)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id, ev.TenantID, ev.SubjectPrincipalID, ev.ActorPrincipalID, string(ev.ActorKind), ev.EntityKind, ev.EntityID,
		ev.Event, ev.FromState, ev.ToState, ev.InstallRevision, ev.ReasonCode, now)
	if err != nil {
		return fmt.Errorf("glovo: append audit: %w", err)
	}
	return nil
}

func connAudit(c *Connection, actor Actor, event, from, reason string) AuditEvent {
	return AuditEvent{
		TenantID: c.Owner.TenantID, SubjectPrincipalID: c.Owner.PrincipalID,
		ActorPrincipalID: actor.PrincipalID, ActorKind: actor.Kind,
		EntityKind: "connection", EntityID: c.ConnectionID, Event: event,
		FromState: from, ToState: string(c.State), InstallRevision: c.InstallRevision, ReasonCode: reason,
	}
}

// endConnection is the one path every terminal transition takes, so none can
// skip the purge. ids must already be locked by the caller (L1 and L2, or L1
// exclusive). It moves the still-live ones among ids to `to`, clears
// secret_ref (returning the released reference on the ended Connection),
// appends one audit event per ended connection carrying the caller's actor,
// then calls the EndPurger and the RevocationHook with the ended ids, all on
// tx. A purger or hook error is returned and the caller's transaction rolls
// back.
func (s *Store) endConnection(ctx context.Context, tx pgx.Tx, ids []string, to ConnectionState, reason string, actor Actor) ([]Connection, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	now := s.now()
	rows, err := tx.Query(ctx, `
WITH old AS (
  SELECT connection_id, state, secret_ref FROM glovo.glovo_connections
   WHERE connection_id = ANY($1) AND state IN ('pending_handoff','pending_provider','active')
   FOR UPDATE)
UPDATE glovo.glovo_connections c
   SET state = $2, end_reason = $3, ended_at = $4, updated_at = $4, secret_ref = NULL, version = c.version + 1
  FROM old WHERE c.connection_id = old.connection_id
RETURNING `+connColsAs("c")+`, old.state, COALESCE(old.secret_ref, '')`, ids, string(to), reason, now)
	if err != nil {
		return nil, fmt.Errorf("glovo: end connections: %w", err)
	}
	type ended struct {
		c    *Connection
		from string
	}
	var got []ended
	for rows.Next() {
		var from, released string
		c, err := scanConn(rows, &from, &released)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("glovo: scan ended connection: %w", err)
		}
		c.ReleasedSecretRef = released
		got = append(got, ended{c, from})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("glovo: end connections: %w", err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].c.ConnectionID < got[j].c.ConnectionID })
	out := make([]Connection, 0, len(got))
	endedIDs := make([]string, 0, len(got))
	for _, e := range got {
		if err := s.appendAudit(ctx, tx, connAudit(e.c, actor, "connection_"+string(to), e.from, reason)); err != nil {
			return nil, err
		}
		out = append(out, *e.c)
		endedIDs = append(endedIDs, e.c.ConnectionID)
	}
	if len(endedIDs) == 0 {
		return out, nil
	}
	if s.purger != nil {
		if err := s.purger(ctx, tx, endedIDs); err != nil {
			return nil, fmt.Errorf("glovo: end purger: %w", err)
		}
	}
	if s.hook != nil {
		if err := s.hook(ctx, tx, endedIDs, actor.PrincipalID); err != nil {
			return nil, fmt.Errorf("glovo: revocation hook: %w", err)
		}
	}
	return out, nil
}
