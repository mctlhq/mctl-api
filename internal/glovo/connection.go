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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// ConnectInput is the input of Connect and Reconnect.
type ConnectInput struct {
	Owner                   Owner
	ExpectedInstallRevision int64
	IdempotencyKey          string
	// Actor is not part of the request hash, so a replay by another actor is
	// still a replay.
	Actor Actor
	// TerminalOnly (Reconnect only): a live prior is refused connection_exists
	// instead of being superseded; a prior that is terminal, by state or by
	// expires_at <= clock_timestamp(), takes the terminal branch.
	TerminalOnly bool
	// AfterLocks runs on the mutation's own transaction after L1 and L2 and
	// before the insert. An error aborts and is returned as is. The replay
	// lookup runs first: on a replay AfterLocks does not run.
	AfterLocks func(ctx context.Context, tx pgx.Tx) error
}

// ActivateInput is the input of ActivateTx.
type ActivateInput struct {
	Owner                   Owner
	ConnectionID            string
	ExpectedVersion         int64
	ExpectedInstallRevision int64
	ExpiresIn               time.Duration
	// Actor is derived from an authenticated worker principal in ctx when zero.
	Actor      Actor
	AfterLocks func(ctx context.Context, tx pgx.Tx) error
}

func (in ConnectInput) validate(reconnect bool, prior string) error {
	if err := in.Owner.validate(); err != nil {
		return err
	}
	if err := in.Actor.validate(); err != nil {
		return err
	}
	if in.ExpectedInstallRevision < 1 || in.IdempotencyKey == "" || len(in.IdempotencyKey) > maxIdempotencyKeyLen {
		return refuse(CodeInvalidRequest)
	}
	if reconnect && !strings.HasPrefix(prior, prefixConnection) {
		return refuse(CodeInvalidRequest)
	}
	return nil
}

func requestHash(in ConnectInput, prior string) string {
	sum := sha256.Sum256([]byte(lengthPrefixed("glovo-connect-request/v1", [][2]string{
		{"tenant", in.Owner.TenantID}, {"principal", in.Owner.PrincipalID},
		{"revision", strconv.FormatInt(in.ExpectedInstallRevision, 10)}, {"prior", prior},
	})))
	return hex.EncodeToString(sum[:])
}

// Connect creates a connection for the owner in state pending_handoff.
func (s *Store) Connect(ctx context.Context, in ConnectInput) (*ConnectResult, error) {
	return s.connect(ctx, in, "", false)
}

// Reconnect creates a new connection (a new gcn_ id, supersedes_id set to the
// prior one). A live prior is ended through endConnection with reason
// superseded unless in.TerminalOnly; a terminal prior is left alone (one that
// has lapsed by expires_at is first moved to expired). A prior that is not the
// owner's is ErrNotFound.
func (s *Store) Reconnect(ctx context.Context, in ConnectInput, priorConnectionID string) (*ConnectResult, error) {
	return s.connect(ctx, in, priorConnectionID, true)
}

func (s *Store) connect(ctx context.Context, in ConnectInput, prior string, reconnect bool) (*ConnectResult, error) {
	if err := in.validate(reconnect, prior); err != nil {
		return nil, err
	}
	hash := requestHash(in, prior)
	var res *ConnectResult
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if s.beforeL2 != nil {
			s.beforeL2()
		}
		if err := s.withLocks(ctx, tx, in.Owner.TenantID, in.Owner.PrincipalID, lockShared); err != nil {
			return err
		}
		// Replay first: a retry returns the original connection in whatever
		// state it is now, and runs nothing else.
		var storedHash, storedID string
		err := tx.QueryRow(ctx, `SELECT request_hash, connection_id FROM glovo.glovo_connect_requests
 WHERE tenant_id = $1 AND principal_id = $2 AND idempotency_key = $3`,
			in.Owner.TenantID, in.Owner.PrincipalID, in.IdempotencyKey).Scan(&storedHash, &storedID)
		switch {
		case err == nil:
			if storedHash != hash {
				return refuse(CodeIdempotencyReused)
			}
			c, err := getConnection(ctx, tx, in.Owner, storedID)
			if err != nil {
				return err
			}
			res = &ConnectResult{Connection: c, Replayed: true}
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("glovo: read connect request: %w", err)
		}

		var installID, instState string
		var instRev int64
		err = tx.QueryRow(ctx, `SELECT install_id, install_revision, state FROM glovo.glovo_installs
 WHERE tenant_id = $1 FOR SHARE`, in.Owner.TenantID).Scan(&installID, &instRev, &instState)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && InstallState(instState) != InstallInstalled) {
			return refuse(CodeNoInstall)
		}
		if err != nil {
			return fmt.Errorf("glovo: read install: %w", err)
		}
		if instRev != in.ExpectedInstallRevision {
			return refuse(CodeStaleInstall)
		}

		supersedes := ""
		var ended []Connection
		if reconnect {
			supersedes = prior
			var lapsed bool
			c, err := scanConn(tx.QueryRow(ctx, `SELECT `+connCols+`,
  (expires_at IS NOT NULL AND expires_at <= clock_timestamp())
  FROM glovo.glovo_connections
 WHERE connection_id = $1 AND tenant_id = $2 AND principal_id = $3 FOR UPDATE`,
				prior, in.Owner.TenantID, in.Owner.PrincipalID), &lapsed)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("glovo: read prior connection: %w", err)
			}
			if c.State.Live() {
				switch {
				case lapsed:
					e, err := s.endConnection(ctx, tx, []string{prior}, Expired, ReasonExpired, in.Actor)
					if err != nil {
						return err
					}
					ended = append(ended, e...)
				case in.TerminalOnly:
					return refuse(CodeConnectionExists)
				default:
					e, err := s.endConnection(ctx, tx, []string{prior}, Revoked, ReasonSuperseded, in.Actor)
					if err != nil {
						return err
					}
					ended = append(ended, e...)
				}
			}
		}

		if in.AfterLocks != nil {
			if err := in.AfterLocks(ctx, tx); err != nil {
				return err
			}
		}

		id, err := newPrefixedID(prefixConnection, s.now())
		if err != nil {
			return err
		}
		// created_at is the database wall clock after L2 exclusive is held, so
		// the order of one owner's rows follows lock order; now() would be
		// the transaction start.
		c, err := scanConn(tx.QueryRow(ctx, `WITH t AS (SELECT clock_timestamp() AS n)
INSERT INTO glovo.glovo_connections
  (connection_id, tenant_id, principal_id, install_id, install_revision, state, supersedes_id, created_at, updated_at, version)
SELECT $1, $2, $3, $4, $5, 'pending_handoff', $6, t.n, t.n, 1 FROM t
RETURNING `+connCols, id, in.Owner.TenantID, in.Owner.PrincipalID, installID, instRev, supersedes))
		if err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == "glovo_connections_one_live" {
				return refuse(CodeConnectionExists)
			}
			return fmt.Errorf("glovo: insert connection: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo.glovo_connect_requests
  (tenant_id, principal_id, idempotency_key, request_hash, connection_id, created_at)
  VALUES ($1, $2, $3, $4, $5, $6)`,
			in.Owner.TenantID, in.Owner.PrincipalID, in.IdempotencyKey, hash, id, s.now()); err != nil {
			return fmt.Errorf("glovo: insert connect request: %w", err)
		}
		event := "connection_connected"
		if reconnect {
			event = "connection_reconnected"
		}
		if err := s.appendAudit(ctx, tx, connAudit(c, in.Actor, event, "", "")); err != nil {
			return err
		}
		if s.failAfterWrite != nil {
			if err := s.failAfterWrite(); err != nil {
				return err
			}
		}
		res = &ConnectResult{Connection: c, Ended: ended}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// lockOwnedConnection reads the owner's connection FOR UPDATE in one
// statement; a miss, foreign or absent, is ErrNotFound. lapsed is the database
// clock's verdict on expires_at.
func lockOwnedConnection(ctx context.Context, q dbq.Querier, owner Owner, id string) (*Connection, bool, error) {
	var lapsed bool
	c, err := scanConn(q.QueryRow(ctx, `SELECT `+connCols+`,
  (expires_at IS NOT NULL AND expires_at <= clock_timestamp())
  FROM glovo.glovo_connections
 WHERE connection_id = $1 AND tenant_id = $2 AND principal_id = $3 FOR UPDATE`,
		id, owner.TenantID, owner.PrincipalID), &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrNotFound
	}
	if err != nil {
		return nil, false, fmt.Errorf("glovo: read connection: %w", err)
	}
	return c, lapsed, nil
}

// ActivateTx moves a pending_handoff connection to active on the caller's
// transaction: pending_handoff -> pending_provider -> active, two audited
// steps, with expires_at = clock_timestamp() + ExpiresIn computed in SQL. It
// begins and commits nothing; a refusal after AfterLocks leaves the rollback
// to the caller. Order: actor and ExpiresIn (invalid_request, before any
// lock), L1 shared and L2 exclusive, AfterLocks, the owner-scoped lookup
// (not_found), the state, the install revision, the version, the writes. The
// state is checked before the version so a terminal row reports its terminal
// code.
func (s *Store) ActivateTx(ctx context.Context, tx pgx.Tx, in ActivateInput) (*Connection, error) {
	actor := in.Actor
	if actor == (Actor{}) {
		if a, ok := ActorFrom(ctx); ok {
			actor = a
		}
	}
	if err := in.Owner.validate(); err != nil {
		return nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, err
	}
	if in.ExpiresIn <= 0 || in.ExpiresIn > MaxConnectionTTL || in.ConnectionID == "" {
		return nil, refuse(CodeInvalidRequest)
	}
	if err := advisory(ctx, tx, installLockKey(in.Owner.TenantID), lockShared); err != nil {
		return nil, err
	}
	if err := advisory(ctx, tx, ownerLockKey(in.Owner.TenantID, in.Owner.PrincipalID), lockExclusive); err != nil {
		return nil, err
	}
	if in.AfterLocks != nil {
		if err := in.AfterLocks(ctx, tx); err != nil {
			return nil, err
		}
	}
	c, lapsed, err := lockOwnedConnection(ctx, tx, in.Owner, in.ConnectionID)
	if err != nil {
		return nil, err
	}
	switch c.State {
	case PendingHandoff:
	case PendingProvider:
		return nil, refuse(CodeInvalidTransition)
	case Active:
		if lapsed {
			return nil, refuse(CodeConnectionExpired)
		}
		return nil, refuse(CodeInvalidTransition)
	case Revoked:
		return nil, refuse(CodeConnectionRevoked)
	case Expired:
		return nil, refuse(CodeConnectionExpired)
	default:
		return nil, refuse(CodeNoConnection)
	}
	var instRev int64
	var instState string
	err = tx.QueryRow(ctx, `SELECT install_revision, state FROM glovo.glovo_installs WHERE tenant_id = $1 FOR SHARE`,
		in.Owner.TenantID).Scan(&instRev, &instState)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && InstallState(instState) != InstallInstalled) {
		return nil, refuse(CodeNoInstall)
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read install: %w", err)
	}
	if instRev != in.ExpectedInstallRevision || c.InstallRevision != instRev {
		return nil, refuse(CodeStaleInstall)
	}
	if c.Version != in.ExpectedVersion {
		return nil, refuse(CodeStaleVersion)
	}
	now := s.now()
	step1, err := scanConn(tx.QueryRow(ctx, `UPDATE glovo.glovo_connections
  SET state = 'pending_provider', version = version + 1, updated_at = $2
  WHERE connection_id = $1 RETURNING `+connCols, c.ConnectionID, now))
	if err != nil {
		return nil, fmt.Errorf("glovo: activate step 1: %w", err)
	}
	if err := s.appendAudit(ctx, tx, connAudit(step1, actor, "connection_pending_provider", string(PendingHandoff), "")); err != nil {
		return nil, err
	}
	step2, err := scanConn(tx.QueryRow(ctx, `UPDATE glovo.glovo_connections
  SET state = 'active', version = version + 1, updated_at = $2,
      expires_at = clock_timestamp() + ($3::bigint * interval '1 microsecond')
  WHERE connection_id = $1 RETURNING `+connCols, c.ConnectionID, now, in.ExpiresIn.Microseconds()))
	if err != nil {
		return nil, fmt.Errorf("glovo: activate step 2: %w", err)
	}
	if err := s.appendAudit(ctx, tx, connAudit(step2, actor, "connection_active", string(PendingProvider), "")); err != nil {
		return nil, err
	}
	return step2, nil
}

// Transition moves one of the owner's connections along the edge table. The
// actor comes from ActorFrom(ctx) only: with no Actor and no authenticated
// worker principal the call is invalid_request and writes nothing. to =
// active is invalid_request from every from-state (ActivateTx is the only
// activation). Terminal targets go through endConnection and return the
// released secret reference on the Connection. ref, when non-nil and the
// target is not terminal, is recorded as the connection's secret reference.
func (s *Store) Transition(ctx context.Context, owner Owner, connectionID string, to ConnectionState,
	expectedVersion int64, reason string, ref *SecretRef) (*Connection, error) {
	actor, ok := ActorFrom(ctx)
	if !ok || actor.validate() != nil {
		return nil, refuse(CodeInvalidRequest)
	}
	if to == Active || !to.valid() {
		return nil, refuse(CodeInvalidRequest)
	}
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if reason != "" && !validReason(reason) {
		return nil, refuse(CodeInvalidRequest)
	}
	if ref != nil && !strings.HasPrefix(ref.ID, prefixSecretRef) {
		return nil, refuse(CodeInvalidRequest)
	}
	if reason == "" {
		reason = string(to)
	}
	var out *Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, owner.TenantID, owner.PrincipalID, lockShared); err != nil {
			return err
		}
		c, _, err := lockOwnedConnection(ctx, tx, owner, connectionID)
		if err != nil {
			return err
		}
		if !CanTransition(c.State, to) {
			return refuse(CodeInvalidTransition)
		}
		if c.Version != expectedVersion {
			return refuse(CodeStaleVersion)
		}
		if to.Terminal() {
			ended, err := s.endConnection(ctx, tx, []string{c.ConnectionID}, to, reason, actor)
			if err != nil {
				return err
			}
			if len(ended) != 1 {
				return refuse(CodeInvalidTransition)
			}
			out = &ended[0]
			return nil
		}
		var refID *string
		if ref != nil {
			refID = &ref.ID
		}
		n, err := scanConn(tx.QueryRow(ctx, `UPDATE glovo.glovo_connections
  SET state = $2, version = version + 1, updated_at = $3, secret_ref = COALESCE($4, secret_ref)
  WHERE connection_id = $1 RETURNING `+connCols, c.ConnectionID, string(to), s.now(), refID))
		if err != nil {
			return fmt.Errorf("glovo: transition: %w", err)
		}
		if err := s.appendAudit(ctx, tx, connAudit(n, actor, "connection_"+string(to), string(c.State), reason)); err != nil {
			return err
		}
		out = n
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke ends one of the owner's connections with state revoked. Revoking an
// already revoked connection returns it and writes nothing; an expired or
// failed one is invalid_transition.
func (s *Store) Revoke(ctx context.Context, owner Owner, actor Actor, connectionID, reason string) (*Connection, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, err
	}
	if !validReason(reason) {
		return nil, refuse(CodeInvalidRequest)
	}
	var out *Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, owner.TenantID, owner.PrincipalID, lockShared); err != nil {
			return err
		}
		c, _, err := lockOwnedConnection(ctx, tx, owner, connectionID)
		if err != nil {
			return err
		}
		if c.State == Revoked {
			out = c
			return nil
		}
		if !CanTransition(c.State, Revoked) {
			return refuse(CodeInvalidTransition)
		}
		ended, err := s.endConnection(ctx, tx, []string{c.ConnectionID}, Revoked, reason, actor)
		if err != nil {
			return err
		}
		if len(ended) != 1 {
			return refuse(CodeInvalidTransition)
		}
		out = &ended[0]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeForMembership ends the owner's live connection, if any, with reason
// membership_removed. Who detects the membership change is the caller's.
func (s *Store) RevokeForMembership(ctx context.Context, tenant, principal string, actor Actor) ([]Connection, error) {
	owner := Owner{TenantID: tenant, PrincipalID: principal}
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, err
	}
	var ended []Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, tenant, principal, lockShared); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT connection_id FROM glovo.glovo_connections
 WHERE tenant_id = $1 AND principal_id = $2 AND state IN ('pending_handoff','pending_provider','active')
 ORDER BY connection_id FOR UPDATE`, tenant, principal)
		if err != nil {
			return fmt.Errorf("glovo: list live connections: %w", err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("glovo: scan connection id: %w", err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("glovo: list live connections: %w", err)
		}
		ended, err = s.endConnection(ctx, tx, ids, Revoked, ReasonMembershipRemoved, actor)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ended, nil
}

func getConnection(ctx context.Context, q dbq.Querier, owner Owner, id string) (*Connection, error) {
	c, err := scanConn(q.QueryRow(ctx, `SELECT `+connCols+` FROM glovo.glovo_connections
 WHERE connection_id = $1 AND tenant_id = $2 AND principal_id = $3`, id, owner.TenantID, owner.PrincipalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read connection: %w", err)
	}
	return c, nil
}

// GetConnection returns one of the owner's connections in any state. A missing
// id and another owner's id are the same ErrNotFound, from one statement.
func (s *Store) GetConnection(ctx context.Context, owner Owner, connectionID string) (*Connection, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	return getConnection(ctx, s.pool, owner, connectionID)
}

// GetConnectionForWorker is the one read by id with no owner predicate, for
// the worker routes behind the worker gate: it returns the connection with its
// write-once Owner, or ErrNotFound. It takes no lock and is not an authority;
// the worker then calls LockOwnerShared, ActivateTx or Revoke with the
// returned Owner, and the version read here is re-checked under the locks.
// A source-scan test allows no caller outside handlers_glovo_worker.go.
func (s *Store) GetConnectionForWorker(ctx context.Context, connectionID string) (*Connection, error) {
	c, err := scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+` FROM glovo.glovo_connections WHERE connection_id = $1`, connectionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read connection: %w", err)
	}
	return c, nil
}

// liveRead reads the owner's most recent connection row in one statement (no
// live predicate, no row lock). It returns the row alone when it is live and
// not lapsed. Otherwise it returns the typed not-live code with the row (nil
// when there is none): revoked is connection_revoked; expired, or a live row
// with expires_at <= clock_timestamp() (database clock at statement time,
// never now()), is connection_expired; failed or no row is no_connection.
func liveRead(ctx context.Context, q dbq.Querier, owner Owner) (*Connection, error) {
	if err := owner.validate(); err != nil {
		return nil, err
	}
	var lapsed bool
	c, err := scanConn(q.QueryRow(ctx, `SELECT `+connCols+`,
  (expires_at IS NOT NULL AND expires_at <= clock_timestamp())
  FROM glovo.glovo_connections WHERE tenant_id = $1 AND principal_id = $2
 ORDER BY created_at DESC, connection_id DESC LIMIT 1`, owner.TenantID, owner.PrincipalID), &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(CodeNoConnection)
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read live connection: %w", err)
	}
	switch {
	case c.State.Live() && !lapsed:
		return c, nil
	case c.State.Live() && lapsed, c.State == Expired:
		return c, refuse(CodeConnectionExpired)
	case c.State == Revoked:
		return c, refuse(CodeConnectionRevoked)
	default:
		return c, refuse(CodeNoConnection)
	}
}

// LiveConnection is liveRead on the pool.
func (s *Store) LiveConnection(ctx context.Context, owner Owner) (*Connection, error) {
	return liveRead(ctx, s.pool, owner)
}

// LiveConnectionTx is liveRead on the caller's transaction. The caller must
// hold L2 (shared or exclusive; every writer holds it exclusive). It begins
// and commits nothing.
func (s *Store) LiveConnectionTx(ctx context.Context, tx pgx.Tx, owner Owner) (*Connection, error) {
	return liveRead(ctx, tx, owner)
}

// AppendRefusal appends one audit event (event "refused", reason_code the
// refusal code, from_state = to_state = the entity's current state) for a
// refusal that names an existing install or connection. A foreign or absent
// entity is ErrNotFound and writes nothing.
func (s *Store) AppendRefusal(ctx context.Context, ev RefusalEvent) error {
	if err := validTenant(ev.TenantID); err != nil {
		return err
	}
	if err := ev.Actor.validate(); err != nil {
		return err
	}
	if !Registered(ev.Code) || ev.EntityID == "" {
		return refuse(CodeInvalidRequest)
	}
	id, err := newPrefixedID(prefixAudit, s.now())
	if err != nil {
		return err
	}
	var q string
	switch ev.EntityKind {
	case "connection":
		q = `INSERT INTO glovo.glovo_audit_events
  (event_id, tenant_id, subject_principal_id, actor_principal_id, actor_kind, entity_kind, entity_id,
   event, from_state, to_state, install_revision, reason_code, recorded_at)
 SELECT $1, c.tenant_id, c.principal_id, $4, $5, 'connection', c.connection_id,
   'refused', c.state, c.state, c.install_revision, $6, $7
 FROM glovo.glovo_connections c WHERE c.connection_id = $2 AND c.tenant_id = $3`
	case "install":
		q = `INSERT INTO glovo.glovo_audit_events
  (event_id, tenant_id, subject_principal_id, actor_principal_id, actor_kind, entity_kind, entity_id,
   event, from_state, to_state, install_revision, reason_code, recorded_at)
 SELECT $1, i.tenant_id, '', $4, $5, 'install', i.install_id,
   'refused', i.state, i.state, i.install_revision, $6, $7
 FROM glovo.glovo_installs i WHERE i.install_id = $2 AND i.tenant_id = $3`
	default:
		return refuse(CodeInvalidRequest)
	}
	tag, err := s.pool.Exec(ctx, q, id, ev.EntityID, ev.TenantID, ev.Actor.PrincipalID, string(ev.Actor.Kind), string(ev.Code), s.now())
	if err != nil {
		return fmt.Errorf("glovo: append refusal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAudit returns the tenant's audit events for one entity, oldest first.
// The tenant is part of the predicate: another tenant's entity id returns
// nothing.
func (s *Store) ListAudit(ctx context.Context, tenantID, entityID string) ([]AuditEvent, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT event_id, tenant_id, subject_principal_id, actor_principal_id, actor_kind,
  entity_kind, entity_id, event, from_state, to_state, install_revision, reason_code, recorded_at
 FROM glovo.glovo_audit_events WHERE tenant_id = $1 AND entity_id = $2
 ORDER BY recorded_at, event_id LIMIT 1000`, tenantID, entityID)
	if err != nil {
		return nil, fmt.Errorf("glovo: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var kind string
		if err := rows.Scan(&e.EventID, &e.TenantID, &e.SubjectPrincipalID, &e.ActorPrincipalID, &kind, &e.EntityKind,
			&e.EntityID, &e.Event, &e.FromState, &e.ToState, &e.InstallRevision, &e.ReasonCode, &e.RecordedAt); err != nil {
			return nil, fmt.Errorf("glovo: scan audit: %w", err)
		}
		e.ActorKind = ActorKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IsAllowlisted reports whether the principal is on the tenant's pilot
// allowlist. Read only: the writes belong to the allowlist slice.
func (s *Store) IsAllowlisted(ctx context.Context, tenantID, principalID string) (bool, error) {
	if err := (Owner{TenantID: tenantID, PrincipalID: principalID}).validate(); err != nil {
		return false, err
	}
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM glovo.glovo_pilot_allowlist
 WHERE tenant_id = $1 AND principal_id = $2)`, tenantID, principalID).Scan(&ok); err != nil {
		return false, fmt.Errorf("glovo: read allowlist: %w", err)
	}
	return ok, nil
}
