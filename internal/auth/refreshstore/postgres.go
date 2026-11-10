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
	"github.com/mctlhq/mctl-api/internal/pgshared"
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
-- The principal the session was signed in as (mctl-api#377). Empty for
-- tokens minted before it was recorded; principal mode refuses to refresh
-- those, so their holders sign in again.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS principal_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_principal
    ON oauth_refresh_tokens (principal_id) WHERE principal_id <> '';
-- The client authentication the session was issued under (mctl-api#694).
-- Empty for every session but a private_key_jwt CIMD client's.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT '';
-- The RFC 8707 resource the session's access tokens are minted for
-- (mctl-api#849). Empty is the default API resource.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';
-- Team grants of the Glovo pilot. Additive and inert while the pilot is off:
-- the table stays empty and team_grant_id stays ''. They live here, not in
-- the teamgrant package, so the revocation statements below always find them
-- and a grant shares a transaction with its refresh family.
CREATE TABLE IF NOT EXISTS oauth_team_grants (
    grant_id          TEXT PRIMARY KEY,
    principal_id      TEXT NOT NULL CHECK (principal_id <> ''),
    tenant            TEXT NOT NULL CHECK (tenant <> ''),
    resource          TEXT NOT NULL CHECK (resource <> ''),
    client_id         TEXT NOT NULL,
    refresh_family_id UUID NULL,
    state             TEXT NOT NULL CHECK (state IN ('pending','active','revoked')),
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ NULL,
    revoked_reason    TEXT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_team_grants_one_active
    ON oauth_team_grants (principal_id, client_id, resource) WHERE state IN ('pending','active');
CREATE INDEX IF NOT EXISTS oauth_team_grants_family ON oauth_team_grants (refresh_family_id);
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS team_grant_id TEXT NOT NULL DEFAULT '';
`

// PostgresStore is a Postgres-backed implementation of Store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// rotationGraceWindow is how long after a rotation a replay of the
// predecessor token is treated as a possible lost-response retry (see
// rotateTx) rather than reuse. A package-level var, not a const, so tests can
// shrink it instead of sleeping real wall-clock time.
//
// 30s was too tight to cover the case it exists for. A client that never
// received the rotation response does not retry within the same second: it
// retries on its next scheduled refresh or when the user next touches the
// connector, which is minutes later. Outside the window the replay is read as
// reuse and the WHOLE family is revoked, so every client on that family gets
// `invalid_grant` and the user is told to re-authenticate.
//
// What the 2026-09-17 incident establishes precisely, and what it does not:
// family 9f57b332 (login mashkovd) took twelve replays of one already-rotated
// token in two bursts ten minutes apart, which shows the blast radius — one
// late replay logs out every client on the family. It does NOT establish that
// 2m would have saved it: the log does not carry the rotation time of the
// token that first burst replayed, and every replay after the first hits the
// revoked family anyway. So this window is sized against client retry
// cadence, which is the thing it has to cover, not against that log.
//
// The signal to retune against is already emitted: compare the rate of the
// `oauth refresh token grace-window replay` INFO to the `reuse detected` WARN.
// Replays still being read as reuse mean the window is short for the clients
// in play; grace replays with no reuse mean it is doing its job.
//
// 2m is chosen against the failure it prevents rather than the one it admits.
// A widened window does NOT weaken reuse detection into a free replay: the
// grace path in rotateTx re-issues the ALREADY EXISTING successor and only
// when that successor is still the live tip of the family (not revoked, not
// itself rotated, not expired). A stolen predecessor therefore buys an
// attacker the same token the legitimate client already holds, never a
// second live branch, and the moment the legitimate client rotates again the
// replay stops being honoured.
//
// The default lives in its own const so the floor below it can be pinned by a
// test: rotationGraceWindow itself is mutated by withShortGraceWindow during
// the suite, so reading the var would pin whatever the last test left behind.
const defaultRotationGraceWindow = 2 * time.Minute

var rotationGraceWindow = defaultRotationGraceWindow

// NewPostgresStore creates a PostgresStore and auto-creates the schema.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("oauth refresh store: create schema: %w", err)
	}
	slog.Info("oauth refresh token store initialized")
	return &PostgresStore{pool: pool}, nil
}

// Pool is the pool the store runs on. The team grant store uses it so a grant
// and a refresh token are written on the same database.
func (s *PostgresStore) Pool() *pgxpool.Pool { return s.pool }

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
func (s *PostgresStore) Insert(rawToken, clientID string, sess Session, expiresAt time.Time) error {
	groupsJSON, err := json.Marshal(sess.Groups)
	if err != nil {
		return fmt.Errorf("oauth refresh store: marshal groups: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, principal_id, groups, family_id, parent_token_hash, issued_at, expires_at, auth_method, resource, team_grant_id)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, NOW(), $7, $8, $9, $10)`,
		tokenHash(rawToken), clientID, sess.Login, sess.PrincipalID, groupsJSON, uuid.New(), expiresAt, sess.AuthMethod, sess.Resource, sess.TeamGrantID,
	)
	if err != nil {
		return fmt.Errorf("oauth refresh store: insert: %w", err)
	}
	return nil
}

// InsertBound is Insert for a session bound to a team grant. It inserts the
// token and calls bind on the same transaction with the new family id; bind
// activates the grant. An error from bind rolls the insert back, so either
// both writes commit or neither does.
func (s *PostgresStore) InsertBound(ctx context.Context, rawToken, clientID string, sess Session, expiresAt time.Time, bind func(ctx context.Context, tx pgx.Tx, familyID uuid.UUID) error) error {
	if bind == nil {
		return errors.New("oauth refresh store: insert bound: no bind")
	}
	groupsJSON, err := json.Marshal(sess.Groups)
	if err != nil {
		return fmt.Errorf("oauth refresh store: marshal groups: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return fmt.Errorf("oauth refresh store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	familyID := uuid.New()
	if _, err := tx.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, principal_id, groups, family_id, parent_token_hash, issued_at, expires_at, auth_method, resource, team_grant_id)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, NOW(), $7, $8, $9, $10)`,
		tokenHash(rawToken), clientID, sess.Login, sess.PrincipalID, groupsJSON, familyID, expiresAt, sess.AuthMethod, sess.Resource, sess.TeamGrantID,
	); err != nil {
		return fmt.Errorf("oauth refresh store: insert bound: %w", err)
	}
	if err := bind(ctx, tx, familyID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oauth refresh store: insert bound commit: %w", err)
	}
	return nil
}

// Rotate atomically invalidates oldRawToken and inserts newRawToken in the same
// family. It retries on Postgres serialization failures (up to 3 attempts);
// if all retries fail it returns ErrServerError (transient DB failure, not a
// bad token) so callers map it to HTTP 500 rather than invalid_grant.
func (s *PostgresStore) Rotate(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time) (Session, error) {
	return s.RotateIf(oldRawToken, newRawToken, clientID, newExpiresAt, nil)
}

// RotateIf is Rotate with a precondition; see Store.RotateIf.
func (s *PostgresStore) RotateIf(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time, accept func(Session) error) (Session, error) {
	var wrapped func(context.Context, pgx.Tx, Session) error
	if accept != nil {
		wrapped = func(_ context.Context, _ pgx.Tx, sess Session) error { return accept(sess) }
	}
	return s.RotateIfTx(oldRawToken, newRawToken, clientID, newExpiresAt, wrapped)
}

// RotateIfTx is RotateIf whose accept runs on the rotation's own transaction,
// so it can read the team grant at the same snapshot. accept only reads and
// refuses: a write in it would roll back with its error.
func (s *PostgresStore) RotateIfTx(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time, accept func(ctx context.Context, tx pgx.Tx, s Session) error) (Session, error) {
	backoff := []time.Duration{5 * time.Millisecond, 15 * time.Millisecond}
	for attempt := range 3 {
		sess, err := s.rotateTx(oldRawToken, newRawToken, clientID, newExpiresAt, accept)
		if err == nil || !isSerializationFailure(err) {
			return sess, err
		}
		slog.Warn("oauth refresh store: serialization failure, retrying",
			"attempt", attempt+1, "error", err)
		if attempt < len(backoff) {
			time.Sleep(backoff[attempt])
		}
	}
	return Session{}, ErrServerError
}

func (s *PostgresStore) rotateTx(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time, accept func(context.Context, pgx.Tx, Session) error) (Session, error) {
	oldHash := tokenHash(oldRawToken)
	newHash := tokenHash(newRawToken)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return Session{}, fmt.Errorf("oauth refresh store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var storedClientID, login, principalID, authMethod, resource, teamGrantID string
	var groupsJSON []byte
	var familyID uuid.UUID
	var expiresAt time.Time
	var rotatedAt *time.Time
	var revokedAt *time.Time

	err = tx.QueryRow(ctx,
		`SELECT client_id, login, principal_id, groups, family_id, expires_at, rotated_at, revoked_at, auth_method, resource, team_grant_id
		 FROM oauth_refresh_tokens
		 WHERE token_hash = $1
		 FOR UPDATE`,
		oldHash,
	).Scan(&storedClientID, &login, &principalID, &groupsJSON, &familyID, &expiresAt, &rotatedAt, &revokedAt, &authMethod, &resource, &teamGrantID)
	if err == pgx.ErrNoRows {
		return Session{}, ErrInvalidToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("oauth refresh store: lookup: %w", err)
	}

	if time.Now().After(expiresAt) {
		return Session{}, ErrInvalidToken
	}

	// Reuse detection: token was already rotated → either an honest client is
	// retrying after a lost response, or an attacker replayed an old token.
	//
	// Grace window (rotationGraceWindow): if the rotation was very recent,
	// recompute the deterministic successor the caller would have derived
	// from oldRawToken (see deriveSuccessorRefreshToken) and check whether it
	// is exactly the live, unrevoked child this rotation already committed.
	// A match means the caller is legitimately retrying its own prior call —
	// re-issue that same successor rather than failing it. Any mismatch
	// (wrong client, successor itself already superseded, or missing row) is
	// NOT trusted and falls through to the same ErrInvalidToken a genuine
	// miss gets — this only ever widens success for the one caller who can
	// already prove they held oldRawToken, it never grants anything new.
	//
	// Past the grace window, revoke the whole family to protect the
	// legitimate session. Fail closed: if the revocation write fails, return
	// an error rather than silently reporting successful revocation.
	if rotatedAt != nil {
		// A replay into a family that is already revoked is no new evidence:
		// there is nothing left to revoke, and the client is typically
		// retrying a token it kept after an earlier refusal. Reporting each
		// retry as a fresh theft buried the one revocation that mattered
		// (family 06cef92a: one revocation on 2026-10-17, then a "reuse
		// detected; family revoked" WARN every ~2h for a week).
		if revokedAt != nil {
			slog.Info("oauth refresh token replay into a revoked family",
				"family_id", familyID, "client_id", storedClientID)
			return Session{}, ErrInvalidToken
		}
		if time.Since(*rotatedAt) < rotationGraceWindow {
			var childLogin, childPrincipalID, childAuthMethod, childResource, childTeamGrantID string
			var childGroupsJSON []byte
			var childRevokedAt *time.Time
			var childRotatedAt *time.Time
			var childExpiresAt time.Time
			// FOR UPDATE: without this, a plain SELECT under this
			// transaction's REPEATABLE READ snapshot could still see the
			// child's pre-rotation state (rotated_at = NULL) even after a
			// concurrent B->C rotation has since committed, letting a grace
			// replay of A resurrect an already-superseded B. Locking forces
			// either the up-to-date row or a 40001 serialization error that
			// the outer Rotate retry loop already handles.
			lookupErr := tx.QueryRow(ctx,
				`SELECT login, principal_id, groups, revoked_at, rotated_at, expires_at, auth_method, resource, team_grant_id FROM oauth_refresh_tokens
				 WHERE token_hash = $1 AND parent_token_hash = $2
				   AND family_id = $3 AND client_id = $4
				 FOR UPDATE`,
				newHash, oldHash, familyID, clientID,
			).Scan(&childLogin, &childPrincipalID, &childGroupsJSON, &childRevokedAt, &childRotatedAt, &childExpiresAt, &childAuthMethod, &childResource, &childTeamGrantID)
			if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
				// A real DB error (including a caught-and-surfaced
				// serialization failure) must not be misreported as
				// invalid_grant — that would defeat the point of this fix
				// for the exact case it targets. Let the caller's retry loop
				// and server_error mapping handle it.
				return Session{}, fmt.Errorf("oauth refresh store: grace lookup: %w", lookupErr)
			}
			// The child must still be the live, unexpired tip of the
			// family: not revoked, not itself already superseded by a
			// further rotation (a two-hops-back replay must not resurrect a
			// child that has since been rotated again), and not past its
			// own expiry (a shortened TTL between predecessor issuance and
			// rotation could otherwise let grace replay hand back an
			// already-expired token).
			if lookupErr == nil && childRevokedAt == nil && childRotatedAt == nil && time.Now().Before(childExpiresAt) {
				var childGroups []string
				if err := json.Unmarshal(childGroupsJSON, &childGroups); err != nil {
					return Session{}, fmt.Errorf("oauth refresh store: grace unmarshal groups: %w", err)
				}
				childSess := Session{Login: childLogin, PrincipalID: childPrincipalID, Groups: childGroups, AuthMethod: childAuthMethod, Resource: childResource, TeamGrantID: childTeamGrantID}
				if accept != nil {
					if err := accept(ctx, tx, childSess); err != nil {
						return Session{}, err
					}
				}
				if commitErr := tx.Commit(ctx); commitErr != nil {
					return Session{}, fmt.Errorf("oauth refresh store: grace commit: %w", commitErr)
				}
				slog.Info("oauth refresh token grace-window replay: re-issuing existing successor",
					"family_id", familyID, "login", childLogin)
				return childSess, nil
			}
			return Session{}, ErrInvalidToken
		}
		now := time.Now().UTC()
		// The grant first, in the same commit as the family: a replayed or
		// stolen Glovo refresh token must stop its access tokens passing the
		// per-request grant check.
		if _, execErr := tx.Exec(ctx,
			`UPDATE oauth_team_grants
			 SET state = 'revoked', revoked_at = $1, revoked_reason = 'reuse_detected'
			 WHERE refresh_family_id = $2 AND state IN ('pending','active')`,
			now, familyID,
		); execErr != nil {
			slog.Error("oauth refresh token reuse: failed to revoke team grant",
				"family_id", familyID, "error", execErr)
			return Session{}, fmt.Errorf("oauth refresh store: reuse grant revocation failed: %w", execErr)
		}
		if _, execErr := tx.Exec(ctx,
			`UPDATE oauth_refresh_tokens
			 SET revoked_at = $1, revoked_reason = 'reuse_detected'
			 WHERE family_id = $2 AND revoked_at IS NULL`,
			now, familyID,
		); execErr != nil {
			slog.Error("oauth refresh token reuse: failed to revoke family",
				"family_id", familyID, "error", execErr)
			return Session{}, fmt.Errorf("oauth refresh store: reuse revocation failed: %w", execErr)
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			slog.Error("oauth refresh token reuse: failed to commit family revocation",
				"family_id", familyID, "error", commitErr)
			return Session{}, fmt.Errorf("oauth refresh store: reuse revocation commit failed: %w", commitErr)
		}
		slog.Warn("oauth refresh token reuse detected; family revoked",
			"family_id", familyID, "login", login, "client_id", storedClientID)
		return Session{}, ErrReuseDetected
	}

	if revokedAt != nil {
		return Session{}, ErrInvalidToken
	}
	if storedClientID != clientID {
		return Session{}, ErrClientMismatch
	}

	var groups []string
	if err := json.Unmarshal(groupsJSON, &groups); err != nil {
		groups = nil
	}
	sess := Session{Login: login, PrincipalID: principalID, Groups: groups, AuthMethod: authMethod, Resource: resource, TeamGrantID: teamGrantID}
	if accept != nil {
		// Before any write: a refused session keeps its token un-rotated,
		// and the deferred Rollback releases the row lock.
		if err := accept(ctx, tx, sess); err != nil {
			return Session{}, err
		}
	}

	now := time.Now().UTC()

	// Mark old token as rotated.
	_, err = tx.Exec(ctx,
		`UPDATE oauth_refresh_tokens SET rotated_at = $1 WHERE token_hash = $2`,
		now, oldHash,
	)
	if err != nil {
		return Session{}, fmt.Errorf("oauth refresh store: mark rotated: %w", err)
	}

	// Insert new token inheriting the same family.
	newGroupsJSON, _ := json.Marshal(groups)
	_, err = tx.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, principal_id, groups, family_id, parent_token_hash, issued_at, expires_at, auth_method, resource, team_grant_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		newHash, clientID, login, principalID, newGroupsJSON, familyID, oldHash, now, newExpiresAt, authMethod, resource, teamGrantID,
	)
	if err != nil {
		return Session{}, fmt.Errorf("oauth refresh store: insert rotated: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Session{}, fmt.Errorf("oauth refresh store: commit: %w", err)
	}
	return sess, nil
}

// RevokeFamily revokes all non-revoked tokens in the same family as rawToken,
// and the team grant bound to that family, in one transaction (the grant
// first: it is what the per-request check reads). If clientID is non-empty,
// only tokens belonging to that client are affected.
func (s *PostgresStore) RevokeFamily(rawToken, clientID, reason string) error {
	hash := tokenHash(rawToken)
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("oauth refresh store: revoke family: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx,
		`UPDATE oauth_team_grants
		 SET state = 'revoked', revoked_at = $1, revoked_reason = $2
		 WHERE refresh_family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $3 AND ($4 = '' OR client_id = $4))
		   AND state IN ('pending','active')`,
		now, reason, hash, clientID,
	); err != nil {
		return fmt.Errorf("oauth refresh store: revoke family grant: %w", err)
	}
	if _, err = tx.Exec(ctx,
		`UPDATE oauth_refresh_tokens
		 SET revoked_at = $1, revoked_reason = $2
		 WHERE family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $3)
		   AND ($4 = '' OR client_id = $4)
		   AND revoked_at IS NULL`,
		now, reason, hash, clientID,
	); err != nil {
		return fmt.Errorf("oauth refresh store: revoke family: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oauth refresh store: revoke family commit: %w", err)
	}
	return nil
}

// RevokePrincipal revokes every unrevoked token of principalID and counts
// the families (sessions) it touched. It runs under
// REPEATABLE READ, as rotateTx does: a rotation that commits a successor
// while this runs has also updated a row this statement updates (the
// predecessor's rotated_at), so one of the two fails with a serialization
// error and retries, and the retry sees the other's write. Under READ
// COMMITTED the successor would be invisible here and survive.
func (s *PostgresStore) RevokePrincipal(principalID, reason string) (int64, error) {
	if principalID == "" {
		return 0, errors.New("oauth refresh store: revoke principal: empty principal id")
	}
	backoff := []time.Duration{5 * time.Millisecond, 15 * time.Millisecond}
	for attempt := range 3 {
		n, err := s.revokePrincipalTx(principalID, reason)
		if err == nil || !isSerializationFailure(err) {
			return n, err
		}
		slog.Warn("oauth refresh store: serialization failure revoking a principal, retrying",
			"attempt", attempt+1, "error", err)
		if attempt < len(backoff) {
			time.Sleep(backoff[attempt])
		}
	}
	return 0, ErrServerError
}

func (s *PostgresStore) revokePrincipalTx(principalID, reason string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return 0, fmt.Errorf("oauth refresh store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// The principal's grants first, in the same commit as its families.
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_team_grants
		 SET state = 'revoked', revoked_at = $1, revoked_reason = $2
		 WHERE principal_id = $3 AND state IN ('pending','active')`,
		time.Now().UTC(), reason, principalID,
	); err != nil {
		return 0, fmt.Errorf("oauth refresh store: revoke principal grants: %w", err)
	}
	var sessions int64
	err = tx.QueryRow(ctx,
		`WITH revoked AS (
		   UPDATE oauth_refresh_tokens
		   SET revoked_at = $1, revoked_reason = $2
		   WHERE principal_id = $3 AND revoked_at IS NULL
		   RETURNING family_id)
		 SELECT count(DISTINCT family_id) FROM revoked`,
		time.Now().UTC(), reason, principalID,
	).Scan(&sessions)
	if err != nil {
		return 0, fmt.Errorf("oauth refresh store: revoke principal: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("oauth refresh store: revoke principal commit: %w", err)
	}
	return sessions, nil
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
