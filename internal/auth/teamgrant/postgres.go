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

package teamgrant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore keeps grants in oauth_team_grants, in the refresh-store
// database and on its pool, so a grant and a refresh token can be written in
// one transaction. It runs no DDL: refreshstore's schema creates the table.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps the refresh store's pool.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("team grant store: nil pool")
	}
	return &PostgresStore{pool: pool}, nil
}

const dbTimeout = 5 * time.Second

// SharesRefreshPool marks the store as running on the refresh store's pool,
// the only arrangement in which activation and revocation are atomic with the
// refresh family. Readiness for the Glovo resource requires it.
func (s *PostgresStore) SharesRefreshPool() {}

// Create implements Store.
func (s *PostgresStore) Create(ctx context.Context, g Grant) (Grant, error) {
	if err := validate(g); err != nil {
		return Grant{}, err
	}
	id, err := NewID()
	if err != nil {
		return Grant{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, fmt.Errorf("team grant: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_team_grants SET state = 'revoked', revoked_at = $4, revoked_reason = $5
		 WHERE principal_id = $1 AND client_id = $2 AND resource = $3 AND state IN ('pending','active')`,
		g.PrincipalID, g.ClientID, g.Resource, now, ReasonSuperseded); err != nil {
		return Grant{}, fmt.Errorf("team grant: supersede: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oauth_team_grants (grant_id, principal_id, tenant, resource, client_id, state, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)`,
		id, g.PrincipalID, g.Tenant, g.Resource, g.ClientID, now, g.ExpiresAt.UTC()); err != nil {
		return Grant{}, fmt.Errorf("team grant: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("team grant: commit: %w", err)
	}
	g.ID, g.State, g.RefreshFamilyID, g.CreatedAt = id, StatePending, "", now
	return g, nil
}

// ActivateTx moves a pending grant to active and binds it to the refresh
// family, on tx. It is the only gate at code exchange: zero rows (unknown,
// not pending, expired by the database clock, or a different principal,
// client or resource) is ErrGrantInvalid, and the caller must roll back.
func ActivateTx(ctx context.Context, tx pgx.Tx, grantID, principalID, clientID, resource string, familyID uuid.UUID) error {
	tag, err := tx.Exec(ctx,
		`UPDATE oauth_team_grants SET state = 'active', refresh_family_id = $5
		 WHERE grant_id = $1 AND principal_id = $2 AND client_id = $3 AND resource = $4
		   AND state = 'pending' AND expires_at > now()`,
		grantID, principalID, clientID, resource, familyID)
	if err != nil {
		return fmt.Errorf("team grant: activate: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrGrantInvalid
	}
	return nil
}

const checkSQL = `SELECT grant_id, principal_id, tenant, resource, client_id, COALESCE(refresh_family_id::text, ''), state, created_at, expires_at
	 FROM oauth_team_grants
	 WHERE grant_id = $1 AND principal_id = $2 AND client_id = $3 AND resource = $4
	   AND state = 'active' AND expires_at > now()`

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func check(ctx context.Context, q queryRower, grantID, principalID, clientID, resource string) (Grant, error) {
	var g Grant
	err := q.QueryRow(ctx, checkSQL, grantID, principalID, clientID, resource).Scan(
		&g.ID, &g.PrincipalID, &g.Tenant, &g.Resource, &g.ClientID, &g.RefreshFamilyID, &g.State, &g.CreatedAt, &g.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrGrantInvalid
	}
	if err != nil {
		return Grant{}, fmt.Errorf("team grant: check: %w", err)
	}
	return g, nil
}

// Check implements Store.
func (s *PostgresStore) Check(ctx context.Context, grantID, principalID, clientID, resource string) (Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	return check(ctx, s.pool, grantID, principalID, clientID, resource)
}

// CheckTx is Check on the caller's transaction.
func CheckTx(ctx context.Context, tx pgx.Tx, grantID, principalID, clientID, resource string) (Grant, error) {
	return check(ctx, tx, grantID, principalID, clientID, resource)
}

func (s *PostgresStore) exec(ctx context.Context, sql string, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	if _, err := s.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("team grant: revoke: %w", err)
	}
	return nil
}

// Revoke implements Store.
func (s *PostgresStore) Revoke(ctx context.Context, grantID, reason string) error {
	return s.exec(ctx, `UPDATE oauth_team_grants SET state = 'revoked', revoked_at = now(), revoked_reason = $2
		WHERE grant_id = $1 AND state IN ('pending','active')`, grantID, reason)
}

// RevokeByFamily implements Store.
func (s *PostgresStore) RevokeByFamily(ctx context.Context, familyID, reason string) error {
	id, err := uuid.Parse(familyID)
	if err != nil {
		return fmt.Errorf("team grant: family id: %w", err)
	}
	return s.exec(ctx, `UPDATE oauth_team_grants SET state = 'revoked', revoked_at = now(), revoked_reason = $2
		WHERE refresh_family_id = $1 AND state IN ('pending','active')`, id, reason)
}

// RevokeByPrincipal implements Store.
func (s *PostgresStore) RevokeByPrincipal(ctx context.Context, principalID, reason string) error {
	return s.exec(ctx, `UPDATE oauth_team_grants SET state = 'revoked', revoked_at = now(), revoked_reason = $2
		WHERE principal_id = $1 AND state IN ('pending','active')`, principalID, reason)
}
