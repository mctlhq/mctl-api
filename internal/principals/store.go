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

// Package principals is the canonical principal model, phase 1
// (mctl-api#373).
//
// A principal is an opaque, mctl-api-issued id (prn_<ulid>) for a human, an
// agent or a service. External identities (a numeric GitHub user id, a Dex
// issuer+subject, a Telegram user id, the service principal's name) belong
// to exactly one principal, unique per (provider, issuer, subject). A
// principal is never found by the spelling of a login: a Dex username that
// happens to equal a GitHub login is a different identity, and so a
// different principal.
//
// Phase 1 records principals; it does not authorize on them. The only
// behaviour that changes at authentication is that a disabled principal is
// refused.
package principals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Principal statuses.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

var (
	ErrNotFound = errors.New("principal not found")
	ErrInvalid  = errors.New("invalid principal request")
)

// Principal is one canonical principal.
type Principal struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// ExternalIdentity is one identity a principal proved.
type ExternalIdentity struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id"`
	Provider    string     `json:"provider"`
	Issuer      string     `json:"issuer"`
	Subject     string     `json:"subject"`
	Display     string     `json:"display"`
	VerifiedAt  time.Time  `json:"verified_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

const schema = `
CREATE TABLE IF NOT EXISTS principals (
	id           TEXT PRIMARY KEY,
	kind         TEXT NOT NULL CHECK (kind IN ('human', 'agent', 'service')),
	display_name TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
	created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS external_identities (
	id           TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL REFERENCES principals (id),
	provider     TEXT NOT NULL,
	issuer       TEXT NOT NULL DEFAULT '',
	subject      TEXT NOT NULL,
	-- Informational only (a GitHub login, a Dex preferred_username). For
	-- provider=github it is also how a login-only caller (a local OAuth JWT,
	-- a relayed human) finds its identity; it is kept unique among live
	-- GitHub rows by moving it to whichever id GitHub last reported for it.
	display      TEXT NOT NULL DEFAULT '',
	verified_at  TIMESTAMPTZ NOT NULL,
	revoked_at   TIMESTAMPTZ,
	UNIQUE (provider, issuer, subject)
);
CREATE INDEX IF NOT EXISTS external_identities_principal
	ON external_identities (principal_id);
CREATE INDEX IF NOT EXISTS external_identities_github_display
	ON external_identities (lower(display)) WHERE provider = 'github' AND display <> '';
`

// Store is the Postgres-backed principal store.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewStore connects and creates the schema. It must share a database with
// the surface identity store (SURFACE_IDENTITY_DB_URL, else AUDIT_DB_URL):
// a redeemed link is mirrored into external_identities in the same
// transaction.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("principals: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("principals: create schema: %w", err)
	}
	slog.Info("principal store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database answers.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

const principalColumns = `p.id, p.kind, p.display_name, p.status, p.created_at`

func scanPrincipal(row pgx.Row) (*Principal, error) {
	var p Principal
	if err := row.Scan(&p.ID, &p.Kind, &p.DisplayName, &p.Status, &p.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

func validIdentity(id auth.Identity) error {
	switch {
	case id.Provider == "" || id.Subject == "":
		return fmt.Errorf("%w: provider and subject are required", ErrInvalid)
	case id.Kind != auth.KindHuman && id.Kind != auth.KindAgent && id.Kind != auth.KindService:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalid, id.Kind)
	case id.Provider == auth.ProviderGitHub && strings.TrimLeft(id.Subject, "0123456789") != "":
		return fmt.Errorf("%w: a GitHub subject is the numeric user id", ErrInvalid)
	}
	return nil
}

// Provision returns the principal an external identity belongs to, creating
// the principal and the identity if the identity is new. It is idempotent
// and safe under concurrency: two requests provisioning the same identity at
// once get the same principal.
//
// A revoked identity is refused (auth.ErrIdentityRefused), never silently
// reactivated or given a new principal: revoking it was a decision. The
// principal an identity belongs to never changes here.
func (s *Store) Provision(ctx context.Context, id auth.Identity) (*Principal, error) {
	if err := validIdentity(id); err != nil {
		return nil, err
	}
	var out *Principal
	err := s.withTx(ctx, lockKey(id), func(tx pgx.Tx) error {
		now := s.now()
		var revoked *time.Time
		var p Principal
		err := tx.QueryRow(ctx, `SELECT `+principalColumns+`, x.revoked_at
			FROM external_identities x JOIN principals p ON p.id = x.principal_id
			WHERE x.provider=$1 AND x.issuer=$2 AND x.subject=$3`, id.Provider, id.Issuer, id.Subject).
			Scan(&p.ID, &p.Kind, &p.DisplayName, &p.Status, &p.CreatedAt, &revoked)
		switch {
		case err == nil && revoked != nil:
			return fmt.Errorf("%w: external identity %s was revoked", auth.ErrIdentityRefused, id.Provider)
		case err == nil:
			if _, err := tx.Exec(ctx, `UPDATE external_identities SET verified_at=$4,
				display=CASE WHEN $5::text = '' THEN display ELSE $5::text END
				WHERE provider=$1 AND issuer=$2 AND subject=$3`, id.Provider, id.Issuer, id.Subject, now, id.Display); err != nil {
				return err
			}
			if err := claimGitHubDisplay(ctx, tx, id); err != nil {
				return err
			}
			p.CreatedAt = p.CreatedAt.UTC()
			out = &p
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		created, err := createPrincipal(ctx, tx, id.Kind, id.Display, now)
		if err != nil {
			return err
		}
		if err := insertIdentity(ctx, tx, created.ID, id, now); err != nil {
			return err
		}
		if err := claimGitHubDisplay(ctx, tx, id); err != nil {
			return err
		}
		out = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func createPrincipal(ctx context.Context, tx pgx.Tx, kind, display string, now time.Time) (*Principal, error) {
	pid, err := newPrefixedID(PrincipalIDPrefix, now)
	if err != nil {
		return nil, err
	}
	p := &Principal{ID: pid, Kind: kind, DisplayName: display, Status: StatusActive, CreatedAt: now}
	if _, err := tx.Exec(ctx, `INSERT INTO principals (id, kind, display_name, status, created_at)
		VALUES ($1,$2,$3,$4,$5)`, p.ID, p.Kind, p.DisplayName, p.Status, p.CreatedAt); err != nil {
		return nil, err
	}
	return p, nil
}

func insertIdentity(ctx context.Context, tx pgx.Tx, principalID string, id auth.Identity, now time.Time) error {
	xid, err := newPrefixedID(externalIdentityIDPrefix, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO external_identities
		(id, principal_id, provider, issuer, subject, display, verified_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		xid, principalID, id.Provider, id.Issuer, id.Subject, id.Display, now)
	return err
}

// claimGitHubDisplay moves a GitHub login to the id GitHub just reported
// for it. A login belongs to one GitHub account at a time: when someone
// renames away and another account takes the name, the older row stops
// answering for it, so a login-only lookup can never reach the previous
// owner's principal.
func claimGitHubDisplay(ctx context.Context, tx pgx.Tx, id auth.Identity) error {
	if id.Provider != auth.ProviderGitHub || id.Display == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE external_identities SET display=''
		WHERE provider='github' AND lower(display)=lower($1) AND NOT (issuer=$2 AND subject=$3)`,
		id.Display, id.Issuer, id.Subject)
	return err
}

// ResolveGitHubLogin returns the principal of the live GitHub identity whose
// current login is login, or ErrNotFound.
func (s *Store) ResolveGitHubLogin(ctx context.Context, login string) (*Principal, error) {
	if login == "" {
		return nil, ErrNotFound
	}
	return scanPrincipal(s.pool.QueryRow(ctx, `SELECT `+principalColumns+`
		FROM external_identities x JOIN principals p ON p.id = x.principal_id
		WHERE x.provider='github' AND x.display <> '' AND lower(x.display)=lower($1) AND x.revoked_at IS NULL
		ORDER BY x.verified_at DESC LIMIT 1`, login))
}

// Get returns one principal.
func (s *Store) Get(ctx context.Context, id string) (*Principal, error) {
	return scanPrincipal(s.pool.QueryRow(ctx, `SELECT `+principalColumns+` FROM principals p WHERE p.id=$1`, id))
}

// Identities lists a principal's external identities, oldest first.
func (s *Store) Identities(ctx context.Context, principalID string) ([]ExternalIdentity, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, principal_id, provider, issuer, subject, display, verified_at, revoked_at
		FROM external_identities WHERE principal_id=$1 ORDER BY verified_at, id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExternalIdentity{}
	for rows.Next() {
		var x ExternalIdentity
		if err := rows.Scan(&x.ID, &x.PrincipalID, &x.Provider, &x.Issuer, &x.Subject, &x.Display, &x.VerifiedAt, &x.RevokedAt); err != nil {
			return nil, err
		}
		x.VerifiedAt = x.VerifiedAt.UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}

// SetStatus enables or disables a principal. A disabled principal is refused
// at authentication (within the resolver's cache TTL).
func (s *Store) SetStatus(ctx context.Context, principalID, status string) error {
	if status != StatusActive && status != StatusDisabled {
		return fmt.Errorf("%w: unknown status %q", ErrInvalid, status)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE principals SET status=$2 WHERE id=$1`, principalID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func lockKey(id auth.Identity) string {
	return "principals:" + id.Provider + "|" + id.Issuer + "|" + id.Subject
}

func (s *Store) withTx(ctx context.Context, key string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("principals: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
		return fmt.Errorf("principals: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("principals: commit: %w", err)
	}
	return nil
}
