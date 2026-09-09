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

package domains

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDomainConflict is returned by Create when the hostname is already
// registered to a different team. Callers must not disclose the owning
// team when surfacing this error — same rule as alerts.ErrIDConflict.
var ErrDomainConflict = errors.New("domains store: domain already registered to another team")

// ErrNotFound is returned by Get/GetByDomain when no row matches.
var ErrNotFound = errors.New("domains store: not found")

const domainSchema = `
CREATE TABLE IF NOT EXISTS custom_domains (
    id                 TEXT PRIMARY KEY,
    team               TEXT NOT NULL,
    service            TEXT NOT NULL,
    domain             TEXT NOT NULL,
    status             TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    verified_at        TIMESTAMPTZ,
    last_error         TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS custom_domains_domain ON custom_domains (domain);
CREATE INDEX IF NOT EXISTS custom_domains_team ON custom_domains (team, service);
`

// Store is a PostgreSQL-backed custom domain registry.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a domains store and auto-creates the schema.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("domains store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, domainSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("domains store: create schema: %w", err)
	}
	// Separate Exec, not part of domainSchema: ListByTeam compares
	// lower(team)/lower(service), which cannot use custom_domains_team
	// (team, service) above. Mirrors internal/audit/postgres.go's precedent
	// of adding an index to an already-deployed table outside the schema
	// Exec, so a failure here costs an index (a sequential scan on list),
	// not mctl-api's startup. Non-CONCURRENTLY is fine here (unlike
	// audit's CONCURRENTLY indexes): the table is tiny and the index is
	// built once at startup, so the brief write lock is not observable.
	if _, err := pool.Exec(ctx,
		`CREATE INDEX IF NOT EXISTS custom_domains_team_lower
		 ON custom_domains (lower(team), lower(service))`); err != nil {
		slog.Warn("domains store: could not create custom_domains_team_lower index", "error", err)
	}
	slog.Info("domains store initialized")
	return &Store{pool: pool}, nil
}

// Create inserts a new domain row, idempotent on (team, service, domain): a
// repeat registration of the exact same triple returns the existing row
// instead of creating a duplicate. If the hostname is already registered to
// a different team, ErrDomainConflict is returned without revealing which
// team owns it.
func (s *Store) Create(ctx context.Context, d *Domain) (*Domain, error) {
	now := time.Now().UTC()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	d.UpdatedAt = now
	if d.Status == "" {
		d.Status = StatusPending
	}

	stored := &Domain{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO custom_domains (id, team, service, domain, status, verification_token,
		 created_by, created_at, updated_at, verified_at, last_error)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id, team, service, domain, status, verification_token,
		           created_by, created_at, updated_at, verified_at, last_error`,
		d.ID, d.Team, d.Service, d.Domain, d.Status, d.VerificationToken,
		d.CreatedBy, d.CreatedAt, d.UpdatedAt, d.VerifiedAt, d.LastError,
	).Scan(
		&stored.ID, &stored.Team, &stored.Service, &stored.Domain, &stored.Status,
		&stored.VerificationToken, &stored.CreatedBy, &stored.CreatedAt, &stored.UpdatedAt,
		&stored.VerifiedAt, &stored.LastError,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "custom_domains_domain" {
			existing, getErr := s.GetByDomain(ctx, d.Domain)
			if getErr != nil {
				return nil, fmt.Errorf("domains store: create: domain %q already exists: %w", d.Domain, getErr)
			}
			// EqualFold, not exact: AddDomain lowercases team/service on
			// write, but a row that predates that normalization (the
			// column is plain TEXT, never migrated) can still hold its
			// original casing. Comparing exactly would 409 every
			// re-registration attempt by the row's own team forever,
			// since the caller's value is always lowercased before this
			// point while existing.Team/Service may not be.
			if !strings.EqualFold(existing.Team, d.Team) || !strings.EqualFold(existing.Service, d.Service) {
				return nil, ErrDomainConflict
			}
			return existing, nil
		}
		return nil, fmt.Errorf("domains store: create: %w", err)
	}
	return stored, nil
}

// ListByTeam returns every domain registered for team, optionally filtered
// by service.
// ListByTeam compares team/service case-insensitively (lower() on both
// sides). AddDomain lowercases new registrations, but rows created before
// that normalization landed (or via any future direct-store write) may
// still hold their original casing, and there is no migration rewriting
// them — a caller spelling the team differently than a legacy row was
// stored must still find it.
func (s *Store) ListByTeam(ctx context.Context, team, service string) ([]Domain, error) {
	query := `SELECT id, team, service, domain, status, verification_token,
	          created_by, created_at, updated_at, verified_at, last_error
	          FROM custom_domains WHERE lower(team)=lower($1)`
	args := []interface{}{team}
	if service != "" {
		query += " AND lower(service)=lower($2)"
		args = append(args, service)
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("domains store: list: %w", err)
	}
	defer rows.Close()

	// Non-nil even when empty: the caller serializes this as JSON, and the
	// Backstage proxy this store replaced always returned "domains":[] —
	// never null — for a team with no rows.
	out := []Domain{}
	for rows.Next() {
		var d Domain
		if err := rows.Scan(
			&d.ID, &d.Team, &d.Service, &d.Domain, &d.Status, &d.VerificationToken,
			&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.VerifiedAt, &d.LastError,
		); err != nil {
			return nil, fmt.Errorf("domains store: list: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domains store: list: iterate: %w", err)
	}
	return out, nil
}

// Get returns a single domain by id.
func (s *Store) Get(ctx context.Context, id string) (*Domain, error) {
	d := &Domain{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, team, service, domain, status, verification_token,
		 created_by, created_at, updated_at, verified_at, last_error
		 FROM custom_domains WHERE id=$1`, id).Scan(
		&d.ID, &d.Team, &d.Service, &d.Domain, &d.Status, &d.VerificationToken,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.VerifiedAt, &d.LastError,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("domains store: get: %w", err)
	}
	return d, nil
}

// GetByDomain returns a single domain by hostname.
func (s *Store) GetByDomain(ctx context.Context, domain string) (*Domain, error) {
	d := &Domain{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, team, service, domain, status, verification_token,
		 created_by, created_at, updated_at, verified_at, last_error
		 FROM custom_domains WHERE domain=$1`, domain).Scan(
		&d.ID, &d.Team, &d.Service, &d.Domain, &d.Status, &d.VerificationToken,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.VerifiedAt, &d.LastError,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("domains store: get by domain: %w", err)
	}
	return d, nil
}

// SetStatus updates a domain's status and last_error (status transitions
// driven by the add-custom-domain workflow's status callback).
func (s *Store) SetStatus(ctx context.Context, id, status, lastError string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE custom_domains SET status=$2, last_error=$3, updated_at=now() WHERE id=$1`,
		id, status, lastError,
	)
	if err != nil {
		return fmt.Errorf("domains store: set status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkVerified marks a domain verified (DNS ownership proven). A row already
// promoted to StatusActive by the add-custom-domain workflow's status
// callback is left alone: mctl_verify_domain re-verifies every domain
// returned for a team/service on each call, so an unconditional write here
// would demote every already-active domain back to "verified" (and clear
// last_error) on the next routine status check.
func (s *Store) MarkVerified(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE custom_domains SET status=$2, verified_at=now(), updated_at=now(), last_error=''
		 WHERE id=$1 AND status <> $3`,
		id, StatusVerified, StatusActive,
	)
	if err != nil {
		return fmt.Errorf("domains store: mark verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Zero rows matches two cases the caller must be able to tell apart:
		// the id doesn't exist (ErrNotFound), or it exists but is already
		// StatusActive (a no-op, not an error).
		if _, err := s.Get(ctx, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("domains store: mark verified: check existing status: %w", err)
		}
	}
	return nil
}

// Delete removes a domain row.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM custom_domains WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("domains store: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
