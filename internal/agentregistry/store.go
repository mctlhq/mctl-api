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

package agentregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors — handlers/MCP tools map these to specific HTTP statuses
// instead of a generic 500, same as alerts.ErrIDConflict.
var (
	ErrDefinitionNotFound = errors.New("agentregistry: agent definition not found")
	ErrVersionConflict    = errors.New("agentregistry: version already published")
	ErrVersionNotFound    = errors.New("agentregistry: version not found")
	ErrReleaseNotFound    = errors.New("agentregistry: no release for agent/environment")
	ErrNoRollbackTarget   = errors.New("agentregistry: no prior version to roll back to")
	ErrInvalidEnvironment = errors.New("agentregistry: invalid environment")
)

const agentRegistrySchema = `
CREATE TABLE IF NOT EXISTS agent_definitions (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    owner       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS agent_versions (
    id               SERIAL PRIMARY KEY,
    agent            TEXT NOT NULL REFERENCES agent_definitions(name),
    version          TEXT NOT NULL,
    manifest_json    JSONB NOT NULL,
    git_sha          TEXT NOT NULL,
    image_repository TEXT NOT NULL,
    image_digest     TEXT NOT NULL DEFAULT '',
    prompt_hash      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    created_by       TEXT NOT NULL DEFAULT '',
    UNIQUE (agent, version)
);
CREATE INDEX IF NOT EXISTS agent_versions_agent ON agent_versions (agent);

CREATE TABLE IF NOT EXISTS agent_releases (
    agent          TEXT NOT NULL REFERENCES agent_definitions(name),
    environment    TEXT NOT NULL,
    version        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active',
    traffic_weight INTEGER NOT NULL DEFAULT 100,
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent, environment),
    FOREIGN KEY (agent, version) REFERENCES agent_versions(agent, version)
);

CREATE TABLE IF NOT EXISTS agent_promotions (
    id           SERIAL PRIMARY KEY,
    agent        TEXT NOT NULL,
    environment  TEXT NOT NULL,
    from_version TEXT NOT NULL DEFAULT '',
    to_version   TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    actor        TEXT NOT NULL DEFAULT '',
    rollback_of  INTEGER,
    created_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_promotions_agent_env ON agent_promotions (agent, environment, created_at DESC);
`

// Store is a PostgreSQL-backed agent registry.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates an agent registry store and auto-creates the schema.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, agentRegistrySchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("agentregistry: create schema: %w", err)
	}
	slog.Info("agent registry store initialized")
	return &Store{pool: pool}, nil
}

func validEnvironment(env string) bool {
	return env == EnvironmentProduction || env == EnvironmentShadow
}

// CreateDefinition creates or updates an agent's top-level record.
// Idempotent by design — republishing the same name updates
// description/owner in place, matching the "overwrite an existing entry"
// convention the platform-skill-publish operation already uses.
// created_at is preserved across an update: only the initial INSERT sets it.
func (s *Store) CreateDefinition(ctx context.Context, name, description, owner string) (*AgentDefinition, error) {
	now := time.Now().UTC()
	d := &AgentDefinition{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_definitions (name, description, owner, created_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, owner = EXCLUDED.owner
		 RETURNING name, description, owner, created_at, archived_at`,
		name, description, owner, now,
	).Scan(&d.Name, &d.Description, &d.Owner, &d.CreatedAt, &d.ArchivedAt)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: create definition: %w", err)
	}
	return d, nil
}

// PublishVersion inserts a new immutable agent version. Unlike
// CreateDefinition, this never overwrites — (agent, version) is a
// once-only key, matching the "AgentManifest is a contract" design: a
// published version's manifest_json is what a shadow/canary/rollback
// compares against, and that comparison is meaningless if the row can move
// under it.
func (s *Store) PublishVersion(ctx context.Context, v *AgentVersion) (*AgentVersion, error) {
	now := time.Now().UTC()
	stored := &AgentVersion{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_versions
		   (agent, version, manifest_json, git_sha, image_repository, image_digest, prompt_hash, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, agent, version, manifest_json, git_sha, image_repository, image_digest, prompt_hash, created_at, created_by`,
		v.Agent, v.Version, v.ManifestJSON, v.GitSHA, v.ImageRepository, v.ImageDigest, v.PromptHash, now, v.CreatedBy,
	).Scan(
		&stored.ID, &stored.Agent, &stored.Version, &stored.ManifestJSON, &stored.GitSHA,
		&stored.ImageRepository, &stored.ImageDigest, &stored.PromptHash, &stored.CreatedAt, &stored.CreatedBy,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation on (agent, version)
				return nil, ErrVersionConflict
			case "23503": // foreign_key_violation — agent has no definition yet
				return nil, fmt.Errorf("agentregistry: publish version: %w: %q", ErrDefinitionNotFound, v.Agent)
			}
		}
		return nil, fmt.Errorf("agentregistry: publish version: %w", err)
	}
	return stored, nil
}

// ListVersions returns every published version of one agent, newest first.
func (s *Store) ListVersions(ctx context.Context, agent string) ([]AgentVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent, version, manifest_json, git_sha, image_repository, image_digest, prompt_hash, created_at, created_by
		 FROM agent_versions WHERE agent = $1 ORDER BY created_at DESC`,
		agent,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list versions: %w", err)
	}
	defer rows.Close()

	var versions []AgentVersion
	for rows.Next() {
		var v AgentVersion
		if err := rows.Scan(
			&v.ID, &v.Agent, &v.Version, &v.ManifestJSON, &v.GitSHA,
			&v.ImageRepository, &v.ImageDigest, &v.PromptHash, &v.CreatedAt, &v.CreatedBy,
		); err != nil {
			slog.Error("agentregistry: scan version failed", "error", err)
			continue
		}
		versions = append(versions, v)
	}
	return versions, nil
}

// ResolveRelease returns the version currently released to one
// agent/environment pair — the read path every Temporal DevLoopWorkflow
// activity calls once per agent step (see the plan's phase 4 "pin once at
// workflow start" rule).
func (s *Store) ResolveRelease(ctx context.Context, agent, environment string) (*AgentRelease, error) {
	if !validEnvironment(environment) {
		return nil, fmt.Errorf("agentregistry: resolve release: %w: %q", ErrInvalidEnvironment, environment)
	}
	r := &AgentRelease{}
	err := s.pool.QueryRow(ctx,
		`SELECT agent, environment, version, status, traffic_weight, updated_at, updated_by
		 FROM agent_releases WHERE agent = $1 AND environment = $2`,
		agent, environment,
	).Scan(&r.Agent, &r.Environment, &r.Version, &r.Status, &r.TrafficWeight, &r.UpdatedAt, &r.UpdatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s", ErrReleaseNotFound, agent, environment)
		}
		return nil, fmt.Errorf("agentregistry: resolve release: %w", err)
	}
	return r, nil
}

// PromoteRelease points one agent/environment at a published version.
func (s *Store) PromoteRelease(ctx context.Context, agent, environment, version, reason, actor string) (*AgentRelease, error) {
	if !validEnvironment(environment) {
		return nil, fmt.Errorf("agentregistry: promote: %w: %q", ErrInvalidEnvironment, environment)
	}
	return s.promote(ctx, agent, environment, version, reason, actor, nil)
}

// Rollback reverts one agent/environment to the version it had immediately
// before its current release — the from_version recorded on the most
// recent agent_promotions row for that pair. ErrNoRollbackTarget means
// there is no such row (never promoted) or that row's from_version is
// empty (the very first promotion for this pair, with nothing before it).
func (s *Store) Rollback(ctx context.Context, agent, environment, reason, actor string) (*AgentRelease, error) {
	if !validEnvironment(environment) {
		return nil, fmt.Errorf("agentregistry: rollback: %w: %q", ErrInvalidEnvironment, environment)
	}

	var lastPromotionID int
	var fromVersion string
	err := s.pool.QueryRow(ctx,
		`SELECT id, from_version FROM agent_promotions
		 WHERE agent = $1 AND environment = $2
		 ORDER BY created_at DESC LIMIT 1`,
		agent, environment,
	).Scan(&lastPromotionID, &fromVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("agentregistry: rollback: %s/%s: %w", agent, environment, ErrNoRollbackTarget)
		}
		return nil, fmt.Errorf("agentregistry: rollback: %w", err)
	}
	if fromVersion == "" {
		return nil, fmt.Errorf("agentregistry: rollback: %s/%s: %w", agent, environment, ErrNoRollbackTarget)
	}

	return s.promote(ctx, agent, environment, fromVersion, reason, actor, &lastPromotionID)
}

// promote is the shared implementation behind PromoteRelease and Rollback:
// verify the target version exists, upsert agent_releases, and append an
// agent_promotions audit row recording what it replaced. rollbackOf is nil
// for a forward promotion.
func (s *Store) promote(
	ctx context.Context, agent, environment, version, reason, actor string, rollbackOf *int,
) (*AgentRelease, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agent_versions WHERE agent = $1 AND version = $2)`,
		agent, version,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: check version: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("agentregistry: promote: %w: %s@%s", ErrVersionNotFound, agent, version)
	}

	now := time.Now().UTC()

	// Current release version, if any — becomes from_version on the audit
	// row below. No release yet is expected (first promotion for this
	// pair), not an error.
	var fromVersion string
	_ = s.pool.QueryRow(ctx,
		`SELECT version FROM agent_releases WHERE agent = $1 AND environment = $2`,
		agent, environment,
	).Scan(&fromVersion)

	release := &AgentRelease{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_releases (agent, environment, version, status, traffic_weight, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, 100, $5, $6)
		 ON CONFLICT (agent, environment) DO UPDATE SET
		   version = EXCLUDED.version, status = EXCLUDED.status,
		   updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
		 RETURNING agent, environment, version, status, traffic_weight, updated_at, updated_by`,
		agent, environment, version, ReleaseStatusActive, now, actor,
	).Scan(&release.Agent, &release.Environment, &release.Version, &release.Status, &release.TrafficWeight, &release.UpdatedAt, &release.UpdatedBy)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: promote: upsert release: %w", err)
	}

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO agent_promotions (agent, environment, from_version, to_version, reason, actor, rollback_of, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		agent, environment, fromVersion, version, reason, actor, rollbackOf, now,
	); err != nil {
		// The release itself already landed — a failed audit-row insert
		// shouldn't roll that back (matches alerts.Store.Create's evidence
		// insert, which logs-and-continues for the same reason).
		slog.Error("agentregistry: record promotion failed", "agent", agent, "environment", environment, "error", err)
	}

	return release, nil
}

// ListPromotions returns the promotion/rollback history for one
// agent/environment pair, newest first.
func (s *Store) ListPromotions(ctx context.Context, agent, environment string) ([]AgentPromotion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent, environment, from_version, to_version, reason, actor, rollback_of, created_at
		 FROM agent_promotions WHERE agent = $1 AND environment = $2 ORDER BY created_at DESC`,
		agent, environment,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list promotions: %w", err)
	}
	defer rows.Close()

	var promotions []AgentPromotion
	for rows.Next() {
		var p AgentPromotion
		if err := rows.Scan(&p.ID, &p.Agent, &p.Environment, &p.FromVersion, &p.ToVersion, &p.Reason, &p.Actor, &p.RollbackOf, &p.CreatedAt); err != nil {
			slog.Error("agentregistry: scan promotion failed", "error", err)
			continue
		}
		promotions = append(promotions, p)
	}
	return promotions, nil
}
