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
	"strings"
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
CREATE INDEX IF NOT EXISTS agent_promotions_agent_env ON agent_promotions (agent, environment, id DESC);

-- Phase 4 (Temporal dev-loop worker): one row per agent step a
-- DevLoopWorkflow ran, written by orchestrator/temporal/activities/state.py
-- after the underlying Argo workflow reaches a terminal phase. Argo
-- workflow objects expire after ttlStrategy.secondsAfterCompletion (as
-- little as 24h), so this is the durable record of "which agent version
-- produced this PR" the plan's phase-4 problem statement calls for.
--
-- Deliberately NOT FK-constrained to agent_definitions(name): a workflow
-- records an execution even when resolve_agent_release found no release
-- yet (version/image_ref empty, the CWFT's own baked-in default image
-- ran) — the whole point is that this table is populated before an agent
-- is ever registered here, not only after.
--
-- UNIQUE(temporal_workflow_id, agent, argo_workflow_name): Temporal
-- activities have at-least-once execution semantics — record_execution can
-- run twice for the same step if the ACK back to the worker is lost after
-- the INSERT committed. Without this, a retry duplicates the row and
-- inflates step counts / confuses "which agent version produced this PR"
-- lookups. argo_workflow_name is always non-empty by the time this table
-- is written (record_execution only ever runs after submit_and_wait
-- returns a real WorkflowResult), so it's safe as part of the key even
-- though the column itself allows ''.
CREATE TABLE IF NOT EXISTS agent_executions (
    id                   SERIAL PRIMARY KEY,
    temporal_workflow_id TEXT NOT NULL,
    agent                TEXT NOT NULL,
    environment          TEXT NOT NULL,
    version              TEXT NOT NULL DEFAULT '',
    image_ref            TEXT NOT NULL DEFAULT '',
    argo_workflow_name   TEXT NOT NULL DEFAULT '',
    phase                TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,
    UNIQUE (temporal_workflow_id, agent, argo_workflow_name)
);
CREATE INDEX IF NOT EXISTS agent_executions_agent ON agent_executions (agent, id DESC);
CREATE INDEX IF NOT EXISTS agent_executions_workflow ON agent_executions (temporal_workflow_id);
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
// convention the platform-skill-publish operation already uses. An update
// with an empty description/owner keeps whatever was already stored rather
// than blanking it out — a CI job that republishes a definition without
// setting owner shouldn't wipe out a previously-set one.
// created_at is preserved across an update: only the initial INSERT sets it.
func (s *Store) CreateDefinition(ctx context.Context, name, description, owner string) (*AgentDefinition, error) {
	now := time.Now().UTC()
	d := &AgentDefinition{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_definitions (name, description, owner, created_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (name) DO UPDATE SET
		   description = COALESCE(NULLIF(EXCLUDED.description, ''), agent_definitions.description),
		   owner = COALESCE(NULLIF(EXCLUDED.owner, ''), agent_definitions.owner)
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
		 FROM agent_versions WHERE agent = $1 ORDER BY id DESC`,
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
	return s.promote(ctx, agent, environment, reason, actor,
		func(context.Context, pgx.Tx) (string, *int, error) { return version, nil, nil })
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
	// Resolving "what was here before" runs inside promote()'s locked
	// transaction (see resolveTarget below) rather than as a separate
	// query beforehand — otherwise a promotion landing between this lookup
	// and the write could make the answer stale before it's even applied.
	return s.promote(ctx, agent, environment, reason, actor, func(ctx context.Context, tx pgx.Tx) (string, *int, error) {
		var lastPromotionID int
		var fromVersion string
		err := tx.QueryRow(ctx,
			`SELECT id, from_version FROM agent_promotions
			 WHERE agent = $1 AND environment = $2
			 ORDER BY id DESC LIMIT 1`,
			agent, environment,
		).Scan(&lastPromotionID, &fromVersion)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", nil, fmt.Errorf("agentregistry: rollback: %s/%s: %w", agent, environment, ErrNoRollbackTarget)
			}
			return "", nil, fmt.Errorf("agentregistry: rollback: %w", err)
		}
		if fromVersion == "" {
			return "", nil, fmt.Errorf("agentregistry: rollback: %s/%s: %w", agent, environment, ErrNoRollbackTarget)
		}
		return fromVersion, &lastPromotionID, nil
	})
}

// promote is the shared implementation behind PromoteRelease and Rollback.
// Everything — target-version resolution (via resolveTarget), the current-
// release read, the release upsert, and the audit-row insert — runs inside
// one transaction, serialized per (agent, environment) by a Postgres
// advisory lock (rather than a row lock, since agent_releases may not have
// a row yet on a pair's first promotion). That closes two races the
// previous unlocked, multi-statement version had: two concurrent promotions
// (or a promote racing a rollback) computing the same stale "current
// version" and both recording it as from_version, and Rollback's own
// "what was here before" lookup going stale between reading it and applying
// it. A failed audit insert now rolls back the release upsert with it,
// instead of leaving a release the audit trail can't explain.
func (s *Store) promote(
	ctx context.Context, agent, environment, reason, actor string,
	resolveTarget func(ctx context.Context, tx pgx.Tx) (version string, rollbackOf *int, err error),
) (*AgentRelease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: promote: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, agent+"/"+environment); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: acquire lock: %w", err)
	}

	version, rollbackOf, err := resolveTarget(ctx, tx)
	if err != nil {
		return nil, err
	}

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agent_versions WHERE agent = $1 AND version = $2)`,
		agent, version,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: check version: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("agentregistry: promote: %w: %s@%s", ErrVersionNotFound, agent, version)
	}

	// Current release version, if any — becomes from_version on the audit
	// row below. No release yet is expected (first promotion for this
	// pair), not an error; any other failure is.
	var fromVersion string
	if err := tx.QueryRow(ctx,
		`SELECT version FROM agent_releases WHERE agent = $1 AND environment = $2`,
		agent, environment,
	).Scan(&fromVersion); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("agentregistry: promote: read current release: %w", err)
	}

	now := time.Now().UTC()
	release := &AgentRelease{}

	if fromVersion == version {
		// Idempotent no-op: promoting to the version that's already current
		// (e.g. a client retrying a promotion whose response it lost). An
		// audit row here would record from_version == to_version, and
		// Rollback resolves purely from the latest such row — so it would
		// "successfully" roll back to the version already live, silently
		// losing the real prior release as a target.
		if err := tx.QueryRow(ctx,
			`SELECT agent, environment, version, status, traffic_weight, updated_at, updated_by
			 FROM agent_releases WHERE agent = $1 AND environment = $2`,
			agent, environment,
		).Scan(&release.Agent, &release.Environment, &release.Version, &release.Status, &release.TrafficWeight, &release.UpdatedAt, &release.UpdatedBy); err != nil {
			return nil, fmt.Errorf("agentregistry: promote: read release for no-op: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("agentregistry: promote: commit: %w", err)
		}
		return release, nil
	}

	if err := tx.QueryRow(ctx,
		`INSERT INTO agent_releases (agent, environment, version, status, traffic_weight, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, 100, $5, $6)
		 ON CONFLICT (agent, environment) DO UPDATE SET
		   version = EXCLUDED.version, status = EXCLUDED.status,
		   updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
		 RETURNING agent, environment, version, status, traffic_weight, updated_at, updated_by`,
		agent, environment, version, ReleaseStatusActive, now, actor,
	).Scan(&release.Agent, &release.Environment, &release.Version, &release.Status, &release.TrafficWeight, &release.UpdatedAt, &release.UpdatedBy); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: upsert release: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO agent_promotions (agent, environment, from_version, to_version, reason, actor, rollback_of, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		agent, environment, fromVersion, version, reason, actor, rollbackOf, now,
	); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: record promotion: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("agentregistry: promote: commit: %w", err)
	}
	return release, nil
}

// ListPromotions returns the promotion/rollback history for one
// agent/environment pair, newest first.
func (s *Store) ListPromotions(ctx context.Context, agent, environment string) ([]AgentPromotion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent, environment, from_version, to_version, reason, actor, rollback_of, created_at
		 FROM agent_promotions WHERE agent = $1 AND environment = $2 ORDER BY id DESC`,
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

// RecordExecution persists one DevLoopWorkflow step's outcome (phase 4).
// version/image_ref are commonly empty — a step that ran before the agent
// had any registered release still gets recorded, with the CWFT's own
// default image having been what actually ran.
func (s *Store) RecordExecution(ctx context.Context, e *AgentExecution) (*AgentExecution, error) {
	if !validEnvironment(e.Environment) {
		return nil, ErrInvalidEnvironment
	}
	now := time.Now().UTC()
	result := &AgentExecution{}
	// ON CONFLICT DO UPDATE (not DO NOTHING): a Temporal activity retry of
	// the exact same step should win with whatever it just observed (e.g. a
	// later poll settling on a different terminal phase is not possible in
	// practice — submit_and_wait only returns once, on a terminal phase —
	// but idempotent-update is the safer default vs. silently keeping stale
	// data on the rare retry). created_at is deliberately excluded from the
	// SET clause so a retry doesn't reset when this step was first recorded.
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_executions
		   (temporal_workflow_id, agent, environment, version, image_ref, argo_workflow_name, phase, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (temporal_workflow_id, agent, argo_workflow_name) DO UPDATE SET
		   environment = EXCLUDED.environment, version = EXCLUDED.version,
		   image_ref = EXCLUDED.image_ref, phase = EXCLUDED.phase
		 RETURNING id, temporal_workflow_id, agent, environment, version, image_ref, argo_workflow_name, phase, created_at`,
		e.TemporalWorkflowID, e.Agent, e.Environment, e.Version, e.ImageRef, e.ArgoWorkflowName, e.Phase, now,
	).Scan(&result.ID, &result.TemporalWorkflowID, &result.Agent, &result.Environment, &result.Version,
		&result.ImageRef, &result.ArgoWorkflowName, &result.Phase, &result.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: record execution: %w", err)
	}
	return result, nil
}

// ListExecutions returns the most recent execution records, newest first.
// agent and workflowID each filter when non-empty (independently — passing
// both ANDs them together); limit is clamped to (0, 100], defaulting to 20.
func (s *Store) ListExecutions(ctx context.Context, agent, workflowID string, limit int) ([]AgentExecution, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	const baseQuery = `SELECT id, temporal_workflow_id, agent, environment, version, image_ref, argo_workflow_name, phase, created_at
		FROM agent_executions`

	var conditions []string
	var args []interface{}
	if agent != "" {
		args = append(args, agent)
		conditions = append(conditions, fmt.Sprintf("agent = $%d", len(args)))
	}
	if workflowID != "" {
		args = append(args, workflowID)
		conditions = append(conditions, fmt.Sprintf("temporal_workflow_id = $%d", len(args)))
	}
	query := baseQuery
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list executions: %w", err)
	}
	defer rows.Close()

	var executions []AgentExecution
	for rows.Next() {
		var e AgentExecution
		if err := rows.Scan(&e.ID, &e.TemporalWorkflowID, &e.Agent, &e.Environment, &e.Version,
			&e.ImageRef, &e.ArgoWorkflowName, &e.Phase, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("agentregistry: scan execution: %w", err)
		}
		executions = append(executions, e)
	}
	return executions, rows.Err()
}
