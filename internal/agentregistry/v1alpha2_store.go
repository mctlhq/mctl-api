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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// topLevelJSONKeys parses specJSON as a JSON object and returns the set of
// its top-level keys, used to check for required policy-ceiling fields
// without imposing a Go struct shape on the caller's spec.
func topLevelJSONKeys(specJSON string) (map[string]struct{}, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(specJSON), &raw); err != nil {
		return nil, fmt.Errorf("spec_json must be a JSON object: %w", err)
	}
	keys := make(map[string]struct{}, len(raw))
	for k := range raw {
		keys[k] = struct{}{}
	}
	return keys, nil
}

// missingRequiredFields is a small helper shared by the two publish paths:
// it collects every empty required field into one message instead of
// failing on the first one, matching requirements.md's "listing every
// missing field in one response" acceptance criterion.
func missingRequiredFields(fields map[string]string) []string {
	var missing []string
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// validateProfileSpec reports every field in RequiredProfilePolicyFields that
// is absent (or explicitly null) from specJSON's top level.
func validateProfileSpec(specJSON string) ([]string, error) {
	fields, err := topLevelJSONKeys(specJSON)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, required := range RequiredProfilePolicyFields {
		if _, ok := fields[required]; !ok {
			missing = append(missing, required)
		}
	}
	return missing, nil
}

// PublishDefinitionVersion inserts a new immutable v1alpha2 AgentDefinition
// version. Unlike CreateDefinition, this never overwrites — (agent, version)
// is a once-only key, same immutability contract as the v1 PublishVersion.
func (s *Store) PublishDefinitionVersion(ctx context.Context, d *DefinitionVersion) (*DefinitionVersion, error) {
	missing := missingRequiredFields(map[string]string{
		"owner":                      d.Owner,
		"sourceManifest.gitSha":      d.SourceManifest.GitSHA,
		"sourceManifest.contentHash": d.SourceManifest.ContentHash,
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("agentregistry: publish definition version: missing required fields: %s", strings.Join(missing, ", "))
	}
	if _, err := ParseRange(d.ProfileRange); err != nil {
		return nil, fmt.Errorf("agentregistry: publish definition version: profile_range: %w", err)
	}

	apiVersion := d.APIVersion
	if apiVersion == "" {
		apiVersion = APIVersionV1Alpha2
	}
	now := time.Now().UTC()
	stored := &DefinitionVersion{}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_definition_versions
		   (agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		    profile_range, lifecycle, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by`,
		d.Agent, d.Version, apiVersion, d.SpecJSON, d.Owner, d.SourceManifest.Repo, d.SourceManifest.Path,
		d.SourceManifest.GitSHA, d.SourceManifest.ContentHash, d.ProfileRange, LifecyclePublished, now, d.CreatedBy,
	).Scan(&stored.ID, &stored.Agent, &stored.Version, &stored.APIVersion, &stored.SpecJSON, &stored.Owner,
		&stored.SourceManifest.Repo, &stored.SourceManifest.Path, &stored.SourceManifest.GitSHA, &stored.SourceManifest.ContentHash,
		&stored.ProfileRange, &stored.Lifecycle, &stored.LifecycleReason, &stored.LifecycleAt, &stored.LifecycleBy,
		&stored.CreatedAt, &stored.CreatedBy)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return nil, ErrVersionConflict
			case "23503":
				return nil, fmt.Errorf("agentregistry: publish definition version: %w: %q", ErrDefinitionNotFound, d.Agent)
			}
		}
		return nil, fmt.Errorf("agentregistry: publish definition version: %w", err)
	}
	return stored, nil
}

// ListDefinitionVersions returns every published v1alpha2 definition version
// for one agent, newest first.
func (s *Store) ListDefinitionVersions(ctx context.Context, agent string) ([]DefinitionVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_definition_versions WHERE agent = $1 ORDER BY id DESC`,
		agent,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list definition versions: %w", err)
	}
	defer rows.Close()

	var versions []DefinitionVersion
	for rows.Next() {
		var v DefinitionVersion
		if err := rows.Scan(&v.ID, &v.Agent, &v.Version, &v.APIVersion, &v.SpecJSON, &v.Owner,
			&v.SourceManifest.Repo, &v.SourceManifest.Path, &v.SourceManifest.GitSHA, &v.SourceManifest.ContentHash,
			&v.ProfileRange, &v.Lifecycle, &v.LifecycleReason, &v.LifecycleAt, &v.LifecycleBy, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("agentregistry: scan definition version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// PublishProfileVersion inserts a new immutable ExecutionProfile version.
// Profile names are a global key space (not namespaced per agent) — see
// design.md's open question.
func (s *Store) PublishProfileVersion(ctx context.Context, p *ProfileVersion) (*ProfileVersion, error) {
	missing := missingRequiredFields(map[string]string{
		"owner":                      p.Owner,
		"sourceManifest.gitSha":      p.SourceManifest.GitSHA,
		"sourceManifest.contentHash": p.SourceManifest.ContentHash,
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("agentregistry: publish profile version: missing required fields: %s", strings.Join(missing, ", "))
	}
	policyMissing, err := validateProfileSpec(p.SpecJSON)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: publish profile version: spec: %w", err)
	}
	if len(policyMissing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingPolicyFields, strings.Join(policyMissing, ", "))
	}

	now := time.Now().UTC()
	stored := &ProfileVersion{}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO agent_profile_versions
		   (profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash, lifecycle, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id, profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		   lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by`,
		p.Profile, p.Version, p.SpecJSON, p.Owner, p.SourceManifest.Repo, p.SourceManifest.Path,
		p.SourceManifest.GitSHA, p.SourceManifest.ContentHash, LifecyclePublished, now, p.CreatedBy,
	).Scan(&stored.ID, &stored.Profile, &stored.Version, &stored.SpecJSON, &stored.Owner,
		&stored.SourceManifest.Repo, &stored.SourceManifest.Path, &stored.SourceManifest.GitSHA, &stored.SourceManifest.ContentHash,
		&stored.Lifecycle, &stored.LifecycleReason, &stored.LifecycleAt, &stored.LifecycleBy, &stored.CreatedAt, &stored.CreatedBy)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrVersionConflict
		}
		return nil, fmt.Errorf("agentregistry: publish profile version: %w", err)
	}
	return stored, nil
}

// ListProfileVersions returns every published version of one
// ExecutionProfile, newest first.
func (s *Store) ListProfileVersions(ctx context.Context, profile string) ([]ProfileVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		   lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_profile_versions WHERE profile = $1 ORDER BY id DESC`,
		profile,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list profile versions: %w", err)
	}
	defer rows.Close()

	var versions []ProfileVersion
	for rows.Next() {
		var v ProfileVersion
		if err := rows.Scan(&v.ID, &v.Profile, &v.Version, &v.SpecJSON, &v.Owner,
			&v.SourceManifest.Repo, &v.SourceManifest.Path, &v.SourceManifest.GitSHA, &v.SourceManifest.ContentHash,
			&v.Lifecycle, &v.LifecycleReason, &v.LifecycleAt, &v.LifecycleBy, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("agentregistry: scan profile version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// validLifecycleTransition allows only published -> deprecated,
// published -> disabled and deprecated -> disabled.
func validLifecycleTransition(from, to string) bool {
	switch {
	case from == LifecyclePublished && (to == LifecycleDeprecated || to == LifecycleDisabled):
		return true
	case from == LifecycleDeprecated && to == LifecycleDisabled:
		return true
	default:
		return false
	}
}

// SetDefinitionVersionLifecycle transitions one definition version's
// lifecycle. The immutable spec_json and provenance columns are left
// untouched — only the lifecycle* columns change.
func (s *Store) SetDefinitionVersionLifecycle(ctx context.Context, agent, version, to, reason, actor string) (*DefinitionVersion, error) {
	var current string
	if err := s.pool.QueryRow(ctx,
		`SELECT lifecycle FROM agent_definition_versions WHERE agent = $1 AND version = $2`,
		agent, version,
	).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrDefinitionVersionNotFound, agent, version)
		}
		return nil, fmt.Errorf("agentregistry: set definition lifecycle: %w", err)
	}
	if !validLifecycleTransition(current, to) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidLifecycleTransition, current, to)
	}

	now := time.Now().UTC()
	stored := &DefinitionVersion{}
	err := s.pool.QueryRow(ctx,
		`UPDATE agent_definition_versions
		 SET lifecycle = $3, lifecycle_reason = $4, lifecycle_at = $5, lifecycle_by = $6
		 WHERE agent = $1 AND version = $2
		 RETURNING id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by`,
		agent, version, to, reason, now, actor,
	).Scan(&stored.ID, &stored.Agent, &stored.Version, &stored.APIVersion, &stored.SpecJSON, &stored.Owner,
		&stored.SourceManifest.Repo, &stored.SourceManifest.Path, &stored.SourceManifest.GitSHA, &stored.SourceManifest.ContentHash,
		&stored.ProfileRange, &stored.Lifecycle, &stored.LifecycleReason, &stored.LifecycleAt, &stored.LifecycleBy,
		&stored.CreatedAt, &stored.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: set definition lifecycle: %w", err)
	}
	return stored, nil
}

// SetProfileVersionLifecycle transitions one profile version's lifecycle,
// same rules as SetDefinitionVersionLifecycle.
func (s *Store) SetProfileVersionLifecycle(ctx context.Context, profile, version, to, reason, actor string) (*ProfileVersion, error) {
	var current string
	if err := s.pool.QueryRow(ctx,
		`SELECT lifecycle FROM agent_profile_versions WHERE profile = $1 AND version = $2`,
		profile, version,
	).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrProfileVersionNotFound, profile, version)
		}
		return nil, fmt.Errorf("agentregistry: set profile lifecycle: %w", err)
	}
	if !validLifecycleTransition(current, to) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidLifecycleTransition, current, to)
	}

	now := time.Now().UTC()
	stored := &ProfileVersion{}
	err := s.pool.QueryRow(ctx,
		`UPDATE agent_profile_versions
		 SET lifecycle = $3, lifecycle_reason = $4, lifecycle_at = $5, lifecycle_by = $6
		 WHERE profile = $1 AND version = $2
		 RETURNING id, profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		   lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by`,
		profile, version, to, reason, now, actor,
	).Scan(&stored.ID, &stored.Profile, &stored.Version, &stored.SpecJSON, &stored.Owner,
		&stored.SourceManifest.Repo, &stored.SourceManifest.Path, &stored.SourceManifest.GitSHA, &stored.SourceManifest.ContentHash,
		&stored.Lifecycle, &stored.LifecycleReason, &stored.LifecycleAt, &stored.LifecycleBy, &stored.CreatedAt, &stored.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: set profile lifecycle: %w", err)
	}
	return stored, nil
}

// definitionVersionRow / profileVersionRow load one version row for
// validation inside a transaction (FOR SHARE — see design.md's write path).
func loadDefinitionVersionForShare(ctx context.Context, tx pgx.Tx, agent, version string) (*DefinitionVersion, error) {
	d := &DefinitionVersion{}
	err := tx.QueryRow(ctx,
		`SELECT id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_definition_versions WHERE agent = $1 AND version = $2 FOR SHARE`,
		agent, version,
	).Scan(&d.ID, &d.Agent, &d.Version, &d.APIVersion, &d.SpecJSON, &d.Owner,
		&d.SourceManifest.Repo, &d.SourceManifest.Path, &d.SourceManifest.GitSHA, &d.SourceManifest.ContentHash,
		&d.ProfileRange, &d.Lifecycle, &d.LifecycleReason, &d.LifecycleAt, &d.LifecycleBy, &d.CreatedAt, &d.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrDefinitionVersionNotFound, agent, version)
		}
		return nil, fmt.Errorf("agentregistry: load definition version: %w", err)
	}
	return d, nil
}

func loadProfileVersionForShare(ctx context.Context, tx pgx.Tx, profile, version string) (*ProfileVersion, error) {
	p := &ProfileVersion{}
	err := tx.QueryRow(ctx,
		`SELECT id, profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		   lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_profile_versions WHERE profile = $1 AND version = $2 FOR SHARE`,
		profile, version,
	).Scan(&p.ID, &p.Profile, &p.Version, &p.SpecJSON, &p.Owner,
		&p.SourceManifest.Repo, &p.SourceManifest.Path, &p.SourceManifest.GitSHA, &p.SourceManifest.ContentHash,
		&p.Lifecycle, &p.LifecycleReason, &p.LifecycleAt, &p.LifecycleBy, &p.CreatedAt, &p.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrProfileVersionNotFound, profile, version)
		}
		return nil, fmt.Errorf("agentregistry: load profile version: %w", err)
	}
	return p, nil
}

// validateBindingPair runs the lifecycle and compatibility checks shared by
// CreateBinding and RollbackBinding: both named versions must be published,
// and the profile version must satisfy the definition's declared range.
func validateBindingPair(def *DefinitionVersion, prof *ProfileVersion) error {
	if def.Lifecycle == LifecycleDeprecated {
		return fmt.Errorf("%w: definition %s@%s", ErrVersionDeprecated, def.Agent, def.Version)
	}
	if def.Lifecycle == LifecycleDisabled {
		return fmt.Errorf("%w: definition %s@%s", ErrVersionDisabled, def.Agent, def.Version)
	}
	if prof.Lifecycle == LifecycleDeprecated {
		return fmt.Errorf("%w: profile %s@%s", ErrVersionDeprecated, prof.Profile, prof.Version)
	}
	if prof.Lifecycle == LifecycleDisabled {
		return fmt.Errorf("%w: profile %s@%s", ErrVersionDisabled, prof.Profile, prof.Version)
	}

	rng, err := ParseRange(def.ProfileRange)
	if err != nil {
		return fmt.Errorf("agentregistry: definition %s@%s has an unparseable stored range: %w", def.Agent, def.Version, err)
	}
	profVersion, err := ParseVersion(prof.Version)
	if err != nil {
		return fmt.Errorf("agentregistry: profile %s@%s has an unparseable version: %w", prof.Profile, prof.Version, err)
	}
	if !rng.Satisfies(profVersion) {
		return fmt.Errorf("%w: definition %s@%s declares range %q, profile %s@%s does not satisfy it",
			ErrIncompatibleProfile, def.Agent, def.Version, def.ProfileRange, prof.Profile, prof.Version)
	}
	return nil
}

// CreateBinding appends a new ReleaseBinding revision for (agent,
// environment), mirroring Store.promote's transaction shape: BEGIN, take a
// per-(agent, environment) advisory lock, validate, insert at MAX(revision)+1,
// COMMIT. See design.md's "Write path" section.
func (s *Store) CreateBinding(ctx context.Context, req CreateBindingRequest) (*ReleaseBinding, error) {
	if !validEnvironment(req.Environment) {
		return nil, fmt.Errorf("agentregistry: create binding: %w: %q", ErrInvalidEnvironment, req.Environment)
	}
	if req.BindingSource == BindingSourceCompatibilityFixture {
		return nil, fmt.Errorf("%w: compatibility-fixture intents are non-promotable; use bindingSource=registry", ErrFixtureNotPromotable)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: create binding: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, req.Agent+"/"+req.Environment); err != nil {
		return nil, fmt.Errorf("agentregistry: create binding: acquire lock: %w", err)
	}

	def, err := loadDefinitionVersionForShare(ctx, tx, req.Agent, req.DefinitionVersion)
	if err != nil {
		return nil, err
	}
	prof, err := loadProfileVersionForShare(ctx, tx, req.Profile, req.ProfileVersion)
	if err != nil {
		return nil, err
	}
	if err := validateBindingPair(def, prof); err != nil {
		return nil, err
	}

	var nextRevision int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(revision), 0) + 1 FROM agent_release_bindings WHERE agent = $1 AND environment = $2`,
		req.Agent, req.Environment,
	).Scan(&nextRevision); err != nil {
		return nil, fmt.Errorf("agentregistry: create binding: compute revision: %w", err)
	}

	now := time.Now().UTC()
	stored := &ReleaseBinding{}
	if err := tx.QueryRow(ctx,
		`INSERT INTO agent_release_bindings
		   (agent, environment, revision, definition_version, profile, profile_version, profile_range,
		    binding_source, intent_repo, intent_path, intent_git_sha, rollback_of, reason, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $13, $14)
		 RETURNING id, agent, environment, revision, definition_version, profile, profile_version, profile_range,
		   binding_source, intent_repo, intent_path, intent_git_sha, rollback_of, reason, created_at, created_by`,
		req.Agent, req.Environment, nextRevision, req.DefinitionVersion, req.Profile, req.ProfileVersion, def.ProfileRange,
		req.BindingSource, req.IntentRepo, req.IntentPath, req.IntentGitSHA, req.Reason, now, req.Actor,
	).Scan(&stored.ID, &stored.Agent, &stored.Environment, &stored.Revision, &stored.DefinitionVersion, &stored.Profile,
		&stored.ProfileVersion, &stored.ProfileRange, &stored.BindingSource, &stored.IntentRepo, &stored.IntentPath,
		&stored.IntentGitSHA, &stored.RollbackOf, &stored.Reason, &stored.CreatedAt, &stored.CreatedBy); err != nil {
		return nil, fmt.Errorf("agentregistry: create binding: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("agentregistry: create binding: commit: %w", err)
	}
	return stored, nil
}

// scanBinding is the shared row-shape for a *ReleaseBinding query.
func scanBinding(row pgx.Row) (*ReleaseBinding, error) {
	b := &ReleaseBinding{}
	err := row.Scan(&b.ID, &b.Agent, &b.Environment, &b.Revision, &b.DefinitionVersion, &b.Profile,
		&b.ProfileVersion, &b.ProfileRange, &b.BindingSource, &b.IntentRepo, &b.IntentPath,
		&b.IntentGitSHA, &b.RollbackOf, &b.Reason, &b.CreatedAt, &b.CreatedBy)
	if err != nil {
		return nil, err
	}
	return b, nil
}

const bindingColumns = `id, agent, environment, revision, definition_version, profile, profile_version, profile_range,
	binding_source, intent_repo, intent_path, intent_git_sha, rollback_of, reason, created_at, created_by`

// ActiveBinding returns the highest-revision ReleaseBinding for (agent,
// environment) — the derived "active" binding. There is no stored active
// flag anywhere; this ORDER BY ... LIMIT 1 is the only definition of active.
func (s *Store) ActiveBinding(ctx context.Context, agent, environment string) (*ReleaseBinding, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+bindingColumns+` FROM agent_release_bindings
		 WHERE agent = $1 AND environment = $2 ORDER BY revision DESC LIMIT 1`,
		agent, environment,
	)
	b, err := scanBinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s", ErrBindingNotFound, agent, environment)
		}
		return nil, fmt.Errorf("agentregistry: active binding: %w", err)
	}
	return b, nil
}

// GetBinding returns one exact (agent, environment, revision) row.
func (s *Store) GetBinding(ctx context.Context, agent, environment string, revision int) (*ReleaseBinding, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+bindingColumns+` FROM agent_release_bindings WHERE agent = $1 AND environment = $2 AND revision = $3`,
		agent, environment, revision,
	)
	b, err := scanBinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s revision %d", ErrBindingNotFound, agent, environment, revision)
		}
		return nil, fmt.Errorf("agentregistry: get binding: %w", err)
	}
	return b, nil
}

// ListBindings returns the full revision history for (agent, environment),
// newest first.
func (s *Store) ListBindings(ctx context.Context, agent, environment string) ([]ReleaseBinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+bindingColumns+` FROM agent_release_bindings WHERE agent = $1 AND environment = $2 ORDER BY revision DESC`,
		agent, environment,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list bindings: %w", err)
	}
	defer rows.Close()

	var bindings []ReleaseBinding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("agentregistry: scan binding: %w", err)
		}
		bindings = append(bindings, *b)
	}
	return bindings, rows.Err()
}

// RollbackBinding appends a new revision that copies revision's
// definition/profile pair, setting rollback_of to the restored row's id.
// The restored pair's lifecycle and compatibility are re-validated inside
// the same transaction, so a since-disabled version cannot be restored.
func (s *Store) RollbackBinding(ctx context.Context, agent, environment string, revision int, reason, actor string) (*ReleaseBinding, error) {
	if !validEnvironment(environment) {
		return nil, fmt.Errorf("agentregistry: rollback binding: %w: %q", ErrInvalidEnvironment, environment)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: rollback binding: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, agent+"/"+environment); err != nil {
		return nil, fmt.Errorf("agentregistry: rollback binding: acquire lock: %w", err)
	}

	targetRow := tx.QueryRow(ctx,
		`SELECT `+bindingColumns+` FROM agent_release_bindings WHERE agent = $1 AND environment = $2 AND revision = $3`,
		agent, environment, revision,
	)
	target, err := scanBinding(targetRow)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s revision %d", ErrBindingNotFound, agent, environment, revision)
		}
		return nil, fmt.Errorf("agentregistry: rollback binding: load target: %w", err)
	}

	def, err := loadDefinitionVersionForShare(ctx, tx, agent, target.DefinitionVersion)
	if err != nil {
		return nil, err
	}
	prof, err := loadProfileVersionForShare(ctx, tx, target.Profile, target.ProfileVersion)
	if err != nil {
		return nil, err
	}
	if err := validateBindingPair(def, prof); err != nil {
		return nil, err
	}

	var nextRevision int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(revision), 0) + 1 FROM agent_release_bindings WHERE agent = $1 AND environment = $2`,
		agent, environment,
	).Scan(&nextRevision); err != nil {
		return nil, fmt.Errorf("agentregistry: rollback binding: compute revision: %w", err)
	}

	now := time.Now().UTC()
	stored := &ReleaseBinding{}
	if err := tx.QueryRow(ctx,
		`INSERT INTO agent_release_bindings
		   (agent, environment, revision, definition_version, profile, profile_version, profile_range,
		    binding_source, intent_repo, intent_path, intent_git_sha, rollback_of, reason, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 RETURNING `+bindingColumns,
		agent, environment, nextRevision, target.DefinitionVersion, target.Profile, target.ProfileVersion, def.ProfileRange,
		target.BindingSource, target.IntentRepo, target.IntentPath, target.IntentGitSHA, target.ID, reason, now, actor,
	).Scan(&stored.ID, &stored.Agent, &stored.Environment, &stored.Revision, &stored.DefinitionVersion, &stored.Profile,
		&stored.ProfileVersion, &stored.ProfileRange, &stored.BindingSource, &stored.IntentRepo, &stored.IntentPath,
		&stored.IntentGitSHA, &stored.RollbackOf, &stored.Reason, &stored.CreatedAt, &stored.CreatedBy); err != nil {
		return nil, fmt.Errorf("agentregistry: rollback binding: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("agentregistry: rollback binding: commit: %w", err)
	}
	return stored, nil
}

// buildResolvedBinding assembles the consumer-facing envelope from a binding
// plus its two version rows.
func buildResolvedBinding(b *ReleaseBinding, def *DefinitionVersion, prof *ProfileVersion) (*ResolvedBinding, error) {
	rng, err := ParseRange(def.ProfileRange)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: resolve: %w", err)
	}
	profVersion, err := ParseVersion(prof.Version)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: resolve: %w", err)
	}

	var intent *ResolvedIntent
	if b != nil && (b.IntentRepo != "" || b.IntentPath != "" || b.IntentGitSHA != "") {
		intent = &ResolvedIntent{Repo: b.IntentRepo, Path: b.IntentPath, GitSHA: b.IntentGitSHA}
	}

	resolved := &ResolvedBinding{
		APIVersion: APIVersionV1Alpha2,
		Agent:      def.Agent,
		Definition: ResolvedDefinition{
			Version:        def.Version,
			Lifecycle:      def.Lifecycle,
			Owner:          def.Owner,
			SourceManifest: def.SourceManifest,
			Spec:           def.SpecJSON,
		},
		Profile: ResolvedProfile{
			Name:           prof.Profile,
			Version:        prof.Version,
			Lifecycle:      prof.Lifecycle,
			SourceManifest: prof.SourceManifest,
			Spec:           prof.SpecJSON,
		},
		Compatibility: ResolvedCompatibility{
			Range:     def.ProfileRange,
			Satisfied: rng.Satisfies(profVersion),
		},
		Intent: intent,
	}
	if b != nil {
		resolved.Environment = b.Environment
		resolved.Revision = b.Revision
		resolved.BindingSource = b.BindingSource
		resolved.RollbackOf = b.RollbackOf
		resolved.CreatedAt = b.CreatedAt
		resolved.CreatedBy = b.CreatedBy
	}
	return resolved, nil
}

// ResolveBinding returns the active binding for (agent, environment) as the
// consumer-facing envelope.
func (s *Store) ResolveBinding(ctx context.Context, agent, environment string) (*ResolvedBinding, error) {
	if !validEnvironment(environment) {
		return nil, fmt.Errorf("agentregistry: resolve binding: %w: %q", ErrInvalidEnvironment, environment)
	}
	b, err := s.ActiveBinding(ctx, agent, environment)
	if err != nil {
		return nil, err
	}
	def, err := s.definitionVersion(ctx, agent, b.DefinitionVersion)
	if err != nil {
		return nil, err
	}
	prof, err := s.profileVersion(ctx, b.Profile, b.ProfileVersion)
	if err != nil {
		return nil, err
	}
	return buildResolvedBinding(b, def, prof)
}

// ResolveExplicit returns the resolve envelope for an explicit definition
// name+version pin against a named profile, optionally with an explicit
// profile version. No environment is consulted, matching requirements.md's
// "resolves ... without consulting any environment" acceptance criterion.
//
// When profileVersion is empty, the highest published (non-deprecated,
// non-disabled) version of `profile` that satisfies the definition's
// declared compatibility range is used — the literal reading of
// requirements.md's "optionally with an explicit profile version": the
// profile family still has to be named (profile versions are a global key
// space keyed on (profile, version), not resolvable from a bare version
// number alone), but pinning the exact version within it is optional.
func (s *Store) ResolveExplicit(ctx context.Context, agent, definitionVersion, profile, profileVersion string) (*ResolvedBinding, error) {
	def, err := s.definitionVersion(ctx, agent, definitionVersion)
	if err != nil {
		return nil, err
	}

	if profileVersion != "" {
		prof, err := s.profileVersion(ctx, profile, profileVersion)
		if err != nil {
			return nil, err
		}
		return buildResolvedBinding(nil, def, prof)
	}

	prof, err := s.highestCompatibleProfileVersion(ctx, profile, def.ProfileRange)
	if err != nil {
		return nil, err
	}
	return buildResolvedBinding(nil, def, prof)
}

// highestCompatibleProfileVersion returns the highest published version of
// profile whose semver satisfies rng, used when an explicit-pin resolve
// omits profile_version.
func (s *Store) highestCompatibleProfileVersion(ctx context.Context, profile, profileRange string) (*ProfileVersion, error) {
	rng, err := ParseRange(profileRange)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: resolve: %w", err)
	}
	versions, err := s.ListProfileVersions(ctx, profile)
	if err != nil {
		return nil, err
	}

	var best *ProfileVersion
	var bestParsed Version
	for i := range versions {
		v := &versions[i]
		if v.Lifecycle != LifecyclePublished {
			continue
		}
		parsed, err := ParseVersion(v.Version)
		if err != nil {
			continue // an unparseable stored version cannot be a valid candidate
		}
		if !rng.Satisfies(parsed) {
			continue
		}
		if best == nil || parsed.Compare(bestParsed) > 0 {
			best = v
			bestParsed = parsed
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: no published version of profile %q satisfies range %q", ErrProfileVersionNotFound, profile, profileRange)
	}
	return best, nil
}

func (s *Store) definitionVersion(ctx context.Context, agent, version string) (*DefinitionVersion, error) {
	d := &DefinitionVersion{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_definition_versions WHERE agent = $1 AND version = $2`,
		agent, version,
	).Scan(&d.ID, &d.Agent, &d.Version, &d.APIVersion, &d.SpecJSON, &d.Owner,
		&d.SourceManifest.Repo, &d.SourceManifest.Path, &d.SourceManifest.GitSHA, &d.SourceManifest.ContentHash,
		&d.ProfileRange, &d.Lifecycle, &d.LifecycleReason, &d.LifecycleAt, &d.LifecycleBy, &d.CreatedAt, &d.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrDefinitionVersionNotFound, agent, version)
		}
		return nil, fmt.Errorf("agentregistry: load definition version: %w", err)
	}
	return d, nil
}

func (s *Store) profileVersion(ctx context.Context, profile, version string) (*ProfileVersion, error) {
	p := &ProfileVersion{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, profile, version, spec_json, owner, source_repo, source_path, source_git_sha, source_content_hash,
		   lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_profile_versions WHERE profile = $1 AND version = $2`,
		profile, version,
	).Scan(&p.ID, &p.Profile, &p.Version, &p.SpecJSON, &p.Owner,
		&p.SourceManifest.Repo, &p.SourceManifest.Path, &p.SourceManifest.GitSHA, &p.SourceManifest.ContentHash,
		&p.Lifecycle, &p.LifecycleReason, &p.LifecycleAt, &p.LifecycleBy, &p.CreatedAt, &p.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s@%s", ErrProfileVersionNotFound, profile, version)
		}
		return nil, fmt.Errorf("agentregistry: load profile version: %w", err)
	}
	return p, nil
}

// CatalogEntry is one agent's full v1alpha2 + v1 catalog view, the shape
// mctl_get_agent returns.
type CatalogEntry struct {
	Name               string                     `json:"name"`
	Description        string                     `json:"description"`
	Owner              string                     `json:"owner"`
	Versions           []AgentVersion             `json:"versions"`
	DefinitionVersions []DefinitionVersion        `json:"definitionVersions"`
	ProfileVersions    []ProfileVersion           `json:"profileVersions,omitempty"`
	ActiveBindings     map[string]*ReleaseBinding `json:"activeBindings"`
}

// CatalogSummary is one agent's summary view, the shape mctl_list_agents
// returns per agent.
type CatalogSummary struct {
	Name                   string         `json:"name"`
	Owner                  string         `json:"owner"`
	VersionCount           int            `json:"versionCount"`
	DefinitionVersionCount int            `json:"definitionVersionCount"`
	ActiveBindings         map[string]int `json:"activeBindingRevisions"`
}

// ListCatalog returns every registered agent with its owner, version counts
// and active binding revision per environment — the mctl_list_agents shape.
func (s *Store) ListCatalog(ctx context.Context) ([]CatalogSummary, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, owner FROM agent_definitions ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list catalog: %w", err)
	}
	defer rows.Close()

	var names []string
	owners := map[string]string{}
	for rows.Next() {
		var name, owner string
		if err := rows.Scan(&name, &owner); err != nil {
			return nil, fmt.Errorf("agentregistry: scan agent definition: %w", err)
		}
		names = append(names, name)
		owners[name] = owner
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	summaries := make([]CatalogSummary, 0, len(names))
	for _, name := range names {
		summary := CatalogSummary{Name: name, Owner: owners[name], ActiveBindings: map[string]int{}}

		if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_versions WHERE agent = $1`, name).Scan(&summary.VersionCount); err != nil {
			return nil, fmt.Errorf("agentregistry: count versions: %w", err)
		}
		if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_definition_versions WHERE agent = $1`, name).Scan(&summary.DefinitionVersionCount); err != nil {
			return nil, fmt.Errorf("agentregistry: count definition versions: %w", err)
		}
		for _, env := range []string{EnvironmentProduction, EnvironmentShadow} {
			b, err := s.ActiveBinding(ctx, name, env)
			if err != nil {
				if errors.Is(err, ErrBindingNotFound) {
					continue
				}
				return nil, err
			}
			summary.ActiveBindings[env] = b.Revision
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// GetCatalogEntry returns one agent's full catalog entry — the
// mctl_get_agent shape. ProfileVersions is scoped to the profile families
// this agent's active bindings actually reference — profile names are a
// global key space (design.md's open question), so "every profile version"
// in the abstract would mean the whole registry's profile catalog, not
// anything owned by this agent; every published version of each referenced
// profile is what lets a caller see that profile's own lifecycle history
// without a second mctl_list_agent_versions-style round trip.
func (s *Store) GetCatalogEntry(ctx context.Context, name string) (*CatalogEntry, error) {
	def := &AgentDefinition{}
	if err := s.pool.QueryRow(ctx,
		`SELECT name, description, owner, created_at, archived_at FROM agent_definitions WHERE name = $1`, name,
	).Scan(&def.Name, &def.Description, &def.Owner, &def.CreatedAt, &def.ArchivedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrDefinitionNotFound, name)
		}
		return nil, fmt.Errorf("agentregistry: get catalog entry: %w", err)
	}

	versions, err := s.ListVersions(ctx, name)
	if err != nil {
		return nil, err
	}
	definitionVersions, err := s.ListDefinitionVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	entry := &CatalogEntry{
		Name:               def.Name,
		Description:        def.Description,
		Owner:              def.Owner,
		Versions:           versions,
		DefinitionVersions: definitionVersions,
		ActiveBindings:     map[string]*ReleaseBinding{},
	}
	referencedProfiles := map[string]bool{}
	for _, env := range []string{EnvironmentProduction, EnvironmentShadow} {
		b, err := s.ActiveBinding(ctx, name, env)
		if err != nil {
			if errors.Is(err, ErrBindingNotFound) {
				continue
			}
			return nil, err
		}
		entry.ActiveBindings[env] = b
		referencedProfiles[b.Profile] = true
	}
	for profile := range referencedProfiles {
		profileVersions, err := s.ListProfileVersions(ctx, profile)
		if err != nil {
			return nil, err
		}
		entry.ProfileVersions = append(entry.ProfileVersions, profileVersions...)
	}
	return entry, nil
}
