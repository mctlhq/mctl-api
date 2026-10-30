package deployplan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// IDPrefix labels deploy plan ids.
const IDPrefix = "dpl_"

const (
	// DefaultTTL is a plan's lifetime when the caller names none.
	DefaultTTL = 30 * time.Minute
	// MinTTL and MaxTTL bound a caller-supplied ttl_seconds.
	MinTTL = 60 * time.Second
	MaxTTL = 24 * time.Hour
)

const schema = `
CREATE TABLE IF NOT EXISTS deploy_plans (
  id                   TEXT PRIMARY KEY CHECK (id LIKE 'dpl\_%'),
  digest               TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  schema_version       TEXT NOT NULL,
  tenant               TEXT NOT NULL,
  service              TEXT NOT NULL,
  environment          TEXT NOT NULL CHECK (environment = 'preview'),
  intent               JSONB NOT NULL,
  intent_canonical     TEXT NOT NULL,
  revision             TEXT NOT NULL CHECK (revision ~ '^[0-9a-f]{40}$'),
  gitops_base_sha      TEXT NOT NULL CHECK (gitops_base_sha ~ '^[0-9a-f]{40}$'),
  action               TEXT NOT NULL CHECK (action IN ('onboard','update')),
  preview_id           TEXT NOT NULL,
  values_before_sha256 TEXT NOT NULL,
  values_after         TEXT NOT NULL,
  diff                 TEXT NOT NULL,
  host                 TEXT NOT NULL,
  requires_approval    BOOLEAN NOT NULL,
  required_role        TEXT NOT NULL,
  approval_reason      TEXT NOT NULL,
  created_by           TEXT NOT NULL,
  surface              TEXT NOT NULL,
  idempotency_key      TEXT,
  created_at           TIMESTAMPTZ NOT NULL,
  expires_at           TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at
                         AND expires_at <= created_at + interval '24 hours')
);
CREATE UNIQUE INDEX IF NOT EXISTS deploy_plans_idem
  ON deploy_plans (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS deploy_plans_tenant ON deploy_plans (tenant, created_at DESC);
CREATE OR REPLACE FUNCTION deploy_plans_immutable() RETURNS trigger
  LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'deploy_plans rows are immutable'; END $$;
DROP TRIGGER IF EXISTS deploy_plans_no_update ON deploy_plans;
CREATE TRIGGER deploy_plans_no_update BEFORE UPDATE ON deploy_plans
  FOR EACH ROW EXECUTE FUNCTION deploy_plans_immutable();
`

const planColumns = `id, digest, schema_version, tenant, service, environment, intent, intent_canonical,
	revision, gitops_base_sha, action, preview_id, values_before_sha256, values_after, diff, host,
	requires_approval, required_role, approval_reason, created_by, surface, COALESCE(idempotency_key, ''),
	created_at, expires_at`

// Store keeps deploy plans in Postgres. Rows are immutable: there is no
// update method and a trigger rejects any UPDATE.
type Store struct {
	pool        *pgxpool.Pool
	releaseOnce sync.Once
	now         func() time.Time
}

// NewStore connects and creates the schema if needed.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("deployplan: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("deployplan: create schema: %w", err)
	}
	slog.Info("deploy-plan store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.releaseOnce.Do(func() { pgshared.Release(s.pool) }) }

// Now is the store's clock.
func (s *Store) Now() time.Time { return s.now() }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// NewID returns a fresh plan id.
func NewID() string { return IDPrefix + uuid.NewString() }

// Insert stores p. A repeated (created_by, idempotency_key) with the same
// digest returns the stored plan and replayed=true; with a different digest
// it returns an *IdempotencyConflictError naming the stored plan.
func (s *Store) Insert(ctx context.Context, p *Plan) (*Plan, bool, error) {
	if p.ID == "" {
		p.ID = NewID()
	}
	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Microsecond)
	p.ExpiresAt = p.ExpiresAt.UTC().Truncate(time.Microsecond)
	var idem *string
	if p.IdempotencyKey != "" {
		idem = &p.IdempotencyKey
	}
	row := s.pool.QueryRow(ctx, `
INSERT INTO deploy_plans (id, digest, schema_version, tenant, service, environment, intent, intent_canonical,
	revision, gitops_base_sha, action, preview_id, values_before_sha256, values_after, diff, host,
	requires_approval, required_role, approval_reason, created_by, surface, idempotency_key, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
ON CONFLICT (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
RETURNING `+planColumns,
		p.ID, p.Digest, p.SchemaVersion, p.Tenant, p.Service, p.Environment, p.Intent, p.IntentCanonical,
		p.Revision, p.GitopsBaseSHA, string(p.Action), p.PreviewID, p.ValuesBeforeSHA256, p.ValuesAfter, p.Diff, p.Host,
		p.RequiresApproval, p.RequiredRole, p.ApprovalReason, p.CreatedBy, p.Surface, idem, p.CreatedAt, p.ExpiresAt)
	stored, err := scanPlan(row)
	if err == nil {
		return stored, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("deployplan: insert: %w", err)
	}
	if idem == nil {
		return nil, false, errors.New("deployplan: insert returned no row")
	}
	existing, err := scanPlan(s.pool.QueryRow(ctx,
		`SELECT `+planColumns+` FROM deploy_plans WHERE created_by = $1 AND idempotency_key = $2`,
		p.CreatedBy, p.IdempotencyKey))
	if err != nil {
		return nil, false, fmt.Errorf("deployplan: reading the plan an idempotency key names: %w", err)
	}
	if existing.Digest != p.Digest {
		return nil, false, &IdempotencyConflictError{PlanID: existing.ID}
	}
	return existing, true, nil
}

// Get returns the plan with that id, or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*Plan, error) {
	p, err := scanPlan(s.pool.QueryRow(ctx, `SELECT `+planColumns+` FROM deploy_plans WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("deployplan: get: %w", err)
	}
	return p, nil
}

func scanPlan(row pgx.Row) (*Plan, error) {
	var p Plan
	var action string
	if err := row.Scan(&p.ID, &p.Digest, &p.SchemaVersion, &p.Tenant, &p.Service, &p.Environment, &p.Intent,
		&p.IntentCanonical, &p.Revision, &p.GitopsBaseSHA, &action, &p.PreviewID, &p.ValuesBeforeSHA256,
		&p.ValuesAfter, &p.Diff, &p.Host, &p.RequiresApproval, &p.RequiredRole, &p.ApprovalReason,
		&p.CreatedBy, &p.Surface, &p.IdempotencyKey, &p.CreatedAt, &p.ExpiresAt); err != nil {
		return nil, err
	}
	p.Action = Action(action)
	p.CreatedAt = p.CreatedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return &p, nil
}
