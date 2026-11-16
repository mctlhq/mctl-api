package deployplan

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RecordIDPrefix labels deployment record ids.
const RecordIDPrefix = "dep_"

// Record status values. A record is written as RecordSubmitting once the
// grant is spent, and moves once to RecordSubmitted or RecordSubmitFailed.
const (
	RecordSubmitting   = "submitting"
	RecordSubmitted    = "submitted"
	RecordSubmitFailed = "submit_failed"
)

// Health values. HealthUnknown is the only value a record starts with and
// the only one any reader may assume: nothing below reports success that it
// did not observe (mctl-api#1047).
const (
	HealthUnknown   = "unknown"
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
)

// Run results: how the submitted workflow ended, written once by the
// reconciler from the workflow's phase. Absent while it runs or when the
// outcome could not be observed.
const (
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidImageDigest reports whether s is an image digest the record accepts.
func ValidImageDigest(s string) bool { return digestRE.MatchString(s) }

// ErrRecordNotFound is the store's answer for an id or plan with no record.
var ErrRecordNotFound = errors.New("deployplan: deployment record not found")

// ErrRecordExists is Insert's answer when the plan already has a record: a
// plan is applied at most once.
var ErrRecordExists = errors.New("deployplan: the plan already has a deployment record")

// Record is one apply of one plan (mctl-api#1047): what was planned, who
// granted it, what was submitted, and, once observed, what ran. The fields
// that come from the plan and the grant never change; status moves once out
// of submitting; image digest, Argo revision and health are each written at
// most once, by the server, never by the caller.
type Record struct {
	ID                   string `json:"id"`
	PlanID               string `json:"plan_id"`
	PlanDigest           string `json:"plan_digest"`
	Tenant               string `json:"tenant"`
	Service              string `json:"service"`
	Environment          string `json:"environment"`
	Revision             string `json:"revision"`
	GitopsSHA            string `json:"gitops_sha"`
	PreviewID            string `json:"preview_id"`
	Host                 string `json:"host"`
	ApprovalID           string `json:"approval_id"`
	DecidedByPrincipalID string `json:"decided_by_principal_id"`
	AppliedBy            string `json:"applied_by"`
	Status               string `json:"status"`
	Workflow             string `json:"workflow,omitempty"`
	// WorkflowRef is the name the workflow is submitted under, fixed before
	// the submit so an ambiguous submit can be resolved by looking it up.
	WorkflowRef  string    `json:"-"`
	RunResult    string    `json:"run_result,omitempty"`
	ImageDigest  string    `json:"image_digest,omitempty"`
	ArgoRevision string    `json:"argo_revision,omitempty"`
	Health       string    `json:"health"`
	HealthURL    string    `json:"health_url,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

const recordSchema = `
CREATE TABLE IF NOT EXISTS deploy_records (
  id                      TEXT PRIMARY KEY CHECK (id LIKE 'dep\_%'),
  plan_id                 TEXT NOT NULL UNIQUE REFERENCES deploy_plans (id),
  plan_digest             TEXT NOT NULL CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
  tenant                  TEXT NOT NULL,
  service                 TEXT NOT NULL,
  environment             TEXT NOT NULL,
  revision                TEXT NOT NULL CHECK (revision ~ '^[0-9a-f]{40}$'),
  gitops_sha              TEXT NOT NULL CHECK (gitops_sha ~ '^[0-9a-f]{40}$'),
  preview_id              TEXT NOT NULL,
  host                    TEXT NOT NULL,
  approval_id             TEXT NOT NULL UNIQUE,
  decided_by_principal_id TEXT NOT NULL CHECK (decided_by_principal_id <> ''),
  applied_by              TEXT NOT NULL CHECK (applied_by <> ''),
  status                  TEXT NOT NULL CHECK (status IN ('submitting','submitted','submit_failed')),
  workflow                TEXT,
  image_digest            TEXT CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  argo_revision           TEXT,
  health                  TEXT NOT NULL CHECK (health IN ('unknown','healthy','unhealthy')),
  health_url              TEXT,
  created_at              TIMESTAMPTZ NOT NULL,
  updated_at              TIMESTAMPTZ NOT NULL
);
ALTER TABLE deploy_records ADD COLUMN IF NOT EXISTS workflow_ref TEXT;
ALTER TABLE deploy_records ADD COLUMN IF NOT EXISTS run_result TEXT CHECK (run_result IN ('succeeded','failed'));
CREATE INDEX IF NOT EXISTS deploy_records_tenant ON deploy_records (tenant, service, created_at DESC);
CREATE OR REPLACE FUNCTION deploy_records_guard() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id, NEW.plan_id, NEW.plan_digest, NEW.tenant, NEW.service, NEW.environment, NEW.revision,
      NEW.gitops_sha, NEW.preview_id, NEW.host, NEW.approval_id, NEW.decided_by_principal_id,
      NEW.applied_by, NEW.created_at, NEW.workflow_ref)
     IS DISTINCT FROM
     (OLD.id, OLD.plan_id, OLD.plan_digest, OLD.tenant, OLD.service, OLD.environment, OLD.revision,
      OLD.gitops_sha, OLD.preview_id, OLD.host, OLD.approval_id, OLD.decided_by_principal_id,
      OLD.applied_by, OLD.created_at, OLD.workflow_ref) THEN
    RAISE EXCEPTION 'deploy_records: planned and granted fields are immutable';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND OLD.status <> 'submitting' THEN
    RAISE EXCEPTION 'deploy_records: status moves once out of submitting';
  END IF;
  IF NEW.workflow IS DISTINCT FROM OLD.workflow AND OLD.workflow IS NOT NULL THEN
    RAISE EXCEPTION 'deploy_records: workflow is written once';
  END IF;
  IF NEW.workflow IS NOT NULL AND NEW.workflow_ref IS NOT NULL AND NEW.workflow <> NEW.workflow_ref THEN
    RAISE EXCEPTION 'deploy_records: workflow differs from the name it was submitted under';
  END IF;
  IF NEW.run_result IS DISTINCT FROM OLD.run_result AND OLD.run_result IS NOT NULL THEN
    RAISE EXCEPTION 'deploy_records: run_result is written once';
  END IF;
  IF NEW.run_result IS NOT NULL AND NEW.status <> 'submitted' THEN
    RAISE EXCEPTION 'deploy_records: only a submitted record has a run result';
  END IF;
  IF NEW.image_digest IS DISTINCT FROM OLD.image_digest AND OLD.image_digest IS NOT NULL THEN
    RAISE EXCEPTION 'deploy_records: image_digest is written once';
  END IF;
  IF NEW.argo_revision IS DISTINCT FROM OLD.argo_revision AND OLD.argo_revision IS NOT NULL THEN
    RAISE EXCEPTION 'deploy_records: argo_revision is written once';
  END IF;
  IF NEW.health IS DISTINCT FROM OLD.health AND OLD.health <> 'unknown' THEN
    RAISE EXCEPTION 'deploy_records: health is written once';
  END IF;
  IF NEW.health_url IS DISTINCT FROM OLD.health_url AND OLD.health_url IS NOT NULL THEN
    RAISE EXCEPTION 'deploy_records: health_url is written once';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deploy_records_guard ON deploy_records;
CREATE TRIGGER deploy_records_guard BEFORE UPDATE ON deploy_records
  FOR EACH ROW EXECUTE FUNCTION deploy_records_guard();
CREATE OR REPLACE FUNCTION deploy_records_no_delete() RETURNS trigger
  LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'deploy_records rows are not deleted'; END $$;
DROP TRIGGER IF EXISTS deploy_records_no_delete ON deploy_records;
CREATE TRIGGER deploy_records_no_delete BEFORE DELETE ON deploy_records
  FOR EACH ROW EXECUTE FUNCTION deploy_records_no_delete();
`

const recordColumns = `id, plan_id, plan_digest, tenant, service, environment, revision, gitops_sha,
	preview_id, host, approval_id, decided_by_principal_id, applied_by, status,
	COALESCE(workflow, ''), COALESCE(image_digest, ''), COALESCE(argo_revision, ''), health,
	COALESCE(health_url, ''), created_at, updated_at, COALESCE(workflow_ref, ''), COALESCE(run_result, '')`

// NewRecord is the record of an apply about to be submitted: the plan's
// fields, the spent grant and its decider, status submitting, health
// unknown. workflowRef is the name the workflow will be submitted under.
// now is the store's clock.
func NewRecord(p *Plan, approvalID, decidedBy, appliedBy, workflowRef string, now time.Time) *Record {
	now = now.UTC().Truncate(time.Microsecond)
	return &Record{
		ID: RecordIDPrefix + uuid.NewString(), PlanID: p.ID, PlanDigest: p.Digest,
		Tenant: p.Tenant, Service: p.Service, Environment: p.Environment,
		Revision: p.Revision, GitopsSHA: p.GitopsBaseSHA, PreviewID: p.PreviewID, Host: p.Host,
		ApprovalID: approvalID, DecidedByPrincipalID: decidedBy, AppliedBy: appliedBy, WorkflowRef: workflowRef,
		Status: RecordSubmitting, Health: HealthUnknown, CreatedAt: now, UpdatedAt: now,
	}
}

// InsertRecord stores a new record. A plan or grant that already has one
// is ErrRecordExists.
func (s *Store) InsertRecord(ctx context.Context, r *Record) (*Record, error) {
	if r.Status != RecordSubmitting || r.Health != HealthUnknown {
		return nil, errors.New("deployplan: a record starts as submitting with unknown health")
	}
	row := s.pool.QueryRow(ctx, `
INSERT INTO deploy_records (id, plan_id, plan_digest, tenant, service, environment, revision, gitops_sha,
	preview_id, host, approval_id, decided_by_principal_id, applied_by, status, health, created_at, updated_at,
	workflow_ref)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NULLIF($18,''))
ON CONFLICT DO NOTHING
RETURNING `+recordColumns,
		r.ID, r.PlanID, r.PlanDigest, r.Tenant, r.Service, r.Environment, r.Revision, r.GitopsSHA,
		r.PreviewID, r.Host, r.ApprovalID, r.DecidedByPrincipalID, r.AppliedBy, r.Status, r.Health,
		r.CreatedAt, r.UpdatedAt, r.WorkflowRef)
	stored, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRecordExists
	}
	if err != nil {
		return nil, fmt.Errorf("deployplan: insert record: %w", err)
	}
	return stored, nil
}

// SetRecordSubmission moves a submitting record to submitted (with its
// workflow) or submit_failed. A record not in submitting is an error.
func (s *Store) SetRecordSubmission(ctx context.Context, id, status, workflow string) (*Record, error) {
	if status != RecordSubmitted && status != RecordSubmitFailed {
		return nil, fmt.Errorf("deployplan: %q is not a submission outcome", status)
	}
	if (status == RecordSubmitted) != (workflow != "") {
		return nil, errors.New("deployplan: a submitted record names its workflow, a failed one does not")
	}
	var wf *string
	if workflow != "" {
		wf = &workflow
	}
	r, err := scanRecord(s.pool.QueryRow(ctx, `
UPDATE deploy_records SET status = $2, workflow = $3, updated_at = $4
WHERE id = $1 AND status = 'submitting'
RETURNING `+recordColumns, id, status, wf, s.now().Truncate(time.Microsecond)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("deployplan: record %s is not awaiting submission", id)
	}
	if err != nil {
		return nil, fmt.Errorf("deployplan: set submission: %w", err)
	}
	return r, nil
}

// SetRunResult records how a submitted record's workflow ended, and the
// image digest it ran when one was observed (empty leaves it unset). It
// applies once: a record that is not submitted, or already has a result,
// is an error.
func (s *Store) SetRunResult(ctx context.Context, id, result, imageDigest string) (*Record, error) {
	if result != RunSucceeded && result != RunFailed {
		return nil, fmt.Errorf("deployplan: %q is not a run result", result)
	}
	if imageDigest != "" && !digestRE.MatchString(imageDigest) {
		return nil, fmt.Errorf("deployplan: %q is not an image digest", imageDigest)
	}
	r, err := scanRecord(s.pool.QueryRow(ctx, `
UPDATE deploy_records SET run_result = $2, image_digest = COALESCE(image_digest, NULLIF($3, '')), updated_at = $4
WHERE id = $1 AND status = 'submitted' AND run_result IS NULL
RETURNING `+recordColumns, id, result, imageDigest, s.now().Truncate(time.Microsecond)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("deployplan: record %s is not awaiting a run result", id)
	}
	if err != nil {
		return nil, fmt.Errorf("deployplan: set run result: %w", err)
	}
	return r, nil
}

// RecordsToReconcile lists records whose outcome a reconciler can still
// observe: submitting with a known workflow name, or submitted without a
// run result. Only records created after since, ordered by (created_at,
// id) and strictly after the cursor (zero values start from the oldest).
func (s *Store) RecordsToReconcile(ctx context.Context, since, afterCreated time.Time, afterID string, limit int) ([]*Record, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+recordColumns+` FROM deploy_records
WHERE created_at > $1
  AND ((status = 'submitting' AND workflow_ref IS NOT NULL) OR (status = 'submitted' AND run_result IS NULL))
  AND (created_at, id) > ($2, $3)
ORDER BY created_at, id
LIMIT $4`, since, afterCreated, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("deployplan: list records to reconcile: %w", err)
	}
	defer rows.Close()
	var out []*Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("deployplan: list records to reconcile: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deployplan: list records to reconcile: %w", err)
	}
	return out, nil
}

// GetRecord returns the record with that id, or ErrRecordNotFound.
func (s *Store) GetRecord(ctx context.Context, id string) (*Record, error) {
	return s.getRecord(ctx, `SELECT `+recordColumns+` FROM deploy_records WHERE id = $1`, id)
}

// RecordForPlan returns the plan's record, or ErrRecordNotFound.
func (s *Store) RecordForPlan(ctx context.Context, planID string) (*Record, error) {
	return s.getRecord(ctx, `SELECT `+recordColumns+` FROM deploy_records WHERE plan_id = $1`, planID)
}

func (s *Store) getRecord(ctx context.Context, q, arg string) (*Record, error) {
	r, err := scanRecord(s.pool.QueryRow(ctx, q, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRecordNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("deployplan: get record: %w", err)
	}
	return r, nil
}

func scanRecord(row pgx.Row) (*Record, error) {
	var r Record
	if err := row.Scan(&r.ID, &r.PlanID, &r.PlanDigest, &r.Tenant, &r.Service, &r.Environment, &r.Revision,
		&r.GitopsSHA, &r.PreviewID, &r.Host, &r.ApprovalID, &r.DecidedByPrincipalID, &r.AppliedBy, &r.Status,
		&r.Workflow, &r.ImageDigest, &r.ArgoRevision, &r.Health, &r.HealthURL, &r.CreatedAt, &r.UpdatedAt,
		&r.WorkflowRef, &r.RunResult); err != nil {
		return nil, err
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return &r, nil
}
