package workitems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS work_items (
    id                     TEXT PRIMARY KEY,
    tenant                 TEXT NOT NULL,
    owner_principal        TEXT NOT NULL,
    visibility             TEXT NOT NULL,
    origin_surface         TEXT NOT NULL,
    title                  TEXT NOT NULL,
    external_key           TEXT NOT NULL DEFAULT '',
    state                  TEXT NOT NULL,
    waiting_reason         TEXT NOT NULL DEFAULT '',
    superseded_by          TEXT NOT NULL DEFAULT '',
    state_version          BIGINT NOT NULL,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    completed_at           TIMESTAMPTZ,
    schema_version         TEXT NOT NULL,
    create_idempotency_key TEXT,
    create_request_hash    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS work_items_tenant_idempotency
    ON work_items (tenant, create_idempotency_key)
    WHERE create_idempotency_key IS NOT NULL;
-- Open-work dedupe: one non-terminal item per (tenant, external_key), the
-- same shape as alerts_tenant_fingerprint_open.
CREATE UNIQUE INDEX IF NOT EXISTS work_items_tenant_external_key_open
    ON work_items (tenant, external_key)
    WHERE external_key <> '' AND state IN ('active', 'waiting');
CREATE INDEX IF NOT EXISTS work_items_tenant_state
    ON work_items (tenant, state, updated_at DESC);

CREATE TABLE IF NOT EXISTS work_item_events (
    work_item_id    TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    seq             BIGINT NOT NULL,
    kind            TEXT NOT NULL,
    from_state      TEXT NOT NULL DEFAULT '',
    to_state        TEXT NOT NULL DEFAULT '',
    actor_principal TEXT NOT NULL,
    surface         TEXT NOT NULL DEFAULT '',
    request_id      TEXT NOT NULL DEFAULT '',
    detail          JSONB,
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (work_item_id, seq)
);

-- text is nullable so a retention sweep can drop it and keep the row.
CREATE TABLE IF NOT EXISTS work_item_intents (
    id              BIGSERIAL PRIMARY KEY,
    work_item_id    TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    actor_principal TEXT NOT NULL,
    surface         TEXT NOT NULL DEFAULT '',
    text            TEXT,
    params          JSONB,
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS work_item_intents_item ON work_item_intents (work_item_id, id);

CREATE TABLE IF NOT EXISTS work_item_executions (
    id                        TEXT PRIMARY KEY,
    work_item_id              TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    engine                    TEXT NOT NULL,
    engine_ref                TEXT NOT NULL,
    attempt                   INTEGER NOT NULL,
    resumed_from_execution_id TEXT NOT NULL DEFAULT '',
    phase                     TEXT NOT NULL,
    started_at                TIMESTAMPTZ NOT NULL,
    ended_at                  TIMESTAMPTZ,
    UNIQUE (work_item_id, engine, engine_ref),
    UNIQUE (work_item_id, attempt)
);
-- At most one non-terminal execution per work item.
CREATE UNIQUE INDEX IF NOT EXISTS work_item_executions_one_open
    ON work_item_executions (work_item_id)
    WHERE phase IN ('Pending', 'Running');

CREATE TABLE IF NOT EXISTS work_item_surface_refs (
    work_item_id      TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    surface           TEXT NOT NULL,
    external_id       TEXT NOT NULL,
    actor_external_id TEXT NOT NULL DEFAULT '',
    first_seen_at     TIMESTAMPTZ NOT NULL,
    last_seen_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (work_item_id, surface, external_id)
);

-- Per-item idempotency for every mutation other than create.
CREATE TABLE IF NOT EXISTS work_item_requests (
    work_item_id    TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    operation       TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    result_id       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (work_item_id, idempotency_key)
);
`

const itemColumns = `id, tenant, owner_principal, visibility, origin_surface, title, external_key,
	state, waiting_reason, superseded_by, state_version, created_by, created_at, updated_at,
	completed_at, schema_version`

const executionColumns = `id, work_item_id, engine, engine_ref, attempt, resumed_from_execution_id,
	phase, started_at, ended_at`

// Operations recorded in work_item_requests.
const (
	opTransition = "transition"
	opResume     = "resume"
	opIntent     = "intent"
	opExecution  = "execution"
)

// Store is the Postgres-backed work-item store. Every mutation of one item
// runs in one transaction under pg_advisory_xact_lock(hashtext('workitem:' ||
// id)), the agentregistry.promote pattern, so two surfaces racing on the same
// item resolve to one effect and one idempotent replay or 409.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewStore connects and creates the schema if needed.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("workitems: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("workitems: create schema: %w", err)
	}
	slog.Info("work-items store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func (s *Store) withTx(ctx context.Context, lockKey string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("workitems: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("workitems: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("workitems: commit: %w", err)
	}
	return nil
}

func scanItem(row pgx.Row) (*WorkItem, error) {
	var w WorkItem
	if err := row.Scan(&w.ID, &w.Tenant, &w.OwnerPrincipal, &w.Visibility, &w.OriginSurface, &w.Title,
		&w.ExternalKey, &w.State, &w.WaitingReason, &w.SupersededBy, &w.StateVersion, &w.CreatedBy,
		&w.CreatedAt, &w.UpdatedAt, &w.CompletedAt, &w.SchemaVersion); err != nil {
		return nil, err
	}
	w.CreatedAt = w.CreatedAt.UTC()
	w.UpdatedAt = w.UpdatedAt.UTC()
	if w.CompletedAt != nil {
		t := w.CompletedAt.UTC()
		w.CompletedAt = &t
	}
	return &w, nil
}

func scanExecution(row pgx.Row) (*Execution, error) {
	var e Execution
	if err := row.Scan(&e.ID, &e.WorkItemID, &e.Engine, &e.EngineRef, &e.Attempt,
		&e.ResumedFromExecutionID, &e.Phase, &e.StartedAt, &e.EndedAt); err != nil {
		return nil, err
	}
	e.StartedAt = e.StartedAt.UTC()
	if e.EndedAt != nil {
		t := e.EndedAt.UTC()
		e.EndedAt = &t
	}
	return &e, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getItem(ctx context.Context, q querier, id string) (*WorkItem, error) {
	w, err := scanItem(q.QueryRow(ctx, `SELECT `+itemColumns+` FROM work_items WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: get: %w", err)
	}
	return w, nil
}

// Get returns one work item or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*WorkItem, error) {
	return getItem(ctx, s.pool, id)
}

// Create opens a work item, or returns the one this request already opened
// (same tenant and idempotency key) or the open one already carrying its
// external_key. created is false on either replay.
func (s *Store) Create(ctx context.Context, in CreateInput) (*WorkItem, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *WorkItem
	created := false
	err := s.withTx(ctx, "workitem-create:"+in.Tenant, func(tx pgx.Tx) error {
		if in.IdempotencyKey != "" {
			var id, hash string
			err := tx.QueryRow(ctx, `SELECT id, create_request_hash FROM work_items
				WHERE tenant=$1 AND create_idempotency_key=$2`, in.Tenant, in.IdempotencyKey).Scan(&id, &hash)
			if err == nil {
				if hash != in.RequestHash {
					return ErrIdempotencyKeyReuse
				}
				w, err := getItem(ctx, tx, id)
				out = w
				return err
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("workitems: create: idempotency lookup: %w", err)
			}
		}
		if in.ExternalKey != "" {
			w, err := scanItem(tx.QueryRow(ctx, `SELECT `+itemColumns+` FROM work_items
				WHERE tenant=$1 AND external_key=$2 AND state IN ('active','waiting')`, in.Tenant, in.ExternalKey))
			if err == nil {
				out = w
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("workitems: create: external key lookup: %w", err)
			}
		}

		now := s.now()
		var key, hash *string
		if in.IdempotencyKey != "" {
			key, hash = &in.IdempotencyKey, &in.RequestHash
		}
		w, err := scanItem(tx.QueryRow(ctx, `INSERT INTO work_items (`+itemColumns+`,
				create_idempotency_key, create_request_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'`+StateActive+`','','',1,$3,$8,$8,NULL,$9,$10,$11)
			RETURNING `+itemColumns,
			WorkItemIDPrefix+uuid.NewString(), in.Tenant, in.Actor, in.Visibility, in.OriginSurface,
			in.Title, in.ExternalKey, now, SchemaVersion, key, hash))
		if err != nil {
			return fmt.Errorf("workitems: create: %w", err)
		}
		if err := appendEvent(ctx, tx, w.ID, EventCreated, "", StateActive, in.Mutation, nil, now); err != nil {
			return err
		}
		out, created = w, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

func appendEvent(ctx context.Context, tx pgx.Tx, id, kind, from, to string, m Mutation, detail any, at time.Time) error {
	var raw []byte
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("workitems: event detail: %w", err)
		}
		raw = b
	}
	_, err := tx.Exec(ctx, `INSERT INTO work_item_events
		(work_item_id, seq, kind, from_state, to_state, actor_principal, surface, request_id, detail, created_at)
		VALUES ($1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM work_item_events WHERE work_item_id=$1),
		        $2,$3,$4,$5,$6,$7,$8,$9)`,
		id, kind, from, to, m.Actor, m.Surface, m.RequestID, raw, at)
	if err != nil {
		return fmt.Errorf("workitems: append event: %w", err)
	}
	return nil
}

// replayed looks up a per-item idempotency key. It returns the recorded
// result id and true on a replay of the same request, ErrIdempotencyKeyReuse
// when the key was used for something else, and false when the key is new.
func replayed(ctx context.Context, tx pgx.Tx, id, op string, m Mutation) (string, bool, error) {
	if m.IdempotencyKey == "" {
		return "", false, nil
	}
	var gotOp, hash, result string
	err := tx.QueryRow(ctx, `SELECT operation, request_hash, result_id FROM work_item_requests
		WHERE work_item_id=$1 AND idempotency_key=$2`, id, m.IdempotencyKey).Scan(&gotOp, &hash, &result)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("workitems: idempotency lookup: %w", err)
	}
	if gotOp != op || hash != m.RequestHash {
		return "", false, ErrIdempotencyKeyReuse
	}
	return result, true, nil
}

func remember(ctx context.Context, tx pgx.Tx, id, op, result string, m Mutation, at time.Time) error {
	if m.IdempotencyKey == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO work_item_requests
		(work_item_id, idempotency_key, operation, request_hash, result_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, m.IdempotencyKey, op, m.RequestHash, result, at)
	if err != nil {
		return fmt.Errorf("workitems: record idempotency key: %w", err)
	}
	return nil
}

func lockedItem(ctx context.Context, tx pgx.Tx, id string) (*WorkItem, error) {
	return getItem(ctx, tx, id)
}

// Transition applies one lifecycle action. A replay of the same request
// returns the item as it is now.
func (s *Store) Transition(ctx context.Context, in TransitionInput) (*WorkItem, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var out *WorkItem
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := lockedItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		if _, ok, err := replayed(ctx, tx, cur.ID, opTransition, in.Mutation); err != nil || ok {
			out = cur
			return err
		}
		if cur.StateVersion != in.ExpectedStateVersion {
			return &ConflictError{Err: ErrVersionConflict, Current: cur}
		}
		to, err := Next(cur.State, in.Action)
		if err != nil {
			return &ConflictError{Err: err, Current: cur}
		}
		if in.Action == ActionSupersede {
			next, err := getItem(ctx, tx, in.SupersededBy)
			if errors.Is(err, ErrNotFound) || (err == nil && next.Tenant != cur.Tenant) {
				return invalid("superseded_by %s is not a work item in tenant %s", in.SupersededBy, cur.Tenant)
			}
			if err != nil {
				return err
			}
		}
		now := s.now()
		var completedAt *time.Time
		if IsTerminal(to) {
			completedAt = &now
		}
		// The version guard repeats the check above in SQL: it holds even
		// if a caller ever reaches this without the advisory lock.
		w, err := scanItem(tx.QueryRow(ctx, `UPDATE work_items SET state=$2, waiting_reason=$3,
				superseded_by=$4, state_version=state_version+1, updated_at=$5, completed_at=$6
			WHERE id=$1 AND state_version=$7 RETURNING `+itemColumns,
			cur.ID, to, in.WaitingReason, in.SupersededBy, now, completedAt, cur.StateVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return &ConflictError{Err: ErrVersionConflict, Current: cur}
		}
		if err != nil {
			return fmt.Errorf("workitems: transition: %w", err)
		}
		detail := map[string]string{"action": in.Action}
		if in.WaitingReason != "" {
			detail["waiting_reason"] = in.WaitingReason
		}
		if in.SupersededBy != "" {
			detail["superseded_by"] = in.SupersededBy
		}
		if err := appendEvent(ctx, tx, cur.ID, EventStateChanged, cur.State, to, in.Mutation, detail, now); err != nil {
			return err
		}
		if err := remember(ctx, tx, cur.ID, opTransition, "", in.Mutation, now); err != nil {
			return err
		}
		out = w
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Resume starts a new execution continuing a prior one. It refuses while an
// execution is still Pending or Running, and on a terminal item. A replay
// returns the execution the first request started.
func (s *Store) Resume(ctx context.Context, in ResumeInput) (*WorkItem, *Execution, bool, error) {
	if err := in.validate(); err != nil {
		return nil, nil, false, err
	}
	var item *WorkItem
	var exec *Execution
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := lockedItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		if result, ok, err := replayed(ctx, tx, cur.ID, opResume, in.Mutation); err != nil {
			return err
		} else if ok {
			item = cur
			exec, err = getExecution(ctx, tx, cur.ID, result)
			return err
		}
		if cur.StateVersion != in.ExpectedStateVersion {
			return &ConflictError{Err: ErrVersionConflict, Current: cur}
		}
		if IsTerminal(cur.State) {
			return &ConflictError{Err: fmt.Errorf("%w: resume from %s", ErrInvalidTransition, cur.State), Current: cur}
		}
		execs, err := listExecutions(ctx, tx, cur.ID)
		if err != nil {
			return err
		}
		from := in.ResumedFromExecutionID
		for i := range execs {
			if !IsTerminalPhase(execs[i].Phase) {
				return &ConflictError{Err: ErrExecutionActive, Current: cur}
			}
		}
		if from == "" && len(execs) > 0 {
			from = execs[len(execs)-1].ID
		}
		if from != "" && !containsExecution(execs, from) {
			return invalid("resumed_from_execution_id %s is not an execution of %s", from, cur.ID)
		}
		now := s.now()
		exec, err = insertExecution(ctx, tx, cur.ID, in.Engine, in.EngineRef, PhasePending, from, len(execs)+1, now)
		if err != nil {
			return err
		}
		to := cur.State
		if cur.State == StateWaiting {
			if to, err = Next(cur.State, ActionResume); err != nil {
				return &ConflictError{Err: err, Current: cur}
			}
		}
		item, err = scanItem(tx.QueryRow(ctx, `UPDATE work_items SET state=$2, waiting_reason='',
				state_version=state_version+1, updated_at=$3
			WHERE id=$1 AND state_version=$4 RETURNING `+itemColumns, cur.ID, to, now, cur.StateVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return &ConflictError{Err: ErrVersionConflict, Current: cur}
		}
		if err != nil {
			return fmt.Errorf("workitems: resume: %w", err)
		}
		detail := map[string]string{"execution_id": exec.ID}
		if from != "" {
			detail["resumed_from_execution_id"] = from
		}
		if err := appendEvent(ctx, tx, cur.ID, EventResumed, cur.State, to, in.Mutation, detail, now); err != nil {
			return err
		}
		if err := remember(ctx, tx, cur.ID, opResume, exec.ID, in.Mutation, now); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}
	return item, exec, created, nil
}

func containsExecution(execs []Execution, id string) bool {
	for i := range execs {
		if execs[i].ID == id {
			return true
		}
	}
	return false
}

func insertExecution(ctx context.Context, tx pgx.Tx, itemID, engine, ref, phase, from string, attempt int, now time.Time) (*Execution, error) {
	var ended *time.Time
	if IsTerminalPhase(phase) {
		ended = &now
	}
	e, err := scanExecution(tx.QueryRow(ctx, `INSERT INTO work_item_executions (`+executionColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+executionColumns,
		ExecutionIDPrefix+uuid.NewString(), itemID, engine, ref, attempt, from, phase, now, ended))
	if err != nil {
		return nil, fmt.Errorf("workitems: insert execution: %w", err)
	}
	return e, nil
}

func getExecution(ctx context.Context, q querier, itemID, id string) (*Execution, error) {
	e, err := scanExecution(q.QueryRow(ctx, `SELECT `+executionColumns+` FROM work_item_executions
		WHERE work_item_id=$1 AND id=$2`, itemID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: execution %s of %s: %w", id, itemID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: get execution: %w", err)
	}
	return e, nil
}

type rowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func listExecutions(ctx context.Context, q rowsQuerier, itemID string) ([]Execution, error) {
	rows, err := q.Query(ctx, `SELECT `+executionColumns+` FROM work_item_executions
		WHERE work_item_id=$1 ORDER BY attempt`, itemID)
	if err != nil {
		return nil, fmt.Errorf("workitems: list executions: %w", err)
	}
	defer rows.Close()
	out := []Execution{}
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: list executions: %w", err)
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// Executions lists a work item's executions, oldest attempt first.
func (s *Store) Executions(ctx context.Context, itemID string) ([]Execution, error) {
	return listExecutions(ctx, s.pool, itemID)
}

// AttachExecution correlates an engine run with a non-terminal work item,
// or records a later phase of one already attached under the same
// (engine, engine_ref). A finished execution's phase never changes.
func (s *Store) AttachExecution(ctx context.Context, in ExecutionInput) (*Execution, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *Execution
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := lockedItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		if result, ok, err := replayed(ctx, tx, cur.ID, opExecution, in.Mutation); err != nil {
			return err
		} else if ok {
			out, err = getExecution(ctx, tx, cur.ID, result)
			return err
		}
		now := s.now()
		existing, err := scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM work_item_executions
			WHERE work_item_id=$1 AND engine=$2 AND engine_ref=$3`, cur.ID, in.Engine, in.EngineRef))
		switch {
		case err == nil:
			if existing.Phase != in.Phase {
				if IsTerminalPhase(existing.Phase) {
					return &ConflictError{
						Err:     fmt.Errorf("%w: execution %s already ended %s", ErrInvalidTransition, existing.ID, existing.Phase),
						Current: cur,
					}
				}
				var ended *time.Time
				if IsTerminalPhase(in.Phase) {
					ended = &now
				}
				existing, err = scanExecution(tx.QueryRow(ctx, `UPDATE work_item_executions SET phase=$2, ended_at=$3
					WHERE id=$1 RETURNING `+executionColumns, existing.ID, in.Phase, ended))
				if err != nil {
					return fmt.Errorf("workitems: update execution: %w", err)
				}
			}
			out = existing
		case errors.Is(err, pgx.ErrNoRows):
			if IsTerminal(cur.State) {
				return &ConflictError{Err: fmt.Errorf("%w: attach to %s", ErrInvalidTransition, cur.State), Current: cur}
			}
			execs, err := listExecutions(ctx, tx, cur.ID)
			if err != nil {
				return err
			}
			if !IsTerminalPhase(in.Phase) {
				for i := range execs {
					if !IsTerminalPhase(execs[i].Phase) {
						return &ConflictError{Err: ErrExecutionActive, Current: cur}
					}
				}
			}
			out, err = insertExecution(ctx, tx, cur.ID, in.Engine, in.EngineRef, in.Phase, "", len(execs)+1, now)
			if err != nil {
				return err
			}
			detail := map[string]string{"execution_id": out.ID, "engine": in.Engine, "engine_ref": in.EngineRef}
			if err := appendEvent(ctx, tx, cur.ID, EventExecutionAttached, "", "", in.Mutation, detail, now); err != nil {
				return err
			}
			created = true
		default:
			return fmt.Errorf("workitems: find execution: %w", err)
		}
		return remember(ctx, tx, cur.ID, opExecution, out.ID, in.Mutation, now)
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// AppendIntent records a bounded intent on a non-terminal work item.
func (s *Store) AppendIntent(ctx context.Context, in IntentInput) (*Intent, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *Intent
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := lockedItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		if result, ok, err := replayed(ctx, tx, cur.ID, opIntent, in.Mutation); err != nil {
			return err
		} else if ok {
			out, err = getIntent(ctx, tx, cur.ID, result)
			return err
		}
		if IsTerminal(cur.State) {
			return &ConflictError{Err: fmt.Errorf("%w: intent on %s", ErrInvalidTransition, cur.State), Current: cur}
		}
		now := s.now()
		var params []byte
		if len(in.Params) > 0 {
			params = in.Params
		}
		var intent Intent
		var text *string
		err = tx.QueryRow(ctx, `INSERT INTO work_item_intents
			(work_item_id, actor_principal, surface, text, params, created_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			RETURNING id, work_item_id, actor_principal, surface, text, params, created_at`,
			cur.ID, in.Actor, in.Surface, in.Text, params, now).Scan(
			&intent.ID, &intent.WorkItemID, &intent.ActorPrincipal, &intent.Surface, &text, &intent.Params, &intent.CreatedAt)
		if err != nil {
			return fmt.Errorf("workitems: append intent: %w", err)
		}
		if text != nil {
			intent.Text = *text
		}
		intent.CreatedAt = intent.CreatedAt.UTC()
		// The event names the intent; it never copies the text.
		if err := appendEvent(ctx, tx, cur.ID, EventIntentAppended, "", "", in.Mutation,
			map[string]int64{"intent_id": intent.ID}, now); err != nil {
			return err
		}
		if err := remember(ctx, tx, cur.ID, opIntent, fmt.Sprint(intent.ID), in.Mutation, now); err != nil {
			return err
		}
		out, created = &intent, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

func getIntent(ctx context.Context, q querier, itemID, id string) (*Intent, error) {
	var intent Intent
	var text *string
	err := q.QueryRow(ctx, `SELECT id, work_item_id, actor_principal, surface, text, params, created_at
		FROM work_item_intents WHERE work_item_id=$1 AND id::text=$2`, itemID, id).Scan(
		&intent.ID, &intent.WorkItemID, &intent.ActorPrincipal, &intent.Surface, &text, &intent.Params, &intent.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: intent %s of %s: %w", id, itemID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: get intent: %w", err)
	}
	if text != nil {
		intent.Text = *text
	}
	intent.CreatedAt = intent.CreatedAt.UTC()
	return &intent, nil
}

// LinkSurface correlates a surface-native conversation with a work item, or
// refreshes last_seen_at on an existing correlation.
func (s *Store) LinkSurface(ctx context.Context, in SurfaceRefInput) (*SurfaceRef, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out SurfaceRef
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := lockedItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		now := s.now()
		var inserted bool
		err = tx.QueryRow(ctx, `INSERT INTO work_item_surface_refs
			(work_item_id, surface, external_id, actor_external_id, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$5)
			ON CONFLICT (work_item_id, surface, external_id) DO UPDATE SET
			    last_seen_at=EXCLUDED.last_seen_at,
			    actor_external_id=CASE WHEN EXCLUDED.actor_external_id <> '' THEN EXCLUDED.actor_external_id
			                           ELSE work_item_surface_refs.actor_external_id END
			RETURNING work_item_id, surface, external_id, actor_external_id, first_seen_at, last_seen_at, (xmax = 0)`,
			cur.ID, in.Surface, in.ExternalID, in.ActorExternalID, now).Scan(
			&out.WorkItemID, &out.Surface, &out.ExternalID, &out.ActorExternalID, &out.FirstSeenAt, &out.LastSeenAt, &inserted)
		if err != nil {
			return fmt.Errorf("workitems: link surface: %w", err)
		}
		out.FirstSeenAt, out.LastSeenAt = out.FirstSeenAt.UTC(), out.LastSeenAt.UTC()
		if inserted {
			// Correlation metadata only: the event names the surface, never
			// the external ids (contract "Retention and privacy").
			if err := appendEvent(ctx, tx, cur.ID, EventSurfaceLinked, "", "", in.Mutation, nil, now); err != nil {
				return err
			}
			created = true
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &out, created, nil
}

// Events returns a work item's lifecycle history in order.
func (s *Store) Events(ctx context.Context, itemID string) ([]Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT work_item_id, seq, kind, from_state, to_state, actor_principal,
			surface, request_id, detail, created_at
		FROM work_item_events WHERE work_item_id=$1 ORDER BY seq`, itemID)
	if err != nil {
		return nil, fmt.Errorf("workitems: events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.WorkItemID, &e.Seq, &e.Kind, &e.FromState, &e.ToState, &e.ActorPrincipal,
			&e.Surface, &e.RequestID, &e.Detail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("workitems: events: %w", err)
		}
		e.CreatedAt = e.CreatedAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// List returns work items matching f, most recently updated first.
func (s *Store) List(ctx context.Context, f ListFilter) ([]WorkItem, error) {
	state := f.State
	if state == "" {
		state = FilterOpen
	}
	if state != FilterOpen && !validState(state) {
		return nil, invalid("unknown state filter %q", state)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	query := `SELECT ` + itemColumns + ` FROM work_items WHERE TRUE`
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.Tenants != nil {
		query += ` AND tenant = ANY(` + arg(f.Tenants) + `)`
	}
	if state == FilterOpen {
		query += ` AND state IN ('active','waiting')`
	} else {
		query += ` AND state = ` + arg(state)
	}
	if f.Owner != "" {
		query += ` AND owner_principal = ` + arg(f.Owner)
	}
	if f.Viewer != "" {
		query += ` AND (visibility = 'tenant' OR owner_principal = ` + arg(f.Viewer) + `)`
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ` + arg(limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("workitems: list: %w", err)
	}
	defer rows.Close()
	out := []WorkItem{}
	for rows.Next() {
		w, err := scanItem(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: list: %w", err)
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}
