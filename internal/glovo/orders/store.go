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

// Package orders is the owner-scoped Glovo order index of mctl-api#988 (M1b/1):
// one canonical order row per (tenant, owner, idempotency key), immutable
// basket snapshots, a write-once approval reference and an effect row, all in
// schema glovo of the one shared database and all written on the caller's
// pgx.Tx. It is dark: no route, MCP tool or startup wiring uses it yet, and
// Ready is not_ready until the work-item grants of mctl-api#989 exist.
//
// Lifecycle (the database enforces the same matrix for raw SQL; every write
// also CASes on version and state):
//
//	(new)       -> open        Create (snapshot 1, write-once execution_id)
//	open        -> open        AppendSnapshot
//	open        -> finalized   Finalize
//	finalized   -> finalized   BindApproval (write-once approval_ref)
//	open, finalized -> cancelled   MarkCancelled
//	finalized   -> dispatched  MarkDispatched (writes the effect row)
//	dispatched  -> cancelled | unknown | closed   MarkCancelled, MarkUnknown, MarkClosed
//
// Refusal map (glovo.Code; the wire status comes only from mctl-api#957
// design 4.1): a missing, foreign or malformed order, an execution of another
// tenant or owner -> not_found; no, revoked, expired connection or moved
// install revision -> no_connection, connection_revoked, connection_expired,
// stale_install; invalid basket or malformed input -> invalid_request; a wrong
// expected fingerprint -> fingerprint_changed; a reused key with another hash
// -> idempotency_key_reused; a version or state CAS miss, a write-once column
// already set or a unique violation on orders_execution, orders_approval or
// orders_command -> invalid_transition; lock_timeout -> tenant_busy; any other
// database error or a wrong isolation level -> unavailable; a nil
// collaborator or an unready schema -> not_ready.
//
// Locks: the order row is level L3 of the canonical lock order of mctl-api#957
// design 6b; the caller holds L1 and L2 (the #959 owner advisory key) before
// calling a method that re-reads the connection.
package orders

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Not-ready reasons of this slice.
const (
	NotReadyCollaborator = "collaborator_missing"
	NotReadyRoleMismatch = "runtime_role_mismatch"
	NotReadyVersion      = "orders_schema_version_mismatch"
	NotReadyTable        = "orders_table_missing"
	NotReadyTriggers     = "orders_triggers_mismatch"
	NotReadyOwner        = "orders_object_owner_mismatch"
	NotReadySchema       = "orders_schema_privileges"
	NotReadyWorkItems    = "work_items_select_missing"
	NotReadySequence     = "orders_sequence_privilege"
)

// JoinKind is the kind of an opaque join ref.
type JoinKind string

const (
	JoinTenant          JoinKind = "tenant"
	JoinPrincipal       JoinKind = "principal"
	JoinInstallRevision JoinKind = "install_revision"
)

// ActorKind is the closed set of glovo.order_events.actor_kind.
type ActorKind string

const (
	ActorOwner         ActorKind = "owner"
	ActorControlWorker ActorKind = "control_worker"
	ActorSystem        ActorKind = "system"
)

// Actor is the one source of an event's actor columns.
type Actor struct {
	Kind ActorKind
	ID   string
}

func (a Actor) validate() error {
	switch a.Kind {
	case ActorOwner, ActorControlWorker, ActorSystem:
		if a.ID != "" && len(a.ID) <= 128 {
			return nil
		}
	}
	return glovo.Refuse(glovo.CodeInvalidRequest)
}

// Scope is the owner path scope, from the verified caller.
type Scope struct{ Tenant, PrincipalID string }

func (s Scope) validate() error {
	if s.Tenant == "" || len(s.Tenant) > 253 || len(s.PrincipalID) <= len(glovo.PrincipalPrefix) ||
		s.PrincipalID[:len(glovo.PrincipalPrefix)] != glovo.PrincipalPrefix || len(s.PrincipalID) > 128 {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	return nil
}

// Snapshot is one row of order_snapshots.
type Snapshot struct {
	OrderRef    string
	Seq         int
	LineCount   int
	Fingerprint string
	Canonical   []byte
	CreatedAt   time.Time
}

// Connections is the #959 live connection read on the caller's transaction.
type Connections interface {
	LiveConnectionTx(ctx context.Context, tx pgx.Tx, owner glovo.Owner) (*glovo.Connection, error)
}

// Executions is provided by the #989 work-items store.
type Executions interface {
	ExecutionBindingTx(ctx context.Context, q dbq.Querier, executionID string) (tenant, ownerPrincipalID, workItemID, workflowID string, err error)
}

// Order is one order row. order_id (pord_) stays unexported.
type Order struct {
	orderID                string
	OrderRef               string
	Tenant                 string
	OwnerPrincipalID       string
	ConnectionID           string
	InstallID              string
	InstallRevision        int64
	State                  string
	FinalBasketFingerprint string
	FinalSnapshotSeq       int
	ApprovalRef            string
	CommandID              string
	ExecutionID            string
	IdempotencyKey         string
	RequestHash            string
	Version                int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// Order states.
const (
	StateOpen       = "open"
	StateFinalized  = "finalized"
	StateDispatched = "dispatched"
	StateCancelled  = "cancelled"
	StateUnknown    = "unknown"
	StateClosed     = "closed"
)

var (
	orderRefRE    = regexp.MustCompile(`^ordr_[A-Za-z0-9]{16,40}$`)
	executionIDRE = regexp.MustCompile(`^we_[A-Za-z0-9]{16,40}$`)
	approvalRefRE = regexp.MustCompile(`^aar_[A-Za-z0-9]{16,40}$`)
	commandIDRE   = regexp.MustCompile(`^cmd_[A-Za-z0-9]{26}$`)
	fingerprintRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const (
	base62            = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	maxIdempotencyKey = 200
)

func randAlnum(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < 248 { // 248 = 62*4: no modulo bias
				out = append(out, base62[int(b)%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}

func newID(prefix string) (string, error) {
	s, err := randAlnum(26)
	if err != nil {
		return "", fmt.Errorf("glovo orders: crypto/rand: %w", err)
	}
	return prefix + s, nil
}

// NewOrderRef mints "ordr_" + 26 base62 characters from crypto/rand. It is the
// only minting entry point: #957 calls it before it derives the workflow id.
func NewOrderRef() string {
	s, err := newID("ordr_")
	if err != nil {
		panic("glovo orders: crypto/rand unavailable: " + err.Error())
	}
	return s
}

// Store is the order store. It begins, commits and rolls back nothing on the
// caller's behalf: every write method takes the caller's pgx.Tx.
type Store struct {
	pool                       *pgxpool.Pool
	runtimeRole, migrationRole string
	conns                      Connections
	execs                      Executions
	clock                      func() time.Time
}

// NewStore wraps the shared pool. It runs no DDL and fails closed when the
// recorded schema version is missing or differs from the compiled one. A nil
// collaborator is allowed here and makes every method, and Ready, not_ready.
func NewStore(ctx context.Context, pool *pgxpool.Pool, runtimeRole, migrationRole string, conns Connections, execs Executions) (*Store, error) {
	if pool == nil {
		return nil, errors.New("glovo orders: nil pool")
	}
	if !roleNameRE.MatchString(runtimeRole) || !roleNameRE.MatchString(migrationRole) {
		return nil, errors.New("glovo orders: invalid role name")
	}
	s := &Store{pool: pool, runtimeRole: runtimeRole, migrationRole: migrationRole, conns: conns, execs: execs, clock: time.Now}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("glovo orders: ping: %w", err)
	}
	if err := s.checkVersion(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) now() time.Time { return s.clock().UTC() }

func (s *Store) checkVersion(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT version FROM glovo.orders_schema_version`)
	if err != nil {
		return fmt.Errorf("glovo orders: read schema version (was ApplySchema run?): %w", err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("glovo orders: scan schema version: %w", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("glovo orders: read schema version: %w", err)
	}
	if len(got) != 1 || got[0] != schemaVersion {
		return fmt.Errorf("glovo orders: schema version %v does not match the compiled version %d", got, schemaVersion)
	}
	return nil
}

func (s *Store) ready() error {
	if s == nil || s.pool == nil || s.conns == nil || s.execs == nil {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	return nil
}

func notReady(reason string) error { return &glovo.NotReadyError{Reason: reason} }

func checkFailed(err error) error {
	return &glovo.NotReadyError{Reason: glovo.NotReadyCheckFailed, Cause: err}
}

// Ready reports nil only when this store may be used: both collaborators are
// present; current_user is the runtime role and is not the migration role;
// the schema version matches; every table resolves; pg_trigger equals
// triggerInventory exactly (present, enabled, expected function, owned by the
// migration role, no unlisted trigger); schema glovo, every table of this
// slice and every trigger function is owned by exactly the migration role and
// current_user is not a member of that owner; the runtime role holds exactly
// the registered grants; and it can read the work-item tables the insert guard
// joins. Anything else, including a check that could not run, is not_ready.
func (s *Store) Ready(ctx context.Context) error {
	if s == nil || s.pool == nil || s.conns == nil || s.execs == nil {
		return notReady(NotReadyCollaborator)
	}
	var cur string
	if err := s.pool.QueryRow(ctx, `SELECT current_user::text`).Scan(&cur); err != nil {
		return checkFailed(err)
	}
	if cur != s.runtimeRole || cur == s.migrationRole {
		return notReady(NotReadyRoleMismatch)
	}
	if err := s.checkVersion(ctx); err != nil {
		return &glovo.NotReadyError{Reason: NotReadyVersion, Cause: err}
	}
	for _, t := range orderTables {
		var present bool
		if err := s.pool.QueryRow(ctx, `SELECT to_regclass('glovo.' || $1) IS NOT NULL`, t).Scan(&present); err != nil {
			return checkFailed(err)
		}
		if !present {
			return notReady(NotReadyTable)
		}
	}
	if err := s.checkTriggers(ctx); err != nil {
		return err
	}
	if err := s.checkOwners(ctx); err != nil {
		return err
	}
	var usage, create bool
	if err := s.pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'glovo', 'USAGE'),
  has_schema_privilege(current_user, 'glovo', 'CREATE')`).Scan(&usage, &create); err != nil {
		return checkFailed(err)
	}
	if !usage || create {
		return notReady(NotReadySchema)
	}
	for _, t := range orderTables {
		if err := glovo.VerifyGrants(ctx, s.pool, t); err != nil {
			return err
		}
	}
	var seq bool
	if err := s.pool.QueryRow(ctx, `SELECT has_sequence_privilege(current_user, 'glovo.order_events_id_seq', 'USAGE')`).Scan(&seq); err != nil {
		return checkFailed(err)
	}
	if !seq {
		return notReady(NotReadySequence)
	}
	var items bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('public.work_items') IS NOT NULL
   AND to_regclass('public.work_item_executions') IS NOT NULL
   AND has_table_privilege(current_user, to_regclass('public.work_items')::oid, 'SELECT')
   AND has_table_privilege(current_user, to_regclass('public.work_item_executions')::oid, 'SELECT')`).Scan(&items); err != nil {
		return checkFailed(err)
	}
	if !items {
		return notReady(NotReadyWorkItems)
	}
	return nil
}

func (s *Store) checkTriggers(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
SELECT c.relname::text, t.tgname::text, p.proname::text, t.tgenabled::text, t.tgtype::int,
       pg_get_userbyid(p.proowner)::text, pn.nspname::text
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_namespace pn ON pn.oid = p.pronamespace
 WHERE n.nspname = 'glovo' AND c.relname = ANY($1) AND NOT t.tgisinternal`, orderTables)
	if err != nil {
		return checkFailed(err)
	}
	defer rows.Close()
	want := map[string]triggerSpec{}
	for _, t := range triggerInventory {
		want[t.Table+"/"+t.Name] = t
	}
	seen := 0
	for rows.Next() {
		var table, name, fn, enabled, owner, fnSchema string
		var tgtype int
		if err := rows.Scan(&table, &name, &fn, &enabled, &tgtype, &owner, &fnSchema); err != nil {
			return checkFailed(err)
		}
		spec, ok := want[table+"/"+name]
		if !ok {
			return notReady(NotReadyTriggers) // an unlisted trigger
		}
		if enabled != "O" || fn != spec.Function || fnSchema != "glovo" || tgtype != spec.TgType || owner != s.migrationRole {
			return notReady(NotReadyTriggers)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return checkFailed(err)
	}
	if seen != len(triggerInventory) {
		return notReady(NotReadyTriggers)
	}
	return nil
}

// checkOwners requires schema glovo, every table of this slice and every
// trigger function to be owned by exactly the migration role, and
// current_user not to be a member of that owner (which also covers inherited
// membership).
func (s *Store) checkOwners(ctx context.Context) error {
	var funcs []string
	for _, t := range triggerInventory {
		funcs = append(funcs, t.Function)
	}
	var bad int
	if err := s.pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo'
          AND (pg_get_userbyid(nspowner) <> $1 OR pg_has_role(current_user, nspowner, 'MEMBER')))
     + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'glovo' AND c.relname = ANY($2)
           AND (pg_get_userbyid(c.relowner) <> $1 OR pg_has_role(current_user, c.relowner, 'MEMBER')))
     + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'glovo' AND p.proname = ANY($3)
           AND (pg_get_userbyid(p.proowner) <> $1 OR pg_has_role(current_user, p.proowner, 'MEMBER')))`,
		s.migrationRole, orderTables, funcs).Scan(&bad); err != nil {
		return checkFailed(err)
	}
	if bad != 0 {
		return notReady(NotReadyOwner)
	}
	return nil
}

// refuse maps a database or collaborator error to the refusal map of the
// package comment. A *glovo.Error passes through unchanged.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return ge
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "55P03":
			return glovo.Refuse(glovo.CodeTenantBusy)
		case "23505":
			switch pe.ConstraintName {
			case "orders_execution", "orders_approval", "orders_command":
				return glovo.Refuse(glovo.CodeInvalidTransition)
			case "orders_order_ref_key":
				return glovo.Refuse(glovo.CodeInvalidRequest)
			}
		case "23000", "23514":
			return glovo.Refuse(glovo.CodeInvalidTransition)
		}
	}
	return glovo.Refuse(glovo.CodeUnavailable)
}

var orderColumns = `o.order_id, o.order_ref, o.tenant, o.owner_principal_id, o.connection_id, o.install_id, o.install_revision,
 o.state, o.final_basket_fingerprint, o.final_snapshot_seq, o.approval_ref, o.command_id, o.execution_id,
 o.idempotency_key, o.request_hash, o.version, o.created_at, o.updated_at`

func scanOrder(r pgx.Row) (*Order, error) {
	var o Order
	if err := r.Scan(&o.orderID, &o.OrderRef, &o.Tenant, &o.OwnerPrincipalID, &o.ConnectionID, &o.InstallID, &o.InstallRevision,
		&o.State, &o.FinalBasketFingerprint, &o.FinalSnapshotSeq, &o.ApprovalRef, &o.CommandID, &o.ExecutionID,
		&o.IdempotencyKey, &o.RequestHash, &o.Version, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	return &o, nil
}

// readOrder runs the one statement of every owner-path lookup: a miss, a
// foreign row and a malformed ref are the same statement and the same
// not_found.
func readOrder(ctx context.Context, q dbq.Querier, sc Scope, orderRef string, lock bool) (*Order, error) {
	sql := `SELECT ` + orderColumns + ` FROM glovo.orders o WHERE o.order_ref = $1 AND o.tenant = $2 AND o.owner_principal_id = $3`
	if lock {
		sql += ` FOR UPDATE OF o`
	}
	o, err := scanOrder(q.QueryRow(ctx, sql, orderRef, sc.Tenant, sc.PrincipalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return o, nil
}

func (s *Store) appendEvent(ctx context.Context, q dbq.Querier, tenant, orderRef string, a Actor, event, from, to string, seq int) error {
	_, err := q.Exec(ctx, `INSERT INTO glovo.order_events (tenant, order_ref, actor_kind, actor_id, event, from_state, to_state, snapshot_seq, recorded_at)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, tenant, orderRef, string(a.Kind), a.ID, event, from, to, seq, s.now())
	if err != nil {
		return mapErr(err)
	}
	return nil
}
