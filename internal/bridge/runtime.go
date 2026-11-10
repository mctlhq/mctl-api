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

package bridge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// The role model of mctl-api#957 design 6d.1 for the bridge tables. The
// migration role (glovo_migrator) owns every bridge table and applies all DDL
// and every grant through ApplySchema; the runtime role (glovo_runtime) only
// holds the DML listed in RuntimeGrants and opens the store through
// NewRuntimeStore, which runs no DDL. NewStore keeps its old behaviour for a
// deployment that never ran ApplySchema.

// RuntimeSchemaVersion is the version ApplySchema records in
// bridge_schema_version and NewRuntimeStore requires.
const RuntimeSchemaVersion = 1

// Reasons NewRuntimeStore and VerifyRuntimeGrants report; every one is a
// not_ready (glovo.NotReadyError).
const (
	NotReadySchemaMissing  = "bridge_schema_missing"
	NotReadySchemaVersion  = "bridge_schema_version_mismatch"
	NotReadyReadLevel      = "bridge_read_level"
	NotReadyBridgeGrants   = "bridge_grants_mismatch"
	NotReadyBridgeCheckSQL = "bridge_check_failed"
)

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// runtimeSchema is the DDL this slice adds to bridgeSchema (design 4,
// Platform impact): the backstop for "one place_order_fake row per aar_", the
// colocation probe table and the single-row mode selector.
const runtimeSchema = `
CREATE UNIQUE INDEX IF NOT EXISTS bridge_commands_mutating_approval
    ON bridge_commands (approval_ref) WHERE operation_kind = 'place_order_fake';
CREATE TABLE IF NOT EXISTS bridge_colocation_probe (
    nonce      TEXT        PRIMARY KEY CHECK (nonce ~ '^[0-9a-f]{32}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS bridge_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version   INT     NOT NULL CHECK (version >= 1)
);
`

// bridgeSequence is the only sequence of the bridge tables (BIGSERIAL id of
// bridge_command_transitions).
const bridgeSequence = "bridge_command_transitions_id_seq"

// ownedRelations are the relations ApplySchema refuses to touch when another
// role owns them.
var ownedRelations = []string{
	"bridge_commands", "bridge_command_transitions", "bridge_signal_outbox", "bridge_write_permits",
	"bridge_colocation_probe", "bridge_schema_version", "bridge_read_results", "bridge_read_schema_version",
	bridgeSequence,
}

// TableGrant is one row of the runtime role's grant table for a bridge table:
// table-level privileges and a column-level UPDATE list (exclusive with a
// table-level UPDATE).
type TableGrant struct {
	Table         string
	Privileges    []string
	UpdateColumns []string
}

// RuntimeGrants is the bridge part of the one grant table of mctl-api#957
// design 6d.1 for glovo_runtime. Every right not listed is absent. The two
// bridge_read_* rows are created and granted by ApplyReadSchemaTx (#986) and
// are listed here so that the proof compares the whole table.
func RuntimeGrants() []TableGrant {
	return []TableGrant{
		{Table: "bridge_commands", Privileges: []string{"SELECT", "INSERT", "UPDATE"}},
		{Table: "bridge_signal_outbox", Privileges: []string{"SELECT", "INSERT", "UPDATE"}},
		{Table: "bridge_command_transitions", Privileges: []string{"SELECT", "INSERT"}},
		{Table: "bridge_write_permits", Privileges: []string{"SELECT", "INSERT"}},
		{Table: "bridge_read_results", Privileges: []string{"SELECT", "INSERT", "DELETE"}, UpdateColumns: []string{"data", "erased_at"}},
		{Table: "bridge_colocation_probe", Privileges: []string{"SELECT", "INSERT", "DELETE"}},
		{Table: "bridge_schema_version", Privileges: []string{"SELECT"}},
		{Table: "bridge_read_schema_version", Privileges: []string{"SELECT"}},
	}
}

func (g TableGrant) row() glovo.GrantRow {
	return glovo.GrantRow{Table: g.Table, Privileges: g.Privileges, UpdateColumns: g.UpdateColumns}
}

// SchemaOption adds a grant to an "existing consumer" role (design 6d.1, R3).
type SchemaOption func(*schemaOpts)

type schemaOpts struct{ workItemsRole, maintenanceRole string }

// WithWorkItemsRole names the work-items role, which receives SELECT on
// bridge_colocation_probe so the one-database proof can read the nonce.
func WithWorkItemsRole(role string) SchemaOption {
	return func(o *schemaOpts) { o.workItemsRole = role }
}

// WithMaintenanceRole names the bridge maintenance role (cmd/bridge-scrub),
// which receives SELECT and UPDATE (result) on bridge_commands.
func WithMaintenanceRole(role string) SchemaOption {
	return func(o *schemaOpts) { o.maintenanceRole = role }
}

// ApplySchema is the one place the bridge DDL runs when the roles are split
// (mctl-api#985 design 4). It runs under the migration role, which becomes the
// owner of every bridge object, in one transaction under the schema advisory
// locks: bridgeSchema, #986's read objects (ApplyReadSchemaTx), the backstop
// unique index, the colocation probe table, the grants of RuntimeGrants and,
// last, the bridge_schema_version row that selects NewRuntimeStore. It is safe
// to run twice. It refuses, naming them and changing nothing, a bridge table
// that another role owns (a bridge created earlier by NewStore: the ownership
// transfer is an operator step, OPEN-957-6), a recorded version above the
// compiled one, and a runtime role that does not exist.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string, opts ...SchemaOption) error {
	if !roleNameRE.MatchString(runtimeRole) {
		return errors.New("bridge: invalid runtime role name")
	}
	var so schemaOpts
	for _, o := range opts {
		o(&so)
	}
	for _, r := range []string{so.workItemsRole, so.maintenanceRole} {
		if r != "" && !roleNameRE.MatchString(r) {
			return errors.New("bridge: invalid role name")
		}
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("bridge: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("bridge: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The Glovo slices lock "glovo-schema" for every DDL pass; the bridge adds
	// its own key.
	for _, key := range []string{"bridge-schema", "glovo-schema"} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return fmt.Errorf("bridge: schema lock: %w", err)
		}
	}
	if err := checkBridgeOwnership(ctx, tx); err != nil {
		return err
	}
	for _, r := range []string{runtimeRole, so.workItemsRole, so.maintenanceRole} {
		if r == "" {
			continue
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, r).Scan(&ok); err != nil {
			return fmt.Errorf("bridge: role probe: %w", err)
		}
		if !ok {
			return fmt.Errorf("bridge: role %q does not exist", r)
		}
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('bridge_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("bridge: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM bridge_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("bridge: read schema version: %w", err)
		}
		if recorded != nil && *recorded > RuntimeSchemaVersion {
			return fmt.Errorf("bridge: recorded schema version %d is above the compiled version %d", *recorded, RuntimeSchemaVersion)
		}
	}
	if _, err := tx.Exec(ctx, bridgeSchema); err != nil {
		return fmt.Errorf("bridge: apply schema: %w", err)
	}
	if err := ApplyReadSchemaTx(ctx, tx, runtimeRole); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, runtimeSchema); err != nil {
		return fmt.Errorf("bridge: apply runtime schema: %w", err)
	}
	if err := grantRuntime(ctx, tx, runtimeRole); err != nil {
		return err
	}
	if so.workItemsRole != "" {
		role := pgx.Identifier{so.workItemsRole}.Sanitize()
		for _, s := range []string{`REVOKE ALL ON TABLE bridge_colocation_probe FROM ` + role, `GRANT SELECT ON TABLE bridge_colocation_probe TO ` + role} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("bridge: grant to the work-items role: %w", err)
			}
		}
	}
	if so.maintenanceRole != "" {
		role := pgx.Identifier{so.maintenanceRole}.Sanitize()
		for _, s := range []string{`REVOKE ALL ON TABLE bridge_commands FROM ` + role, `GRANT SELECT ON TABLE bridge_commands TO ` + role,
			`GRANT UPDATE (result) ON TABLE bridge_commands TO ` + role} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("bridge: grant to the maintenance role: %w", err)
			}
		}
	}
	// The version row is the mode selector and is written last: a half-applied
	// schema never selects NewRuntimeStore.
	if _, err := tx.Exec(ctx, `DELETE FROM bridge_schema_version`); err != nil {
		return fmt.Errorf("bridge: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bridge_schema_version (version) VALUES ($1)`, RuntimeSchemaVersion); err != nil {
		return fmt.Errorf("bridge: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("bridge: commit schema: %w", err)
	}
	return nil
}

// checkBridgeOwnership refuses a bridge relation that current_user (the
// migration role) does not own, naming every one.
func checkBridgeOwnership(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = ANY($1) AND c.relkind IN ('r', 'S')
		  AND pg_get_userbyid(c.relowner) <> current_user ORDER BY c.relname`, ownedRelations)
	if err != nil {
		return fmt.Errorf("bridge: ownership check: %w", err)
	}
	defer rows.Close()
	var bad []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return fmt.Errorf("bridge: ownership check: %w", err)
		}
		bad = append(bad, n)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("bridge: ownership check: %w", err)
	}
	if len(bad) > 0 {
		return fmt.Errorf("bridge: %s not owned by the migration role (created earlier by another role; the ownership transfer is an operator step)", strings.Join(bad, ", "))
	}
	return nil
}

// grantRuntime resets and re-applies the runtime role's rights on the tables
// ApplySchema owns the grants of, so a drifted extra right is removed. The
// bridge_read_* rows are granted by ApplyReadSchemaTx.
func grantRuntime(ctx context.Context, tx pgx.Tx, runtimeRole string) error {
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, g := range RuntimeGrants() {
		if strings.HasPrefix(g.Table, "bridge_read_") {
			continue
		}
		tbl := pgx.Identifier{g.Table}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
			return fmt.Errorf("bridge: revoke on %s: %w", g.Table, err)
		}
		if len(g.Privileges) > 0 {
			if _, err := tx.Exec(ctx, `GRANT `+strings.Join(g.Privileges, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("bridge: grant on %s: %w", g.Table, err)
			}
		}
	}
	seq := pgx.Identifier{bridgeSequence}.Sanitize()
	if _, err := tx.Exec(ctx, `REVOKE ALL ON SEQUENCE `+seq+` FROM `+role); err != nil {
		return fmt.Errorf("bridge: revoke on the transition sequence: %w", err)
	}
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SEQUENCE `+seq+` TO `+role); err != nil {
		return fmt.Errorf("bridge: grant on the transition sequence: %w", err)
	}
	return nil
}

func bridgeNotReady(reason string, cause error) error {
	return &glovo.NotReadyError{Reason: reason, Cause: cause}
}

// SchemaMigrated reports whether ApplySchema has run on the database q reads:
// bridge_schema_version exists. to_regclass needs no table privilege, so the
// probe also works for the legacy bridge role that no longer owns the tables.
// A failed probe is an error, never "not migrated".
func SchemaMigrated(ctx context.Context, q dbq.Querier) (bool, error) {
	var present bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('public.bridge_schema_version') IS NOT NULL`).Scan(&present); err != nil {
		return false, fmt.Errorf("bridge: schema probe: %w", err)
	}
	return present, nil
}

// VerifyRuntimeGrants compares the current user's rights on every bridge
// table, and on the transition sequence, with RuntimeGrants, in both
// directions. A mismatch, a missing table or a check that could not run is a
// not_ready answer.
func VerifyRuntimeGrants(ctx context.Context, q dbq.Querier) error {
	for _, g := range RuntimeGrants() {
		if err := glovo.VerifyRelationGrants(ctx, q, g.Table, g.row()); err != nil {
			return bridgeNotReady(NotReadyBridgeGrants, fmt.Errorf("%s: %w", g.Table, err))
		}
	}
	var usage, update, sel bool
	if err := q.QueryRow(ctx, `SELECT has_sequence_privilege(current_user, $1, 'USAGE'),
		has_sequence_privilege(current_user, $1, 'UPDATE'), has_sequence_privilege(current_user, $1, 'SELECT')`, bridgeSequence).Scan(&usage, &update, &sel); err != nil {
		return bridgeNotReady(NotReadyBridgeCheckSQL, err)
	}
	// USAGE (nextval) is the one right the runtime role holds; UPDATE (setval)
	// and SELECT must stay absent.
	if !usage || update || sel {
		return bridgeNotReady(NotReadyBridgeGrants, errors.New("transition sequence"))
	}
	return nil
}

// NewRuntimeStore wraps the shared GLOVO_DB_URL pool (opened by the wiring,
// which keeps owning it) as a bridge store. It runs no DDL. It fails closed
// with a not_ready answer unless bridge_schema_version holds exactly the
// compiled version, the read level (#986 CheckReadLevel) is present and the
// current user's grants are exactly RuntimeGrants. Once it passes it lets the
// store enqueue and lease v1alpha2 commands (#986 EnableWireVersions): there
// is no other caller of EnableWireVersions.
func NewRuntimeStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("bridge: nil pool")
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("bridge: ping: %w", err)
	}
	var present bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.bridge_schema_version') IS NOT NULL`).Scan(&present); err != nil {
		return nil, bridgeNotReady(NotReadySchemaMissing, err)
	}
	if !present {
		return nil, bridgeNotReady(NotReadySchemaMissing, nil)
	}
	rows, err := pool.Query(ctx, `SELECT version FROM bridge_schema_version`)
	if err != nil {
		return nil, bridgeNotReady(NotReadySchemaVersion, err)
	}
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, bridgeNotReady(NotReadySchemaVersion, err)
		}
		got = append(got, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, bridgeNotReady(NotReadySchemaVersion, err)
	}
	if len(got) != 1 || got[0] != RuntimeSchemaVersion {
		return nil, bridgeNotReady(NotReadySchemaVersion, fmt.Errorf("recorded %v, compiled %d", got, RuntimeSchemaVersion))
	}
	if err := CheckReadLevel(ctx, pool); err != nil {
		return nil, bridgeNotReady(NotReadyReadLevel, err)
	}
	if err := VerifyRuntimeGrants(ctx, pool); err != nil {
		return nil, err
	}
	s := &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }, fence: refusingFence{}, borrowed: true}
	if err := s.EnableWireVersions(ctx); err != nil {
		return nil, bridgeNotReady(NotReadyReadLevel, err)
	}
	return s, nil
}

// CommandEffect is the read-only pair (status, effect_state) of a Glovo
// place_order_fake command, for mctl-api#985 reconcileOrder and #957 section
// 3a. An absent id, a foreign tenant and any other kind are all
// ErrCommandNotFound, so the three cannot be told apart; a failed read is an
// error, never a pair.
func (s *Store) CommandEffect(ctx context.Context, q dbq.Querier, tenants []string, commandID string) (status, effectState string, err error) {
	if tenants == nil {
		tenants = []string{}
	}
	err = q.QueryRow(ctx, `SELECT status, effect_state FROM bridge_commands
		WHERE command_id = $1 AND operation_kind = 'place_order_fake' AND tenant = ANY($2)`, commandID, tenants).Scan(&status, &effectState)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrCommandNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("bridge: read command effect: %w", err)
	}
	return status, effectState, nil
}

// cancelRow applies the Cancel semantics to a locked, open command: cancelled,
// cancel_requested, and a permitted effect becomes unknown because the
// provider may already have acted.
func cancelRow(ctx context.Context, tx pgx.Tx, commandID, fromStatus string, leaseEpoch int64, actor string) error {
	if _, err := tx.Exec(ctx, `UPDATE bridge_commands SET status='cancelled', cancel_requested=true, updated_at=now(),
			effect_state = CASE WHEN effect_state='permitted' THEN 'unknown' ELSE effect_state END
		WHERE command_id=$1`, commandID); err != nil {
		return fmt.Errorf("bridge: cancel: %w", err)
	}
	return addTransition(ctx, tx, commandID, fromStatus, StatusCancelled, leaseEpoch, actor, "")
}

// CancelOpenForConnections cancels every open (pending or leased) command of
// the given connections on the caller's transaction: it is the revocation hook
// every #959 connection-ending path calls after L1 and L2, so a command
// without a permit can never get one and a permitted one becomes unknown. It
// locks the commands ORDER BY command_id (L5 of the #957 lock order) and
// applies the semantics of Store.Cancel to each. It is a plain Go function on
// the revoker's transaction, with the runtime role's own bridge_commands
// rights; there is no SECURITY DEFINER function.
func CancelOpenForConnections(ctx context.Context, tx pgx.Tx, gcnIDs []string, actor string) error {
	if len(gcnIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT command_id, status, lease_epoch FROM bridge_commands
		WHERE connection_ref = ANY($1) AND status IN ('pending','leased') ORDER BY command_id FOR UPDATE`, gcnIDs)
	if err != nil {
		return fmt.Errorf("bridge: lock open commands: %w", err)
	}
	type open struct {
		id, status string
		epoch      int64
	}
	var locked []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.status, &o.epoch); err != nil {
			rows.Close()
			return fmt.Errorf("bridge: scan open command: %w", err)
		}
		locked = append(locked, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("bridge: lock open commands: %w", err)
	}
	for _, o := range locked {
		if err := cancelRow(ctx, tx, o.id, o.status, o.epoch, actor); err != nil {
			return err
		}
	}
	return nil
}
