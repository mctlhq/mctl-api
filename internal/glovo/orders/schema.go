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

package orders

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// schemaVersion is the version recorded in glovo.orders_schema_version.
const schemaVersion = 1

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ordersSchema is the DDL of the order tables, in schema glovo. It is
// idempotent and is run only by ApplySchema, under the migration role that
// owns every object. The runtime role never runs DDL.
const ordersSchema = `
CREATE TABLE IF NOT EXISTS glovo.join_refs (
  kind TEXT NOT NULL CHECK (kind IN ('tenant','principal','install_revision')),
  ref TEXT NOT NULL, tenant TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',
  subject_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (kind, ref), UNIQUE (kind, tenant, subject_id));
CREATE TABLE IF NOT EXISTS glovo.orders (
  order_id TEXT PRIMARY KEY,
  order_ref TEXT NOT NULL UNIQUE,
  tenant TEXT NOT NULL, owner_principal_id TEXT NOT NULL,
  connection_id TEXT NOT NULL, install_id TEXT NOT NULL, install_revision BIGINT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'fake' CHECK (provider = 'fake'),
  state TEXT NOT NULL DEFAULT 'open'
    CHECK (state IN ('open','finalized','dispatched','cancelled','unknown','closed')),
  final_basket_fingerprint TEXT NOT NULL DEFAULT '',
  final_snapshot_seq INTEGER NOT NULL DEFAULT 0,
  approval_ref TEXT NOT NULL DEFAULT '', command_id TEXT NOT NULL DEFAULT '',
  execution_id TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant, owner_principal_id, idempotency_key),
  CHECK (order_ref ~ '^ordr_[A-Za-z0-9]{16,40}$'),
  CHECK (state IN ('open','cancelled') OR final_basket_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (state NOT IN ('dispatched','unknown','closed') OR command_id ~ '^cmd_[A-Za-z0-9]{26}$'),
  CHECK (approval_ref = '' OR approval_ref ~ '^aar_[A-Za-z0-9]{16,40}$'),
  CHECK (execution_id = '' OR execution_id ~ '^we_[A-Za-z0-9]{16,40}$'));
CREATE UNIQUE INDEX IF NOT EXISTS orders_approval ON glovo.orders (approval_ref) WHERE approval_ref <> '';
CREATE UNIQUE INDEX IF NOT EXISTS orders_command ON glovo.orders (command_id) WHERE command_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS orders_execution ON glovo.orders (execution_id) WHERE execution_id <> '';
CREATE TABLE IF NOT EXISTS glovo.order_snapshots (
  order_id TEXT NOT NULL REFERENCES glovo.orders (order_id), seq INTEGER NOT NULL,
  basket_fingerprint TEXT NOT NULL, basket_canonical BYTEA NOT NULL,
  line_count INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (order_id, seq),
  CHECK (basket_fingerprint = 'sha256:' || encode(sha256(basket_canonical), 'hex')));
CREATE TABLE IF NOT EXISTS glovo.order_effects (
  effect_id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES glovo.orders (order_id),
  tenant TEXT NOT NULL, owner_principal_id TEXT NOT NULL,
  effect_kind TEXT NOT NULL CHECK (effect_kind = 'place_order_fake'),
  execution_id TEXT NOT NULL UNIQUE, basket_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant, owner_principal_id, idempotency_key));
CREATE TABLE IF NOT EXISTS glovo.order_events (
  id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL, order_ref TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('owner','control_worker','system')),
  actor_id TEXT NOT NULL, event TEXT NOT NULL,
  from_state TEXT NOT NULL DEFAULT '', to_state TEXT NOT NULL DEFAULT '',
  snapshot_seq INTEGER NOT NULL DEFAULT 0, recorded_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS glovo.orders_schema_version (version INT NOT NULL);
`

// ordersFunctions are the five trigger functions of triggerInventory. They run
// as the invoker; none is SECURITY DEFINER. Every statement of the guards is
// schema-qualified.
const ordersFunctions = `
CREATE OR REPLACE FUNCTION glovo.orders_immutable_rows() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$f$;

CREATE OR REPLACE FUNCTION glovo.orders_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'orders are never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.order_id IS DISTINCT FROM OLD.order_id OR NEW.order_ref IS DISTINCT FROM OLD.order_ref
     OR NEW.tenant IS DISTINCT FROM OLD.tenant OR NEW.owner_principal_id IS DISTINCT FROM OLD.owner_principal_id
     OR NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.install_id IS DISTINCT FROM OLD.install_id
     OR NEW.install_revision IS DISTINCT FROM OLD.install_revision OR NEW.provider IS DISTINCT FROM OLD.provider
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
     OR NEW.execution_id IS DISTINCT FROM OLD.execution_id THEN
    RAISE EXCEPTION 'an order identity column is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state <> OLD.state AND NOT ((OLD.state, NEW.state) IN (
       ('open','finalized'), ('open','cancelled'), ('finalized','dispatched'), ('finalized','cancelled'),
       ('dispatched','cancelled'), ('dispatched','unknown'), ('dispatched','closed'), ('unknown','closed'))) THEN
    RAISE EXCEPTION 'order transition not allowed' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (OLD.final_basket_fingerprint <> '' AND NEW.final_basket_fingerprint <> OLD.final_basket_fingerprint)
     OR (OLD.final_snapshot_seq <> 0 AND NEW.final_snapshot_seq <> OLD.final_snapshot_seq)
     OR (OLD.approval_ref <> '' AND NEW.approval_ref <> OLD.approval_ref)
     OR (OLD.command_id <> '' AND NEW.command_id <> OLD.command_id) THEN
    RAISE EXCEPTION 'a write-once order column cannot change' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state = 'open' AND NEW.state = 'finalized' THEN
    IF NEW.final_snapshot_seq < 1 OR NOT EXISTS (
         SELECT 1 FROM glovo.order_snapshots s
          WHERE s.order_id = NEW.order_id AND s.seq = NEW.final_snapshot_seq
            AND s.basket_fingerprint = NEW.final_basket_fingerprint) THEN
      RAISE EXCEPTION 'the final fingerprint matches no snapshot' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF NEW.final_basket_fingerprint <> OLD.final_basket_fingerprint OR NEW.final_snapshot_seq <> OLD.final_snapshot_seq THEN
    RAISE EXCEPTION 'the fingerprint is set only on finalize' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.approval_ref = '' AND NEW.approval_ref <> '' AND NOT (OLD.state = 'finalized' AND NEW.state = 'finalized') THEN
    RAISE EXCEPTION 'approval_ref is set only while finalized' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.command_id = '' AND NEW.command_id <> ''
     AND NOT (OLD.state = 'finalized' AND NEW.state = 'dispatched' AND NEW.approval_ref <> '') THEN
    RAISE EXCEPTION 'command_id is set only on dispatch of an approved order' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;

CREATE OR REPLACE FUNCTION glovo.orders_insert_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.state <> 'open' OR NEW.final_basket_fingerprint <> '' OR NEW.approval_ref <> '' OR NEW.command_id <> ''
     OR NEW.final_snapshot_seq <> 0 OR NEW.version <> 1 OR NEW.execution_id = '' THEN
    RAISE EXCEPTION 'an order is inserted open and empty' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT EXISTS (
       SELECT 1 FROM public.work_item_executions e JOIN public.work_items w ON w.id = e.work_item_id
        WHERE e.id = NEW.execution_id AND w.tenant = NEW.tenant AND w.owner_principal_id = NEW.owner_principal_id) THEN
    RAISE EXCEPTION 'the execution is not bound to this tenant and owner' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;

CREATE OR REPLACE FUNCTION glovo.order_snapshots_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE st TEXT;
BEGIN
  SELECT o.state INTO st FROM glovo.orders o WHERE o.order_id = NEW.order_id FOR SHARE;
  IF st IS DISTINCT FROM 'open' THEN
    RAISE EXCEPTION 'a snapshot is appended to an open order only' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;

CREATE OR REPLACE FUNCTION glovo.order_effects_insert_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE o glovo.orders%ROWTYPE;
BEGIN
  SELECT * INTO o FROM glovo.orders x WHERE x.order_id = NEW.order_id FOR SHARE;
  IF NOT FOUND OR o.state <> 'finalized' OR o.tenant <> NEW.tenant OR o.owner_principal_id <> NEW.owner_principal_id
     OR o.execution_id <> NEW.execution_id OR o.final_basket_fingerprint <> NEW.basket_fingerprint THEN
    RAISE EXCEPTION 'an effect is recorded for a finalized order of the same owner' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;
`

// triggerSpec is one entry of triggerInventory.
type triggerSpec struct {
	Table    string
	Name     string
	Function string
	Event    string // "UPDATE OR DELETE" or "INSERT"
	TgType   int    // pg_trigger.tgtype: ROW 1, BEFORE 2, INSERT 4, DELETE 8, UPDATE 16
}

const (
	tgRowBefore    = 1 | 2
	tgInsert       = 4
	tgUpdateDelete = 8 | 16
)

// triggerInventory is the single list of the eight triggers on the order
// tables. ApplySchema creates from it and Ready compares pg_trigger with it,
// so they cannot drift.
var triggerInventory = []triggerSpec{
	{"join_refs", "join_refs_immutable", "orders_immutable_rows", "UPDATE OR DELETE", tgRowBefore | tgUpdateDelete},
	{"order_snapshots", "order_snapshots_immutable", "orders_immutable_rows", "UPDATE OR DELETE", tgRowBefore | tgUpdateDelete},
	{"order_effects", "order_effects_immutable", "orders_immutable_rows", "UPDATE OR DELETE", tgRowBefore | tgUpdateDelete},
	{"order_events", "order_events_immutable", "orders_immutable_rows", "UPDATE OR DELETE", tgRowBefore | tgUpdateDelete},
	{"orders", "orders_guard", "orders_guard", "UPDATE OR DELETE", tgRowBefore | tgUpdateDelete},
	{"orders", "orders_insert_guard", "orders_insert_guard", "INSERT", tgRowBefore | tgInsert},
	{"order_snapshots", "order_snapshots_guard", "order_snapshots_guard", "INSERT", tgRowBefore | tgInsert},
	{"order_effects", "order_effects_insert_guard", "order_effects_insert_guard", "INSERT", tgRowBefore | tgInsert},
}

// orderTables are the tables of this slice. The version table is last.
var orderTables = []string{"join_refs", "orders", "order_snapshots", "order_effects", "order_events", "orders_schema_version"}

// orderUpdateColumns is the only column-level UPDATE the runtime role holds.
var orderUpdateColumns = []string{"state", "final_basket_fingerprint", "final_snapshot_seq", "approval_ref", "command_id", "version", "updated_at"}

// The #988 rows of mctl-api#957 design 6d.1, registered with the #959 registry.
func init() {
	appendOnly := []string{"SELECT", "INSERT"}
	glovo.RegisterGrants(
		glovo.GrantRow{Table: "join_refs", Privileges: appendOnly, Description: "opaque join refs, append-only"},
		glovo.GrantRow{Table: "orders", Privileges: appendOnly, UpdateColumns: orderUpdateColumns, Description: "orders; column-level UPDATE of the lifecycle columns only"},
		glovo.GrantRow{Table: "order_snapshots", Privileges: appendOnly, Description: "append-only basket snapshots"},
		glovo.GrantRow{Table: "order_effects", Privileges: appendOnly, Description: "append-only effect rows"},
		glovo.GrantRow{Table: "order_events", Privileges: appendOnly, Description: "append-only order events"},
		glovo.GrantRow{Table: "orders_schema_version", Privileges: []string{"SELECT"}, Description: "recorded order schema version, read at start"},
	)
}

func triggerDDL() string {
	var b strings.Builder
	b.WriteString("DO $$\nBEGIN\n")
	for _, t := range triggerInventory {
		fmt.Fprintf(&b, `  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '%[2]s' AND tgrelid = 'glovo.%[1]s'::regclass) THEN
    CREATE TRIGGER %[2]s BEFORE %[4]s ON glovo.%[1]s FOR EACH ROW EXECUTE FUNCTION glovo.%[3]s();
  END IF;
`, t.Table, t.Name, t.Function, t.Event)
	}
	b.WriteString("END $$;\n")
	return b.String()
}

// ApplySchema creates schema glovo and the order tables, trigger functions and
// triggers, grants the runtime role exactly the registered rows and records
// the schema version. It runs only under the migration role, which becomes
// the owner of every object, in one transaction under a schema advisory lock.
// It refuses a schema or an object in schema glovo that another role owns, a
// recorded version above the compiled one, and a runtimeRole that does not
// match ^[a-z_][a-z0-9_]{0,62}$.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string) error {
	if !roleNameRE.MatchString(runtimeRole) {
		return fmt.Errorf("glovo orders: invalid runtime role name")
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("glovo orders: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovo orders: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-orders-schema'))`); err != nil {
		return fmt.Errorf("glovo orders: schema lock: %w", err)
	}
	// The #959 slice takes this lock for its own DDL: both write schema glovo.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-schema'))`); err != nil {
		return fmt.Errorf("glovo orders: schema lock: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS glovo`); err != nil {
		return fmt.Errorf("glovo orders: create schema: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('glovo.orders_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("glovo orders: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM glovo.orders_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("glovo orders: read schema version: %w", err)
		}
		if recorded != nil && *recorded > schemaVersion {
			return fmt.Errorf("glovo orders: recorded schema version %d is above the compiled version %d", *recorded, schemaVersion)
		}
	}
	for _, stmt := range []string{ordersSchema, ordersFunctions, triggerDDL()} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("glovo orders: apply schema: %w", err)
		}
	}
	// IF NOT EXISTS must not have adopted a foreign object.
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}

	role := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SCHEMA glovo TO `+role); err != nil {
		return fmt.Errorf("glovo orders: grant schema usage: %w", err)
	}
	for _, t := range orderTables {
		row, ok := glovo.GrantFor(t)
		if !ok {
			return fmt.Errorf("glovo orders: no grant row registered for %s", t)
		}
		tbl := pgx.Identifier{"glovo", t}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
			return fmt.Errorf("glovo orders: revoke on %s: %w", t, err)
		}
		if len(row.Privileges) > 0 {
			if _, err := tx.Exec(ctx, `GRANT `+strings.Join(row.Privileges, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo orders: grant on %s: %w", t, err)
			}
		}
		if len(row.UpdateColumns) > 0 {
			cols := make([]string, len(row.UpdateColumns))
			for i, c := range row.UpdateColumns {
				cols[i] = pgx.Identifier{c}.Sanitize()
			}
			if _, err := tx.Exec(ctx, `GRANT UPDATE (`+strings.Join(cols, ", ")+`) ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo orders: grant columns on %s: %w", t, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL ON SEQUENCE glovo.order_events_id_seq FROM `+role); err != nil {
		return fmt.Errorf("glovo orders: revoke sequence: %w", err)
	}
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SEQUENCE glovo.order_events_id_seq TO `+role); err != nil {
		return fmt.Errorf("glovo orders: grant sequence: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.orders_schema_version`); err != nil {
		return fmt.Errorf("glovo orders: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.orders_schema_version (version) VALUES ($1)`, schemaVersion); err != nil {
		return fmt.Errorf("glovo orders: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovo orders: commit schema: %w", err)
	}
	return nil
}

// checkOwnership refuses schema glovo, or any relation or function in it, that
// current_user (the migration role) does not own.
func checkOwnership(ctx context.Context, tx pgx.Tx) error {
	var bad int
	if err := tx.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo' AND pg_get_userbyid(nspowner) <> current_user)
     + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'glovo' AND pg_get_userbyid(c.relowner) <> current_user)
     + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'glovo' AND pg_get_userbyid(p.proowner) <> current_user)`).Scan(&bad); err != nil {
		return fmt.Errorf("glovo orders: ownership check: %w", err)
	}
	if bad != 0 {
		return fmt.Errorf("glovo orders: schema glovo or an object in it is not owned by the migration role")
	}
	return nil
}
