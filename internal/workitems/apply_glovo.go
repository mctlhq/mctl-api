package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Database enforcement of the Glovo approval machine (mctl-api#989 task 1,
// design section 2). Everything here is created by ApplyGlovoApprovalSchema
// under the migration role, never by the runtime role: a trigger on a table the
// runtime role owns could be disabled by that role.

// glovoApprovalSchemaVersion is recorded in glovo.approval_schema_version.
// Version 2 adds the basket approval kind and its binding table
// (mctl-api#1006).
const glovoApprovalSchemaVersion = 2

// glovoRuntimeUpdateColumns is the exact column-level UPDATE the Glovo runtime
// role holds on action_approval_requests (#957 design 6d.1).
var glovoRuntimeUpdateColumns = []string{
	"state", "decided_by", "decided_at", "reason", "decided_by_principal_id",
	"decided_via_principal_id", "decided_context_digest", "authority_basis", "authz_mode",
	"fresh_until", "consumed_at", "reserved_at",
}

// glovoPublicGrants is what the Glovo runtime role holds on the work-items
// tables it reads and creates executions in (#957 design 6d.1, "existing
// consumers"): SELECT and INSERT, nothing else.
var glovoPublicGrants = []struct {
	Table      string
	Privileges []string
}{
	{"work_items", []string{"SELECT", "INSERT"}},
	{"work_item_executions", []string{"SELECT", "INSERT"}},
	{"work_item_events", []string{"SELECT", "INSERT"}},
}

// The grant rows of this slice in schema glovo, registered with the #959
// registry so glovo.Ready does not report the tables as unregistered.
func init() {
	glovo.RegisterGrants(
		glovo.GrantRow{Table: "approval_bindings", Privileges: []string{"SELECT", "INSERT"}, UpdateColumns: []string{"command_id"},
			Description: "approval bindings; column-level UPDATE of command_id only"},
		glovo.GrantRow{Table: "approval_schema_version", Privileges: []string{"SELECT"},
			Description: "recorded approval schema version, read at start"},
		glovo.GrantRow{Table: "basket_approval_bindings", Privileges: []string{"SELECT", "INSERT"},
			Description: "basket approval bindings (mctl-api#1006); insert-only"},
	)
}

// glovoApprovalRelations and glovoApprovalFunctions are the objects of this
// slice in schema glovo, held to the migration role by the ownership check.
var (
	glovoApprovalRelations = []string{"approval_bindings", "approval_schema_version", "basket_approval_bindings"}
	glovoApprovalFunctions = []string{"aar_guard", "approval_bindings_guard", "aar_binding_required", "basket_approval_bindings_guard"}
)

const glovoApprovalTables = `
CREATE TABLE IF NOT EXISTS glovo.approval_bindings (
  approval_id        TEXT PRIMARY KEY REFERENCES public.action_approval_requests (id),
  tenant             TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL CHECK (owner_principal_id LIKE 'prn\_%'),
  execution_id       TEXT NOT NULL,
  work_item_id       TEXT NOT NULL,
  order_ref          TEXT NOT NULL UNIQUE CHECK (order_ref ~ '^ordr_[A-Za-z0-9]{16,40}$'),
  connection_ref     TEXT NOT NULL CHECK (connection_ref ~ '^gcn_[A-Za-z0-9]{16,40}$'),
  install_id         TEXT NOT NULL,
  install_revision   TEXT NOT NULL CHECK (install_revision ~ '^[1-9][0-9]{0,18}$'),
  basket_fingerprint TEXT NOT NULL CHECK (basket_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  provider           TEXT NOT NULL,
  command_id         TEXT NOT NULL DEFAULT '',
  created_at         TIMESTAMPTZ NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS approval_bindings_command
  ON glovo.approval_bindings (command_id) WHERE command_id <> '';
CREATE TABLE IF NOT EXISTS glovo.approval_schema_version (version INT NOT NULL);
-- What the owner's approval of one frozen basket revision is bound to
-- (mctl-api#1006). Insert-only: approval_bindings_guard's sibling below
-- refuses every UPDATE and DELETE. No order, connection, execution or work
-- item: a basket approval has no effect to bind.
CREATE TABLE IF NOT EXISTS glovo.basket_approval_bindings (
  approval_id        TEXT PRIMARY KEY REFERENCES public.action_approval_requests (id),
  tenant             TEXT NOT NULL CHECK (tenant <> ''),
  owner_principal_id TEXT NOT NULL CHECK (owner_principal_id LIKE 'prn\_%'),
  basket_id          TEXT NOT NULL CHECK (basket_id ~ '^gbk_[A-Za-z0-9]{26}$'),
  revision           BIGINT NOT NULL CHECK (revision >= 1),
  basket_fingerprint TEXT NOT NULL CHECK (basket_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  created_at         TIMESTAMPTZ NOT NULL,
  UNIQUE (basket_id, revision));
`

// glovoApprovalChecks widens the state CHECK and adds the kind and state
// CHECKs. Each is guarded (replace-once keyed on 'reserved', or added when
// absent), created NOT VALID and then validated, so a restart is a no-op and
// existing rows are checked rather than trusted.
const glovoApprovalChecks = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.action_approval_requests'::regclass
                     AND conname = 'action_approval_requests_state_check'
                     AND pg_get_constraintdef(oid) LIKE '%''reserved''%') THEN
        ALTER TABLE public.action_approval_requests
            DROP CONSTRAINT IF EXISTS action_approval_requests_state_check,
            ADD CONSTRAINT action_approval_requests_state_check
                CHECK (state IN ('pending', 'approved', 'denied', 'consumed', 'in_flight', 'executed', 'reserved', 'unknown')) NOT VALID;
    END IF;
    -- Replace-once keyed on the basket kind (mctl-api#1006): a database of
    -- version 1 carries the one-kind CHECK under the same name.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.action_approval_requests'::regclass
                     AND conname = 'action_approval_requests_glovo_kind_chk'
                     AND strpos(pg_get_constraintdef(oid), 'glovo.basket_approval') > 0) THEN
        ALTER TABLE public.action_approval_requests
            DROP CONSTRAINT IF EXISTS action_approval_requests_glovo_kind_chk,
            ADD CONSTRAINT action_approval_requests_glovo_kind_chk
                CHECK (action_kind NOT LIKE 'glovo.%' OR action_kind IN ('glovo.place_order_fake', 'glovo.basket_approval')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.action_approval_requests'::regclass
                     AND conname = 'action_approval_requests_glovo_states_chk') THEN
        ALTER TABLE public.action_approval_requests
            ADD CONSTRAINT action_approval_requests_glovo_states_chk
                CHECK (CASE WHEN action_kind LIKE 'glovo.%' THEN state NOT IN ('in_flight', 'executed')
                            ELSE state NOT IN ('reserved', 'unknown') END) NOT VALID;
    END IF;
END $$;
ALTER TABLE public.action_approval_requests VALIDATE CONSTRAINT action_approval_requests_state_check;
ALTER TABLE public.action_approval_requests VALIDATE CONSTRAINT action_approval_requests_glovo_kind_chk;
ALTER TABLE public.action_approval_requests VALIDATE CONSTRAINT action_approval_requests_glovo_states_chk;
`

// glovoApprovalFunctionsSQL are the three trigger functions. They run as the
// invoker (none is SECURITY DEFINER) and every statement is schema-qualified.
// The binding row is a RECORD, not glovo.approval_bindings%ROWTYPE: plpgsql
// resolves a declared type when it compiles the function, which needs USAGE on
// schema glovo, and the work-items role, which has none, fires aar_guard on
// every generic approval it writes.
// __RUNTIME_ROLE__ is the runtime role as an SQL literal, written into aar_guard at apply
// time. A generic row (neither OLD nor NEW a Glovo kind) returns at once and
// touches nothing in schema glovo, so the work-items role, which has no
// privilege there, keeps writing generic approvals.
const glovoApprovalFunctionsSQL = `
CREATE OR REPLACE FUNCTION glovo.approval_bindings_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'approval bindings are never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.approval_id IS DISTINCT FROM OLD.approval_id OR NEW.tenant IS DISTINCT FROM OLD.tenant
     OR NEW.owner_principal_id IS DISTINCT FROM OLD.owner_principal_id OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
     OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id OR NEW.order_ref IS DISTINCT FROM OLD.order_ref
     OR NEW.connection_ref IS DISTINCT FROM OLD.connection_ref OR NEW.install_id IS DISTINCT FROM OLD.install_id
     OR NEW.install_revision IS DISTINCT FROM OLD.install_revision OR NEW.basket_fingerprint IS DISTINCT FROM OLD.basket_fingerprint
     OR NEW.provider IS DISTINCT FROM OLD.provider OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'an approval binding column is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.command_id IS DISTINCT FROM OLD.command_id
     AND NOT (OLD.command_id = '' AND NEW.command_id ~ '^cmd_[A-Za-z0-9]{26}$') THEN
    RAISE EXCEPTION 'command_id is written once, from empty to a cmd_ id' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;

CREATE OR REPLACE FUNCTION glovo.aar_binding_required() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE b RECORD;
BEGIN
  IF NEW.action_kind NOT LIKE 'glovo.%' THEN
    RETURN NULL;
  END IF;
  IF NEW.action_kind = 'glovo.basket_approval' THEN
    SELECT * INTO b FROM glovo.basket_approval_bindings x WHERE x.approval_id = NEW.id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'a glovo approval is committed with its binding' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.artifact_hash <> b.basket_fingerprint OR NEW.args_digest <> b.basket_fingerprint
       OR NEW.execution_id <> b.basket_id OR NEW.work_item_id <> ''
       OR NEW.subject_principal_id <> b.owner_principal_id THEN
      RAISE EXCEPTION 'the approval and its binding disagree' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NULL;
  END IF;
  SELECT * INTO b FROM glovo.approval_bindings x WHERE x.approval_id = NEW.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'a glovo approval is committed with its binding' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.artifact_hash <> b.basket_fingerprint OR NEW.execution_id <> b.execution_id
     OR NEW.work_item_id <> b.work_item_id OR NEW.subject_principal_id <> b.owner_principal_id THEN
    RAISE EXCEPTION 'the approval and its binding disagree' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NULL;
END
$f$;

CREATE OR REPLACE FUNCTION glovo.basket_approval_bindings_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION 'basket approval bindings are insert-only' USING ERRCODE = 'integrity_constraint_violation';
END
$f$;

CREATE OR REPLACE FUNCTION glovo.aar_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  oldg BOOLEAN := false;
  newg BOOLEAN := false;
  b RECORD;
BEGIN
  IF TG_OP <> 'INSERT' THEN oldg := OLD.action_kind LIKE 'glovo.%'; END IF;
  IF TG_OP <> 'DELETE' THEN newg := NEW.action_kind LIKE 'glovo.%'; END IF;
  IF NOT oldg AND NOT newg THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'a glovo approval is never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF current_user::text <> __RUNTIME_ROLE__ THEN
    RAISE EXCEPTION 'only the glovo runtime role writes a glovo approval' USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.action_kind NOT IN ('glovo.place_order_fake', 'glovo.basket_approval') OR NEW.state <> 'pending'
       OR NEW.decided_by <> '' OR NEW.decided_at IS NOT NULL OR NEW.reason <> ''
       OR NEW.decided_by_principal_id <> '' OR NEW.decided_via_principal_id <> ''
       OR NEW.decided_context_digest <> '' OR NEW.authority_basis <> '' OR NEW.authz_mode <> ''
       OR NEW.fresh_until IS NOT NULL OR NEW.consumed_at IS NOT NULL OR NEW.reserved_at IS NOT NULL
       OR NEW.executed_at IS NOT NULL THEN
      RAISE EXCEPTION 'a glovo approval is inserted pending and undecided' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.action_kind = 'glovo.place_order_fake' AND (NEW.requested_by <> 'service:glovo-prepare'
           OR NEW.policy_rule_id <> 'glovo.order.owner-approval' OR NEW.policy_version <> '1'))
       OR (NEW.action_kind = 'glovo.basket_approval' AND (NEW.requested_by <> 'service:glovo-basket'
           OR NEW.policy_rule_id <> 'glovo.basket.owner-approval' OR NEW.policy_version <> '1'))
       OR NEW.intent_source = '' OR NEW.policy_decision = ''
       OR cardinality(NEW.policy_reasons) = 0 OR NEW.artifact_hash !~ '^sha256:[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'a glovo approval carries its complete policy context' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE of a row that is, or becomes, a Glovo kind.
  IF NEW.action_kind IS DISTINCT FROM OLD.action_kind OR NEW.intent_hash IS DISTINCT FROM OLD.intent_hash
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
     OR NEW.work_item_id IS DISTINCT FROM OLD.work_item_id OR NEW.subject_principal_id IS DISTINCT FROM OLD.subject_principal_id
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by OR NEW.artifact_hash IS DISTINCT FROM OLD.artifact_hash
     OR NEW.policy_rule_id IS DISTINCT FROM OLD.policy_rule_id OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.target IS DISTINCT FROM OLD.target OR NEW.args_digest IS DISTINCT FROM OLD.args_digest THEN
    RAISE EXCEPTION 'a glovo approval identity column is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.state = OLD.state THEN
    IF NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
       OR NEW.reason IS DISTINCT FROM OLD.reason OR NEW.decided_by_principal_id IS DISTINCT FROM OLD.decided_by_principal_id
       OR NEW.decided_via_principal_id IS DISTINCT FROM OLD.decided_via_principal_id
       OR NEW.decided_context_digest IS DISTINCT FROM OLD.decided_context_digest
       OR NEW.authority_basis IS DISTINCT FROM OLD.authority_basis OR NEW.authz_mode IS DISTINCT FROM OLD.authz_mode
       OR NEW.fresh_until IS DISTINCT FROM OLD.fresh_until OR NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.reserved_at IS DISTINCT FROM OLD.reserved_at OR NEW.executed_at IS DISTINCT FROM OLD.executed_at THEN
      RAISE EXCEPTION 'a recorded glovo decision does not change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT ((OLD.state, NEW.state) IN (
       ('pending','approved'), ('pending','denied'), ('approved','reserved'), ('approved','denied'),
       ('reserved','consumed'), ('reserved','unknown'))) THEN
    RAISE EXCEPTION 'glovo approval transition not allowed' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- A basket approval is only ever decided: it is never reserved, consumed
  -- or revoked, because nothing spends it (mctl-api#1006).
  IF OLD.action_kind = 'glovo.basket_approval' AND OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'glovo approval transition not allowed' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- Outside the transition's own columns, the recorded decision is kept.
  IF OLD.state <> 'pending' AND (
       NEW.decided_by_principal_id IS DISTINCT FROM OLD.decided_by_principal_id
       OR NEW.decided_via_principal_id IS DISTINCT FROM OLD.decided_via_principal_id
       OR NEW.decided_context_digest IS DISTINCT FROM OLD.decided_context_digest
       OR NEW.authority_basis IS DISTINCT FROM OLD.authority_basis OR NEW.authz_mode IS DISTINCT FROM OLD.authz_mode
       OR NEW.fresh_until IS DISTINCT FROM OLD.fresh_until) THEN
    RAISE EXCEPTION 'a recorded glovo decision does not change' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state = 'pending' AND NEW.state = 'approved' AND OLD.action_kind = 'glovo.basket_approval' THEN
    SELECT * INTO b FROM glovo.basket_approval_bindings x WHERE x.approval_id = OLD.id;
    IF NOT FOUND OR NEW.decided_by_principal_id <> b.owner_principal_id
       OR NEW.authority_basis <> 'resource_owner' OR NEW.fresh_until IS NULL
       OR OLD.expires_at <= clock_timestamp() THEN
      RAISE EXCEPTION 'only the basket owner approves, before expiry, under resource_owner' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF OLD.state = 'pending' AND NEW.state = 'denied' AND OLD.action_kind = 'glovo.basket_approval' THEN
    SELECT * INTO b FROM glovo.basket_approval_bindings x WHERE x.approval_id = OLD.id;
    IF NOT FOUND OR NEW.decided_by_principal_id <> b.owner_principal_id THEN
      RAISE EXCEPTION 'only the basket owner refuses a basket approval' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF OLD.state = 'pending' AND NEW.state = 'approved' THEN
    SELECT * INTO b FROM glovo.approval_bindings x WHERE x.approval_id = OLD.id;
    IF NOT FOUND OR NEW.decided_by_principal_id <> b.owner_principal_id
       OR NEW.authority_basis <> 'resource_owner' OR NEW.fresh_until IS NULL
       OR OLD.expires_at <= clock_timestamp() THEN
      RAISE EXCEPTION 'only the order owner approves, before expiry, under resource_owner' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF OLD.state = 'approved' AND NEW.state = 'reserved' THEN
    SELECT * INTO b FROM glovo.approval_bindings x WHERE x.approval_id = OLD.id;
    IF NOT FOUND OR b.command_id = '' OR NEW.reserved_at IS NULL
       OR OLD.expires_at <= clock_timestamp() OR OLD.fresh_until IS NULL OR OLD.fresh_until <= clock_timestamp() THEN
      RAISE EXCEPTION 'reserve needs a bound command and an unexpired approval' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF OLD.state = 'reserved' AND NEW.state = 'consumed' THEN
    IF NEW.consumed_at IS NULL OR OLD.expires_at <= clock_timestamp()
       OR OLD.fresh_until IS NULL OR OLD.fresh_until <= clock_timestamp() THEN
      RAISE EXCEPTION 'a reserved approval is consumed before expiry only' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  RETURN NEW;
END
$f$;
`

// triggerSQL creates the three triggers when absent and enables them, so a
// trigger that was disabled by hand is repaired by the next apply.
const glovoApprovalTriggersSQL = `
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aar_guard' AND tgrelid = 'public.action_approval_requests'::regclass) THEN
    CREATE TRIGGER aar_guard BEFORE INSERT OR UPDATE OR DELETE ON public.action_approval_requests
      FOR EACH ROW EXECUTE FUNCTION glovo.aar_guard();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'aar_binding_required' AND tgrelid = 'public.action_approval_requests'::regclass) THEN
    CREATE CONSTRAINT TRIGGER aar_binding_required AFTER INSERT ON public.action_approval_requests
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION glovo.aar_binding_required();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'approval_bindings_guard' AND tgrelid = 'glovo.approval_bindings'::regclass) THEN
    CREATE TRIGGER approval_bindings_guard BEFORE UPDATE OR DELETE ON glovo.approval_bindings
      FOR EACH ROW EXECUTE FUNCTION glovo.approval_bindings_guard();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'basket_approval_bindings_guard' AND tgrelid = 'glovo.basket_approval_bindings'::regclass) THEN
    CREATE TRIGGER basket_approval_bindings_guard BEFORE UPDATE OR DELETE ON glovo.basket_approval_bindings
      FOR EACH ROW EXECUTE FUNCTION glovo.basket_approval_bindings_guard();
  END IF;
END $$;
ALTER TABLE public.action_approval_requests ENABLE TRIGGER aar_guard;
ALTER TABLE public.action_approval_requests ENABLE TRIGGER aar_binding_required;
ALTER TABLE glovo.approval_bindings ENABLE TRIGGER approval_bindings_guard;
ALTER TABLE glovo.basket_approval_bindings ENABLE TRIGGER basket_approval_bindings_guard;
`

// ApplyGlovoApprovalSchema creates the Glovo approval enforcement: the widened
// state CHECK, the kind and state CHECKs, glovo.approval_bindings, the three
// trigger functions and triggers, the version row and the grants of the Glovo
// runtime role (#957 design 6d.1), and nothing else. It first runs ApplySchema
// (the generic block, under the same migration role), then does its own work in
// one transaction under the schema advisory locks. It is idempotent, refuses a
// relation or function of the slice that another role owns, a recorded
// version above the compiled one, and a runtimeRole equal to the work-items
// role (the work-items role gets nothing in schema glovo).
//
// The work-items role is passed as WithWorkItemsRole (OPEN-989-9).
func ApplyGlovoApprovalSchema(ctx context.Context, migrationConnStr, runtimeRole string, opts ...ApplyOption) error {
	cfg := newApplyConfig(opts)
	if !roleNameRE.MatchString(runtimeRole) {
		return errors.New("workitems: invalid glovo runtime role name")
	}
	if cfg.workItemsRole == runtimeRole {
		return errors.New("workitems: the glovo runtime role is not the work-items role")
	}
	// The generic block grants the work-items role only; the runtime role is
	// given its own, narrower rows below.
	if err := ApplySchema(ctx, migrationConnStr, "", opts...); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("workitems: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("workitems: begin approval schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if cfg.txSetup != nil {
		if err := cfg.txSetup(ctx, tx); err != nil {
			return fmt.Errorf("workitems: approval schema tx setup: %w", err)
		}
	}
	for _, k := range []string{"glovo-approval-schema", "glovo-schema"} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, k); err != nil {
			return fmt.Errorf("workitems: approval schema lock: %w", err)
		}
	}
	if err := checkGenericOwnership(ctx, tx); err != nil {
		return err
	}
	if err := checkGlovoApprovalOwnership(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS glovo`); err != nil {
		return fmt.Errorf("workitems: create schema glovo: %w", err)
	}
	if err := checkGlovoApprovalOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('glovo.approval_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("workitems: probe approval schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM glovo.approval_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("workitems: read approval schema version: %w", err)
		}
		if recorded != nil && *recorded > glovoApprovalSchemaVersion {
			return fmt.Errorf("workitems: recorded approval schema version %d is above the compiled version %d", *recorded, glovoApprovalSchemaVersion)
		}
	}
	literal := "'" + strings.ReplaceAll(runtimeRole, "'", "''") + "'"
	for _, stmt := range []struct{ name, sql string }{
		{"checks", glovoApprovalChecks},
		{"tables", glovoApprovalTables},
		{"functions", strings.ReplaceAll(glovoApprovalFunctionsSQL, "__RUNTIME_ROLE__", literal)},
		{"triggers", glovoApprovalTriggersSQL},
	} {
		if _, err := tx.Exec(ctx, stmt.sql); err != nil {
			return fmt.Errorf("workitems: apply approval %s: %w", stmt.name, err)
		}
	}
	// IF NOT EXISTS must not have adopted a foreign object.
	if err := checkGlovoApprovalOwnership(ctx, tx); err != nil {
		return err
	}
	if err := grantGlovoRuntime(ctx, tx, runtimeRole); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.approval_schema_version`); err != nil {
		return fmt.Errorf("workitems: reset approval schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.approval_schema_version (version) VALUES ($1)`, glovoApprovalSchemaVersion); err != nil {
		return fmt.Errorf("workitems: record approval schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("workitems: commit approval schema: %w", err)
	}
	return nil
}

// grantGlovoRuntime makes the runtime role's rights on the objects of this
// slice, and on the three work-items tables it uses, equal the #957 design
// 6d.1 rows: revoke, then grant.
func grantGlovoRuntime(ctx context.Context, tx pgx.Tx, runtimeRole string) error {
	role := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SCHEMA glovo TO `+role); err != nil {
		return fmt.Errorf("workitems: grant schema usage: %w", err)
	}
	for _, name := range glovoApprovalRelations {
		row, ok := glovo.GrantFor(name)
		if !ok {
			return fmt.Errorf("workitems: no grant row registered for glovo.%s", name)
		}
		if err := grantRow(ctx, tx, role, pgx.Identifier{"glovo", name}.Sanitize(), row.Privileges, row.UpdateColumns); err != nil {
			return err
		}
	}
	if err := grantRow(ctx, tx, role, `public.action_approval_requests`, []string{"SELECT", "INSERT"}, glovoRuntimeUpdateColumns); err != nil {
		return err
	}
	for _, g := range glovoPublicGrants {
		if err := grantRow(ctx, tx, role, pgx.Identifier{"public", g.Table}.Sanitize(), g.Privileges, nil); err != nil {
			return err
		}
	}
	return nil
}

func grantRow(ctx context.Context, tx pgx.Tx, role, tbl string, privs, updateCols []string) error {
	if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
		return fmt.Errorf("workitems: revoke on %s: %w", tbl, err)
	}
	if len(privs) > 0 {
		if _, err := tx.Exec(ctx, `GRANT `+strings.Join(privs, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
			return fmt.Errorf("workitems: grant on %s: %w", tbl, err)
		}
	}
	if len(updateCols) > 0 {
		cols := make([]string, len(updateCols))
		for i, c := range updateCols {
			cols[i] = pgx.Identifier{c}.Sanitize()
		}
		if _, err := tx.Exec(ctx, `GRANT UPDATE (`+strings.Join(cols, ", ")+`) ON TABLE `+tbl+` TO `+role); err != nil {
			return fmt.Errorf("workitems: grant columns on %s: %w", tbl, err)
		}
	}
	return nil
}

// GlovoApprovalForeignOwned lists schema glovo, and the relations and
// functions of the approval slice in it, that current_user (the migration
// role) does not own.
func GlovoApprovalForeignOwned(ctx context.Context, q dbq.Querier) ([]string, error) {
	var out []string
	err := q.QueryRow(ctx, `
SELECT coalesce(array_agg(x ORDER BY x), '{}') FROM (
  SELECT 'schema glovo' AS x FROM pg_namespace WHERE nspname = 'glovo' AND pg_get_userbyid(nspowner) <> current_user
  UNION ALL
  SELECT 'glovo.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'glovo' AND c.relname = ANY($1) AND pg_get_userbyid(c.relowner) <> current_user
  UNION ALL
  SELECT 'glovo.' || p.proname || '()' FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'glovo' AND p.proname = ANY($2) AND pg_get_userbyid(p.proowner) <> current_user) s`,
		glovoApprovalRelations, glovoApprovalFunctions).Scan(&out)
	if err != nil {
		return nil, fmt.Errorf("workitems: approval ownership check: %w", err)
	}
	return out, nil
}

// ApprovalStepForeignOwned is everything ApplyGlovoApprovalSchema refuses on
// for ownership: the generic block, then the approval slice. The migrator's
// preflight uses it so the two cannot drift.
func ApprovalStepForeignOwned(ctx context.Context, q dbq.Querier) ([]string, error) {
	g, err := GenericForeignOwned(ctx, q)
	if err != nil {
		return nil, err
	}
	a, err := GlovoApprovalForeignOwned(ctx, q)
	if err != nil {
		return nil, err
	}
	return append(g, a...), nil
}

// checkGlovoApprovalOwnership refuses schema glovo, or a relation or function
// of this slice in it, that current_user (the migration role) does not own.
func checkGlovoApprovalOwnership(ctx context.Context, q dbq.Querier) error {
	foreign, err := GlovoApprovalForeignOwned(ctx, q)
	if err != nil {
		return err
	}
	if len(foreign) != 0 {
		return errors.New("workitems: schema glovo or an object of the approval schema is not owned by the migration role")
	}
	return nil
}
