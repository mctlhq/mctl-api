package workitems

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Generic work-items DDL under a migration role (mctl-api#989 task 2b).
//
// NewStore has always run the whole generic DDL block on the runtime pool, so
// the runtime role owned every work-items table. A trigger on a table the
// runtime role owns can be disabled by that role, so the Glovo approval
// guards need an owner that is not the runtime role. ApplySchema runs exactly
// the statements NewStore runs, under the migration role, grants the
// work-items role the DML its existing statements use, and records a schema
// version. NewStore then only verifies that version when it does not own the
// tables, and sends no DDL.

// workItemsSchemaVersion is recorded in public.work_items_schema_version.
const workItemsSchemaVersion = 1

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// genericSchemaBlocks is the one DDL block of NewStore, in its order. NewStore
// (legacy, owner mode) and ApplySchema both run it, so they cannot drift.
var genericSchemaBlocks = []struct{ name, sql string }{
	{"schema", schema},
	{"snapshot schema", snapshotSchema},
	{"action approval schema", actionApprovalSchema},
	{"execution request schema", executionRequestSchema},
	{"agent run token schema", agentRunTokenSchema},
}

// genericRelations are the relations the block creates, owned by the
// migration role after ApplySchema. TestGenericRelationsCoverTheDDL holds the
// list to the DDL text.
var genericRelations = []string{
	"work_items", "work_item_events", "work_item_intents", "work_item_executions",
	"work_item_surface_refs", "work_item_create_requests", "work_item_requests",
	"execution_provenance", "work_item_context_snapshots", "action_approval_requests",
	"work_item_execution_requests", "agent_run_tokens", "work_items_schema_version",
}

// genericFunctions are the trigger functions the block creates in schema public.
var genericFunctions = []string{"execution_provenance_immutable", "work_item_context_snapshots_immutable"}

// genericGrants is what the work-items role holds on each table: exactly the
// DML its existing statements use (INSERT/UPDATE/DELETE/SELECT per table, read
// off the statements in this package). DELETE exists only on agent_run_tokens
// (the expiry sweep); no code path deletes a work item.
var genericGrants = []struct {
	Table      string
	Privileges []string
}{
	{"work_items", []string{"SELECT", "INSERT", "UPDATE"}},
	{"work_item_events", []string{"SELECT", "INSERT"}},
	{"work_item_intents", []string{"SELECT", "INSERT"}},
	{"work_item_executions", []string{"SELECT", "INSERT", "UPDATE"}},
	{"work_item_surface_refs", []string{"SELECT", "INSERT", "UPDATE"}},
	{"work_item_create_requests", []string{"SELECT", "INSERT"}},
	{"work_item_requests", []string{"SELECT", "INSERT"}},
	{"execution_provenance", []string{"SELECT", "INSERT"}},
	{"work_item_context_snapshots", []string{"SELECT", "INSERT"}},
	{"action_approval_requests", []string{"SELECT", "INSERT", "UPDATE"}},
	{"work_item_execution_requests", []string{"SELECT", "INSERT", "UPDATE"}},
	{"agent_run_tokens", []string{"SELECT", "INSERT", "UPDATE", "DELETE"}},
	{"work_items_schema_version", []string{"SELECT"}},
}

// ApplyOption configures ApplySchema and ApplyGlovoApprovalSchema.
type ApplyOption func(*applyConfig)

type applyConfig struct {
	workItemsRole string
	txSetup       TxSetup
}

// TxSetup runs first inside each schema transaction, before any lock is
// taken (see glovo.TxSetup). ApplyGlovoApprovalSchema runs two transactions
// (the generic block, then the approval block) and calls it in both.
type TxSetup func(ctx context.Context, tx pgx.Tx) error

// WithTxSetup installs a TxSetup.
func WithTxSetup(f TxSetup) ApplyOption { return func(c *applyConfig) { c.txSetup = f } }

// CompiledWorkItemsSchemaVersion is the version ApplySchema records in
// public.work_items_schema_version.
func CompiledWorkItemsSchemaVersion() int { return workItemsSchemaVersion }

// CompiledGlovoApprovalSchemaVersion is the version ApplyGlovoApprovalSchema
// records in glovo.approval_schema_version.
func CompiledGlovoApprovalSchemaVersion() int { return glovoApprovalSchemaVersion }

// WithWorkItemsRole names the work-items role (WORK_ITEMS_DB_URL) that
// receives the generic DML grants. Without it ApplySchema issues no generic
// grants. The #957 section 6d.1 signature carries only one role name, so the
// work-items role is passed here (OPEN-989-9 in the pull request).
func WithWorkItemsRole(role string) ApplyOption {
	return func(c *applyConfig) { c.workItemsRole = role }
}

func newApplyConfig(opts []ApplyOption) applyConfig {
	var c applyConfig
	for _, o := range opts {
		o(&c)
	}
	return c
}

// ApplySchema runs every statement NewStore runs, under the migration role,
// records the schema version and grants the work-items role (WithWorkItemsRole)
// its explicit DML. It runs in one transaction under an advisory lock, on an
// empty database and again with no change, and refuses a relation or function
// of the block that another role owns (the ownership transfer of an existing
// database is an operator step of the migration job), and a recorded version
// above the compiled one.
//
// runtimeRole is the role the caller will run work-items traffic as; it is
// validated and, when it is not the work-items role, receives nothing here.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string, opts ...ApplyOption) error {
	cfg := newApplyConfig(opts)
	if runtimeRole != "" && !roleNameRE.MatchString(runtimeRole) {
		return errors.New("workitems: invalid runtime role name")
	}
	if cfg.workItemsRole == "" {
		cfg.workItemsRole = runtimeRole
	}
	if cfg.workItemsRole != "" && !roleNameRE.MatchString(cfg.workItemsRole) {
		return errors.New("workitems: invalid work-items role name")
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("workitems: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("workitems: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if cfg.txSetup != nil {
		if err := cfg.txSetup(ctx, tx); err != nil {
			return fmt.Errorf("workitems: schema tx setup: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('workitems-schema'))`); err != nil {
		return fmt.Errorf("workitems: schema lock: %w", err)
	}
	if err := checkGenericOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('public.work_items_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("workitems: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM public.work_items_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("workitems: read schema version: %w", err)
		}
		if recorded != nil && *recorded > workItemsSchemaVersion {
			return fmt.Errorf("workitems: recorded schema version %d is above the compiled version %d", *recorded, workItemsSchemaVersion)
		}
	}
	for _, b := range genericSchemaBlocks {
		if _, err := tx.Exec(ctx, b.sql); err != nil {
			return fmt.Errorf("workitems: apply %s: %w", b.name, err)
		}
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.work_items_schema_version (version INT NOT NULL)`); err != nil {
		return fmt.Errorf("workitems: create schema version table: %w", err)
	}
	// IF NOT EXISTS must not have adopted a foreign object.
	if err := checkGenericOwnership(ctx, tx); err != nil {
		return err
	}
	if cfg.workItemsRole != "" {
		if err := grantGeneric(ctx, tx, cfg.workItemsRole); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.work_items_schema_version`); err != nil {
		return fmt.Errorf("workitems: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.work_items_schema_version (version) VALUES ($1)`, workItemsSchemaVersion); err != nil {
		return fmt.Errorf("workitems: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("workitems: commit schema: %w", err)
	}
	return nil
}

// grantGeneric makes the work-items role's rights on the generic tables equal
// genericGrants: revoke, then grant.
func grantGeneric(ctx context.Context, tx pgx.Tx, role string) error {
	r := pgx.Identifier{role}.Sanitize()
	for _, g := range genericGrants {
		tbl := pgx.Identifier{"public", g.Table}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+r); err != nil {
			return fmt.Errorf("workitems: revoke on %s: %w", g.Table, err)
		}
		if _, err := tx.Exec(ctx, `GRANT `+strings.Join(g.Privileges, ", ")+` ON TABLE `+tbl+` TO `+r); err != nil {
			return fmt.Errorf("workitems: grant on %s: %w", g.Table, err)
		}
	}
	if _, err := tx.Exec(ctx, `REVOKE ALL ON SEQUENCE public.work_item_intents_id_seq FROM `+r); err != nil {
		return fmt.Errorf("workitems: revoke sequence: %w", err)
	}
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SEQUENCE public.work_item_intents_id_seq TO `+r); err != nil {
		return fmt.Errorf("workitems: grant sequence: %w", err)
	}
	return nil
}

// GenericForeignOwned lists the relations and functions of the generic block
// that current_user (the migration role) does not own.
func GenericForeignOwned(ctx context.Context, q dbq.Querier) ([]string, error) {
	var out []string
	err := q.QueryRow(ctx, `
SELECT coalesce(array_agg(x ORDER BY x), '{}') FROM (
  SELECT 'public.' || c.relname AS x FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY($1) AND pg_get_userbyid(c.relowner) <> current_user
  UNION ALL
  SELECT 'public.' || p.proname || '()' FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = ANY($2) AND pg_get_userbyid(p.proowner) <> current_user) s`,
		genericRelations, genericFunctions).Scan(&out)
	if err != nil {
		return nil, fmt.Errorf("workitems: ownership check: %w", err)
	}
	return out, nil
}

// checkGenericOwnership refuses a relation or function of the generic block
// that current_user (the migration role) does not own.
func checkGenericOwnership(ctx context.Context, q dbq.Querier) error {
	foreign, err := GenericForeignOwned(ctx, q)
	if err != nil {
		return err
	}
	if len(foreign) != 0 {
		return errors.New("workitems: an object of the generic work-items schema is not owned by the migration role")
	}
	return nil
}

// ownsTables reports whether current_user may run the generic DDL: the tables
// do not exist yet, or current_user is (a member of) their owner.
func ownsTables(ctx context.Context, q dbq.Querier) (bool, error) {
	var oid *uint32
	var owns bool
	err := q.QueryRow(ctx, `SELECT c.oid, pg_has_role(current_user, c.relowner, 'MEMBER')
  FROM pg_class c WHERE c.oid = to_regclass('public.work_items')`).Scan(&oid, &owns)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return owns, nil
}

// verifySchemaVersion is NewStore's check when it does not own the tables.
func verifySchemaVersion(ctx context.Context, q dbq.Querier) error {
	rows, err := q.Query(ctx, `SELECT version FROM public.work_items_schema_version`)
	if err != nil {
		return fmt.Errorf("workitems: read schema version (was ApplySchema run?): %w", err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("workitems: scan schema version: %w", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("workitems: read schema version: %w", err)
	}
	if len(got) != 1 || got[0] != workItemsSchemaVersion {
		return fmt.Errorf("workitems: schema version %v does not match the compiled version %d", got, workItemsSchemaVersion)
	}
	return nil
}
