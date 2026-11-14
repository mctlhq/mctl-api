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
	"strings"

	"github.com/jackc/pgx/v5"
)

// ReadSchemaLevel is the compiled level of the v1alpha2 read schema.
// bridge_read_schema_version holds the level ApplyReadSchemaTx applied; the
// read paths refuse (ErrReadUnavailable) below it.
const ReadSchemaLevel = 1

const readKindList = `'read_history','read_preview','read_basket'`

// Querier is the read side shared by a pool and a transaction.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// CheckReadLevel reports ErrReadUnavailable when bridge_read_schema_version is
// missing or below ReadSchemaLevel. It never errors a transaction: the table
// is probed with to_regclass before it is read.
func CheckReadLevel(ctx context.Context, q Querier) error {
	var present bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('bridge_read_schema_version') IS NOT NULL`).Scan(&present); err != nil {
		return fmt.Errorf("%w: read level probe: %v", ErrReadUnavailable, err)
	}
	if !present {
		return fmt.Errorf("%w: read schema not applied", ErrReadUnavailable)
	}
	var level int
	switch err := q.QueryRow(ctx, `SELECT COALESCE(max(level), 0) FROM bridge_read_schema_version`).Scan(&level); {
	case err != nil:
		return fmt.Errorf("%w: read level: %v", ErrReadUnavailable, err)
	case level < ReadSchemaLevel:
		return fmt.Errorf("%w: read schema level %d is below %d", ErrReadUnavailable, level, ReadSchemaLevel)
	}
	return nil
}

// ApplyReadSchemaTx is the one owner of the v1alpha2 read DDL. It runs in the
// caller's transaction under the migration role, which must own
// bridge_commands; the runtime role cannot run it. Every step tests the
// catalog first, so a second and every later run changes nothing and takes no
// ACCESS EXCLUSIVE lock. Nothing is dropped and re-added on a normal run, no
// NOT NULL is relaxed, and the level row is written last.
//
// runtimeRole, when non-empty, receives the grants of mctl-api#957 design
// 6d.1: SELECT, INSERT, DELETE and UPDATE (data, erased_at) on
// bridge_read_results, and SELECT on bridge_read_schema_version. The table
// level grant the runtime role already holds on bridge_commands covers the
// new columns.
func ApplyReadSchemaTx(ctx context.Context, tx pgx.Tx, runtimeRole string) error {
	exec := func(what, sql string, args ...any) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("bridge: read schema %s: %w", what, err)
		}
		return nil
	}
	exists := func(sql string, args ...any) (bool, error) {
		var ok bool
		if err := tx.QueryRow(ctx, sql, args...).Scan(&ok); err != nil {
			return false, fmt.Errorf("bridge: read schema probe: %w", err)
		}
		return ok, nil
	}

	// Concurrent migrators serialize here; released with the transaction.
	if err := exec("lock", `SELECT pg_advisory_xact_lock(hashtext('mctl-bridge-read-schema'))`); err != nil {
		return err
	}
	var owned *bool
	if err := tx.QueryRow(ctx, `SELECT (pg_get_userbyid(c.relowner) = current_user) FROM pg_class c WHERE c.oid = to_regclass('bridge_commands')`).Scan(&owned); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bridge: read schema owner check: %w", err)
	}
	if owned == nil {
		return errors.New("bridge: read schema: bridge_commands does not exist")
	}
	if !*owned {
		return errors.New("bridge: read schema: bridge_commands is not owned by the migration role")
	}

	for _, col := range []string{"wire_version", "read_request_id", "install_revision_ref"} {
		have, err := exists(`SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('bridge_commands')
			AND attname = $1 AND NOT attisdropped)`, col)
		if err != nil {
			return err
		}
		if have {
			continue
		}
		ddl := map[string]string{
			"wire_version":         `ALTER TABLE bridge_commands ADD COLUMN IF NOT EXISTS wire_version TEXT NOT NULL DEFAULT 'bridge.mctl.ai/v1alpha1'`,
			"read_request_id":      `ALTER TABLE bridge_commands ADD COLUMN IF NOT EXISTS read_request_id TEXT`,
			"install_revision_ref": `ALTER TABLE bridge_commands ADD COLUMN IF NOT EXISTS install_revision_ref TEXT`,
		}[col]
		if err := exec("column "+col, ddl); err != nil {
			return err
		}
	}

	hasConstraint := func(name string) (bool, error) {
		return exists(`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = to_regclass('bridge_commands') AND conname = $1)`, name)
	}
	// Constraints are added NOT VALID, then validated once in the same guarded
	// step (VALIDATE takes only SHARE UPDATE EXCLUSIVE).
	for _, c := range []struct{ name, ddl string }{
		{"bridge_commands_kind_v2_chk", `ALTER TABLE bridge_commands DROP CONSTRAINT IF EXISTS bridge_commands_kind_chk,
			ADD CONSTRAINT bridge_commands_kind_v2_chk CHECK (operation_kind IN
			('quote','read_status','place_order_fake','cancel_order_fake',` + readKindList + `)) NOT VALID`},
		{"bridge_commands_read_shape_chk", `ALTER TABLE bridge_commands ADD CONSTRAINT bridge_commands_read_shape_chk CHECK (
			(operation_kind IN (` + readKindList + `)
				AND wire_version = 'bridge.mctl.ai/v1alpha2'
				AND read_request_id IS NOT NULL
				AND COALESCE(install_revision_ref ~ '^irv_[A-Za-z0-9]{16,40}$', false)
				AND workflow_id = '' AND order_ref = '' AND execution_id = '' AND work_item_id = '')
			OR (operation_kind NOT IN (` + readKindList + `)
				AND install_revision_ref IS NULL AND read_request_id IS NULL
				AND workflow_id <> '' AND order_ref <> '' AND execution_id <> '' AND work_item_id <> '')) NOT VALID`},
		{"bridge_commands_wire_version_chk", `ALTER TABLE bridge_commands ADD CONSTRAINT bridge_commands_wire_version_chk CHECK (
			wire_version = 'bridge.mctl.ai/v1alpha1'
			OR (wire_version = 'bridge.mctl.ai/v1alpha2' AND (operation_kind IN (` + readKindList + `)
				OR (operation_kind = 'place_order_fake' AND approval_ref <> '')))) NOT VALID`},
	} {
		have, err := hasConstraint(c.name)
		if err != nil {
			return err
		}
		if have {
			continue
		}
		if err := exec("constraint "+c.name, c.ddl); err != nil {
			return err
		}
		if err := exec("validate "+c.name, `ALTER TABLE bridge_commands VALIDATE CONSTRAINT `+c.name); err != nil {
			return err
		}
	}

	// bridge_commands_sequence becomes a partial unique index that excludes the
	// read kinds (every read has execution_id '' and sequence 1).
	var indexdef *string
	if err := tx.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema()
		AND tablename = 'bridge_commands' AND indexname = 'bridge_commands_sequence'`).Scan(&indexdef); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bridge: read schema index probe: %w", err)
	}
	if indexdef == nil || !strings.Contains(*indexdef, "operation_kind") {
		if indexdef != nil {
			if err := exec("drop sequence index", `DROP INDEX bridge_commands_sequence`); err != nil {
				return err
			}
		}
		if err := exec("sequence index", `CREATE UNIQUE INDEX bridge_commands_sequence ON bridge_commands (execution_id, sequence)
			WHERE operation_kind NOT IN (`+readKindList+`)`); err != nil {
			return err
		}
	}
	haveIdx, err := exists(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
		AND tablename = 'bridge_commands' AND indexname = 'bridge_commands_read_request')`)
	if err != nil {
		return err
	}
	if !haveIdx {
		if err := exec("read request index", `CREATE UNIQUE INDEX bridge_commands_read_request ON bridge_commands (tenant, read_request_id)
			WHERE read_request_id IS NOT NULL`); err != nil {
			return err
		}
	}

	haveResults, err := exists(`SELECT to_regclass('bridge_read_results') IS NOT NULL`)
	if err != nil {
		return err
	}
	if !haveResults {
		if err := exec("results table", `CREATE TABLE bridge_read_results (
			result_ref         TEXT        PRIMARY KEY,
			command_id         TEXT        NOT NULL UNIQUE,
			read_kind          TEXT        NOT NULL,
			tenant             TEXT        NOT NULL,
			owner_principal_id TEXT        NOT NULL,
			tenant_ref         TEXT        NOT NULL,
			principal_ref      TEXT        NOT NULL,
			connection_ref     TEXT        NOT NULL,
			install_revision   TEXT        NOT NULL,
			data               BYTEA,
			data_digest        TEXT        NOT NULL,
			size_bytes         INTEGER     NOT NULL,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
			expires_at         TIMESTAMPTZ NOT NULL,
			erased_at          TIMESTAMPTZ,
			CONSTRAINT bridge_read_results_kind_chk CHECK (read_kind IN (`+readKindList+`))
		)`); err != nil {
			return err
		}
		if err := exec("results index", `CREATE INDEX bridge_read_results_expires ON bridge_read_results (expires_at)`); err != nil {
			return err
		}
	}
	haveLevel, err := exists(`SELECT to_regclass('bridge_read_schema_version') IS NOT NULL`)
	if err != nil {
		return err
	}
	if !haveLevel {
		if err := exec("level table", `CREATE TABLE bridge_read_schema_version (level INT NOT NULL)`); err != nil {
			return err
		}
	}

	if runtimeRole != "" {
		roleOK, err := exists(`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, runtimeRole)
		if err != nil {
			return err
		}
		if !roleOK {
			return fmt.Errorf("bridge: read schema: runtime role %q does not exist", runtimeRole)
		}
		role := pgx.Identifier{runtimeRole}.Sanitize()
		has, err := exists(`SELECT has_table_privilege($1, 'bridge_read_results', 'SELECT')
			AND has_table_privilege($1, 'bridge_read_results', 'INSERT')
			AND has_table_privilege($1, 'bridge_read_results', 'DELETE')
			AND has_column_privilege($1, 'bridge_read_results', 'data', 'UPDATE')
			AND has_column_privilege($1, 'bridge_read_results', 'erased_at', 'UPDATE')`, runtimeRole)
		if err != nil {
			return err
		}
		if !has {
			if err := exec("results grant", `GRANT SELECT, INSERT, DELETE, UPDATE (data, erased_at) ON bridge_read_results TO `+role); err != nil {
				return err
			}
		}
		has, err = exists(`SELECT has_table_privilege($1, 'bridge_read_schema_version', 'SELECT')`, runtimeRole)
		if err != nil {
			return err
		}
		if !has {
			if err := exec("level grant", `GRANT SELECT ON bridge_read_schema_version TO `+role); err != nil {
				return err
			}
		}
	}

	// The level row is written last: a half-applied schema never reports ready.
	var cur *int
	if err := tx.QueryRow(ctx, `SELECT max(level) FROM bridge_read_schema_version`).Scan(&cur); err != nil {
		return fmt.Errorf("bridge: read schema level probe: %w", err)
	}
	switch {
	case cur == nil:
		return exec("level row", `INSERT INTO bridge_read_schema_version (level) VALUES ($1)`, ReadSchemaLevel)
	case *cur < ReadSchemaLevel:
		return exec("level row", `UPDATE bridge_read_schema_version SET level = $1`, ReadSchemaLevel)
	}
	return nil
}
