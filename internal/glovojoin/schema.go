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

package glovojoin

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// schemaVersion is the version recorded in glovo.join_schema_version.
const schemaVersion = 1

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// joinSchema is the DDL of the four join tables (mctl-api#957 design 5, 5a,
// 2b, 6c), in schema glovo. It is idempotent and is run only by ApplySchema,
// under the migration role that owns every object. The runtime role never
// runs DDL. Every key holds opaque values only: no payload, token or secret.
const joinSchema = `
CREATE TABLE IF NOT EXISTS glovo.join_previews (
  id TEXT PRIMARY KEY CHECK (id ~ '^gpv_[A-Za-z0-9_-]{22,64}$'),
  tenant TEXT NOT NULL, principal_id TEXT NOT NULL, connection_id TEXT NOT NULL,
  install_id TEXT NOT NULL, install_revision BIGINT NOT NULL CHECK (install_revision >= 1),
  approval_basket BYTEA, fingerprint TEXT NOT NULL DEFAULT '',
  payload_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  consumed_order_ref TEXT CHECK (consumed_order_ref ~ '^ordr_[A-Za-z0-9]{16,40}$'),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CHECK ((approval_basket IS NULL AND fingerprint = '')
      OR fingerprint = 'sha256:' || encode(sha256(approval_basket), 'hex')));
CREATE UNIQUE INDEX IF NOT EXISTS join_previews_consumed
  ON glovo.join_previews (consumed_order_ref) WHERE consumed_order_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS join_previews_expires ON glovo.join_previews (expires_at);

CREATE TABLE IF NOT EXISTS glovo.join_scope_refs (
  ref_hash TEXT PRIMARY KEY CHECK (ref_hash ~ '^[0-9a-f]{64}$'),
  principal_id TEXT NOT NULL, tenant TEXT NOT NULL,
  install_id TEXT NOT NULL, install_revision BIGINT NOT NULL CHECK (install_revision >= 1),
  grant_family_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'));
CREATE INDEX IF NOT EXISTS join_scope_refs_expires ON glovo.join_scope_refs (expires_at);

CREATE TABLE IF NOT EXISTS glovo.join_read_refs (
  tenant TEXT NOT NULL, principal_id TEXT NOT NULL, connection_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pho','cursor')),
  ref TEXT NOT NULL CHECK (ref <> ''),
  created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant, principal_id, connection_id, kind, ref),
  CHECK (expires_at > created_at));
CREATE INDEX IF NOT EXISTS join_read_refs_expires ON glovo.join_read_refs (expires_at);

CREATE TABLE IF NOT EXISTS glovo.control_starts (
  order_ref TEXT PRIMARY KEY CHECK (order_ref ~ '^ordr_[A-Za-z0-9]{16,40}$'),
  workflow_id TEXT NOT NULL UNIQUE,
  input BYTEA NOT NULL,
  input_digest TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','started','failed_terminal')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TIMESTAMPTZ NOT NULL,
  started_run_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  CHECK (input_digest = 'sha256:' || encode(sha256(input), 'hex')),
  CHECK (workflow_id LIKE 'asst-glovo-%' AND right(workflow_id, length(order_ref) + 1) = '-' || order_ref),
  CHECK (state <> 'started' OR started_run_id <> ''),
  CHECK (state = 'started' OR started_run_id = ''));
CREATE INDEX IF NOT EXISTS control_starts_due ON glovo.control_starts (next_attempt_at) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS glovo.join_schema_version (version INT NOT NULL);
`

// joinTables are the tables of this slice. The version table is last.
var joinTables = []string{"join_previews", "join_scope_refs", "join_read_refs", "control_starts", "join_schema_version"}

// controlStartUpdateColumns is the only column-level UPDATE the runtime role
// holds on control_starts: input and input_digest are INSERT-only (design 6c,
// round 4 F2), so a runtime bug cannot rewrite the stored workflow input.
var controlStartUpdateColumns = []string{"state", "attempts", "next_attempt_at", "started_run_id", "updated_at"}

// The #957 rows of design 6d.1, registered with the #959 registry. Whoever
// wires glovojoin into cmd/api must import this package there, so the rows
// exist when glovo.Ready compares the schema with the registry.
func init() {
	sweepable := []string{"SELECT", "INSERT", "DELETE"}
	glovo.RegisterGrants(
		glovo.GrantRow{Table: "join_previews", Privileges: sweepable, UpdateColumns: []string{"consumed_order_ref"}, Description: "preview rows; bounded expiry sweep; single-use claim column only"},
		glovo.GrantRow{Table: "join_scope_refs", Privileges: sweepable, Description: "hashed scope refs; bounded expiry sweep"},
		glovo.GrantRow{Table: "join_read_refs", Privileges: sweepable, Description: "issued history refs and cursors; bounded expiry sweep"},
		glovo.GrantRow{Table: "control_starts", Privileges: []string{"SELECT", "INSERT"}, UpdateColumns: controlStartUpdateColumns, Description: "workflow-start outbox; input and digest are insert-only"},
		glovo.GrantRow{Table: "join_schema_version", Privileges: []string{"SELECT"}, Description: "recorded join schema version, read at start"},
	)
}

// ApplySchema creates schema glovo and the join tables, grants the runtime
// role exactly the registered rows and records the schema version. It runs
// only under the migration role, which becomes the owner of every object, in
// one transaction under the schema advisory locks. It refuses a schema or an
// object in schema glovo that another role owns, a recorded version above the
// compiled one, and a runtimeRole that does not match ^[a-z_][a-z0-9_]{0,62}$.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string) error {
	if !roleNameRE.MatchString(runtimeRole) {
		return fmt.Errorf("glovo join: invalid runtime role name")
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("glovo join: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovo join: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The other slices take their own lock and the #959 one for their DDL: all
	// of them write schema glovo.
	for _, key := range []string{"glovo-join-schema", "glovo-schema"} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return fmt.Errorf("glovo join: schema lock: %w", err)
		}
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS glovo`); err != nil {
		return fmt.Errorf("glovo join: create schema: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('glovo.join_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("glovo join: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM glovo.join_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("glovo join: read schema version: %w", err)
		}
		if recorded != nil && *recorded > schemaVersion {
			return fmt.Errorf("glovo join: recorded schema version %d is above the compiled version %d", *recorded, schemaVersion)
		}
	}
	if _, err := tx.Exec(ctx, joinSchema); err != nil {
		return fmt.Errorf("glovo join: apply schema: %w", err)
	}
	// IF NOT EXISTS must not have adopted a foreign object.
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}

	role := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := tx.Exec(ctx, `GRANT USAGE ON SCHEMA glovo TO `+role); err != nil {
		return fmt.Errorf("glovo join: grant schema usage: %w", err)
	}
	for _, t := range joinTables {
		row, ok := glovo.GrantFor(t)
		if !ok {
			return fmt.Errorf("glovo join: no grant row registered for %s", t)
		}
		tbl := pgx.Identifier{"glovo", t}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
			return fmt.Errorf("glovo join: revoke on %s: %w", t, err)
		}
		if len(row.Privileges) > 0 {
			if _, err := tx.Exec(ctx, `GRANT `+strings.Join(row.Privileges, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo join: grant on %s: %w", t, err)
			}
		}
		if len(row.UpdateColumns) > 0 {
			cols := make([]string, len(row.UpdateColumns))
			for i, c := range row.UpdateColumns {
				cols[i] = pgx.Identifier{c}.Sanitize()
			}
			if _, err := tx.Exec(ctx, `GRANT UPDATE (`+strings.Join(cols, ", ")+`) ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo join: grant columns on %s: %w", t, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.join_schema_version`); err != nil {
		return fmt.Errorf("glovo join: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.join_schema_version (version) VALUES ($1)`, schemaVersion); err != nil {
		return fmt.Errorf("glovo join: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovo join: commit schema: %w", err)
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
		return fmt.Errorf("glovo join: ownership check: %w", err)
	}
	if bad != 0 {
		return fmt.Errorf("glovo join: schema glovo or an object in it is not owned by the migration role")
	}
	return nil
}
