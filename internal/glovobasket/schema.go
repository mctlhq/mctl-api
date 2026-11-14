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

package glovobasket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// SchemaVersion is the version recorded in glovo.basket_schema_version.
// Version 2 adds the frozen snapshot of the approved revision to
// glovo.basket_approval_bindings (snapshot_canonical, snapshot_lines), so an
// approval no longer needs basket_revisions to be shown or re-checked; the
// foreign key into basket_revisions stays until the basket tables move out
// of this database.
const SchemaVersion = 2

// MinVerifiedSchemaVersion is the oldest recorded version VerifySchema still
// accepts. A build that knows version 2 keeps serving a database that is
// still at version 1 (it then writes no snapshot itself: the database fills
// it once migrated), so deploying the binary and running the migrator can
// happen in either order.
const MinVerifiedSchemaVersion = 1

// approvalSchemaMin is the glovo approval schema version that has
// glovo.basket_approval_bindings (internal/workitems).
const approvalSchemaMin = 2

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

var basketTables = []string{"baskets", "basket_revisions", "basket_schema_version"}

// The rows of the runtime role, registered with the #959 registry so
// glovo.Store.Ready compares them with the catalog. cmd/api imports this
// package, so they exist wherever that check runs.
func init() {
	glovo.RegisterGrants(
		glovo.GrantRow{Table: "baskets", Privileges: []string{"SELECT", "INSERT"},
			UpdateColumns: []string{"current_revision", "updated_at"},
			Description:   "basket heads (mctl-api#1006); identity immutable, no delete"},
		glovo.GrantRow{Table: "basket_revisions", Privileges: []string{"SELECT", "INSERT"},
			Description: "frozen basket revisions (mctl-api#1006); insert-only"},
		glovo.GrantRow{Table: "basket_schema_version", Privileges: []string{"SELECT"},
			Description: "recorded basket schema version, read at start"},
	)
}

// basketSchema is the DDL of the basket tables. It is idempotent and is run
// only by ApplySchema, under the migration role. A revision is immutable once
// written; an update of a basket appends a revision. The approval binding
// table of internal/workitems gets a foreign key to the exact revision, so an
// approval can only ever name a revision that exists, of the same owner's own
// basket, with the same fingerprint.
const basketSchema = `
CREATE TABLE IF NOT EXISTS glovo.baskets (
  basket_id          TEXT PRIMARY KEY CHECK (basket_id ~ '^gbk_[A-Za-z0-9]{26}$'),
  tenant             TEXT NOT NULL CHECK (tenant <> ''),
  owner_principal_id TEXT NOT NULL CHECK (owner_principal_id LIKE 'prn\_%'),
  client_key         TEXT NOT NULL CHECK (length(client_key) BETWEEN 1 AND 128),
  current_revision   BIGINT NOT NULL CHECK (current_revision >= 1),
  created_at         TIMESTAMPTZ NOT NULL,
  updated_at         TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant, owner_principal_id, client_key),
  UNIQUE (basket_id, tenant, owner_principal_id));
CREATE INDEX IF NOT EXISTS baskets_owner ON glovo.baskets (tenant, owner_principal_id);

CREATE TABLE IF NOT EXISTS glovo.basket_revisions (
  basket_id          TEXT NOT NULL,
  revision           BIGINT NOT NULL CHECK (revision >= 1),
  tenant             TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  lines              JSONB NOT NULL CHECK (jsonb_typeof(lines) = 'array' AND jsonb_array_length(lines) <= 30),
  currency           TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  store_ref          TEXT NOT NULL CHECK (store_ref ~ '^pst_[A-Za-z0-9]{16,40}$'),
  subtotal_minor     BIGINT NOT NULL CHECK (subtotal_minor >= 0),
  delivery_fee_minor BIGINT NOT NULL CHECK (delivery_fee_minor >= 0),
  service_fee_minor  BIGINT NOT NULL CHECK (service_fee_minor >= 0),
  discount_minor     BIGINT NOT NULL CHECK (discount_minor >= 0),
  total_minor        BIGINT NOT NULL CHECK (total_minor >= 0),
  canonical          BYTEA,
  basket_fingerprint TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (basket_id, revision),
  FOREIGN KEY (basket_id, tenant, owner_principal_id) REFERENCES glovo.baskets (basket_id, tenant, owner_principal_id),
  UNIQUE (basket_id, revision, basket_fingerprint, tenant, owner_principal_id),
  CHECK (total_minor = subtotal_minor + delivery_fee_minor + service_fee_minor - discount_minor),
  CHECK ((canonical IS NULL AND basket_fingerprint = '' AND jsonb_array_length(lines) = 0)
      OR (canonical IS NOT NULL AND jsonb_array_length(lines) > 0
          AND basket_fingerprint = 'sha256:' || encode(sha256(canonical), 'hex'))));

CREATE TABLE IF NOT EXISTS glovo.basket_schema_version (version INT NOT NULL);

-- A revision is frozen: no UPDATE, no DELETE, whoever asks.
CREATE OR REPLACE FUNCTION glovo.basket_revisions_frozen() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION 'a basket revision is immutable' USING ERRCODE = 'integrity_constraint_violation';
END
$f$;

-- A basket head keeps its identity and only moves forward; it is never deleted.
CREATE OR REPLACE FUNCTION glovo.baskets_guard() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'a basket is never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.basket_id <> OLD.basket_id OR NEW.tenant <> OLD.tenant OR NEW.owner_principal_id <> OLD.owner_principal_id
     OR NEW.client_key <> OLD.client_key OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'a basket keeps its identity' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.current_revision <> OLD.current_revision + 1 THEN
    RAISE EXCEPTION 'a basket moves one revision at a time' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM glovo.basket_revisions r WHERE r.basket_id = NEW.basket_id AND r.revision = NEW.current_revision) THEN
    RAISE EXCEPTION 'a basket points at a written revision' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$f$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'basket_revisions_frozen' AND tgrelid = 'glovo.basket_revisions'::regclass) THEN
    CREATE TRIGGER basket_revisions_frozen BEFORE UPDATE OR DELETE ON glovo.basket_revisions
      FOR EACH ROW EXECUTE FUNCTION glovo.basket_revisions_frozen();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'basket_revisions_no_truncate' AND tgrelid = 'glovo.basket_revisions'::regclass) THEN
    CREATE TRIGGER basket_revisions_no_truncate BEFORE TRUNCATE ON glovo.basket_revisions
      FOR EACH STATEMENT EXECUTE FUNCTION glovo.basket_revisions_frozen();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'baskets_guard' AND tgrelid = 'glovo.baskets'::regclass) THEN
    CREATE TRIGGER baskets_guard BEFORE UPDATE OR DELETE ON glovo.baskets
      FOR EACH ROW EXECUTE FUNCTION glovo.baskets_guard();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'basket_approval_bindings_revision_fk'
                  AND conrelid = 'glovo.basket_approval_bindings'::regclass) THEN
    ALTER TABLE glovo.basket_approval_bindings ADD CONSTRAINT basket_approval_bindings_revision_fk
      FOREIGN KEY (basket_id, revision, basket_fingerprint, tenant, owner_principal_id)
      REFERENCES glovo.basket_revisions (basket_id, revision, basket_fingerprint, tenant, owner_principal_id);
  END IF;
END $$;
ALTER TABLE glovo.basket_revisions ENABLE TRIGGER basket_revisions_frozen;
ALTER TABLE glovo.basket_revisions ENABLE TRIGGER basket_revisions_no_truncate;
ALTER TABLE glovo.baskets ENABLE TRIGGER baskets_guard;
` + basketSnapshotSchema

// basketSnapshotSchema is version 2: every basket approval binding carries
// the canonical form and the priced lines of the revision it approves, frozen
// with it. The fingerprint CHECK ties the snapshot to the binding's own
// basket_fingerprint, so a snapshot that is not the approved content cannot
// be stored. Existing bindings are backfilled from basket_revisions (the
// foreign key guarantees the revision exists), and a binding inserted without
// a snapshot, by a build that does not write one yet, is filled from the same
// revision by a BEFORE INSERT trigger; a binding whose revision cannot be
// found keeps a NULL snapshot and the CHECK refuses it.
//
// The table is otherwise insert-only (basket_approval_bindings_guard): the
// backfill disables that guard for its one UPDATE, inside this transaction,
// under the table lock, and enables it again before the transaction ends, so
// no other session ever sees it disabled.
const basketSnapshotSchema = `
LOCK TABLE glovo.basket_approval_bindings IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE glovo.basket_approval_bindings
  ADD COLUMN IF NOT EXISTS snapshot_canonical BYTEA,
  ADD COLUMN IF NOT EXISTS snapshot_lines JSONB;

CREATE OR REPLACE FUNCTION glovo.basket_approval_bindings_snapshot() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.snapshot_canonical IS NULL AND NEW.snapshot_lines IS NULL THEN
    SELECT r.canonical, r.lines INTO NEW.snapshot_canonical, NEW.snapshot_lines
      FROM glovo.basket_revisions r
     WHERE r.basket_id = NEW.basket_id AND r.revision = NEW.revision AND r.basket_fingerprint = NEW.basket_fingerprint
       AND r.tenant = NEW.tenant AND r.owner_principal_id = NEW.owner_principal_id;
  END IF;
  RETURN NEW;
END
$f$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM glovo.basket_approval_bindings WHERE snapshot_canonical IS NULL OR snapshot_lines IS NULL) THEN
    ALTER TABLE glovo.basket_approval_bindings DISABLE TRIGGER basket_approval_bindings_guard;
    UPDATE glovo.basket_approval_bindings b SET snapshot_canonical = r.canonical, snapshot_lines = r.lines
      FROM glovo.basket_revisions r
     WHERE (b.snapshot_canonical IS NULL OR b.snapshot_lines IS NULL)
       AND r.basket_id = b.basket_id AND r.revision = b.revision AND r.basket_fingerprint = b.basket_fingerprint
       AND r.tenant = b.tenant AND r.owner_principal_id = b.owner_principal_id;
    ALTER TABLE glovo.basket_approval_bindings ENABLE TRIGGER basket_approval_bindings_guard;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'basket_approval_bindings_snapshot_chk'
                  AND conrelid = 'glovo.basket_approval_bindings'::regclass) THEN
    ALTER TABLE glovo.basket_approval_bindings ADD CONSTRAINT basket_approval_bindings_snapshot_chk
      CHECK (snapshot_canonical IS NOT NULL AND snapshot_lines IS NOT NULL
             AND basket_fingerprint = 'sha256:' || encode(sha256(snapshot_canonical), 'hex')
             AND jsonb_typeof(snapshot_lines) = 'array'
             AND jsonb_array_length(snapshot_lines) BETWEEN 1 AND 30) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'basket_approval_bindings_snapshot'
                  AND tgrelid = 'glovo.basket_approval_bindings'::regclass) THEN
    CREATE TRIGGER basket_approval_bindings_snapshot BEFORE INSERT ON glovo.basket_approval_bindings
      FOR EACH ROW EXECUTE FUNCTION glovo.basket_approval_bindings_snapshot();
  END IF;
END $$;
ALTER TABLE glovo.basket_approval_bindings VALIDATE CONSTRAINT basket_approval_bindings_snapshot_chk;
ALTER TABLE glovo.basket_approval_bindings ENABLE TRIGGER basket_approval_bindings_guard;
ALTER TABLE glovo.basket_approval_bindings ENABLE TRIGGER basket_approval_bindings_snapshot;
`

// ApplySchema creates the basket tables, grants the runtime role exactly the
// registered rows and records the schema version, in one transaction under
// the migration role. Nothing in cmd/api calls it: the schema is applied by an
// operator (or a test), never at boot. It needs the glovo approval schema of
// internal/workitems at version 2 or later, which owns
// glovo.basket_approval_bindings.
func ApplySchema(ctx context.Context, migrationConnStr, runtimeRole string, opts ...SchemaOption) error {
	var cfg schemaConfig
	for _, o := range opts {
		o(&cfg)
	}
	if !roleNameRE.MatchString(runtimeRole) {
		return errors.New("glovo basket: invalid runtime role name")
	}
	conn, err := pgx.Connect(ctx, migrationConnStr)
	if err != nil {
		return fmt.Errorf("glovo basket: connect as migration role: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovo basket: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if cfg.txSetup != nil {
		if err := cfg.txSetup(ctx, tx); err != nil {
			return fmt.Errorf("glovo basket: schema tx setup: %w", err)
		}
	}
	for _, key := range []string{"glovo-basket-schema", "glovo-approval-schema", "glovo-schema"} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
			return fmt.Errorf("glovo basket: schema lock: %w", err)
		}
	}
	var approvalVersion *int
	if err := tx.QueryRow(ctx, `SELECT CASE WHEN to_regclass('glovo.approval_schema_version') IS NULL THEN NULL
		ELSE (SELECT max(version) FROM glovo.approval_schema_version) END`).Scan(&approvalVersion); err != nil {
		return fmt.Errorf("glovo basket: read approval schema version: %w", err)
	}
	if approvalVersion == nil || *approvalVersion < approvalSchemaMin {
		return fmt.Errorf("glovo basket: the glovo approval schema must be at version %d or later first", approvalSchemaMin)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	var haveVersion bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('glovo.basket_schema_version') IS NOT NULL`).Scan(&haveVersion); err != nil {
		return fmt.Errorf("glovo basket: probe schema version: %w", err)
	}
	if haveVersion {
		var recorded *int
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM glovo.basket_schema_version`).Scan(&recorded); err != nil {
			return fmt.Errorf("glovo basket: read schema version: %w", err)
		}
		if recorded != nil && *recorded > SchemaVersion {
			return fmt.Errorf("glovo basket: recorded schema version %d is above the compiled version %d", *recorded, SchemaVersion)
		}
	}
	if _, err := tx.Exec(ctx, basketSchema); err != nil {
		return fmt.Errorf("glovo basket: apply schema: %w", err)
	}
	if err := checkOwnership(ctx, tx); err != nil {
		return err
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, t := range basketTables {
		row, ok := glovo.GrantFor(t)
		if !ok {
			return fmt.Errorf("glovo basket: no grant row registered for %s", t)
		}
		tbl := pgx.Identifier{"glovo", t}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON TABLE `+tbl+` FROM `+role); err != nil {
			return fmt.Errorf("glovo basket: revoke on %s: %w", t, err)
		}
		if _, err := tx.Exec(ctx, `GRANT `+strings.Join(row.Privileges, ", ")+` ON TABLE `+tbl+` TO `+role); err != nil {
			return fmt.Errorf("glovo basket: grant on %s: %w", t, err)
		}
		if len(row.UpdateColumns) > 0 {
			cols := make([]string, len(row.UpdateColumns))
			for i, c := range row.UpdateColumns {
				cols[i] = pgx.Identifier{c}.Sanitize()
			}
			if _, err := tx.Exec(ctx, `GRANT UPDATE (`+strings.Join(cols, ", ")+`) ON TABLE `+tbl+` TO `+role); err != nil {
				return fmt.Errorf("glovo basket: grant columns on %s: %w", t, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM glovo.basket_schema_version`); err != nil {
		return fmt.Errorf("glovo basket: reset schema version: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.basket_schema_version (version) VALUES ($1)`, SchemaVersion); err != nil {
		return fmt.Errorf("glovo basket: record schema version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovo basket: commit schema: %w", err)
	}
	return nil
}

// ForeignOwned lists schema glovo, and the basket relations and functions in
// it, that current_user (the migration role) does not own: what ApplySchema
// refuses. The migrator's preflight calls it too.
func ForeignOwned(ctx context.Context, q dbq.Querier) ([]string, error) {
	var out []string
	if err := q.QueryRow(ctx, `
SELECT coalesce(array_agg(x ORDER BY x), '{}') FROM (
  SELECT 'schema glovo' AS x FROM pg_namespace WHERE nspname = 'glovo' AND pg_get_userbyid(nspowner) <> current_user
  UNION ALL
  SELECT 'glovo.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'glovo' AND c.relname = ANY($1) AND pg_get_userbyid(c.relowner) <> current_user
  UNION ALL
  SELECT 'glovo.' || p.proname || '()' FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'glovo' AND p.proname IN ('basket_revisions_frozen', 'baskets_guard', 'basket_approval_bindings_snapshot')
      AND pg_get_userbyid(p.proowner) <> current_user) s`, basketTables).Scan(&out); err != nil {
		return nil, fmt.Errorf("glovo basket: ownership check: %w", err)
	}
	return out, nil
}

func checkOwnership(ctx context.Context, tx pgx.Tx) error {
	foreign, err := ForeignOwned(ctx, tx)
	if err != nil {
		return err
	}
	if len(foreign) != 0 {
		return errors.New("glovo basket: schema glovo or a basket object in it is not owned by the migration role")
	}
	return nil
}

// ErrSchemaNotReady is VerifySchema's refusal: the schema was read and is not
// what this build needs.
var ErrSchemaNotReady = errors.New("glovo basket: schema not ready")

// VerifySchema is the boot check of cmd/api; see VerifySchemaVersion.
func VerifySchema(ctx context.Context, q dbq.Querier) error {
	_, err := VerifySchemaVersion(ctx, q)
	return err
}

// VerifySchemaVersion checks that the recorded version is one this build
// serves (MinVerifiedSchemaVersion to SchemaVersion), that every guard
// trigger of that version is present and enabled, and that the binding
// foreign key exists; at version 2 also that the snapshot trigger is enabled
// and the snapshot CHECK is validated. It returns the recorded version. A
// failed read is returned as is, never as "absent" and never as a version.
func VerifySchemaVersion(ctx context.Context, q dbq.Querier) (int, error) {
	var version *int
	var triggers, fk, snapTrigger, snapCheck int
	if err := q.QueryRow(ctx, `
SELECT (SELECT max(version) FROM glovo.basket_schema_version),
       (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'glovo' AND t.tgenabled = 'O'
           AND ((c.relname = 'basket_revisions' AND t.tgname IN ('basket_revisions_frozen', 'basket_revisions_no_truncate'))
             OR (c.relname = 'baskets' AND t.tgname = 'baskets_guard'))),
       (SELECT count(*) FROM pg_constraint WHERE conname = 'basket_approval_bindings_revision_fk'
         AND conrelid = 'glovo.basket_approval_bindings'::regclass AND convalidated),
       (SELECT count(*) FROM pg_trigger WHERE tgname = 'basket_approval_bindings_snapshot'
         AND tgrelid = 'glovo.basket_approval_bindings'::regclass AND tgenabled = 'O'),
       (SELECT count(*) FROM pg_constraint WHERE conname = 'basket_approval_bindings_snapshot_chk'
         AND conrelid = 'glovo.basket_approval_bindings'::regclass AND convalidated)`).Scan(&version, &triggers, &fk, &snapTrigger, &snapCheck); err != nil {
		return 0, fmt.Errorf("glovo basket: verify schema: %w", err)
	}
	switch {
	case version == nil || *version < MinVerifiedSchemaVersion || *version > SchemaVersion:
		return 0, fmt.Errorf("%w: schema version is not %d to %d", ErrSchemaNotReady, MinVerifiedSchemaVersion, SchemaVersion)
	case triggers != 3:
		return 0, fmt.Errorf("%w: a guard trigger is missing or disabled", ErrSchemaNotReady)
	case fk != 1:
		return 0, fmt.Errorf("%w: the approval binding foreign key is missing", ErrSchemaNotReady)
	case *version >= 2 && snapTrigger != 1:
		return 0, fmt.Errorf("%w: the binding snapshot trigger is missing or disabled", ErrSchemaNotReady)
	case *version >= 2 && snapCheck != 1:
		return 0, fmt.Errorf("%w: the binding snapshot check is missing or not validated", ErrSchemaNotReady)
	}
	return *version, nil
}

// TxSetup runs first inside the schema transaction, before any lock is taken
// (see glovo.TxSetup).
type TxSetup func(ctx context.Context, tx pgx.Tx) error

// SchemaOption configures ApplySchema.
type SchemaOption func(*schemaConfig)

type schemaConfig struct{ txSetup TxSetup }

// WithTxSetup installs a TxSetup.
func WithTxSetup(f TxSetup) SchemaOption { return func(c *schemaConfig) { c.txSetup = f } }
