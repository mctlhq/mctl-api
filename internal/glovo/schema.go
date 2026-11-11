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

package glovo

// schemaVersion is the version recorded in glovo.glovo_schema_version. NewStore
// fails closed on any other value.
const schemaVersion = 2

// glovoSchema is the DDL of every glovo_* table of this slice, in schema
// glovo. It is idempotent and is run only by ApplySchema, under the migration
// role that owns every object. The named CHECKs are added in a DO block that
// tests pg_constraint and tolerates duplicate_object, so a database created by
// an earlier build, or two migrators starting at once, both converge.
const glovoSchema = `
CREATE TABLE IF NOT EXISTS glovo.glovo_installs (
  install_id       TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL UNIQUE,
  install_revision BIGINT NOT NULL CHECK (install_revision >= 1),
  state            TEXT NOT NULL,
  installed_by     TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL,
  updated_at       TIMESTAMPTZ NOT NULL,
  version          BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS glovo.glovo_connections (
  connection_id    TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL,
  principal_id     TEXT NOT NULL,
  install_id       TEXT NOT NULL REFERENCES glovo.glovo_installs (install_id),
  install_revision BIGINT NOT NULL,
  state            TEXT NOT NULL,
  secret_ref       TEXT,
  supersedes_id    TEXT NOT NULL DEFAULT '',
  end_reason       TEXT NOT NULL DEFAULT '',
  created_at       TIMESTAMPTZ NOT NULL,
  updated_at       TIMESTAMPTZ NOT NULL,
  ended_at         TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ,
  version          BIGINT NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, principal_id, connection_id, install_revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS glovo_connections_one_live
  ON glovo.glovo_connections (tenant_id, principal_id)
  WHERE state IN ('pending_handoff','pending_provider','active');
CREATE INDEX IF NOT EXISTS glovo_connections_tenant_live
  ON glovo.glovo_connections (tenant_id, install_revision)
  WHERE state IN ('pending_handoff','pending_provider','active');
CREATE INDEX IF NOT EXISTS glovo_connections_owner_recent
  ON glovo.glovo_connections (tenant_id, principal_id, created_at DESC, connection_id DESC);
CREATE TABLE IF NOT EXISTS glovo.glovo_connect_requests (
  tenant_id       TEXT NOT NULL,
  principal_id    TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash    TEXT NOT NULL,
  connection_id   TEXT NOT NULL REFERENCES glovo.glovo_connections (connection_id),
  created_at      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, principal_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS glovo.glovo_audit_events (
  event_id             TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL,
  subject_principal_id TEXT NOT NULL DEFAULT '',
  actor_principal_id   TEXT NOT NULL,
  actor_kind           TEXT NOT NULL,
  entity_kind          TEXT NOT NULL,
  entity_id            TEXT NOT NULL,
  event                TEXT NOT NULL,
  from_state           TEXT NOT NULL DEFAULT '',
  to_state             TEXT NOT NULL,
  install_revision     BIGINT NOT NULL,
  reason_code          TEXT NOT NULL DEFAULT '',
  recorded_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS glovo_audit_events_entity
  ON glovo.glovo_audit_events (tenant_id, entity_id, recorded_at);
CREATE INDEX IF NOT EXISTS glovo_audit_events_recorded
  ON glovo.glovo_audit_events (recorded_at);
CREATE TABLE IF NOT EXISTS glovo.glovo_pilot_allowlist (
  tenant_id    TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  added_by     TEXT NOT NULL,
  added_at     TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant_id, principal_id)
);
CREATE TABLE IF NOT EXISTS glovo.glovo_schema_version (version INT NOT NULL);

DO $$
DECLARE c record;
BEGIN
  FOR c IN SELECT * FROM (VALUES
    ('glovo_installs', 'glovo_installs_state_check', $c$state IN ('installed','uninstalled')$c$),
    ('glovo_connections', 'glovo_connections_state_check', $c$state IN ('pending_handoff','pending_provider','active','expired','failed','revoked')$c$),
    ('glovo_connections', 'glovo_connections_principal_check', $c$principal_id LIKE 'prn\_%'$c$),
    ('glovo_connections', 'glovo_connections_active_expiry_check', $c$state <> 'active' OR expires_at IS NOT NULL$c$),
    ('glovo_connections', 'glovo_connections_secret_ref_check', $c$secret_ref IS NULL OR secret_ref LIKE 'gsr\_%'$c$),
    ('glovo_connections', 'glovo_connections_terminal_check', $c$state IN ('pending_handoff','pending_provider','active') OR ended_at IS NOT NULL$c$),
    ('glovo_pilot_allowlist', 'glovo_pilot_allowlist_principal_check', $c$principal_id LIKE 'prn\_%'$c$),
    ('glovo_audit_events', 'glovo_audit_events_actor_kind_check', $c$actor_kind IN ('user','owner','admin','worker','system')$c$)
  ) AS t(tbl, name, expr)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = c.name AND conrelid = ('glovo.' || c.tbl)::regclass) THEN
      BEGIN
        EXECUTE format('ALTER TABLE glovo.%I ADD CONSTRAINT %I CHECK (%s)', c.tbl, c.name, c.expr);
      EXCEPTION WHEN duplicate_object THEN NULL;
      END;
    END IF;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION glovo.glovo_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION 'glovo_audit_events is append-only' USING ERRCODE = 'integrity_constraint_violation';
END
$f$;

CREATE OR REPLACE FUNCTION glovo.glovo_connections_no_delete() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION 'glovo_connections rows are never deleted' USING ERRCODE = 'integrity_constraint_violation';
END
$f$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'glovo_audit_events_immutable'
                  AND tgrelid = 'glovo.glovo_audit_events'::regclass) THEN
    CREATE TRIGGER glovo_audit_events_immutable BEFORE UPDATE OR DELETE ON glovo.glovo_audit_events
      FOR EACH ROW EXECUTE FUNCTION glovo.glovo_audit_immutable();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'glovo_audit_events_no_truncate'
                  AND tgrelid = 'glovo.glovo_audit_events'::regclass) THEN
    CREATE TRIGGER glovo_audit_events_no_truncate BEFORE TRUNCATE ON glovo.glovo_audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION glovo.glovo_audit_immutable();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'glovo_connections_no_delete'
                  AND tgrelid = 'glovo.glovo_connections'::regclass) THEN
    CREATE TRIGGER glovo_connections_no_delete BEFORE DELETE ON glovo.glovo_connections
      FOR EACH ROW EXECUTE FUNCTION glovo.glovo_connections_no_delete();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'glovo_connections_no_truncate'
                  AND tgrelid = 'glovo.glovo_connections'::regclass) THEN
    CREATE TRIGGER glovo_connections_no_truncate BEFORE TRUNCATE ON glovo.glovo_connections
      FOR EACH STATEMENT EXECUTE FUNCTION glovo.glovo_connections_no_delete();
  END IF;
END $$;
`

// slice959Tables lists the tables this slice creates, in grant order.
var slice959Tables = []string{
	"glovo_installs", "glovo_connections", "glovo_connect_requests",
	"glovo_audit_events", "glovo_pilot_allowlist", "glovo_schema_version",
}

// guardTriggers are the triggers Ready requires to be enabled.
var guardTriggers = [][2]string{
	{"glovo_audit_events", "glovo_audit_events_immutable"},
	{"glovo_audit_events", "glovo_audit_events_no_truncate"},
	{"glovo_connections", "glovo_connections_no_delete"},
	{"glovo_connections", "glovo_connections_no_truncate"},
}
