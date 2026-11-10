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

import (
	"context"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Reasons Ready reports. Every one is a not_ready.
const (
	NotReadyExplicitURL      = "explicit_url_missing"
	NotReadyHook             = "revocation_hook_missing"
	NotReadyPurger           = "end_purger_missing"
	NotReadyRoleMismatch     = "runtime_role_mismatch"
	NotReadyRolePrivileged   = "runtime_role_privileged"
	NotReadyRoleOwner        = "runtime_role_owns_or_is_owner"
	NotReadyVersion          = "schema_version_mismatch"
	NotReadyOwner            = "object_owner_mismatch"
	NotReadySchemaPrivileges = "schema_privileges"
	NotReadyGrants           = "grants_mismatch"
	NotReadyUnregistered     = "table_not_registered"
	NotReadyTableMissing     = "table_missing"
	NotReadyTrigger          = "trigger_disabled_or_missing"
	NotReadyCheckFailed      = "check_failed"
)

// NotReadyError is the answer of Ready. It matches errors.Is against
// &Error{Code: CodeNotReady}.
type NotReadyError struct {
	Reason string
	Cause  error
}

func (e *NotReadyError) Error() string { return "not_ready: " + e.Reason }
func (e *NotReadyError) Unwrap() error { return e.Cause }
func (e *NotReadyError) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t != nil && t.Code == CodeNotReady
}

func notReady(reason string) error { return &NotReadyError{Reason: reason} }

func checkFailed(err error) error { return &NotReadyError{Reason: NotReadyCheckFailed, Cause: err} }

var tablePrivileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
var columnPrivileges = []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"}

// Ready reports nil only when this store may be used: the pool was opened from
// an explicit GLOVO_DB_URL; a RevocationHook (and, when required, an
// EndPurger) is installed; current_user is the runtime role with no
// superuser, createrole, createdb or bypassrls attribute, owns nothing and is
// not a member of the owner role; schema glovo, every table and every function
// in it is owned by exactly the migration role; the schema version matches;
// every table in schema glovo has a registered grant row and the runtime role
// holds exactly those rights; and the audit and no-delete triggers are
// enabled. A failed check, including one that could not run, is not_ready.
func (s *Store) Ready(ctx context.Context) error {
	if !s.explicitURL {
		return notReady(NotReadyExplicitURL)
	}
	if s.hook == nil {
		return notReady(NotReadyHook)
	}
	if s.purgerRequired && s.purger == nil {
		return notReady(NotReadyPurger)
	}
	if s.runtimeRole == s.migrationRole {
		return notReady(NotReadyRoleOwner)
	}

	var cur string
	var super, createRole, createDB, bypass, member bool
	if err := s.pool.QueryRow(ctx, `SELECT current_user::text, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,
  pg_has_role(current_user, $1, 'MEMBER')
  FROM pg_roles r WHERE r.rolname = current_user`, s.migrationRole).Scan(&cur, &super, &createRole, &createDB, &bypass, &member); err != nil {
		return checkFailed(err)
	}
	if cur != s.runtimeRole {
		return notReady(NotReadyRoleMismatch)
	}
	if super || createRole || createDB || bypass {
		return notReady(NotReadyRolePrivileged)
	}
	if member {
		return notReady(NotReadyRoleOwner)
	}
	if err := s.checkVersion(ctx); err != nil {
		return &NotReadyError{Reason: NotReadyVersion, Cause: err}
	}

	var badOwners int
	if err := s.pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo' AND pg_get_userbyid(nspowner) <> $1)
     + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'glovo' AND pg_get_userbyid(c.relowner) <> $1)
     + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'glovo' AND pg_get_userbyid(p.proowner) <> $1)`, s.migrationRole).Scan(&badOwners); err != nil {
		return checkFailed(err)
	}
	if badOwners != 0 {
		return notReady(NotReadyOwner)
	}

	var usage, create bool
	if err := s.pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'glovo', 'USAGE'),
  has_schema_privilege(current_user, 'glovo', 'CREATE')`).Scan(&usage, &create); err != nil {
		return checkFailed(err)
	}
	if !usage || create {
		return notReady(NotReadySchemaPrivileges)
	}

	type tbl struct {
		oid  uint32
		name string
	}
	rows, err := s.pool.Query(ctx, `SELECT c.oid, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'glovo' AND c.relkind IN ('r', 'p') ORDER BY c.relname`)
	if err != nil {
		return checkFailed(err)
	}
	var tables []tbl
	present := map[string]bool{}
	for rows.Next() {
		var t tbl
		if err := rows.Scan(&t.oid, &t.name); err != nil {
			rows.Close()
			return checkFailed(err)
		}
		tables = append(tables, t)
		present[t.name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return checkFailed(err)
	}
	for _, name := range slice959Tables {
		if !present[name] {
			return notReady(NotReadyTableMissing)
		}
	}
	if s.purgerRequired && !present["glovo_handoff_refs"] {
		return notReady(NotReadyTableMissing)
	}
	for _, t := range tables {
		row, ok := grantFor(t.name)
		if !ok {
			return notReady(NotReadyUnregistered)
		}
		if err := s.checkGrants(ctx, t.oid, row); err != nil {
			return err
		}
	}

	for _, g := range guardTriggers {
		var enabled string
		err := s.pool.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger
 WHERE tgname = $2 AND tgrelid = ('glovo.' || $1)::regclass AND NOT tgisinternal`, g[0], g[1]).Scan(&enabled)
		if err != nil || enabled != "O" {
			return notReady(NotReadyTrigger)
		}
	}
	return nil
}

// checkGrants compares the runtime role's table-level and column-level rights
// on one table with its registered row, in both directions.
func (s *Store) checkGrants(ctx context.Context, oid uint32, row GrantRow) error {
	return checkGrantsOn(ctx, s.pool, oid, row)
}

// VerifyGrants compares the current user's table-level and column-level
// rights on glovo.<table> with the row another slice registered with
// RegisterGrants, in both directions, so a slice reuses the one registry and
// hand-codes no copy of it. A table with no registered row, a missing table or
// a mismatch is a not_ready answer; a check that could not run is too.
func VerifyGrants(ctx context.Context, q dbq.Querier, table string) error {
	row, ok := grantFor(table)
	if !ok {
		return notReady(NotReadyUnregistered)
	}
	var oid *uint32
	if err := q.QueryRow(ctx, `SELECT to_regclass('glovo.' || quote_ident($1))::oid`, table).Scan(&oid); err != nil {
		return checkFailed(err)
	}
	if oid == nil {
		return notReady(NotReadyTableMissing)
	}
	return checkGrantsOn(ctx, q, *oid, row)
}

func checkGrantsOn(ctx context.Context, q dbq.Querier, oid uint32, row GrantRow) error {
	expectTable := map[string]bool{}
	for _, p := range row.Privileges {
		expectTable[p] = true
	}
	var sel []string
	for _, p := range tablePrivileges {
		sel = append(sel, fmt.Sprintf("has_table_privilege(current_user, $1::oid, '%s')", p))
	}
	got := make([]bool, len(tablePrivileges))
	dest := make([]any, len(got))
	for i := range got {
		dest[i] = &got[i]
	}
	if err := q.QueryRow(ctx, "SELECT "+strings.Join(sel, ", "), oid).Scan(dest...); err != nil {
		return checkFailed(err)
	}
	for i, p := range tablePrivileges {
		if got[i] != expectTable[p] {
			return notReady(NotReadyGrants)
		}
	}

	var cs []string
	for _, p := range columnPrivileges {
		cs = append(cs, fmt.Sprintf("has_column_privilege(current_user, a.attrelid, a.attnum, '%s')", p))
	}
	rows, err := q.Query(ctx, `SELECT a.attname, `+strings.Join(cs, ", ")+` FROM pg_attribute a
 WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attname`, oid)
	if err != nil {
		return checkFailed(err)
	}
	defer rows.Close()
	updateCols := map[string]bool{}
	for _, c := range row.UpdateColumns {
		updateCols[c] = true
	}
	for rows.Next() {
		var name string
		has := make([]bool, len(columnPrivileges))
		d := []any{&name}
		for i := range has {
			d = append(d, &has[i])
		}
		if err := rows.Scan(d...); err != nil {
			return checkFailed(err)
		}
		for i, p := range columnPrivileges {
			want := expectTable[p] || (p == "UPDATE" && updateCols[name])
			if has[i] != want {
				return notReady(NotReadyGrants)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return checkFailed(err)
	}
	return nil
}
