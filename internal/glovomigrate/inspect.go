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

package glovomigrate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// component is one recorded schema version of a step.
type component struct {
	label    string
	table    string // schema-qualified version table
	compiled int
	// reading
	present  bool // the version table exists
	rows     int
	recorded int // max(version), valid when rows > 0
	// unread: deliberately not read because a refusal already decides the
	// step (the migration role cannot select from tables another role owns).
	unread bool
}

func (c component) newer() bool {
	return !c.unread && c.present && c.rows > 0 && c.recorded > c.compiled
}
func (c component) current() bool {
	return !c.unread && c.present && c.rows == 1 && c.recorded == c.compiled
}
func (c component) text() string {
	switch {
	case c.unread:
		return "not read (ownership refusal)"
	case !c.present:
		return "none (table absent)"
	case c.rows == 0:
		return "none (table empty)"
	case c.rows > 1:
		return fmt.Sprintf("%d (%d rows, expected 1)", c.recorded, c.rows)
	}
	return fmt.Sprintf("%d", c.recorded)
}

// stepState is what the read-only preflight found for one step.
type stepState struct {
	name       string
	components []component
	// problems are objects of the step that are missing, disabled or owned by
	// another role: they make verify fail and a re-apply is expected to repair
	// them (unless they are refusals).
	problems []string
	// refusals are conditions the apply step itself refuses on; a real run
	// stops before changing anything.
	refusals []string
}

func (s stepState) newer() bool {
	for _, c := range s.components {
		if c.newer() {
			return true
		}
	}
	return false
}

func (s stepState) recordedText() string {
	var p []string
	for _, c := range s.components {
		p = append(p, c.label+" "+c.text())
	}
	return strings.Join(p, ", ")
}

func (s stepState) ready() bool {
	for _, c := range s.components {
		if !c.current() {
			return false
		}
	}
	return len(s.problems) == 0 && len(s.refusals) == 0
}

func (s stepState) describe(m Mode) string {
	var target []string
	for _, c := range s.components {
		target = append(target, fmt.Sprintf("%s %d", c.label, c.compiled))
	}
	action := "would re-apply (idempotent, state-identical)"
	switch {
	case s.newer():
		action = "REFUSE: a recorded version is newer than this binary"
	case len(s.refusals) > 0:
		action = "REFUSE: " + strings.Join(s.refusals, "; ")
	default:
		fresh, upgrade := false, false
		for _, c := range s.components {
			if !c.present || c.rows == 0 {
				fresh = true
			} else if c.recorded < c.compiled {
				upgrade = true
			}
		}
		switch {
		case fresh:
			action = "would create"
		case upgrade:
			action = "would upgrade"
		case len(s.problems) > 0:
			action = "would repair: " + strings.Join(s.problems, "; ")
		}
	}
	if m == ModeVerify {
		switch {
		case s.ready():
			action = "ok"
		case len(s.problems) > 0:
			action = "not ready: " + strings.Join(s.problems, "; ")
		default:
			action = "not ready"
		}
	}
	return fmt.Sprintf("step %s: recorded [%s] target [%s] -> %s", s.name, s.recordedText(), strings.Join(target, ", "), action)
}

func observeErr(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrCouldNotObserve, what, err)
}

// preflight connects, proves the role, and reads the three steps in one
// read-only transaction. Every failed read is ErrCouldNotObserve.
func preflight(ctx context.Context, cfg *Config) ([]stepState, error) {
	conn, err := pgx.Connect(ctx, cfg.DSN)
	if err != nil {
		return nil, observeErr("connect as the migration role", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, observeErr("begin read-only transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := cfg.setup(ctx, tx); err != nil {
		if errors.Is(err, ErrRefused) {
			return nil, err
		}
		return nil, observeErr("prepare the read-only transaction", err)
	}

	var super bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		return nil, observeErr("read the role attributes", err)
	}
	if super {
		return nil, fmt.Errorf("%w: the migration role must not be a superuser", ErrRefused)
	}

	var out []stepState
	for _, read := range []func(context.Context, pgx.Tx) (stepState, error){readBase, readApproval, readBasket} {
		s, err := read(ctx, tx)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func readComponent(ctx context.Context, tx pgx.Tx, c *component) error {
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, c.table).Scan(&c.present); err != nil {
		return observeErr("probe "+c.table, err)
	}
	if !c.present {
		return nil
	}
	var max *int
	// c.table is a constant of this package, never operator input.
	if err := tx.QueryRow(ctx, `SELECT count(*), max(version) FROM `+c.table).Scan(&c.rows, &max); err != nil {
		return observeErr("read "+c.table, err)
	}
	if max != nil {
		c.recorded = *max
	}
	return nil
}

func readBase(ctx context.Context, tx pgx.Tx) (stepState, error) {
	s := stepState{name: StepBase, components: []component{{label: "glovo", table: "glovo.glovo_schema_version", compiled: glovo.CompiledSchemaVersion()}}}
	if err := readComponent(ctx, tx, &s.components[0]); err != nil {
		return s, err
	}
	var exists bool
	var foreign int
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'glovo'),
	  (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo' AND pg_get_userbyid(nspowner) <> current_user)
	  + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	      WHERE n.nspname = 'glovo' AND c.relkind IN ('r','p','S','v') AND pg_get_userbyid(c.relowner) <> current_user)`).Scan(&exists, &foreign); err != nil {
		return s, observeErr("read schema glovo ownership", err)
	}
	if foreign > 0 {
		s.refusals = append(s.refusals, fmt.Sprintf("%d object(s) of schema glovo are not owned by the migration role", foreign))
	}
	if !exists {
		s.problems = append(s.problems, "schema glovo is absent")
	}
	return s, nil
}

// approvalTriggers are the four enabled guards VerifyGlovoApprovalSchema counts.
var approvalTriggers = [][2]string{
	{"public.action_approval_requests", "aar_guard"},
	{"public.action_approval_requests", "aar_binding_required"},
	{"glovo.approval_bindings", "approval_bindings_guard"},
	{"glovo.basket_approval_bindings", "basket_approval_bindings_guard"},
}

func readApproval(ctx context.Context, tx pgx.Tx) (stepState, error) {
	s := stepState{name: StepApproval, components: []component{
		{label: "work-items", table: "public.work_items_schema_version", compiled: workitems.CompiledWorkItemsSchemaVersion()},
		{label: "approval", table: "glovo.approval_schema_version", compiled: workitems.CompiledGlovoApprovalSchemaVersion()},
	}}
	// Ownership of the shared tables: the real risk of the activation (the
	// legacy role owns them until the operator's ownership transfer).
	rows, err := tx.Query(ctx, `SELECT c.oid::regclass::text, pg_get_userbyid(c.relowner) <> current_user
	  FROM pg_class c WHERE c.oid IN (to_regclass('public.action_approval_requests'),
	    to_regclass('glovo.approval_bindings'), to_regclass('glovo.basket_approval_bindings'))
	  ORDER BY 1`)
	if err != nil {
		return s, observeErr("read approval table owners", err)
	}
	var foreign []string
	for rows.Next() {
		var rel string
		var other bool
		if err := rows.Scan(&rel, &other); err != nil {
			rows.Close()
			return s, observeErr("scan approval table owners", err)
		}
		if other {
			foreign = append(foreign, rel)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, observeErr("read approval table owners", err)
	}
	if len(foreign) > 0 {
		// A decided refusal outranks reading further: the version tables of
		// public are the very objects this role cannot select from yet.
		s.refusals = append(s.refusals, strings.Join(foreign, ", ")+" not owned by the migration role (the ownership transfer of runbook step D1 is not done)")
		for i := range s.components {
			s.components[i].unread = true
		}
		return s, nil
	}
	for i := range s.components {
		if err := readComponent(ctx, tx, &s.components[i]); err != nil {
			return s, err
		}
	}
	missing, err := missingTriggers(ctx, tx, approvalTriggers)
	if err != nil {
		return s, err
	}
	s.problems = append(s.problems, missing...)
	return s, nil
}

var basketTriggers = [][2]string{
	{"glovo.basket_revisions", "basket_revisions_frozen"},
	{"glovo.basket_revisions", "basket_revisions_no_truncate"},
	{"glovo.baskets", "baskets_guard"},
}

func readBasket(ctx context.Context, tx pgx.Tx) (stepState, error) {
	s := stepState{name: StepBasket, components: []component{{label: "basket", table: "glovo.basket_schema_version", compiled: glovobasket.SchemaVersion}}}
	if err := readComponent(ctx, tx, &s.components[0]); err != nil {
		return s, err
	}
	missing, err := missingTriggers(ctx, tx, basketTriggers)
	if err != nil {
		return s, err
	}
	s.problems = append(s.problems, missing...)
	var fk bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'basket_approval_bindings_revision_fk'
	  AND conrelid = to_regclass('glovo.basket_approval_bindings') AND convalidated)`).Scan(&fk); err != nil {
		return s, observeErr("read the basket binding foreign key", err)
	}
	if !fk {
		s.problems = append(s.problems, "basket_approval_bindings_revision_fk missing or not validated")
	}
	var foreign int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	  WHERE n.nspname = 'glovo' AND c.relname IN ('baskets','basket_revisions','basket_schema_version')
	    AND pg_get_userbyid(c.relowner) <> current_user`).Scan(&foreign); err != nil {
		return s, observeErr("read basket table owners", err)
	}
	if foreign > 0 {
		s.refusals = append(s.refusals, fmt.Sprintf("%d basket table(s) are not owned by the migration role", foreign))
	}
	return s, nil
}

// missingTriggers lists the (table, trigger) pairs that are absent or not
// enabled. A failed read is an error; an absent table is "missing", which
// to_regclass reports without error.
func missingTriggers(ctx context.Context, tx pgx.Tx, want [][2]string) ([]string, error) {
	var out []string
	for _, w := range want {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = to_regclass($1)
		  AND t.tgname = $2 AND t.tgenabled = 'O' AND NOT t.tgisinternal)`, w[0], w[1]).Scan(&enabled); err != nil {
			return nil, observeErr("read trigger "+w[1], err)
		}
		if !enabled {
			out = append(out, "trigger "+w[1]+" missing or disabled")
		}
	}
	sort.Strings(out)
	return out, nil
}
