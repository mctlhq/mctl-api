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
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// These tests prove two contracts of the migrator.
//
//  1. Preflight and apply agree. A refusal is correct only if the step it
//     guards would really have failed, and a step that would fail for a reason
//     the catalog can show must be refused before anything is committed. The
//     oracle is Config.ignoreRefusals: it applies the steps anyway.
//  2. Atomicity. Each Apply* transaction is atomic: a failed unit leaves
//     nothing behind, the units before it stay committed, no later unit runs,
//     and a re-run resumes.

// forced applies the steps although the preflight refused them.
func (e *env) forced() error {
	c := e.cfg(ModeApply)
	c.ignoreRefusals = true
	return e.run(c)
}

// The privilege matrix: for every state a database can be in and every
// creation privilege a step needs, the preflight refuses exactly when the
// forced apply fails, and a refusal changes nothing. The legacy-era row is the
// regression of mctl-api#1018: step 1 commits and step 2 then fails for want
// of CREATE on schema public, a privilege the preflight can read.
func TestCreatePrivilegeMatrixPreflightAgreesWithApply(t *testing.T) {
	ctx := context.Background()
	states := []struct {
		name  string
		build func(e *env)
		glovo bool // schema glovo exists in this state
	}{
		{"empty", func(e *env) {}, false},
		{"legacy-era", func(e *env) { e.legacyEra() }, false},
		{"base-only", func(e *env) {
			if err := glovo.ApplySchema(ctx, e.dsn(e.mig), e.rt); err != nil {
				e.t.Fatal(err)
			}
		}, true},
		{"applied", func(e *env) {
			if err := e.run(e.cfg(ModeApply)); err != nil {
				e.t.Fatal(err)
			}
		}, true},
	}
	revokes := []struct {
		name, want string
		needsGlovo bool
		steps      []string // the steps whose DDL needs the privilege on every run
		stmts      func(e *env) []string
	}{
		// CREATE SCHEMA IF NOT EXISTS glovo (step 1) and the work-items DDL's schema (step 2).
		{"database CREATE", "CREATE on the database", false, []string{StepBase, StepApproval}, func(e *env) []string {
			return []string{fmt.Sprintf(`REVOKE CREATE ON DATABASE %s FROM %s`, e.db, e.mig)}
		}},
		// CREATE TABLE/INDEX IF NOT EXISTS and CREATE OR REPLACE FUNCTION in public (step 2 only).
		{"schema public CREATE", "CREATE on schema public", false, []string{StepApproval}, func(e *env) []string {
			return []string{`REVOKE CREATE ON SCHEMA public FROM PUBLIC`, fmt.Sprintf(`ALTER SCHEMA public OWNER TO %s`, e.legacy)}
		}},
		// Every CREATE ... IF NOT EXISTS / OR REPLACE inside an existing schema glovo (all three steps).
		{"schema glovo CREATE", "CREATE on schema glovo", true, []string{StepBase, StepApproval, StepBasket}, func(e *env) []string {
			return []string{fmt.Sprintf(`REVOKE CREATE ON SCHEMA glovo FROM %s`, e.mig)}
		}},
		// Every step creates plpgsql trigger functions (CREATE OR REPLACE FUNCTION needs USAGE on the language).
		{"language plpgsql USAGE", "USAGE on language plpgsql", false, []string{StepBase, StepApproval, StepBasket}, func(e *env) []string {
			return []string{`REVOKE USAGE ON LANGUAGE plpgsql FROM PUBLIC`}
		}},
	}
	for _, st := range states {
		t.Run(st.name+"/no revocation", func(t *testing.T) {
			e := newEnv(t)
			st.build(e)
			if err := e.run(e.cfg(ModeApply)); err != nil {
				t.Fatalf("with every privilege the apply must succeed: %v\n%s", err, e.buf.String())
			}
			e.assertBootChecks()
		})
		for _, rv := range revokes {
			if rv.needsGlovo && !st.glovo {
				continue
			}
			t.Run(st.name+"/"+rv.name, func(t *testing.T) {
				e := newEnv(t)
				st.build(e)
				for _, s := range rv.stmts(e) {
					e.exec(e.root(), s)
				}
				// Dry-run says it, verify is not "clean".
				e.refusedUpFront(e.cfg(ModeApply), rv.want)
				if err := e.run(e.cfg(ModeDryRun)); err != nil {
					t.Fatalf("dry-run: %v\n%s", err, e.buf.String())
				}
				// Each step reports exactly the refusals its own DDL needs, so a check
				// missing from one step is not hidden by another step's check.
				for _, step := range StepNames() {
					if got, want := strings.Contains(e.buf.String(), "would REFUSE at "+step), slices.Contains(rv.steps, step); got != want {
						t.Fatalf("%s: dry-run refuses at %s = %v, want %v\n%s", rv.name, step, got, want, e.buf.String())
					}
				}
				// The oracle: the step the preflight guards really fails when forced,
				// and it fails as a step failure, not as a catalog problem.
				if err := e.forced(); !errors.Is(err, ErrStepFailed) {
					t.Fatalf("the preflight refused %q but the forced apply did not fail as a step: %v", rv.name, err)
				}
			})
		}
	}
}

// Every object a step touches, owned by another role on an already existing
// database (legacy era or fully applied), is refused up front, and the refusal
// is right: forcing the steps makes one fail. An object the preflight does not
// refuse must be one the steps do not care about, which the success of the
// run proves. Indexes and triggers have no owner of their own; the check that
// guards them is the ownership of their table.
func TestEveryObjectTheStepsTouchIsOwnershipChecked(t *testing.T) {
	type obj struct{ kind, schema, name, ident, alter string }
	collect := func(e *env) []obj {
		ctx := context.Background()
		c := e.root()
		var out []obj
		rows, err := c.Query(ctx, `SELECT n.nspname, c.relname, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname IN ('glovo','public') AND c.relkind IN ('r','p','S','v','m') AND pg_get_userbyid(c.relowner) = $1 ORDER BY 1, 2`, e.mig)
		if err != nil {
			e.t.Fatal(err)
		}
		for rows.Next() {
			var ns, n, k string
			if err := rows.Scan(&ns, &n, &k); err != nil {
				e.t.Fatal(err)
			}
			id := pgx.Identifier{ns, n}.Sanitize()
			switch k {
			case "S":
				out = append(out, obj{"sequence", ns, n, id, `ALTER SEQUENCE ` + id + ` OWNER TO %s`})
			case "v":
				out = append(out, obj{"view", ns, n, id, `ALTER VIEW ` + id + ` OWNER TO %s`})
			case "m":
				out = append(out, obj{"matview", ns, n, id, `ALTER MATERIALIZED VIEW ` + id + ` OWNER TO %s`})
			default:
				out = append(out, obj{"table", ns, n, id, `ALTER TABLE ` + id + ` OWNER TO %s`})
			}
		}
		rows.Close()
		fr, err := c.Query(ctx, `SELECT n.nspname, p.proname, p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		  WHERE n.nspname IN ('glovo','public') AND pg_get_userbyid(p.proowner) = $1 ORDER BY 1, 2`, e.mig)
		if err != nil {
			e.t.Fatal(err)
		}
		for fr.Next() {
			var ns, n, sig string
			if err := fr.Scan(&ns, &n, &sig); err != nil {
				e.t.Fatal(err)
			}
			out = append(out, obj{"function", ns, n, sig, `ALTER FUNCTION ` + sig + ` OWNER TO %s`})
		}
		fr.Close()
		return out
	}
	// tableOf lists the table of every non-internal trigger and every index in the two schemas.
	tableOf := func(e *env) (idx, trg []string) {
		ctx := context.Background()
		c := e.root()
		for _, q := range []struct {
			sql string
			dst *[]string
		}{
			{`SELECT DISTINCT n.nspname || '.' || t.relname FROM pg_index i JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
			   WHERE n.nspname IN ('glovo','public') AND pg_get_userbyid(t.relowner) = '` + e.mig + `'`, &idx},
			{`SELECT DISTINCT n.nspname || '.' || t.relname FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid JOIN pg_namespace n ON n.oid = t.relnamespace
			   WHERE NOT g.tgisinternal AND n.nspname IN ('glovo','public') AND pg_get_userbyid(t.relowner) = '` + e.mig + `'`, &trg},
		} {
			rows, err := c.Query(ctx, q.sql)
			if err != nil {
				e.t.Fatal(err)
			}
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					e.t.Fatal(err)
				}
				*q.dst = append(*q.dst, s)
			}
			rows.Close()
		}
		return
	}
	for _, variant := range []struct {
		name  string
		build func(e *env)
	}{
		{"legacy-era", func(e *env) { e.legacyEra() }},
		{"applied", func(e *env) {
			if err := e.run(e.cfg(ModeApply)); err != nil {
				e.t.Fatal(err)
			}
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			e0 := newEnv(t)
			variant.build(e0)
			objs := collect(e0)
			if len(objs) < 5 {
				t.Fatalf("expected many objects on a %s database, found %d", variant.name, len(objs))
			}
			refusedTables := map[string]bool{}
			var unchecked []string
			for _, o := range objs {
				// The forced run is the oracle and it changes the database (on a
				// legacy-era one step 1 commits: that is the very hazard), so every
				// object gets a database of its own there. A fully applied database
				// is unchanged by it and is reused.
				e := e0
				if variant.name == "legacy-era" {
					e = newEnv(t)
					variant.build(e)
				}
				root := e.root()
				if _, err := root.Exec(context.Background(), fmt.Sprintf(o.alter, e.legacy)); err != nil {
					if o.kind == "sequence" && strings.Contains(err.Error(), "cannot change owner of sequence") {
						continue // an owned sequence cannot have another owner than its table
					}
					t.Fatalf("giving %s %s to the legacy role: %v", o.kind, o.ident, err)
				}
				before := e.dump()
				var order []string
				c := e.cfg(ModeApply)
				c.onStep = func(n string) { order = append(order, n) }
				err := e.run(c)
				switch {
				case errors.Is(err, ErrRefused):
					if ExitCode(err) != ExitRefused {
						t.Fatalf("%s %s: refusal with exit %d", o.kind, o.ident, ExitCode(err))
					}
					if !strings.Contains(err.Error(), o.name) {
						t.Fatalf("%s %s: the refusal does not name it: %v", o.kind, o.ident, err)
					}
					if len(order) != 0 || e.dump() != before {
						t.Fatalf("%s %s: steps ran (%v) or the database changed before the refusal", o.kind, o.ident, order)
					}
					if err := e.run(e.cfg(ModeDryRun)); err != nil || !strings.Contains(e.buf.String(), "would REFUSE") {
						t.Fatalf("%s %s dry-run: %v\n%s", o.kind, o.ident, err, e.buf.String())
					}
					if err := e.run(e.cfg(ModeVerify)); !errors.Is(err, ErrNotReady) {
						t.Fatalf("%s %s verify: %v", o.kind, o.ident, err)
					}
					// Agreement: the refusal is right only if the steps would fail.
					if ferr := e.forced(); !errors.Is(ferr, ErrStepFailed) {
						t.Errorf("%s %s: refused up front, but forcing the steps did not fail (%v): the refusal is over-strict", o.kind, o.ident, ferr)
					}
					if o.kind == "table" {
						refusedTables[o.schema+"."+o.name] = true
					}
				case err == nil:
					unchecked = append(unchecked, o.kind+" "+o.ident)
				default:
					t.Errorf("%s %s foreign-owned: neither refused up front nor applied: %v", o.kind, o.ident, err)
				}
				e.exec(root, fmt.Sprintf(o.alter, e.mig))
			}
			// Every table, function and view the steps touch must be ownership
			// checked. What is unchecked must be something no step touches.
			if len(unchecked) > 0 {
				t.Logf("objects the steps do not touch (a foreign owner is harmless): %s", strings.Join(unchecked, ", "))
			}
			for _, u := range unchecked {
				if strings.HasPrefix(u, "function") || strings.HasPrefix(u, "table") {
					t.Errorf("%s is not ownership checked, yet the steps create or replace it", u)
				}
			}
			idx, trg := tableOf(e0)
			for _, tbl := range slices.Concat(idx, trg) {
				if !refusedTables[tbl] {
					t.Errorf("indexes/triggers on %s are touched by the steps but its ownership is not checked", tbl)
				}
			}
		})
	}
}

// failureCase injects one failure at the start of one apply step, after the
// preflight has passed, so the failing unit does all its DDL and fails at its
// last statements (the grants). Each case names the objects of every unit.
type failureCase struct {
	name     string
	at       string // step whose start triggers the failure
	dropRole func(e *env) string
	present  []string // regclass/regprocedure that must exist after the failure
	absent   []string // ... and must not
	ran      []string // steps attempted, in order
	prefix   []string // units committed before the failing one: "base", "generic", "approval"
}

// The four transaction units.
var (
	baseObjs     = []string{"glovo.glovo_schema_version"}
	genericObjs  = []string{"public.work_items", "public.work_item_events"}
	approvalObjs = []string{"glovo.approval_schema_version", "glovo.approval_bindings", "glovo.aar_guard()"}
	basketObjs   = []string{"glovo.basket_schema_version", "glovo.baskets", "glovo.baskets_guard()"}
)

func (e *env) exists(name string) bool {
	e.t.Helper()
	var ok bool
	q := `SELECT to_regclass($1) IS NOT NULL`
	if strings.HasSuffix(name, ")") {
		q = `SELECT to_regprocedure($1) IS NOT NULL`
	}
	if err := e.root().QueryRow(context.Background(), q, name).Scan(&ok); err != nil {
		e.t.Fatal(err)
	}
	return ok
}

// normalized replaces the per-test role names so two databases can be compared.
func (e *env) normalized(s string) string {
	for from, to := range map[string]string{e.mig: "MIG", e.rt: "RT", e.wi: "WI", e.legacy: "LEG", e.blind: "BLIND"} {
		s = strings.ReplaceAll(s, from, to)
	}
	return s
}

// referenceDump is the catalog of a second database of the same era after only
// the units that committed before the failing one, with the failing step's role
// gone as it is in the failure run.
func (e *env) referenceDump(era string, fc failureCase) string {
	e.t.Helper()
	ctx := context.Background()
	r := newEnv(e.t)
	if era == "legacy-era" {
		r.legacyEra()
	}
	for _, u := range fc.prefix {
		var err error
		switch u {
		case "base":
			err = glovo.ApplySchema(ctx, r.dsn(r.mig), r.rt)
		case "generic":
			err = workitems.ApplySchema(ctx, r.dsn(r.mig), "", workitems.WithWorkItemsRole(r.wi))
		case "approval":
			err = workitems.ApplyGlovoApprovalSchema(ctx, r.dsn(r.mig), r.rt, workitems.WithWorkItemsRole(r.wi))
		}
		if err != nil {
			e.t.Fatalf("reference unit %s: %v", u, err)
		}
	}
	switch fc.dropRole(e) {
	case e.rt:
		r.dropRole(r.rt)
	case e.wi:
		r.dropRole(r.wi)
	}
	return r.normalized(r.dump())
}

// The atomicity contract, for every unit and on both kinds of database: the
// failed unit rolls back completely (the whole catalog equals what it was just
// before the unit), the units before it stay committed, no later unit runs,
// and fixing the cause and re-running resumes to a state boot accepts.
func TestEachApplyUnitIsAtomicAndEarlierUnitsStayCommitted(t *testing.T) {
	cases := []failureCase{
		{"glovo base fails at its grants", StepBase, func(e *env) string { return e.rt },
			nil, slices.Concat(baseObjs, genericObjs, approvalObjs, basketObjs), []string{StepBase}, nil},
		{"generic work-items block fails at its grants", StepApproval, func(e *env) string { return e.wi },
			baseObjs, slices.Concat(genericObjs, approvalObjs, basketObjs), []string{StepBase, StepApproval}, []string{"base"}},
		{"glovo approval transaction fails at its grants", StepApproval, func(e *env) string { return e.rt },
			slices.Concat(baseObjs, genericObjs), slices.Concat(approvalObjs, basketObjs), []string{StepBase, StepApproval}, []string{"base", "generic"}},
		{"basket fails at its grants", StepBasket, func(e *env) string { return e.rt },
			slices.Concat(baseObjs, genericObjs, approvalObjs), basketObjs, []string{StepBase, StepApproval, StepBasket}, []string{"base", "generic", "approval"}},
	}
	for _, fc := range cases {
		for _, era := range []string{"empty", "legacy-era"} {
			t.Run(fc.name+"/"+era, func(t *testing.T) {
				e := newEnv(t)
				if era == "legacy-era" {
					e.legacyEra()
				}
				var order []string
				var role string
				c := e.cfg(ModeApply)
				c.onStep = func(n string) {
					order = append(order, n)
					if n == fc.at && role == "" {
						role = fc.dropRole(e)
						e.dropRole(role)
					}
				}
				if err := e.run(c); !errors.Is(err, ErrStepFailed) {
					t.Fatalf("expected the unit to fail: %v\n%s", err, e.buf.String())
				}
				if !slices.Equal(order, fc.ran) {
					t.Fatalf("steps attempted %v, want %v", order, fc.ran)
				}
				// The whole catalog equals the reference: the same era with only the
				// committed units applied (and the same role gone). Anything the failed
				// unit left behind, a table, a column, a function, a grant, shows.
				if got, want := e.normalized(e.dump()), e.referenceDump(era, fc); got != want {
					t.Fatalf("the failed unit left changes behind (rollback is not complete):\nreference:\n%s\nafter the failure:\n%s", want, got)
				}
				for _, n := range fc.present {
					if !e.exists(n) {
						t.Errorf("%s must stay committed", n)
					}
				}
				for _, n := range fc.absent {
					if era == "legacy-era" && slices.Contains(genericObjs, n) {
						continue // the legacy era already has the generic objects
					}
					if e.exists(n) {
						t.Errorf("%s exists although its unit failed or never ran", n)
					}
				}
				// Fix the cause; the re-run completes from where it stopped.
				e.exec(e.root(), fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER`, role, testPassword))
				e.exec(e.root(), fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.db, role))
				if err := e.run(e.cfg(ModeApply)); err != nil {
					t.Fatalf("resume: %v\n%s", err, e.buf.String())
				}
				e.assertBootChecks()
			})
		}
	}
}
