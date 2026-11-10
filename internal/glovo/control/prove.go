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

package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// The one-database proof of mctl-api#985 design 4. The bridge, #959, #988 and
// #989 write paths share one transaction only if they share one database and
// one role; a proof that cannot run is a failed proof, never a pass.

// proofTables are the relations every participating slice owns. They must all
// resolve from the shared pool.
var proofTables = []string{
	"public.bridge_commands", "public.bridge_write_permits", "public.bridge_colocation_probe",
	"public.action_approval_requests", "glovo.approval_bindings",
	"glovo.orders", "glovo.order_snapshots", "glovo.order_effects", "glovo.order_events", "glovo.join_refs",
	"glovo.glovo_installs", "glovo.glovo_connections", "glovo.control_starts",
}

// ProveOneDatabase runs the proof once. It requires the Glovo and bridge
// stores to share one pool, then:
//
//  1. inserts a fresh 128-bit nonce on that pool and commits;
//  2. reads it back through the shared pool and the work-items pool (one
//     database, not merely one cluster);
//  3. requires both pools to report pg_is_in_recovery() = false;
//  4. requires every participating relation to resolve, the bridge grants to
//     equal the 6d.1 table exactly, the Glovo store to be ready, the role to be
//     unprivileged (no rolsuper, rolcreaterole, rolcreatedb or rolbypassrls),
//     to own nothing in schema glovo or among the bridge relations and to be a
//     member of no owner role, every non-internal trigger of those relations to
//     be enabled for origin sessions, and the work-items pool to be another role
//     without USAGE on schema glovo;
//  5. deletes the nonce.
//
// The nonce is deleted whether or not the proof passed.
func ProveOneDatabase(ctx context.Context, bs *bridge.Store, gs *glovo.Store, workItems *pgxpool.Pool) (err error) {
	if bs == nil || gs == nil || workItems == nil || bs.Pool() == nil || gs.Pool() == nil {
		return errors.New("control: proof needs the bridge store, the Glovo store and the work-items pool")
	}
	pool := bs.Pool()
	if gs.Pool() != pool {
		return errors.New("control: the bridge and Glovo stores do not share one pool")
	}
	if workItems == pool {
		return errors.New("control: the work-items pool is the shared pool")
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("control: nonce: %w", err)
	}
	nonce := hex.EncodeToString(raw[:])
	if _, err := pool.Exec(ctx, `INSERT INTO bridge_colocation_probe (nonce) VALUES ($1)`, nonce); err != nil {
		return fmt.Errorf("control: write nonce: %w", err)
	}
	defer func() {
		if _, derr := pool.Exec(context.WithoutCancel(ctx), `DELETE FROM bridge_colocation_probe WHERE nonce = $1`, nonce); derr != nil && err == nil {
			err = fmt.Errorf("control: delete nonce: %w", derr)
		}
	}()
	for name, q := range map[string]dbq.Querier{"shared": pool, "work-items": workItems} {
		var seen bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.bridge_colocation_probe WHERE nonce = $1)`, nonce).Scan(&seen); err != nil {
			return fmt.Errorf("control: read nonce on the %s pool: %w", name, err)
		}
		if !seen {
			return fmt.Errorf("control: the %s pool does not see the nonce: not one database", name)
		}
		var recovery bool
		if err := q.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&recovery); err != nil {
			return fmt.Errorf("control: recovery check on the %s pool: %w", name, err)
		}
		if recovery {
			return fmt.Errorf("control: the %s pool is a standby", name)
		}
	}
	for _, t := range proofTables {
		var present bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, t).Scan(&present); err != nil {
			return fmt.Errorf("control: resolve %s: %w", t, err)
		}
		if !present {
			return fmt.Errorf("control: %s is missing", t)
		}
	}
	if err := bridge.VerifyRuntimeGrants(ctx, pool); err != nil {
		return fmt.Errorf("control: bridge grants: %w", err)
	}
	if err := gs.Ready(ctx); err != nil {
		return fmt.Errorf("control: glovo store: %w", err)
	}
	if err := proveRole(ctx, pool); err != nil {
		return err
	}
	if err := proveTriggers(ctx, pool); err != nil {
		return err
	}
	return proveWorkItemsRole(ctx, pool, workItems)
}

// proveRole requires the shared role to be unprivileged and to own nothing it
// writes through: CREATEROLE alone would let it grant itself the migrator.
func proveRole(ctx context.Context, pool dbq.Querier) error {
	var bad int
	if err := pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_roles WHERE rolname = current_user
          AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls))
     + (SELECT count(*) FROM pg_namespace WHERE nspname = 'glovo'
          AND (pg_get_userbyid(nspowner) = current_user::text OR pg_has_role(current_user, nspowner, 'MEMBER')))
     + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE (n.nspname = 'glovo' OR c.relname LIKE 'bridge\_%' OR c.relname = 'action_approval_requests')
           AND c.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND (pg_get_userbyid(c.relowner) = current_user::text OR pg_has_role(current_user, c.relowner, 'MEMBER')))`).Scan(&bad); err != nil {
		return fmt.Errorf("control: role check: %w", err)
	}
	if bad != 0 {
		return errors.New("control: the shared role is privileged, owns a relation or is a member of an owner role")
	}
	return nil
}

// proveTriggers requires every non-internal trigger of schema glovo, of the
// bridge relations and of the approval table to be enabled for origin
// sessions (tgenabled = 'O'). A disabled guard is a silently open table.
func proveTriggers(ctx context.Context, pool dbq.Querier) error {
	var disabled int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE NOT t.tgisinternal AND t.tgenabled <> 'O'
   AND (n.nspname = 'glovo' OR c.relname LIKE 'bridge\_%' OR c.relname = 'action_approval_requests')`).Scan(&disabled); err != nil {
		return fmt.Errorf("control: trigger check: %w", err)
	}
	if disabled != 0 {
		return errors.New("control: a guard trigger is not enabled for origin sessions")
	}
	return nil
}

// proveWorkItemsRole requires the work-items pool to be a different role with
// no USAGE on schema glovo.
func proveWorkItemsRole(ctx context.Context, shared dbq.Querier, wi dbq.Querier) error {
	var sharedUser, wiUser string
	var usage bool
	if err := shared.QueryRow(ctx, `SELECT current_user::text`).Scan(&sharedUser); err != nil {
		return fmt.Errorf("control: shared role: %w", err)
	}
	if err := wi.QueryRow(ctx, `SELECT current_user::text, has_schema_privilege(current_user, 'glovo', 'USAGE')`).Scan(&wiUser, &usage); err != nil {
		return fmt.Errorf("control: work-items role: %w", err)
	}
	if wiUser == sharedUser {
		return errors.New("control: the work-items pool uses the shared role")
	}
	if usage {
		return errors.New("control: the work-items role has USAGE on schema glovo")
	}
	return nil
}

// Proof holds the sticky result of ProveOneDatabase. Err is nil only after a
// run that passed; before a run, and after any failure, it is not_ready for the
// life of the process.
type Proof struct {
	mu  sync.Mutex
	ran bool
	err error
}

// Run runs fn once and records the result. A second call returns the first
// result without running fn again, so a failure is never retried into a pass.
func (p *Proof) Run(fn func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ran {
		return p.err
	}
	p.ran = true
	p.err = fn()
	return p.err
}

// Err is the readiness view of the proof: not_ready until it passed.
func (p *Proof) Err() error {
	if p == nil {
		return refuse(glovo.CodeNotReady, "one-database proof not run")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ran {
		return refuse(glovo.CodeNotReady, "one-database proof not run")
	}
	if p.err != nil {
		return refuse(glovo.CodeNotReady, "one-database proof failed: "+p.err.Error())
	}
	return nil
}
