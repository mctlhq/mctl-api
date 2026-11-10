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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

const glovoOptsTestPW = "pw-glovo-opts-test" //nolint:gosec // throwaway password of roles in a scratch database

// The production Glovo store must carry the handoff end purger and require it.
// Required is observable through Ready: with a slice 961 table missing, a
// store that requires the purger reports not_ready (table_missing); one that
// does not, never looks for the table.
func newGlovoOptsDB(t *testing.T, tag string) (urlFor func(string) string, rt, mig string) {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sfx := fmt.Sprintf("%x", os.Getpid()) + fmt.Sprintf("%d", len(t.Name())) + tag
	db, mig, rt := "g961opts_"+sfx, "g961optsm_"+sfx, "g961optsr_"+sfx
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, mig, glovoOptsTestPW),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, rt, glovoOptsTestPW),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, db, mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, db, rt),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, db))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rt))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, mig))
	})
	urlFor = func(user string) string {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword(user, glovoOptsTestPW)
		u.Path = "/" + db
		return u.String()
	}
	return urlFor, rt, mig
}

func TestGlovoStoreOptionsInstallAndRequireEndPurger(t *testing.T) {
	ctx := context.Background()
	urlFor, rt, mig := newGlovoOptsDB(t, "a")
	if err := glovo.ApplySchema(ctx, urlFor(mig), rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	pool, err := pgxpool.New(ctx, urlFor(rt))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := glovo.NewStore(ctx, pool, rt, mig, glovoStoreOptions(false)...)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if !store.EndPurgerInstalled() {
		t.Fatal("the production store has no end purger")
	}
	if err := store.Ready(ctx); err != nil {
		t.Fatalf("intact schema is not ready: %v", err)
	}
	// Required: a missing slice 961 table is table_missing, not ready.
	mp, err := pgxpool.New(ctx, urlFor(mig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mp.Close)
	if _, err := mp.Exec(ctx, `ALTER TABLE glovo.glovo_handoff_refs RENAME TO glovo_handoff_refs_gone`); err != nil {
		t.Fatalf("rename: %v", err)
	}
	var nr *glovo.NotReadyError
	if err := store.Ready(ctx); !errors.As(err, &nr) || nr.Reason != glovo.NotReadyTableMissing {
		t.Fatalf("a required purger with its table missing must be not_ready table_missing, got %v", err)
	}
}

// The boot-time proof of the real revocation hook: without the bridge schema on
// the Glovo pool it fails (so a flag-on boot is refused, never given a hook
// that would break every connection end); once the schema is applied with the
// runtime grants it passes.
func TestProveBridgeHookTablesOnTheGlovoPool(t *testing.T) {
	ctx := context.Background()
	urlFor, rt, mig := newGlovoOptsDB(t, "b")
	if err := glovo.ApplySchema(ctx, urlFor(mig), rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	pool, err := pgxpool.New(ctx, urlFor(rt))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := proveBridgeHookTables(ctx, pool); err == nil {
		t.Fatal("the proof passed on a database with no bridge schema")
	}
	if err := bridge.ApplySchema(ctx, urlFor(mig), rt); err != nil {
		t.Fatalf("bridge.ApplySchema: %v", err)
	}
	if err := proveBridgeHookTables(ctx, pool); err != nil {
		t.Fatalf("the proof failed with the schema and grants in place: %v", err)
	}
	// A grant the hook needs, taken away, fails the proof.
	mp, err := pgxpool.New(ctx, urlFor(mig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mp.Close)
	if _, err := mp.Exec(ctx, `REVOKE UPDATE ON bridge_commands FROM `+rt); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := proveBridgeHookTables(ctx, pool); err == nil {
		t.Fatal("the proof passed with UPDATE on bridge_commands revoked")
	}
}
