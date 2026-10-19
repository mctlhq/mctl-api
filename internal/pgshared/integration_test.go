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

package pgshared_test

import (
	"context"
	"os"
	"testing"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/pgshared"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// The mode cmd/api runs in: real stores on one real pool. Every other store
// test runs with sharing off, so this is the test that covers sharing
// end to end. It runs against the Postgres service validate.yml provides.
func TestStoresShareOnePoolAgainstPostgres(t *testing.T) {
	connStr := os.Getenv("TEST_DB_URL")
	if connStr == "" {
		t.Skip("TEST_DB_URL not set; skipping Postgres-backed pgshared test")
	}
	pgshared.WithSharing(t)
	// The cap assertion below is about the default, not an exported override.
	t.Setenv("DB_POOL_MAX_CONNS", "")
	ctx := context.Background()

	ps, err := principals.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("principals.NewStore: %v", err)
	}
	defer ps.Close()
	as, err := alerts.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("alerts.NewStore: %v", err)
	}
	// Idempotent: the explicit double Close below is the assertion, this one
	// keeps an early failure from also failing the registry check.
	defer as.Close()

	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.Config().MaxConns; got != pgshared.DefaultMaxConns {
		t.Errorf("shared pool MaxConns = %d, want %d", got, pgshared.DefaultMaxConns)
	}
	if got := pool.Stat().TotalConns(); got > pgshared.DefaultMaxConns {
		t.Errorf("shared pool holds %d connections, over the cap", got)
	}
	pgshared.Release(pool)

	if err := ps.Ping(ctx); err != nil {
		t.Fatalf("principals before alerts closed: %v", err)
	}
	if _, err := as.List(ctx, alerts.ListFilter{}); err != nil {
		t.Fatalf("alerts on the shared pool: %v", err)
	}

	// Closing one store, twice, must leave the pool the other still uses.
	as.Close()
	as.Close()
	if err := ps.Ping(ctx); err != nil {
		t.Fatalf("principals after alerts closed twice: %v", err)
	}
}
