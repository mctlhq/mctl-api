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

// Package pgshared hands every Postgres-backed store one process-wide
// pgxpool per connection string (mctl-api#508).
//
// Each store used to open its own pool, and pgx sizes an unconfigured pool at
// max(4, NumCPU) -- 8 in the pod, where nproc reports the node's CPUs. Sixteen
// stores on the same AUDIT_DB_URL meant a ceiling of 128 connections per
// replica against a `mctl-api` role limit of 64 on shared-pg, while at most a
// handful were ever active. Sharing one bounded pool keeps the ceiling under
// the role limit; the stores never set session state, so nothing leaks from
// one store's queries into another's.
//
// Two rules follow from sharing:
//
//   - Never acquire a connection while holding one from the same pool. A
//     store that calls another store from inside its own transaction draws
//     both connections from one pool, and once every slot is held by a
//     caller waiting for a second one, the pool deadlocks until contexts
//     expire. Resolve cross-store facts before opening the transaction (as
//     evidence.Ingest does).
//   - Pools are keyed on the exact connection string, so two env vars
//     naming one database with any spelling difference get two pools and
//     twice the budget.
//   - A coarse lock held inside a transaction now stalls every store, not
//     only its own. A pg_advisory_xact_lock waiter keeps its pool slot while
//     it waits, and the slots are shared: principals' GitHub-login lock
//     (principals.Provision) can hold several of them during a burst of
//     cache misses, such as a rolling update. Keep such locks fine-grained or
//     short, and watch mctl_api_db_pool_empty_acquires_total.
//
// Sharing is switched on by the binary (EnableSharing in cmd/api). Until then
// every Open builds its own pool, as each store did before: tests close a
// store's pool to simulate a failed read, and pgxpool has no way to report
// that a pool was closed, so a registry would go on handing out the dead one.
package pgshared

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultMaxConns bounds a shared pool whose connection string does not set
// pool_max_conns. cmd/api holds one pool per distinct database URL: today the
// main one and LIFECYCLE_DB_URL's. Each pod also holds up to three connections
// outside any pool: the readiness probe's (OpenDedicated) and two
// customer-deletion lock sessions. The deployment runs two replicas, and a
// rolling update (maxSurge 25%, rounded up) adds a third pod, so the worst
// case is 3 x (2 x 8 + 3) = 57 against the `mctl-api` role's connectionLimit
// of 64. At most a handful of connections were ever active at once.
const DefaultMaxConns = 8

type entry struct {
	pool *pgxpool.Pool
	refs int
}

var (
	mu      sync.Mutex
	sharing bool
	byConn  = map[string]*entry{}
	byPool  = map[*pgxpool.Pool]string{}
)

// EnableSharing makes Open hand out one pool per connection string. Call it
// once at startup, before the first store is built.
func EnableSharing() {
	mu.Lock()
	defer mu.Unlock()
	sharing = true
}

// ValidateEnv reports a malformed DB_POOL_MAX_CONNS, so the binary can refuse
// to boot on it instead of failing every store's init in turn.
func ValidateEnv() error {
	_, err := maxConnsFromEnv()
	return err
}

// Open returns the pool shared by every caller with the same connStr,
// creating it on first use (a new pool per call while sharing is off). Each
// successful Open must be paired with exactly one Release, which replaces the
// pool.Close() a store used to call.
//
// The size comes from pool_max_conns in connStr when present, else from
// DB_POOL_MAX_CONNS, else DefaultMaxConns.
func Open(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	mu.Lock()
	defer mu.Unlock()
	if sharing {
		if e, ok := byConn[connStr]; ok {
			e.refs++
			return e.pool, nil
		}
	}
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("pgshared: parse connection string: %w", err)
	}
	source := "connection string"
	if !hasPoolMaxConns(connStr) {
		n, err := maxConnsFromEnv()
		if err != nil {
			return nil, err
		}
		cfg.MaxConns = n
		source = "DB_POOL_MAX_CONNS or default"
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgshared: new pool: %w", err)
	}
	if !sharing {
		return pool, nil
	}
	// Logged once per shared pool, not per store: the size is the number the
	// role's connection budget is built on, whichever way it was set.
	slog.Info("pgshared: pool opened",
		"host", cfg.ConnConfig.Host, "database", cfg.ConnConfig.Database,
		"max_conns", cfg.MaxConns, "size_from", source)
	byConn[connStr] = &entry{pool: pool, refs: 1}
	byPool[pool] = connStr
	return pool, nil
}

// OpenDedicated builds a pool of maxConns connections that is never shared,
// so its caller never queues behind request traffic for a slot -- what a
// readiness probe needs. Close it with pool.Close().
func OpenDedicated(ctx context.Context, connStr string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("pgshared: parse connection string: %w", err)
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgshared: new dedicated pool: %w", err)
	}
	return pool, nil
}

// Release drops one reference to a pool returned by Open and closes the pool
// once the last holder has released it. A pool that is not shared (sharing
// off, or a test building a store on its own pool) is closed directly.
//
// In cmd/api the AUDIT_DB_URL pool never reaches zero: the audit logger and
// the agent-registry, domains, OAuth flow and refresh-token stores have no
// Close, so that pool lives until the process exits.
func Release(pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	mu.Lock()
	connStr, ok := byPool[pool]
	if !ok {
		mu.Unlock()
		pool.Close()
		return
	}
	e := byConn[connStr]
	e.refs--
	if e.refs > 0 {
		mu.Unlock()
		return
	}
	delete(byConn, connStr)
	delete(byPool, pool)
	mu.Unlock()
	pool.Close()
}

// hasPoolMaxConns reports whether connStr sets pool_max_conns itself. It is a
// key in both forms pgx accepts -- a URL query parameter or a keyword/value
// DSN pair -- so a value that merely contains the text does not count.
func hasPoolMaxConns(connStr string) bool {
	if u, err := url.Parse(connStr); err == nil && u.Scheme != "" {
		return u.Query().Has("pool_max_conns")
	}
	for _, f := range strings.Fields(connStr) {
		if k, _, ok := strings.Cut(f, "="); ok && k == "pool_max_conns" {
			return true
		}
	}
	return false
}

func maxConnsFromEnv() (int32, error) {
	raw := strings.TrimSpace(os.Getenv("DB_POOL_MAX_CONNS"))
	if raw == "" {
		return DefaultMaxConns, nil
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("pgshared: DB_POOL_MAX_CONNS must be a positive integer, got %q", raw)
	}
	return int32(n), nil
}
