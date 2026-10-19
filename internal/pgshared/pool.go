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
// Sharing is switched on by the binary (EnableSharing in cmd/api). Until then
// every Open builds its own pool, as each store did before: tests close a
// store's pool to simulate a failed read, and pgxpool has no way to report
// that a pool was closed, so a registry would go on handing out the dead one.
package pgshared

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultMaxConns bounds a shared pool whose connection string does not set
// pool_max_conns. Two replicas each holding one pool per database (the main
// one and LIFECYCLE_DB_URL's) give 2 x 2 x 10 = 40, and a rolling update's
// surge pod 60, all under the role's connectionLimit of 64.
const DefaultMaxConns = 10

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
	if e, ok := byConn[connStr]; ok {
		e.refs++
		return e.pool, nil
	}
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(connStr, "pool_max_conns") {
		n, err := maxConnsFromEnv()
		if err != nil {
			return nil, err
		}
		cfg.MaxConns = n
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if !sharing {
		return pool, nil
	}
	byConn[connStr] = &entry{pool: pool, refs: 1}
	byPool[pool] = connStr
	return pool, nil
}

// Release drops one reference to a pool returned by Open and closes the pool
// once the last holder has released it. A pool that is not shared (sharing
// off, or a test building a store on its own pool) is closed directly.
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
