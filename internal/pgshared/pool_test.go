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

package pgshared

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxpool connects lazily, so none of these tests needs a server: the port
// below is never dialled except by isClosed, which only reads the error kind.
const testConn = "postgres://u@127.0.0.1:1/db?sslmode=disable"

func isClosed(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	conn, err := pool.Acquire(ctx)
	if err == nil {
		conn.Release()
		t.Fatal("acquire unexpectedly succeeded")
	}
	// puddle.ErrClosedPool; matched by text to keep puddle an indirect dependency.
	return strings.Contains(err.Error(), "closed pool")
}

func TestOpenWithoutSharingBuildsAPoolPerCall(t *testing.T) {
	ctx := context.Background()
	a, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("pools shared while sharing is off")
	}
	Release(a)
	if !isClosed(t, a) {
		t.Fatal("Release left an unshared pool open")
	}
	if isClosed(t, b) {
		t.Fatal("closing one unshared pool closed another")
	}
	Release(b)
}

// A pool registered while sharing was on must not leak into an Open made
// after it was switched off.
func TestOpenWithoutSharingIgnoresTheRegistry(t *testing.T) {
	ctx := context.Background()
	EnableSharing()
	shared, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	sharing = false
	mu.Unlock()
	t.Cleanup(func() { Release(shared); resetRegistry(t) })

	fresh, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(fresh)
	if fresh == shared {
		t.Fatal("Open with sharing off returned a registered pool")
	}
}

func TestOpenSharesOnePoolPerConnString(t *testing.T) {
	withSharing(t)
	ctx := context.Background()
	a, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("two Opens of the same connStr returned different pools")
	}
	other, err := Open(ctx, testConn+"&application_name=other")
	if err != nil {
		t.Fatal(err)
	}
	if other == a {
		t.Fatal("different connStrs shared a pool")
	}
	Release(other)

	Release(a)
	if isClosed(t, b) {
		t.Fatal("pool closed while a holder still had it")
	}
	Release(b)
	if !isClosed(t, b) {
		t.Fatal("pool still open after the last Release")
	}

	c, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(c)
	if c == a {
		t.Fatal("Open after the last Release reused the closed pool")
	}
}

func TestOpenPoolSize(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, conn, env string
		want            int32
	}{
		{"default", testConn, "", DefaultMaxConns},
		{"env", testConn, "3", 3},
		{"conn string wins", testConn + "&pool_max_conns=5", "3", 5},
		{"keyword DSN wins", "host=127.0.0.1 port=1 user=u dbname=db sslmode=disable pool_max_conns=4", "3", 4},
		// The key's text inside a value is not the key: the cap still applies.
		{"text in a value", testConn + "&application_name=pool_max_conns_probe", "3", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSharing(t)
			t.Setenv("DB_POOL_MAX_CONNS", tc.env)
			pool, err := Open(ctx, tc.conn)
			if err != nil {
				t.Fatal(err)
			}
			defer Release(pool)
			if got := pool.Config().MaxConns; got != tc.want {
				t.Fatalf("MaxConns = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestOpenDedicatedIsNeverShared(t *testing.T) {
	withSharing(t)
	ctx := context.Background()
	shared, err := Open(ctx, testConn)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(shared)
	probe, err := OpenDedicated(ctx, testConn, 1)
	if err != nil {
		t.Fatal(err)
	}
	if probe == shared {
		t.Fatal("OpenDedicated returned the shared pool")
	}
	if got := probe.Config().MaxConns; got != 1 {
		t.Fatalf("dedicated MaxConns = %d, want 1", got)
	}
	probe.Close()
	if isClosed(t, shared) {
		t.Fatal("closing the dedicated pool closed the shared one")
	}
}

func TestBadEnvIsRefused(t *testing.T) {
	for _, v := range []string{"0", "-1", "ten"} {
		t.Setenv("DB_POOL_MAX_CONNS", v)
		if err := ValidateEnv(); err == nil {
			t.Fatalf("ValidateEnv accepted DB_POOL_MAX_CONNS=%q", v)
		}
		if pool, err := Open(context.Background(), testConn); err == nil {
			Release(pool)
			t.Fatalf("Open accepted DB_POOL_MAX_CONNS=%q", v)
		}
	}
	t.Setenv("DB_POOL_MAX_CONNS", "")
	if err := ValidateEnv(); err != nil {
		t.Fatalf("ValidateEnv with the variable unset = %v", err)
	}
}

func TestReleaseClosesForeignPool(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), testConn)
	if err != nil {
		t.Fatal(err)
	}
	Release(pool)
	if !isClosed(t, pool) {
		t.Fatal("Release left a pool it did not hand out open")
	}
}

// Run with -race: Open and Release from many goroutines on a few
// connection strings must leave the registry empty and every pool closed.
func TestConcurrentOpenRelease(t *testing.T) {
	withSharing(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn := fmt.Sprintf("%s&application_name=c%d", testConn, i%3)
			for j := 0; j < 20; j++ {
				pool, err := Open(ctx, conn)
				if err != nil {
					t.Error(err)
					return
				}
				Release(pool)
			}
		}(i)
	}
	wg.Wait()
}
