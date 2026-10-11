// Copyright 2025 MCTL Authors
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

package flowstore

import (
	"bytes"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	connStr := os.Getenv("TEST_DB_URL")
	if connStr == "" {
		t.Skip("TEST_DB_URL not set; skipping Postgres tests")
	}
	s, err := NewPostgresStore(context.Background(), connStr)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), "DELETE FROM oauth_flow_entries")
		s.pool.Close()
	})
	return s
}

func TestPutTakeOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := t.Name()
	if err := s.Put(ctx, KindCode, key, []byte(`{"a":1}`), time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, found, err := s.Take(ctx, KindCode, key)
	if err != nil || !found || !bytes.Equal(got, []byte(`{"a":1}`)) {
		t.Fatalf("Take = %q, %v, %v; want payload, true, nil", got, found, err)
	}
	if _, found, err := s.Take(ctx, KindCode, key); err != nil || found {
		t.Fatalf("second Take = %v, %v; want not found, nil", found, err)
	}
}

func TestTakeIsScopedByKind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := t.Name()
	if err := s.Put(ctx, KindPending, key, []byte("p"), time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, found, err := s.Take(ctx, KindCode, key); err != nil || found {
		t.Fatalf("Take with the other kind = %v, %v; want not found", found, err)
	}
	if _, found, err := s.Take(ctx, KindPending, key); err != nil || !found {
		t.Fatalf("Take with own kind = %v, %v; want found", found, err)
	}
}

func TestTakeExpiredIsNotFoundAndRemoved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := t.Name()
	if err := s.Put(ctx, KindCode, key, []byte("x"), -time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, found, err := s.Take(ctx, KindCode, key); err != nil || found {
		t.Fatalf("Take expired = %v, %v; want not found", found, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_flow_entries`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows left = %d, %v; want 0", n, err)
	}
}

func TestPutRefusesReusedKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := t.Name()
	exp := time.Minute
	if err := s.Put(ctx, KindCode, key, []byte("first"), exp); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, KindCode, key, []byte("second"), exp); err == nil {
		t.Fatal("second Put with the same key succeeded; want an error")
	}
	got, _, _ := s.Take(ctx, KindCode, key)
	if string(got) != "first" {
		t.Fatalf("payload = %q, want the first one kept", got)
	}
}

// Two replicas redeeming the same code at once: exactly one gets it.
func TestConcurrentTakeReturnsOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := t.Name()
	if err := s.Put(ctx, KindCode, key, []byte("x"), time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, found, err := s.Take(ctx, KindCode, key); err == nil && found {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want 1", wins.Load())
	}
}

func TestGCDeletesOnlyExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, KindCode, "old", []byte("x"), -time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, KindCode, "live", []byte("y"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.GC(ctx); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, found, _ := s.Take(ctx, KindCode, "live"); !found {
		t.Fatal("GC removed a live entry")
	}
	var n int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_flow_entries`).Scan(&n)
	if n != 0 {
		t.Fatalf("rows left = %d, want 0", n)
	}
}

// A closed pool is a failed read, never "not found".
func TestTakeOnFailedReadIsAnError(t *testing.T) {
	s := newTestStore(t)
	s.pool.Close()
	if _, found, err := s.Take(context.Background(), KindCode, "k"); err == nil || found {
		t.Fatalf("Take on closed pool = %v, %v; want an error", found, err)
	}
}
