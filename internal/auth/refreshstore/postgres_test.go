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

// Internal test so we can wipe the table between runs via the unexported pool.
package refreshstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
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
		_, _ = s.pool.Exec(context.Background(), "DELETE FROM oauth_refresh_tokens")
	})
	return s
}

// uniqueTok returns a token unique to the test and index to avoid hash collisions
// across parallel test runs.
func uniqueTok(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s", t.Name(), suffix)
}

func TestInsertAndRotate(t *testing.T) {
	s := newTestStore(t)

	raw1 := uniqueTok(t, "a")
	raw2 := uniqueTok(t, "b")
	const (
		login    = "alice"
		clientID = "client-1"
	)
	groups := []string{"admins"}
	exp := time.Now().Add(30 * 24 * time.Hour)

	if err := s.Insert(raw1, login, clientID, groups, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	gotLogin, gotGroups, err := s.Rotate(raw1, raw2, clientID, exp)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if gotLogin != login {
		t.Errorf("Rotate login = %q, want %q", gotLogin, login)
	}
	if len(gotGroups) != 1 || gotGroups[0] != "admins" {
		t.Errorf("Rotate groups = %v, want [admins]", gotGroups)
	}
}

func TestRotateRejectsUnknownToken(t *testing.T) {
	s := newTestStore(t)
	_, _, err := s.Rotate(uniqueTok(t, "missing"), uniqueTok(t, "new"), "c1", time.Now().Add(time.Hour))
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestRotateRejectsClientMismatch(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	tok := uniqueTok(t, "tok")
	if err := s.Insert(tok, "carol", "right-client", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_, _, err := s.Rotate(tok, uniqueTok(t, "new"), "wrong-client", exp)
	if !errors.Is(err, ErrClientMismatch) {
		t.Errorf("expected ErrClientMismatch, got %v", err)
	}
}

func TestRotateDetectsReuse(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")
	tok3 := uniqueTok(t, "3")
	tok4 := uniqueTok(t, "4")

	if err := s.Insert(tok1, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	// First rotation succeeds.
	if _, _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	// Replaying the already-rotated original token = reuse detection.
	_, _, err := s.Rotate(tok1, tok3, "c2", exp)
	if !errors.Is(err, ErrReuseDetected) {
		t.Errorf("expected ErrReuseDetected, got %v", err)
	}
	// The current token in the family (tok2) should also be revoked now.
	_, _, err = s.Rotate(tok2, tok4, "c2", exp)
	if err == nil {
		t.Error("expected error when using token from revoked family, got nil")
	}
}

func TestConcurrentRotationRace(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	base := uniqueTok(t, "base")
	if err := s.Insert(base, "eve", "c3", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	const n = 5
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.Rotate(base, fmt.Sprintf("%s-r%d", base, i), "c3", exp)
			results[i] = err
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 successful concurrent rotation, got %d (errors: %v)", successes, results)
	}
}

func TestRevokeFamily(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")
	tok3 := uniqueTok(t, "3")

	if err := s.Insert(tok1, "frank", "c4", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tok1, tok2, "c4", exp); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.RevokeFamily(tok1, "c4", "test_revoke"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	_, _, err := s.Rotate(tok2, tok3, "c4", exp)
	if err == nil {
		t.Error("expected error after family revocation, got nil")
	}
}

func TestGCRemovesOldRevokedRows(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(-8 * 24 * time.Hour) // expired 8 days ago
	tok := uniqueTok(t, "gc")
	if err := s.Insert(tok, "grace", "c5", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := s.RevokeFamily(tok, "c5", "gc_test"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if err := s.GC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// After GC the row is gone; any lookup should return not-found.
	_, _, err := s.Rotate(tok, uniqueTok(t, "gc-new"), "c5", time.Now().Add(time.Hour))
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken after GC, got %v", err)
	}
}
