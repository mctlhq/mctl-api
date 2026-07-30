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
	"crypto/sha256"
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

// withShortGraceWindow shrinks rotationGraceWindow for the duration of the
// test so grace-window tests don't need real 30s sleeps.
func withShortGraceWindow(t *testing.T, d time.Duration) {
	t.Helper()
	prev := rotationGraceWindow
	rotationGraceWindow = d
	t.Cleanup(func() { rotationGraceWindow = prev })
}

// TestRotateGraceWindowReplay_Succeeds covers the actual production bug fix:
// a deterministic-derivation caller that retries a refresh with the same
// predecessor within the grace window (e.g. after a dropped response) must
// recover the already-committed successor and succeed, not fail with
// invalid_grant.
func TestRotateGraceWindowReplay_Succeeds(t *testing.T) {
	s := newTestStore(t)
	// A wide window, not a short one: the replay happens immediately after
	// the first rotation with no intentional delay, so a generous window
	// costs nothing here and avoids CI scheduling jitter turning this into a
	// flaky post-grace failure (a tight window measured against wall-clock
	// time is what the boundary-crossing test below is for).
	withShortGraceWindow(t, time.Hour)

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")

	if err := s.Insert(tok1, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	// A deterministic-derivation caller recomputes the exact same successor
	// (tok2) when retrying with predecessor tok1 — replaying that pair within
	// the grace window must succeed and hand back the same session.
	login, groups, err := s.Rotate(tok1, tok2, "c2", exp)
	if err != nil {
		t.Fatalf("grace-window replay: %v", err)
	}
	if login != "dave" {
		t.Errorf("grace replay login = %q, want dave", login)
	}
	if len(groups) != 0 {
		t.Errorf("grace replay groups = %v, want []", groups)
	}

	// The re-issued successor (tok2) must still be usable for a further,
	// genuine rotation afterwards.
	tok3 := uniqueTok(t, "3")
	if _, _, err := s.Rotate(tok2, tok3, "c2", exp); err != nil {
		t.Errorf("Rotate on grace-replayed successor: %v", err)
	}
}

// TestRotateGraceWindow_WrongClientRejected ensures a grace-window replay
// presenting a different client_id than the original rotation is never
// trusted, and doesn't disturb the legitimate successor.
func TestRotateGraceWindow_WrongClientRejected(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour) // wide window; rejection is by client_id, not timing

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")

	if err := s.Insert(tok1, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	if _, _, err := s.Rotate(tok1, tok2, "wrong-client", exp); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for cross-client grace replay, got %v", err)
	}

	// The legitimate successor must remain untouched by the failed attempt.
	tok3 := uniqueTok(t, "3")
	if _, _, err := s.Rotate(tok2, tok3, "c2", exp); err != nil {
		t.Errorf("legitimate successor should still work after rejected cross-client replay: %v", err)
	}
}

// TestRotateGraceWindow_ExpiredSuccessorRejected ensures a grace replay never
// hands back a successor that is itself already past its own expiry — e.g. a
// long-lived predecessor rotated into a short-lived successor (TTL lowered
// between issuance and rotation) must not let a grace-window replay resurrect
// that successor once it's expired, even though the replay itself is still
// within the rotation's grace window.
func TestRotateGraceWindow_ExpiredSuccessorRejected(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour) // isolate the expiry check from timing

	longExp := time.Now().Add(30 * 24 * time.Hour)
	alreadyExpired := time.Now().Add(-time.Minute)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")

	if err := s.Insert(tok1, "dave", "c2", []string{}, longExp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tok1, tok2, "c2", alreadyExpired); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	if _, _, err := s.Rotate(tok1, tok2, "c2", longExp); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for expired successor grace replay, got %v", err)
	}
}

// TestRotateGraceWindow_TwoHopsBackRejected ensures grace recovery is
// single-hop only: replaying a token whose immediate child has itself
// already been superseded must not resurrect that child.
func TestRotateGraceWindow_TwoHopsBackRejected(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour) // wide window so timing can't hide the bug

	exp := time.Now().Add(time.Hour)
	tokA := uniqueTok(t, "a")
	tokB := uniqueTok(t, "b")
	tokC := uniqueTok(t, "c")

	if err := s.Insert(tokA, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tokA, tokB, "c2", exp); err != nil {
		t.Fatalf("rotate A->B: %v", err)
	}
	if _, _, err := s.Rotate(tokB, tokC, "c2", exp); err != nil {
		t.Fatalf("rotate B->C: %v", err)
	}

	// Replaying A (still within its own grace window) must not reissue B,
	// since B is no longer the live tip of the family.
	if _, _, err := s.Rotate(tokA, tokB, "c2", exp); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for two-hops-back replay, got %v", err)
	}

	// C must remain valid.
	tokD := uniqueTok(t, "d")
	if _, _, err := s.Rotate(tokC, tokD, "c2", exp); err != nil {
		t.Errorf("current successor C should still work: %v", err)
	}
}

// TestRotateGraceWindow_ConcurrentReplaySameSuccessor models the real race
// this fix targets: two requests racing to rotate the same predecessor with
// the same deterministically-derived successor. Both must succeed with the
// identical session, and exactly one row must exist for the successor.
func TestRotateGraceWindow_ConcurrentReplaySameSuccessor(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour)

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")
	if err := s.Insert(tok1, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	const n = 5
	var wg sync.WaitGroup
	logins := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			login, _, err := s.Rotate(tok1, tok2, "c2", exp)
			logins[i] = login
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("racer %d: unexpected error: %v", i, err)
		}
		if logins[i] != "dave" {
			t.Errorf("racer %d: login = %q, want dave", i, logins[i])
		}
	}

	var rowCount int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_refresh_tokens WHERE token_hash = $1`,
		tokenHash(tok2),
	).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("expected exactly 1 row for the shared successor, got %d", rowCount)
	}
}

// TestPostgresStore_NeverPersistsRawToken guards the invariant that makes
// deterministic successor derivation safe: only SHA-256 hashes are ever
// written to storage, never a raw or recoverable token value.
func TestPostgresStore_NeverPersistsRawToken(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	tok1 := uniqueTok(t, "1")
	tok2 := uniqueTok(t, "2")
	if err := s.Insert(tok1, "dave", "c2", []string{}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	rows, err := s.pool.Query(context.Background(),
		`SELECT token_hash, parent_token_hash FROM oauth_refresh_tokens`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenHashCol []byte
		var parentHashCol *[]byte
		if err := rows.Scan(&tokenHashCol, &parentHashCol); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(tokenHashCol) != sha256.Size {
			t.Errorf("token_hash is not a SHA-256 digest: %d bytes", len(tokenHashCol))
		}
		if string(tokenHashCol) == tok1 || string(tokenHashCol) == tok2 {
			t.Error("token_hash equals a raw token value")
		}
		if parentHashCol != nil {
			if len(*parentHashCol) != sha256.Size {
				t.Errorf("parent_token_hash is not a SHA-256 digest: %d bytes", len(*parentHashCol))
			}
			if string(*parentHashCol) == tok1 || string(*parentHashCol) == tok2 {
				t.Error("parent_token_hash equals a raw token value")
			}
		}
	}
}

// TestRotateReuseAfterGraceWindow_RevokesFamily covers the pre-existing (and
// unchanged) post-grace behavior: once the grace window has elapsed, a
// replayed predecessor is treated as genuine reuse and the whole family dies.
func TestRotateReuseAfterGraceWindow_RevokesFamily(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, 50*time.Millisecond)

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

	time.Sleep(60 * time.Millisecond) // clear the grace window

	// Replaying the already-rotated original token past the grace window =
	// genuine reuse detection.
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
