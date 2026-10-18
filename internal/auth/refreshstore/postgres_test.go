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

	"github.com/jackc/pgx/v5"
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

	if err := s.Insert(raw1, clientID, Session{Login: login, Groups: groups}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := s.Rotate(raw1, raw2, clientID, exp)
	gotLogin, gotGroups := got.Login, got.Groups
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
	_, err := s.Rotate(uniqueTok(t, "missing"), uniqueTok(t, "new"), "c1", time.Now().Add(time.Hour))
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestRotateRejectsClientMismatch(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	tok := uniqueTok(t, "tok")
	if err := s.Insert(tok, "right-client", Session{Login: "carol", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_, err := s.Rotate(tok, uniqueTok(t, "new"), "wrong-client", exp)
	if !errors.Is(err, ErrClientMismatch) {
		t.Errorf("expected ErrClientMismatch, got %v", err)
	}
}

// withShortGraceWindow overrides rotationGraceWindow for the duration of the
// test, so a grace-window test neither sleeps out the real default nor depends
// on what that default happens to be.
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

	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	// A deterministic-derivation caller recomputes the exact same successor
	// (tok2) when retrying with predecessor tok1 — replaying that pair within
	// the grace window must succeed and hand back the same session.
	got, err := s.Rotate(tok1, tok2, "c2", exp)
	login, groups := got.Login, got.Groups
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
	if _, err := s.Rotate(tok2, tok3, "c2", exp); err != nil {
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

	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	if _, err := s.Rotate(tok1, tok2, "wrong-client", exp); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for cross-client grace replay, got %v", err)
	}

	// The legitimate successor must remain untouched by the failed attempt.
	tok3 := uniqueTok(t, "3")
	if _, err := s.Rotate(tok2, tok3, "c2", exp); err != nil {
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

	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, longExp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tok1, tok2, "c2", alreadyExpired); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	if _, err := s.Rotate(tok1, tok2, "c2", longExp); !errors.Is(err, ErrInvalidToken) {
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

	if err := s.Insert(tokA, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tokA, tokB, "c2", exp); err != nil {
		t.Fatalf("rotate A->B: %v", err)
	}
	if _, err := s.Rotate(tokB, tokC, "c2", exp); err != nil {
		t.Fatalf("rotate B->C: %v", err)
	}

	// Replaying A (still within its own grace window) must not reissue B,
	// since B is no longer the live tip of the family.
	if _, err := s.Rotate(tokA, tokB, "c2", exp); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for two-hops-back replay, got %v", err)
	}

	// C must remain valid.
	tokD := uniqueTok(t, "d")
	if _, err := s.Rotate(tokC, tokD, "c2", exp); err != nil {
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
	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
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
			got, err := s.Rotate(tok1, tok2, "c2", exp)
			login := got.Login
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
	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
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

	if err := s.Insert(tok1, "c2", Session{Login: "dave", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	// First rotation succeeds.
	if _, err := s.Rotate(tok1, tok2, "c2", exp); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	time.Sleep(60 * time.Millisecond) // clear the grace window

	// Replaying the already-rotated original token past the grace window =
	// genuine reuse detection.
	_, err := s.Rotate(tok1, tok3, "c2", exp)
	if !errors.Is(err, ErrReuseDetected) {
		t.Errorf("expected ErrReuseDetected, got %v", err)
	}
	// The current token in the family (tok2) should also be revoked now.
	_, err = s.Rotate(tok2, tok4, "c2", exp)
	if err == nil {
		t.Error("expected error when using token from revoked family, got nil")
	}
}

func TestConcurrentRotationRace(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(time.Hour)
	base := uniqueTok(t, "base")
	if err := s.Insert(base, "c3", Session{Login: "eve", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	const n = 5
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Rotate(base, fmt.Sprintf("%s-r%d", base, i), "c3", exp)
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

	if err := s.Insert(tok1, "c4", Session{Login: "frank", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.Rotate(tok1, tok2, "c4", exp); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.RevokeFamily(tok1, "c4", "test_revoke"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	_, err := s.Rotate(tok2, tok3, "c4", exp)
	if err == nil {
		t.Error("expected error after family revocation, got nil")
	}
}

func TestGCRemovesOldRevokedRows(t *testing.T) {
	s := newTestStore(t)

	exp := time.Now().Add(-8 * 24 * time.Hour) // expired 8 days ago
	tok := uniqueTok(t, "gc")
	if err := s.Insert(tok, "c5", Session{Login: "grace", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := s.RevokeFamily(tok, "c5", "gc_test"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if err := s.GC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// After GC the row is gone; any lookup should return not-found.
	_, err := s.Rotate(tok, uniqueTok(t, "gc-new"), "c5", time.Now().Add(time.Hour))
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken after GC, got %v", err)
	}
}

// The grace window exists to absorb a lost rotation response, and a client
// that never saw one retries on its next refresh cycle — minutes later, not
// milliseconds. A window shorter than a minute therefore fails to cover the
// only case it is for, while still paying its full cost: the replay lands
// outside the window, is read as reuse, and the whole family is revoked, which
// logs every client on it out (2026-09-17, family 9f57b332).
//
// This is a TYPO-GUARD on the default, not coverage of the grace path. It
// asserts a property of a literal, so it catches the one regression that
// actually happened — someone typing the old 30s back — and nothing else: it
// would still pass if the window were read from elsewhere, if
// withShortGraceWindow leaked past a test, or if rotateTx stopped reaching the
// grace branch at all. The behavioural coverage for those lives in the
// rotateTx grace tests above, which drive the var rather than this const.
// Do not read this test's presence as evidence that the 2m value is tested.
func TestDefaultRotationGraceWindow_CoversAClientRetryCycle(t *testing.T) {
	if defaultRotationGraceWindow < time.Minute {
		t.Errorf("defaultRotationGraceWindow = %s, want at least 1m: see the comment on rotationGraceWindow", defaultRotationGraceWindow)
	}
}

// The principal a session was minted for survives every rotation path, the
// grace-window replay included (mctl-api#377): a refresh that dropped it
// would mint a pid-less token, which principal mode refuses.
func TestRotateCarriesThePrincipal(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour)
	const prn = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	exp := time.Now().Add(time.Hour)
	tok1, tok2 := uniqueTok(t, "1"), uniqueTok(t, "2")
	if err := s.Insert(tok1, "c", Session{Login: "erin", PrincipalID: prn, Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.Rotate(tok1, tok2, "c", exp)
	if err != nil || got.PrincipalID != prn || got.Login != "erin" {
		t.Fatalf("Rotate = %+v, %v; want erin / %s", got, err, prn)
	}
	got, err = s.Rotate(tok1, tok2, "c", exp)
	if err != nil || got.PrincipalID != prn {
		t.Fatalf("grace replay = %+v, %v; want %s", got, err, prn)
	}
	got, err = s.Rotate(tok2, uniqueTok(t, "3"), "c", exp)
	if err != nil || got.PrincipalID != prn {
		t.Fatalf("second Rotate = %+v, %v; want %s", got, err, prn)
	}

	// A principal-only session has no login at all.
	tok4 := uniqueTok(t, "4")
	if err := s.Insert(tok4, "c", Session{PrincipalID: prn}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got, err := s.Rotate(tok4, uniqueTok(t, "5"), "c", exp); err != nil || got.PrincipalID != prn || got.Login != "" {
		t.Fatalf("principal-only Rotate = %+v, %v", got, err)
	}
}

// TestRotateCarriesTheAuthMethod checks that a private_key_jwt session keeps
// its method through rotation, a grace-window replay and the successor row,
// so it can never be refreshed as a public client (mctl-api#694).
func TestRotateCarriesTheAuthMethod(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Hour)
	exp := time.Now().Add(time.Hour)
	tok1, tok2 := uniqueTok(t, "1"), uniqueTok(t, "2")
	if err := s.Insert(tok1, "c", Session{Login: "erin", Groups: []string{}, AuthMethod: "private_key_jwt"}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	for i, step := range []struct{ old, next string }{{tok1, tok2}, {tok1, tok2}, {tok2, uniqueTok(t, "3")}} {
		got, err := s.Rotate(step.old, step.next, "c", exp)
		if err != nil || got.AuthMethod != "private_key_jwt" {
			t.Fatalf("step %d: Rotate = %+v, %v", i, got, err)
		}
	}
	tok4 := uniqueTok(t, "4")
	if err := s.Insert(tok4, "c", Session{Login: "erin", Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got, err := s.Rotate(tok4, uniqueTok(t, "5"), "c", exp); err != nil || got.AuthMethod != "" {
		t.Fatalf("public session Rotate = %+v, %v", got, err)
	}
}

func TestRevokePrincipal(t *testing.T) {
	s := newTestStore(t)
	const (
		prn   = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ" //nolint:gosec // G101: a principal id, not a credential
		other = "prn_01JYYYYYYYYYYYYYYYYYYYYYYY" //nolint:gosec // G101: a principal id, not a credential
	)
	exp := time.Now().Add(time.Hour)
	tok := func(n string) string { return uniqueTok(t, n) }

	// Two families under two clients, one of them rotated, plus another
	// principal's session and a login-only one.
	for _, ins := range []struct {
		tok, client string
		sess        Session
	}{
		{tok("a1"), "c1", Session{Login: "alice", PrincipalID: prn, Groups: []string{}}},
		{tok("b1"), "c2", Session{PrincipalID: prn}},
		{tok("o1"), "c1", Session{Login: "bob", PrincipalID: other, Groups: []string{}}},
		{tok("l1"), "c1", Session{Login: "alice", Groups: []string{}}},
	} {
		if err := s.Insert(ins.tok, ins.client, ins.sess, exp); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	if _, err := s.Rotate(tok("a1"), tok("a2"), "c1", exp); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	n, err := s.RevokePrincipal(prn, "identity_unlinked")
	if err != nil {
		t.Fatalf("RevokePrincipal: %v", err)
	}
	// Two sessions: a1 (rotated, still unrevoked) and a2 are one family.
	if n != 2 {
		t.Errorf("RevokePrincipal reported %d sessions, want 2", n)
	}
	if _, err := s.Rotate(tok("a2"), tok("a3"), "c1", exp); err == nil {
		t.Error("the revoked principal's successor still rotates")
	}
	if _, err := s.Rotate(tok("b1"), tok("b2"), "c2", exp); err == nil {
		t.Error("the revoked principal's other family still rotates")
	}
	if _, err := s.Rotate(tok("o1"), tok("o2"), "c1", exp); err != nil {
		t.Errorf("another principal's session was revoked: %v", err)
	}
	if _, err := s.Rotate(tok("l1"), tok("l2"), "c1", exp); err != nil {
		t.Errorf("a session with no principal was revoked: %v", err)
	}

	if n, err := s.RevokePrincipal(prn, "identity_unlinked"); err != nil || n != 0 {
		t.Errorf("second RevokePrincipal = %d, %v; want 0, nil", n, err)
	}
	if _, err := s.RevokePrincipal("", "identity_unlinked"); err == nil {
		t.Error("RevokePrincipal accepted an empty principal id")
	}
}

// TestRevokePrincipalCatchesAConcurrentRotation holds a rotation open at the
// point where its successor is written but not committed, starts
// RevokePrincipal, and commits the rotation only once the revocation is
// waiting on its lock. The successor must end up revoked: a revocation that
// misses it leaves the unlinked identity a live session.
func TestRevokePrincipalCatchesAConcurrentRotation(t *testing.T) {
	s := newTestStore(t)
	const prn = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ" //nolint:gosec // G101: a principal id, not a credential
	exp := time.Now().Add(time.Hour)
	tok1, tok2 := uniqueTok(t, "1"), uniqueTok(t, "2")
	if err := s.Insert(tok1, "c", Session{Login: "erin", PrincipalID: prn, Groups: []string{}}, exp); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// What rotateTx writes: lock the predecessor, mark it rotated, insert
	// the successor in its family.
	if _, err := tx.Exec(ctx,
		`SELECT 1 FROM oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash(tok1)); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_refresh_tokens SET rotated_at = NOW() WHERE token_hash = $1`, tokenHash(tok1)); err != nil {
		t.Fatalf("mark rotated: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens
		 (token_hash, client_id, login, principal_id, groups, family_id, parent_token_hash, issued_at, expires_at)
		 SELECT $1, client_id, login, principal_id, groups, family_id, token_hash, NOW(), expires_at
		 FROM oauth_refresh_tokens WHERE token_hash = $2`,
		tokenHash(tok2), tokenHash(tok1)); err != nil {
		t.Fatalf("insert successor: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := s.RevokePrincipal(prn, "identity_unlinked")
		done <- result{n, err}
	}()

	// Commit only once the revocation is blocked on the predecessor's row.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_locks WHERE NOT granted AND locktype = 'transactionid'`,
		).Scan(&waiting); err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RevokePrincipal never waited on the rotation's lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit rotation: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("RevokePrincipal: %v", res.err)
	}
	var revoked bool
	if err := s.pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token_hash = $1`, tokenHash(tok2),
	).Scan(&revoked); err != nil {
		t.Fatalf("read successor: %v", err)
	}
	if !revoked {
		t.Fatal("the successor committed during the revocation is still live")
	}
	if res.n != 1 {
		t.Errorf("RevokePrincipal reported %d sessions, want the one", res.n)
	}
}
