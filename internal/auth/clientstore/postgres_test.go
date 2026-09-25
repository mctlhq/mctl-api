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

// Internal test so we can wipe the table and rewind timestamps via the
// unexported pool.
package clientstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
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
	wipe := func() { _, _ = s.pool.Exec(context.Background(), "DELETE FROM oauth_registered_clients") }
	wipe()
	t.Cleanup(func() {
		wipe()
		s.Close()
	})
	return s
}

// rewind moves a row's last_seen_at into the past.
func rewind(t *testing.T, s *PostgresStore, clientID string, by time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE oauth_registered_clients SET last_seen_at = last_seen_at - make_interval(secs => $2) WHERE client_id = $1`,
		clientID, by.Seconds()); err != nil {
		t.Fatalf("rewind: %v", err)
	}
}

func TestRegisterAndGet(t *testing.T) {
	s := newTestStore(t)
	uris := []string{"https://a.test/cb", "https://b.test/cb"}
	got, err := s.Register(Client{ClientID: "dcr_1", ClientName: "portal", RedirectURIs: uris}, 10)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got.ClientID != "dcr_1" || got.ClientName != "portal" || !slices.Equal(got.RedirectURIs, uris) {
		t.Fatalf("Register returned %+v", got)
	}
	if got.CreatedAt.IsZero() || got.LastSeenAt.IsZero() {
		t.Fatalf("timestamps not set: %+v", got)
	}
	read, err := s.Get("dcr_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !slices.Equal(read.RedirectURIs, uris) || read.ClientName != "portal" {
		t.Fatalf("Get returned %+v", read)
	}
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
}

// A second process over the same database -- the rollout case -- resolves a
// client the first one registered.
func TestRegistrationVisibleToAnotherPool(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Register(Client{ClientID: "dcr_restart", RedirectURIs: []string{"https://a.test/cb"}}, 10); err != nil {
		t.Fatal(err)
	}
	other, err := NewPostgresStore(context.Background(), os.Getenv("TEST_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Get("dcr_restart"); err != nil {
		t.Fatalf("second store instance cannot resolve the client: %v", err)
	}
}

// A repeated registration returns the first record and only refreshes
// last_seen_at: a racing or replayed registration cannot rewrite the name or
// the callbacks of an existing id.
func TestRegisterIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	first, err := s.Register(Client{ClientID: "dcr_i", ClientName: "portal", RedirectURIs: []string{"https://a.test/cb"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	rewind(t, s, "dcr_i", time.Hour)
	again, err := s.Register(Client{ClientID: "dcr_i", ClientName: "rewritten", RedirectURIs: []string{"https://evil.test/cb"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if again.ClientName != "portal" || !slices.Equal(again.RedirectURIs, []string{"https://a.test/cb"}) {
		t.Errorf("repeat registration rewrote the record: %+v", again)
	}
	if !again.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at moved from %v to %v", first.CreatedAt, again.CreatedAt)
	}
	if time.Since(again.LastSeenAt) > time.Minute {
		t.Errorf("last_seen_at not refreshed: %v", again.LastSeenAt)
	}
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_registered_clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// The cap evicts the least recently seen rows, never the one just written.
func TestRegisterTrimsLeastRecentlySeen(t *testing.T) {
	s := newTestStore(t)
	for i := range 3 {
		id := fmt.Sprintf("dcr_%d", i)
		if _, err := s.Register(Client{ClientID: id, RedirectURIs: []string{"https://a.test/cb"}}, 10); err != nil {
			t.Fatal(err)
		}
		// dcr_0 oldest, dcr_2 newest.
		rewind(t, s, id, time.Duration(3-i)*time.Hour)
	}
	// Use dcr_0 so it becomes the most recent; dcr_1 is now the oldest.
	if err := s.Touch("dcr_0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(Client{ClientID: "dcr_new", RedirectURIs: []string{"https://a.test/cb"}}, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("dcr_1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("least recently seen client survived the cap: err = %v", err)
	}
	for _, id := range []string{"dcr_0", "dcr_2", "dcr_new"} {
		if _, err := s.Get(id); err != nil {
			t.Errorf("client %s evicted: %v", id, err)
		}
	}
}

// Touch is throttled: a fresh row is left alone, a stale one moves.
func TestTouchIsThrottled(t *testing.T) {
	s := newTestStore(t)
	c, err := s.Register(Client{ClientID: "dcr_t", RedirectURIs: []string{"https://a.test/cb"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Touch("dcr_t"); err != nil {
		t.Fatal(err)
	}
	fresh, _ := s.Get("dcr_t")
	if !fresh.LastSeenAt.Equal(c.LastSeenAt) {
		t.Errorf("touch inside the throttle window rewrote last_seen_at")
	}
	rewind(t, s, "dcr_t", 2*touchInterval)
	if err := s.Touch("dcr_t"); err != nil {
		t.Fatal(err)
	}
	moved, _ := s.Get("dcr_t")
	if time.Since(moved.LastSeenAt) > time.Minute {
		t.Errorf("touch past the throttle window did not refresh last_seen_at: %v", moved.LastSeenAt)
	}
	if err := s.Touch("missing"); err != nil {
		t.Errorf("touch of an unknown id: %v", err)
	}
}

func TestGCDeletesOnlyStale(t *testing.T) {
	s := newTestStore(t)
	for _, id := range []string{"dcr_old", "dcr_live"} {
		if _, err := s.Register(Client{ClientID: id, RedirectURIs: []string{"https://a.test/cb"}}, 10); err != nil {
			t.Fatal(err)
		}
	}
	rewind(t, s, "dcr_old", 48*time.Hour)
	if err := s.GC(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("dcr_old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale client survived GC: %v", err)
	}
	if _, err := s.Get("dcr_live"); err != nil {
		t.Errorf("live client deleted by GC: %v", err)
	}
}
