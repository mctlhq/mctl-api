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

package surfaceid

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStoreForTest(t *testing.T, linkTTL time.Duration) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed surface identity test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr, linkTTL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	wipe := func() {
		for _, table := range []string{"surface_identity_links", "surface_identity_challenges"} {
			if _, err := s.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
				t.Fatal(err)
			}
		}
	}
	wipe()
	t.Cleanup(func() { wipe(); s.Close() })
	return s
}

func reason(err error) string {
	var ce *ChallengeError
	if errors.As(err, &ce) {
		return ce.Reason
	}
	return ""
}

func TestChallengeRedeemsIntoALinkOnce(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	c, err := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.ReplaceAll(c.Code, "-", "")) != 32 || c.ExpiresAt.Sub(s.now()) > ChallengeTTL {
		t.Fatalf("challenge = %+v", c)
	}
	// Only the hash is stored.
	var stored int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM surface_identity_challenges WHERE code_hash=$1 OR code_hash=$2`, c.Code, normalizeCode(c.Code)).Scan(&stored)
	if stored != 0 {
		t.Fatal("the code is stored in the clear")
	}
	// A human retyping it in lower case without dashes still matches.
	l, err := s.Redeem(ctx, SurfaceTelegram, strings.ToLower(strings.ReplaceAll(c.Code, "-", "")), "4242")
	if err != nil {
		t.Fatal(err)
	}
	if l.Principal != "github:alice" || l.Surface != SurfaceTelegram || l.ExternalID != "4242" {
		t.Fatalf("link = %+v", l)
	}
	got, err := s.Resolve(ctx, SurfaceTelegram, "4242")
	if err != nil || got.Principal != "github:alice" {
		t.Fatalf("resolve = %+v %v", got, err)
	}
	// Single use.
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242"); !errors.Is(err, ErrChallengeInvalid) || reason(err) != ReasonUsed {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "9999"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("reuse for another id: %v", err)
	}
	if _, err := s.Resolve(ctx, SurfaceTelegram, "9999"); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("reuse created a link: %v", err)
	}
}

func TestChallengeIsBoundToItsSurface(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	if _, err := s.Redeem(ctx, SurfacePortal, c.Code, "alice-session"); !errors.Is(err, ErrChallengeInvalid) || reason(err) != ReasonWrongSource {
		t.Fatalf("wrong surface: %v", err)
	}
	// Exposed to the wrong surface: burnt for the right one too.
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242"); !errors.Is(err, ErrChallengeInvalid) || reason(err) != ReasonUsed {
		t.Fatalf("after a wrong-surface attempt: %v", err)
	}
	for _, surface := range []string{SurfaceTelegram, SurfacePortal} {
		if _, err := s.Resolve(ctx, surface, map[string]string{SurfaceTelegram: "4242", SurfacePortal: "alice-session"}[surface]); !errors.Is(err, ErrLinkNotFound) {
			t.Fatalf("%s link exists: %v", surface, err)
		}
	}
}

func TestExpiredOrUnknownChallengeLinksNothing(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	real := s.now
	s.now = func() time.Time { return real().Add(ChallengeTTL + time.Second) }
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242"); reason(err) != ReasonExpired {
		t.Fatalf("expired: %v", err)
	}
	s.now = real
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242"); reason(err) != ReasonUsed {
		t.Fatalf("expired then retried: %v", err)
	}
	for _, code := range []string{"", "AAAA-BBBB", "not a code"} {
		if _, err := s.Redeem(ctx, SurfaceTelegram, code, "4242"); reason(err) != ReasonUnknown {
			t.Fatalf("code %q: %v", code, err)
		}
	}
	if _, err := s.Resolve(ctx, SurfaceTelegram, "4242"); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("a link exists: %v", err)
	}
}

func TestOnlyHumansOnKnownSurfacesGetChallenges(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	for _, p := range []string{"service:mctl-agent", "surface:telegram", "oidc:alice", "github:", "alice", "github:al ice"} {
		if _, err := s.CreateChallenge(ctx, p, SurfaceTelegram); !errors.Is(err, ErrInvalid) {
			t.Errorf("principal %q: %v", p, err)
		}
	}
	if _, err := s.CreateChallenge(ctx, "github:alice", "slack"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown surface: %v", err)
	}
	for i := 0; i < MaxOpenChallenges; i++ {
		if _, err := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram); !errors.Is(err, ErrTooManyChallenges) {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := s.CreateChallenge(ctx, "github:bob", SurfaceTelegram); err != nil {
		t.Fatalf("the cap is per principal: %v", err)
	}
}

func TestRedeemRefusesMalformedExternalIDs(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	for _, id := range []string{"", "0", "-5", "12a", "github:alice", " 42"} {
		if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, id); !errors.Is(err, ErrInvalid) {
			t.Errorf("external_id %q: %v", id, err)
		}
	}
	// A malformed id is refused before the challenge is looked at, so it
	// stays redeemable.
	if _, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "42"); err != nil {
		t.Fatalf("valid redeem after malformed attempts: %v", err)
	}
}

func TestAnIdentityLinksToOnePrincipal(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	a, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	if _, err := s.Redeem(ctx, SurfaceTelegram, a.Code, "4242"); err != nil {
		t.Fatal(err)
	}
	b, _ := s.CreateChallenge(ctx, "github:bob", SurfaceTelegram)
	if _, err := s.Redeem(ctx, SurfaceTelegram, b.Code, "4242"); !errors.Is(err, ErrLinkConflict) {
		t.Fatalf("second principal on one identity: %v", err)
	}
	if l, _ := s.Resolve(ctx, SurfaceTelegram, "4242"); l.Principal != "github:alice" {
		t.Fatalf("conflict moved the link to %s", l.Principal)
	}
	// Re-linking the same pair is idempotent and keeps the link.
	again, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	l, err := s.Redeem(ctx, SurfaceTelegram, again.Code, "4242")
	if err != nil || l.Principal != "github:alice" {
		t.Fatalf("relink: %+v %v", l, err)
	}
}

func TestRevokedAndExpiredLinksFailClosed(t *testing.T) {
	s := newStoreForTest(t, time.Hour)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	l, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242")
	if err != nil || l.ExpiresAt == nil {
		t.Fatalf("link = %+v %v", l, err)
	}
	// Someone else cannot revoke it, and learns nothing about it.
	if _, err := s.Revoke(ctx, l.ID, "github:mallory", false); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("foreign revoke: %v", err)
	}
	real := s.now
	s.now = func() time.Time { return real().Add(time.Hour + time.Second) }
	if _, err := s.Resolve(ctx, SurfaceTelegram, "4242"); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("expired link: %v", err)
	}
	s.now = real
	if _, err := s.Revoke(ctx, l.ID, "github:alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, SurfaceTelegram, "4242"); !errors.Is(err, ErrLinkRevoked) {
		t.Fatalf("revoked link: %v", err)
	}
	// After revocation the identity can be linked again, even to someone else.
	b, _ := s.CreateChallenge(ctx, "github:bob", SurfaceTelegram)
	if l, err := s.Redeem(ctx, SurfaceTelegram, b.Code, "4242"); err != nil || l.Principal != "github:bob" {
		t.Fatalf("relink after revoke: %+v %v", l, err)
	}
	links, _ := s.Links(ctx, "github:alice")
	if len(links) != 1 || links[0].RevokedAt == nil || links[0].RevokedBy != "github:alice" {
		t.Fatalf("alice's history = %+v", links)
	}
}

func TestConcurrentRedeemsLinkOnce(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	const racers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrChallengeInvalid) {
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d redemptions succeeded", ok)
	}
}

func TestRelinkingRenewsAnExpiringLink(t *testing.T) {
	s := newStoreForTest(t, time.Hour)
	ctx := context.Background()
	c, _ := s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	first, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242")
	if err != nil {
		t.Fatal(err)
	}
	real := s.now
	s.now = func() time.Time { return real().Add(50 * time.Minute) }
	c, _ = s.CreateChallenge(ctx, "github:alice", SurfaceTelegram)
	again, err := s.Redeem(ctx, SurfaceTelegram, c.Code, "4242")
	if err != nil || again.ID != first.ID {
		t.Fatalf("relink = %+v, %v", again, err)
	}
	if !again.ExpiresAt.After(*first.ExpiresAt) {
		t.Fatalf("expires_at %v not renewed past %v", again.ExpiresAt, first.ExpiresAt)
	}
	// Past the original expiry, the renewed link still answers.
	s.now = func() time.Time { return real().Add(time.Hour + time.Minute) }
	if _, err := s.Resolve(ctx, SurfaceTelegram, "4242"); err != nil {
		t.Fatalf("renewed link: %v", err)
	}
}
