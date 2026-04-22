// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package api

import (
	"strconv"
	"testing"
	"time"
)

// TestSaveRateLimiter_EvictsIdleBuckets verifies that buckets for
// (team,user) pairs that have not been seen for longer than the window
// are dropped from the map. Without the opportunistic sweep a long-lived
// process serving many distinct callers would grow l.buckets without bound.
func TestSaveRateLimiter_EvictsIdleBuckets(t *testing.T) {
	t.Parallel()
	var clock time.Time = time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	l := newSaveRateLimiter(10)
	l.now = func() time.Time { return clock }

	// Seed one request each for a handful of keys, staying under
	// sweepEveryOps so the seed loop itself does not trigger a sweep
	// (otherwise it would sweep while the entries are still in-window).
	const seeded = 10
	if seeded >= sweepEveryOps {
		t.Fatalf("test invariant broken: seeded (%d) must stay below sweepEveryOps (%d)", seeded, sweepEveryOps)
	}
	for i := 0; i < seeded; i++ {
		if ok, _ := l.Allow("team-" + strconv.Itoa(i)); !ok {
			t.Fatalf("unexpected limit on call %d — each key has 1 request, budget 10", i)
		}
	}
	if got := len(l.buckets); got != seeded {
		t.Fatalf("expected %d buckets after seeding, got %d", seeded, got)
	}

	// Advance past the 1-hour window so every seeded entry is now stale.
	clock = clock.Add(2 * time.Hour)

	// Make sweepEveryOps more calls against a fresh key; at the sweepEveryOps
	// threshold the opportunistic sweep fires and drops every idle seeded
	// bucket (only the fresh one still has an in-window entry).
	for i := 0; i < sweepEveryOps; i++ {
		l.Allow("fresh-team")
	}
	if got := len(l.buckets); got != 1 {
		t.Fatalf("expected 1 bucket after sweep (only fresh key), got %d", got)
	}
	if _, ok := l.buckets["fresh-team"]; !ok {
		t.Fatalf("fresh key missing from buckets after sweep")
	}
}

// TestSaveRateLimiter_BucketPersistsWithActiveEntries ensures the sweep
// does NOT evict buckets that still hold in-window entries — otherwise the
// limiter would silently drop enforcement for active callers.
func TestSaveRateLimiter_BucketPersistsWithActiveEntries(t *testing.T) {
	t.Parallel()
	var clock time.Time = time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	l := newSaveRateLimiter(2)
	l.now = func() time.Time { return clock }

	if ok, _ := l.Allow("active"); !ok {
		t.Fatalf("first call on active key rejected")
	}
	// Seed enough distinct keys to cross sweepEveryOps, without advancing
	// the clock, so the active key's one entry is still in-window when the
	// sweep fires.
	for i := 0; i < sweepEveryOps; i++ {
		l.Allow("noise-" + strconv.Itoa(i))
	}
	if _, ok := l.buckets["active"]; !ok {
		t.Fatalf("active bucket was wrongly evicted while its entry was still in-window")
	}
	// The budget of 2 should still apply — second call succeeds, third denied.
	if ok, _ := l.Allow("active"); !ok {
		t.Fatalf("second call on active key rejected")
	}
	ok, retry := l.Allow("active")
	if ok {
		t.Fatalf("third call on active key unexpectedly allowed")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}
}
