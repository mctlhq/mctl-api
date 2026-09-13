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

package lifecycle

import (
	"testing"
	"time"
)

// TestClassifyTable enumerates every (store state x legacy answer) pair
// EXPLICITLY, with no default arm and no loop over "the rest".
//
// This table is the reference the shepherd's Python side mirrors, and the
// numbers the soak's exit criteria are written against come out of it. A pair
// that falls through to a default is a pair nobody decided, and it would be
// counted — differently — in two languages.
func TestClassifyTable(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	stalled := now.Add(-20 * time.Hour)

	devloop := func(state string, seenAgo time.Duration) *Ownership {
		o := rec(state, seenAgo, time.Minute, now)
		return o
	}
	stuckDevloop := func() *Ownership {
		// Seen recently, but nothing effected inside the 48 h progress bound.
		o := rec(StateActive, time.Minute, 60*time.Hour, now)
		return o
	}
	steward := func(state string, seenAgo time.Duration) *Ownership {
		o := rec(state, seenAgo, time.Minute, now)
		o.Owner = Owner{Type: OwnerPRSteward, ID: "pr-steward:mctlhq/mctl-web"}
		return o
	}
	// last_seen_at is FROZEN on a handing-off row: handoffStartUpdateSQL pins
	// it, and the store's own comment states that nothing can move it forward
	// at the same epoch because all three writers that could reach it freeze
	// it. So LastSeenAt newer than HandoffStartedAt is a clock ordering the
	// store never produces, and a fixture built that way pins an expectation
	// for a row that cannot exist.
	handingOff := func() *Ownership {
		started := now.Add(-time.Minute)
		o := devloop(StateHandingOff, time.Minute)
		o.LastSeenAt = started
		o.HandoffStartedAt = &started
		return o
	}
	// Stalled AND, necessarily, dead: the freeze means a handoff that has been
	// open past the liveness bound has a last_seen_at at least that old.
	// Store.Recover grants a takeover of it, so it withholds the entity from
	// nobody — which is why it must not classify as agreement.
	handoffStalled := func() *Ownership {
		o := devloop(StateHandingOff, time.Minute)
		o.LastSeenAt = stalled
		o.HandoffStartedAt = &stalled
		return o
	}

	for _, tc := range []struct {
		name          string
		o             *Ownership
		storeReadable bool
		legacy        LegacyAnswer
		wantClass     string
		wantDangerous bool
	}{
		// -- store holds a live DevLoop owner ---------------------------------
		{"devloop healthy / legacy owned", devloop(StateActive, time.Minute), true, LegacyOwned, DivergeAgree, false},
		{"devloop healthy / legacy free", devloop(StateActive, time.Minute), true, LegacyFree, DivergeStoreForbids, false},
		{"devloop handing off / legacy owned", handingOff(), true, LegacyOwned, DivergeAgree, false},
		{"devloop handing off / legacy free", handingOff(), true, LegacyFree, DivergeStoreForbids, false},
		{
			// The P1 case. Status says handoff-stalled, which ranks above
			// dead, but the row IS dead and Recover would hand the entity to
			// somebody else — so against a live DevLoopWorkflow this is the
			// dangerous class, not agreement.
			"devloop handoff stalled (therefore dead) / legacy owned",
			handoffStalled(), true, LegacyOwned, DivergeStorePermits, true,
		},
		{"devloop handoff stalled (therefore dead) / legacy free", handoffStalled(), true, LegacyFree, DivergeAgree, false},

		{
			// `stuck` is one of the held statuses and had no row. A stuck
			// owner is alive and holds the entity legitimately: ADR-010 §4
			// escalates it to a human rather than replacing it.
			"devloop stuck / legacy owned",
			stuckDevloop(), true, LegacyOwned, DivergeAgree, false,
		},
		{"devloop stuck / legacy free", stuckDevloop(), true, LegacyFree, DivergeStoreForbids, false},

		// -- store holds a live owner of a DIFFERENT type ---------------------
		{"steward healthy / legacy owned", steward(StateActive, time.Minute), true, LegacyOwned, DivergeOwnerMismatch, false},
		{"steward healthy / legacy free", steward(StateActive, time.Minute), true, LegacyFree, DivergeStoreForbids, false},

		// -- store holds nothing that withholds the entity --------------------
		// `dead` belongs here: ADR-010 §4 makes it the ONE condition that
		// licenses takeover, so a dead owner does not forbid anything.
		{"devloop dead / legacy owned", devloop(StateActive, 20*time.Hour), true, LegacyOwned, DivergeStorePermits, true},
		{"devloop dead / legacy free", devloop(StateActive, 20*time.Hour), true, LegacyFree, DivergeAgree, false},
		{"released / legacy owned", devloop(StateReleased, time.Minute), true, LegacyOwned, DivergeStorePermits, true},
		{"released / legacy free", devloop(StateReleased, time.Minute), true, LegacyFree, DivergeAgree, false},
		{"terminal / legacy owned", devloop(StateTerminal, time.Minute), true, LegacyOwned, DivergeStorePermits, true},
		{"terminal / legacy free", devloop(StateTerminal, time.Minute), true, LegacyFree, DivergeAgree, false},
		{"no record / legacy owned", nil, true, LegacyOwned, DivergeStorePermits, true},
		{"no record / legacy free", nil, true, LegacyFree, DivergeAgree, false},

		// -- one side has no answer. NOT divergences --------------------------
		{"store unreadable / legacy owned", nil, false, LegacyOwned, DivergeStoreUnknown, false},
		{"store unreadable / legacy free", nil, false, LegacyFree, DivergeStoreUnknown, false},
		{"store unreadable / legacy unknown", nil, false, LegacyUnknown, DivergeStoreUnknown, false},
		{"store healthy / legacy unknown", devloop(StateActive, time.Minute), true, LegacyUnknown, DivergeLegacyUnknown, false},
		{"no record / legacy unknown", nil, true, LegacyUnknown, DivergeLegacyUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.o, tc.storeReadable, tc.legacy, now)
			if got.Class != tc.wantClass {
				t.Fatalf("Class = %q, want %q (detail: %s)", got.Class, tc.wantClass, got.Detail)
			}
			if got.Dangerous != tc.wantDangerous {
				t.Fatalf("Dangerous = %v, want %v", got.Dangerous, tc.wantDangerous)
			}
		})
	}
}

// TestOnlyOneClassIsDangerous pins the property the soak's stop condition is
// written against. If a second class ever becomes dangerous, the alert built on
// this flag starts firing on a case nobody triaged as stop-the-rollout.
func TestOnlyOneClassIsDangerous(t *testing.T) {
	now := time.Now()
	stalled := now.Add(-20 * time.Hour)
	fresh := now.Add(-time.Minute)
	handingOff := rec(StateHandingOff, time.Minute, time.Minute, now)
	handingOff.LastSeenAt = fresh
	handingOff.HandoffStartedAt = &fresh
	handoffStalled := rec(StateHandingOff, time.Minute, time.Minute, now)
	handoffStalled.LastSeenAt = stalled
	handoffStalled.HandoffStartedAt = &stalled
	steward := rec(StateActive, time.Minute, time.Minute, now)
	steward.Owner = Owner{Type: OwnerPRSteward, ID: "pr-steward:mctlhq/mctl-web"}

	dangerous := map[string]bool{}
	for _, legacy := range []LegacyAnswer{LegacyOwned, LegacyFree, LegacyUnknown} {
		for _, o := range []*Ownership{
			nil,
			rec(StateActive, time.Minute, time.Minute, now),
			// stuck: alive, nothing effected inside the progress bound.
			rec(StateActive, time.Minute, 60*time.Hour, now),
			// dead.
			rec(StateActive, 20*time.Hour, time.Minute, now),
			handingOff,
			handoffStalled,
			steward,
			rec(StateReleased, time.Minute, time.Minute, now),
			rec(StateTerminal, time.Minute, time.Minute, now),
		} {
			for _, readable := range []bool{true, false} {
				if d := Classify(o, readable, legacy, now); d.Dangerous {
					dangerous[d.Class] = true
				}
			}
		}
	}
	if len(dangerous) != 1 || !dangerous[DivergeStorePermits] {
		t.Fatalf("dangerous classes = %v, want exactly {%s}", dangerous, DivergeStorePermits)
	}
}
