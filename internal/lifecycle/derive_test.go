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

// A pull-request/review-remediation record: 10 h liveness, 48 h progress.
func rec(state string, seenAgo, progressAgo time.Duration, now time.Time) *Ownership {
	return &Ownership{
		Entity:         EntityRef{Kind: KindPullRequest, ID: "mctlhq/mctl-web#99"},
		Phase:          PhaseReviewRemediation,
		Owner:          Owner{Type: OwnerDevLoopWorkflow, ID: "dev-loop-mctlhq-mctl-web-99"},
		Epoch:          1,
		State:          state,
		LastSeenAt:     now.Add(-seenAgo),
		LastProgressAt: now.Add(-progressAgo),
	}
}

func TestDeriveStatusPrecedence(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	handoffLongAgo := now.Add(-20 * time.Hour)
	handoffJustNow := now.Add(-1 * time.Minute)

	for _, tc := range []struct {
		name string
		o    *Ownership
		want string
	}{
		{"nil record", nil, StatusUnknown},
		{"fresh", rec(StateActive, time.Minute, time.Minute, now), StatusHealthy},
		{
			// Alive and holding it legitimately: ADR-010 §4 escalates a stuck
			// owner to a human, it does not license takeover.
			"alive but idle past the progress bound",
			rec(StateActive, time.Minute, 60*time.Hour, now),
			StatusStuck,
		},
		{
			// Past the liveness bound AND the progress bound. Dead wins:
			// reporting it as stuck would route it to a human instead of to
			// the takeover the bound exists to license.
			"unseen past the liveness bound",
			rec(StateActive, 20*time.Hour, 60*time.Hour, now),
			StatusDead,
		},
		{
			// Released is FINAL. Nobody is expected to have been seen, so the
			// liveness question does not apply — an earlier ordering reported
			// this as "dead", which reads as an owner that needs replacing
			// rather than a row nobody holds.
			"released long ago",
			rec(StateReleased, 40*time.Hour, 40*time.Hour, now),
			StatusReleased,
		},
		{"terminal long ago", rec(StateTerminal, 40*time.Hour, 40*time.Hour, now), StatusTerminal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Derive(tc.o, now).Status; got != tc.want {
				t.Fatalf("Derive().Status = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("handing off, within the bound", func(t *testing.T) {
		o := rec(StateHandingOff, time.Minute, time.Minute, now)
		o.HandoffStartedAt = &handoffJustNow
		if got := Derive(o, now).Status; got != StatusHandingOff {
			t.Fatalf("got %q, want %q", got, StatusHandingOff)
		}
	})

	t.Run("a stalled handoff is reported as stalled, not as handing-off", func(t *testing.T) {
		// The more specific answer is the actionable one: a handoff that never
		// completed needs an operator, while one in flight needs nothing.
		o := rec(StateHandingOff, time.Minute, time.Minute, now)
		o.HandoffStartedAt = &handoffLongAgo
		d := Derive(o, now)
		if d.Status != StatusHandoffStalled {
			t.Fatalf("got %q, want %q", d.Status, StatusHandoffStalled)
		}
		if !d.HandoffStalled {
			t.Fatal("HandoffStalled is false on a stalled handoff")
		}
	})
}

func TestDeriveCarriesTheBoundsItMeasuredAgainst(t *testing.T) {
	// A status of "dead" means nothing without the window it was measured in,
	// and the two phases use different windows (10 h vs 130 m). An operator
	// comparing them should not have to know the bounds table by heart.
	now := time.Now()
	d := Derive(rec(StateActive, time.Minute, time.Minute, now), now)
	if d.LivenessBoundSeconds <= 0 || d.ProgressBoundSeconds <= 0 {
		t.Fatalf("bounds not carried: %+v", d)
	}
	wantLiveness, ok := LivenessBound(KindPullRequest, PhaseReviewRemediation)
	if !ok {
		t.Fatal("the bounds table has no entry for the phase under test")
	}
	if d.LivenessBoundSeconds != int64(wantLiveness.Seconds()) {
		t.Fatalf("liveness bound = %ds, want %ds", d.LivenessBoundSeconds, int64(wantLiveness.Seconds()))
	}
}

func TestDeriveOnAnUnknownPhaseDoesNotClaimDeath(t *testing.T) {
	// The bounds lookup misses, so IsDead answers false by design: refusing to
	// declare an owner dead is the safe direction, because doing so is what
	// lets somebody else act. The status must follow that, not contradict it.
	now := time.Now()
	o := rec(StateActive, 1000*time.Hour, 1000*time.Hour, now)
	o.Phase = "no-such-phase"
	d := Derive(o, now)
	if d.Status == StatusDead {
		t.Fatal("an unknown phase produced a dead verdict, licensing takeover on a bound nobody defined")
	}
	if d.LivenessBoundSeconds != 0 {
		t.Fatalf("an unknown phase reported a bound: %+v", d)
	}
}

// TestDeriveHeldIsTheTakeoverPredicateNotTheStatus pins the distinction a
// consumer got wrong: Status reports the most SPECIFIC thing true of a record,
// and that is not the same question as "may somebody else take this".
//
// A handing-off row past its liveness bound reports `handoff-stalled`, because
// that is more specific than `dead` and more useful to an operator. It is also
// dead, and Store.Recover will grant a takeover of it. Reading "held" off the
// status string therefore reports the entity as withheld while the store is
// prepared to hand it to somebody else.
func TestDeriveHeldIsTheTakeoverPredicateNotTheStatus(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	stalledAt := now.Add(-20 * time.Hour)

	o := rec(StateHandingOff, time.Minute, time.Minute, now)
	// last_seen_at is FROZEN on a handing-off row — handoffStartUpdateSQL pins
	// it and every writer that could reach the row freezes it — so a handoff
	// open past the bound necessarily has a last_seen_at at least that old.
	// A fixture with a fresher last_seen_at describes a row the store cannot
	// produce.
	o.LastSeenAt = stalledAt
	o.HandoffStartedAt = &stalledAt

	d := Derive(o, now)
	if d.Status != StatusHandoffStalled {
		t.Fatalf("Status = %q, want %q", d.Status, StatusHandoffStalled)
	}
	if !d.Dead {
		t.Fatal("a handoff open past the liveness bound is not reported dead")
	}
	if d.Held {
		t.Fatal("a dead handing-off row is reported as withholding the entity, " +
			"while Recover would grant a takeover of it")
	}
}

func TestDeriveDistinguishesAMissingBoundFromAZeroBound(t *testing.T) {
	now := time.Now()
	known := Derive(rec(StateActive, time.Minute, time.Minute, now), now)
	if !known.BoundsKnown {
		t.Fatal("a known phase reports BoundsKnown false")
	}
	o := rec(StateActive, time.Minute, time.Minute, now)
	o.Phase = "no-such-phase"
	if unknown := Derive(o, now); unknown.BoundsKnown {
		t.Fatal("an unknown phase reports its zero bounds as known, so " +
			"\"we do not know the window\" reads as \"the window is zero\"")
	}
}
