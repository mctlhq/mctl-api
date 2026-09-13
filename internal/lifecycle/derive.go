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

import "time"

// Derived status vocabulary. CLOSED: an operator reading a status must be able
// to enumerate what they might see, and a caller switching on it must not have
// a default arm that silently absorbs a status added later.
const (
	StatusHealthy        = "healthy"
	StatusStuck          = "stuck"
	StatusDead           = "dead"
	StatusHandingOff     = "handing-off"
	StatusHandoffStalled = "handoff-stalled"
	StatusReleased       = "released"
	StatusTerminal       = "terminal"
	// StatusUnknown is for a nil record only — "we hold nothing for this
	// entity phase". It is NOT the same as the absence of an answer, which is
	// a 503 at the HTTP layer and never reaches here.
	StatusUnknown = "unknown"
)

// Derived is everything about a record that is computed on read rather than
// stored: ADR-010 keeps the store free of anything that would need a sweeper to
// write it, which means the read side has to do the deriving.
//
// The two bounds travel WITH the answer. A status of "dead" is only meaningful
// against the window it was measured in, and an operator comparing two phases
// (130 m for a proposal, 10 h for a pull request) otherwise has to know the
// bounds table by heart to read either one.
type Derived struct {
	Status               string `json:"status"`
	HandoffStalled       bool   `json:"handoff_stalled"`
	SecondsSinceSeen     int64  `json:"seconds_since_seen"`
	SecondsSinceProgress int64  `json:"seconds_since_progress"`
	LivenessBoundSeconds int64  `json:"liveness_bound_seconds"`
	ProgressBoundSeconds int64  `json:"progress_bound_seconds"`
}

// Derive computes the read-side view of one record.
//
// Status precedence is terminal → released → handoff-stalled → handing-off →
// dead → stuck → healthy, and the order is load-bearing rather than
// stylistic:
//
//   - terminal and released come first because they are FINAL. A released row
//     whose former owner has not been seen for a day is not "dead" — nobody is
//     expected to have been seen; it is released, and the liveness question
//     does not apply to it.
//   - handoff-stalled before handing-off, because a stalled handoff IS a
//     handing-off record and the more specific answer is the actionable one.
//   - dead before stuck, matching IsStuck's own guard: a dead owner is not
//     "alive but idle", and reporting it as stuck would route it to escalation
//     (a human) rather than to takeover, which ADR-010 §4 separates precisely
//     because the remedies differ.
func Derive(o *Ownership, now time.Time) Derived {
	if o == nil {
		return Derived{Status: StatusUnknown}
	}

	liveness, _ := LivenessBound(o.Entity.Kind, o.Phase)
	progress, _ := ProgressBound(o.Entity.Kind, o.Phase)

	d := Derived{
		HandoffStalled:       o.HandoffStalled(now),
		SecondsSinceSeen:     int64(now.Sub(o.LastSeenAt).Seconds()),
		SecondsSinceProgress: int64(now.Sub(o.LastProgressAt).Seconds()),
		LivenessBoundSeconds: int64(liveness.Seconds()),
		ProgressBoundSeconds: int64(progress.Seconds()),
	}

	switch {
	case o.State == StateTerminal:
		d.Status = StatusTerminal
	case o.State == StateReleased:
		d.Status = StatusReleased
	case d.HandoffStalled:
		d.Status = StatusHandoffStalled
	case o.State == StateHandingOff:
		d.Status = StatusHandingOff
	case o.IsDead(now):
		d.Status = StatusDead
	case o.IsStuck(now):
		d.Status = StatusStuck
	default:
		d.Status = StatusHealthy
	}
	return d
}
