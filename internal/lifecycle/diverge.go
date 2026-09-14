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
	"fmt"
	"time"
)

// Divergence classes. This is the REFERENCE table for the observe soak: the
// shepherd's Python side mirrors it, and the two must agree, because a
// divergence counted differently in two places is a divergence nobody can
// explain afterwards.
const (
	// DivergeAgree — both mechanisms permit, or both forbid.
	DivergeAgree = "agree"

	// DivergeStorePermits — the store would license an action the old
	// mechanism forbids. THE ONLY DANGEROUS CLASS.
	//
	// Concretely: no healthy owner in the store, while a live DevLoopWorkflow
	// is driving the PR. Under enforce the shepherd would take a pull request
	// another machine is actively pushing to, which is the double-driving #213
	// exists to prevent. One of these is a stop-the-soak event, not a metric
	// to watch trend downward.
	DivergeStorePermits = "store-permits-old-forbids"

	// DivergeStoreForbids — the store withholds an action the old mechanism
	// permits. Safe by construction: it never licenses anything.
	//
	// Expected in bulk during the soak (bootstrap residue, pr-steward rows the
	// legacy check has no concept of), which is why it is counted separately
	// rather than folded in with the dangerous direction.
	DivergeStoreForbids = "store-forbids-old-permits"

	// DivergeOwnerMismatch — both say the entity is held, and they name
	// different holders. Not dangerous on its own: both stand down. It is
	// reported because it is the class that reveals a mis-wired comparison —
	// see the soak criterion requiring at least one to have been observed.
	DivergeOwnerMismatch = "owner-mismatch"

	// DivergeStoreUnknown — no answer from the store. NOT a divergence: an
	// absent answer is not a disagreement, and counting it as one would make
	// an mctl-api outage look like a correctness problem.
	DivergeStoreUnknown = "store-unknown"

	// DivergeLegacyUnknown — no answer from the old mechanism (no proposal
	// ref, an unparseable slug, Temporal unreachable). Also not a divergence,
	// for the same reason, and separate from the above so an operator can tell
	// which side went quiet.
	DivergeLegacyUnknown = "legacy-unknown"
)

// LegacyAnswer is the old mechanism's verdict: does a live DevLoopWorkflow own
// this entity? Three-valued on purpose — `_dev_loop_owns` returns a bool and
// collapses "no" with "could not tell", which is the collapse this whole
// contract exists to undo. Reintroducing it here would make the soak measure
// the new mechanism against a known-broken reading of the old one.
type LegacyAnswer int

const (
	LegacyUnknown LegacyAnswer = iota
	LegacyOwned
	LegacyFree
)

// Divergence is one comparison.
type Divergence struct {
	Class string `json:"class"`
	// Dangerous marks the single class that licenses an action the old
	// mechanism forbids. A bool rather than a severity, because there are
	// exactly two consequences: stop the rollout, or write it down.
	Dangerous bool   `json:"dangerous"`
	Detail    string `json:"detail,omitempty"`
}

// Classify compares the store's answer with the old mechanism's.
//
// `o` is nil when the store holds no record for the entity phase. That is a
// real answer — "nobody owns this" — and must not be confused with the store
// being unreachable, which the caller signals with storeReadable=false and
// which never reaches this function as a nil record.
func Classify(o *Ownership, storeReadable bool, legacy LegacyAnswer, now time.Time) Divergence {
	return ClassifyDerived(o, Derive(o, now), storeReadable, legacy)
}

// ClassifyDerived is Classify for a caller that ALREADY has the derived view —
// the read surface, which serves `derived` in its response and would otherwise
// derive the same record twice, a few milliseconds apart, on either side of one
// request. Two derivations of one record can disagree: `dead` is a comparison
// against a clock, so a record sitting on its liveness bound can be alive in the
// body and dead in the divergence class of the same answer.
//
// Classify remains the entry point for callers that hold only a record.
func ClassifyDerived(o *Ownership, d Derived, storeReadable bool, legacy LegacyAnswer) Divergence {
	if !storeReadable {
		return Divergence{Class: DivergeStoreUnknown}
	}
	if legacy == LegacyUnknown {
		return Divergence{Class: DivergeLegacyUnknown}
	}

	// "Held" is the question that matters, and it is narrower than "a row
	// exists": a released, terminal or dead owner does not withhold the entity
	// from anybody. `dead` is deliberately on the not-held side — ADR-010 §4
	// makes it the ONE condition that licenses takeover.
	//
	// Derive computes it from the takeover predicate rather than from the
	// status string, and the difference is not cosmetic: a handing-off row
	// past its liveness bound reports as `handoff-stalled` (the more specific
	// status) while being dead and recoverable, so classifying off the status
	// reported it as withheld and turned the one dangerous class into `agree`.
	held := d.Held

	switch {
	case held && legacy == LegacyOwned:
		if o.Owner.Type == OwnerDevLoopWorkflow {
			return Divergence{Class: DivergeAgree}
		}
		// Both stand down, and they disagree about who holds it. The store
		// names a non-DevLoop owner for an entity a live DevLoop is driving.
		return Divergence{
			Class: DivergeOwnerMismatch,
			Detail: fmt.Sprintf(
				"store names %s/%s; a live DevLoopWorkflow is driving the same entity",
				o.Owner.Type, o.Owner.ID),
		}
	case held && legacy == LegacyFree:
		return Divergence{
			Class: DivergeStoreForbids,
			Detail: fmt.Sprintf("store names %s/%s (%s); no live DevLoopWorkflow",
				o.Owner.Type, o.Owner.ID, d.Status),
		}
	case !held && legacy == LegacyOwned:
		return Divergence{
			Class:     DivergeStorePermits,
			Dangerous: true,
			Detail: fmt.Sprintf(
				"store holds no live owner (%s) while a DevLoopWorkflow is driving the entity",
				d.Status),
		}
	default:
		// !held && LegacyFree — both permit.
		return Divergence{Class: DivergeAgree}
	}
}
