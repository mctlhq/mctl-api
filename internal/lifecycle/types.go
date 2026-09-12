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

// Package lifecycle stores durable answers to one question: who is
// responsible for advancing a given entity through a given lifecycle phase.
//
// It is deliberately NOT a second lifecycle database. It holds no proposal
// status, no pull-request state, no review finding and no merge decision —
// GitHub and mctl-gitops remain authoritative for what an entity IS. This
// package is authoritative only for who may act on it.
//
// It is also deliberately NOT a scheduler. There is no timer, no queue, no
// due_at and no background sweep; nothing here calls GitHub, Argo or Temporal.
// Liveness and progress are DERIVED on read by the caller's existing tick (see
// Ownership.IsDead and Ownership.IsStuck) rather than materialised by a sweep,
// because materialising either is precisely what would turn this into one.
//
// See mctl-agents/docs/adr/010-lifecycle-ownership-contract.md.
package lifecycle

import (
	"errors"
	"time"
)

// Entity kinds. Phases are typed per kind (see LegalPhase): a global phase
// vocabulary would make "investigate" a legal phase on a pull request.
const (
	KindDevLoopProposal = "devloop-proposal"
	KindPullRequest     = "pull-request"
)

// Lifecycle phases.
const (
	// PhaseImplement is held by the actor turning an accepted proposal into a
	// pull request.
	PhaseImplement = "implement"
	// PhaseReviewRemediation is held by the actor driving a pull request from
	// blocking review findings to a terminal state.
	PhaseReviewRemediation = "review-remediation"
)

// Ownership states.
//
// There is deliberately no "stale" and no "conflicted" state. Both are derived
// on read — storing them would require something to sweep and write them,
// which is the scheduler this package must not become.
const (
	StateActive     = "active"
	StateHandingOff = "handing-off"
	StateReleased   = "released"
	StateTerminal   = "terminal"
)

// Owner types. These name actors, not permissions: see the package doc and
// ADR-010 §6 — ownership grants neither push nor merge authority.
const (
	// The suppression below is for a genuine gosec false positive, and an
	// entertaining one: G101 matches identifiers against a credential pattern
	// containing "pw", and "ownerdevloopworkflow" contains it across the word
	// boundary in "...loo(pw)orkflow". The value is an actor name.
	OwnerDevLoopWorkflow = "devloop-workflow" //nolint:gosec // G101: accidental "pw" substring, not a credential
	OwnerShepherd        = "shepherd"
	OwnerPRSteward       = "pr-steward"
	OwnerReconciler      = "reconciler"
	OwnerHumanCodeowner  = "human-codeowner"
)

// Event names recorded in lifecycle_events.
const (
	EventOwnerAcquired    = "owner-acquired"
	EventOwnerDenied      = "owner-denied"
	EventProgress         = "progress"
	EventHandoffStarted   = "handoff-started"
	EventHandoffCompleted = "handoff-completed"
	EventOwnerReleased    = "owner-released"
	EventOwnerTerminal    = "owner-terminal"
	EventRecovered        = "recovered"
)

// bounds are per (kind, phase), and there are TWO of them because there are two
// different questions.
//
//	liveness — is the owner still there?  Answered by LastSeenAt, which ANY
//	           tick refreshes, including a poll that found nothing to do.
//	           Losing this is what licenses another actor to take over.
//	progress — is the work moving?  Answered by LastProgressAt, which only an
//	           effected change refreshes. Losing this licenses an ESCALATION
//	           and never a takeover.
//
// An earlier version had one field and one 6h bound, and it was wrong twice.
//
// It could not tolerate a missed tick: with progress at T=0 and ticks at T=4h
// and T=8h, a tick lost to a pod restart leaves the next opportunity at T=8h,
// but a 6h bound calls the owner stale at T=6h. Surviving one missed tick means
// exceeding the interval to the tick AFTER it, so 2x cadence — hence 10h.
//
// Worse, fixing the number would not have fixed the model. A poll that observes
// nothing writes no progress, by design. But a PR waiting on human review or a
// slow CI run produces no state changes for hours, so a perfectly healthy owner
// was indistinguishable from a crashed one, and the reconciler would have taken
// the PR away every 6h from an owner doing exactly the right thing — bumping
// the epoch and fencing it out the moment the review landed. Thrashing caused
// by the safety mechanism.
//
// The rule that produced the single-field design still holds: a heartbeat must
// not prove useful PROGRESS indefinitely. It no longer has to be honoured by
// refusing to record liveness at all.
//
// implement keeps one effective window at 130m, matching the lease
// run_implementer.py already writes; the implementer either finishes an attempt
// or it does not.
type bound struct {
	liveness time.Duration
	progress time.Duration
}

var bounds = map[string]bound{
	KindPullRequest + "/" + PhaseReviewRemediation: {liveness: 10 * time.Hour, progress: 48 * time.Hour},
	KindDevLoopProposal + "/" + PhaseImplement:     {liveness: 130 * time.Minute, progress: 130 * time.Minute},
}

// LegalPhase reports whether phase is defined for kind. The registry is closed:
// an unknown pair is rejected at the boundary rather than stored and puzzled
// over later.
func LegalPhase(kind, phase string) bool {
	_, ok := bounds[kind+"/"+phase]
	return ok
}

// LivenessBound returns the window after which an owner that has not been seen
// is considered dead, which is the only condition that licenses a takeover.
func LivenessBound(kind, phase string) (time.Duration, bool) {
	b, ok := bounds[kind+"/"+phase]
	return b.liveness, ok
}

// ProgressBound returns the window after which an owner that is alive but has
// effected nothing should be escalated to a human.
func ProgressBound(kind, phase string) (time.Duration, bool) {
	b, ok := bounds[kind+"/"+phase]
	return b.progress, ok
}

// EntityRef identifies the thing whose lifecycle is being advanced.
//
// Version is NOT part of the identity and is NOT part of the ownership key. It
// is recorded so a reader can see which version of the entity the owner last
// observed, and it becomes a precondition on an ExecutionClaim (phase 2,
// mctlhq/mctl-agents#352) — never on ownership itself. Ownership must survive a
// review-fix push, because a new head on the same pull request is the normal
// case rather than a handoff; a claim must not.
type EntityRef struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

// Owner is the actor holding durable responsibility.
type Owner struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Ownership is the durable record: actor X holds responsibility for
// (entity, phase) at epoch N.
type Ownership struct {
	Entity EntityRef `json:"entity"`
	Phase  string    `json:"phase"`
	Owner  Owner     `json:"owner"`

	// Epoch is the fencing generation. It increments on handoff and on
	// recovery, so an executor holding a pre-handoff epoch can be rejected
	// without consulting wall-clock time.
	Epoch int `json:"epoch"`

	State string `json:"state"`

	AcquiredAt time.Time `json:"acquired_at"`

	// LastSeenAt advances on ANY tick, including one that found nothing to do.
	// It is evidence that the owner exists, and nothing more — which is all a
	// heartbeat was ever evidence of.
	LastSeenAt time.Time `json:"last_seen_at"`

	// LastProgressAt advances only when the owner effected a state change.
	// A poll that observed nothing writes no progress, so that a heartbeat
	// cannot prove useful work indefinitely — but because liveness now has its
	// own field, that rule no longer makes a healthy owner on a quiet PR look
	// dead.
	LastProgressAt   time.Time `json:"last_progress_at"`
	ProgressEvidence string    `json:"progress_evidence,omitempty"`

	// ProposalRef correlates a proposal-backed pull request to its proposal.
	// It is empty for a proposal-less adopted PR, which is what lets that path
	// use the same row shape without synthesizing a proposal.
	ProposalRef string `json:"proposal_ref,omitempty"`

	// PolicyRef records which policy granted this ownership, so "why does this
	// actor own it" is answerable from the row rather than by re-deriving the
	// environment that produced it.
	PolicyRef string `json:"policy_ref,omitempty"`

	HandoffTo        *Owner     `json:"handoff_to,omitempty"`
	HandoffFrom      *Owner     `json:"handoff_from,omitempty"`
	HandoffStartedAt *time.Time `json:"handoff_started_at,omitempty"`

	ReleasedAt     *time.Time `json:"released_at,omitempty"`
	ReleasedReason string     `json:"released_reason,omitempty"`

	TemporalWorkflowID string `json:"temporal_workflow_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsDead reports whether an active owner has not been seen within its phase's
// liveness bound. Derived, never stored.
//
// This is the ONLY condition that licenses another actor to take ownership.
//
// An unknown (kind, phase) pair reports false: refusing to declare an owner
// dead is the safe direction, because doing so is what lets someone else act.
func (o *Ownership) IsDead(now time.Time) bool {
	if o == nil || (o.State != StateActive && o.State != StateHandingOff) {
		return false
	}
	b, ok := LivenessBound(o.Entity.Kind, o.Phase)
	if !ok {
		return false
	}
	return now.Sub(o.LastSeenAt) > b
}

// IsStuck reports whether an owner is alive but has effected nothing within its
// phase's progress bound.
//
// A stuck owner is ESCALATED, never replaced. Handing a stuck entity to another
// machine produces a second stuck machine and an epoch bump; the thing that is
// missing is a human, not a different worker.
func (o *Ownership) IsStuck(now time.Time) bool {
	if o == nil || o.State != StateActive || o.IsDead(now) {
		return false
	}
	b, ok := ProgressBound(o.Entity.Kind, o.Phase)
	if !ok {
		return false
	}
	return now.Sub(o.LastProgressAt) > b
}

// IsHealthy reports whether this record still entitles its owner to act. A
// stuck-but-alive owner IS healthy in this sense: it holds the entity
// legitimately and nobody else may take it.
func (o *Ownership) IsHealthy(now time.Time) bool {
	return o != nil && o.State == StateActive && !o.IsDead(now)
}

// Event is an append-only record of an ownership transition.
type Event struct {
	ID         int64     `json:"id"`
	Entity     EntityRef `json:"entity"`
	Phase      string    `json:"phase"`
	Event      string    `json:"event"`
	OwnerEpoch int       `json:"owner_epoch"`
	Actor      Owner     `json:"actor"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Sentinel errors. Mapped to HTTP status by the handler layer, following the
// convention in internal/agentregistry and internal/alerts.
var (
	// ErrOwnedByOther means a DIFFERENT healthy actor holds this
	// (entity, phase). The caller must not mutate. The current owner is
	// returned alongside this error so the loser learns who won rather than
	// only that it lost.
	ErrOwnedByOther = errors.New("lifecycle: entity phase is owned by another actor")

	// ErrNotOwner means the caller tried to progress, hand off or release a
	// record whose owner is somebody else. Callers may only drive their own
	// ownership; taking it from a live owner is a recovery operation, not an
	// ordinary write.
	ErrNotOwner = errors.New("lifecycle: caller is not the current owner")

	// ErrEpochMismatch means the caller's fencing epoch is not the current
	// one — ownership moved underneath it.
	ErrEpochMismatch = errors.New("lifecycle: owner epoch is stale")

	// ErrNotFound means no ownership record exists for this (entity, phase).
	ErrNotFound = errors.New("lifecycle: ownership not found")

	// ErrUnknownPhase means the (kind, phase) pair is not in the registry.
	ErrUnknownPhase = errors.New("lifecycle: unknown entity kind or phase")

	// ErrNoHandoff means HandoffComplete was called on a record that is not
	// handing off.
	ErrNoHandoff = errors.New("lifecycle: no handoff in progress")

	// ErrOwnerAlive means Recover was asked to take ownership from an owner
	// that is still within its liveness bound.
	//
	// A client may not assert that an owner is dead; it may only ask the
	// server to re-evaluate it, and this is the server refusing. Letting a
	// caller declare death would put the takeover decision back in the hands
	// of whoever wants to act, which is the shape of the failure this package
	// exists to remove.
	ErrOwnerAlive = errors.New("lifecycle: current owner is still alive")
)
