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

package evidence

// Current vs historical (ADR 018 Amendment 2, "resolve_current"). This is a
// pure, in-memory port of orchestrator/execution_evidence.py's
// resolve_current — the conformance oracle Tier B must reproduce. The
// store (Store.Current) only decides WHICH rows to hand it, and must hand
// it the complete pool: a short list would turn an unknown into
// no_evidence.

import (
	"errors"
	"fmt"
	"strings"
)

// Current-read states (Tier A CURRENT_STATES). unknown_revision and
// ambiguous are unknowns and must never be read as no_evidence.
const (
	CurrentStateCurrent         = "current"
	CurrentStateNoEvidence      = "no_evidence"
	CurrentStateStaleRevision   = "stale_revision"
	CurrentStateUnknownRevision = "unknown_revision"
	CurrentStateAmbiguous       = "ambiguous"
)

// ErrCurrentQueryInvalid: an evidence query argument is malformed (an
// abbreviated or uppercase SHA, a kind outside SUBJECT_KINDS, an unknown
// or repeated current-read parameter, ...). A caller bug, answered 400
// evidence_query_invalid — never no_evidence.
var ErrCurrentQueryInvalid = errors.New("evidence query is invalid")

// SubjectQuery names the subject and the revision the caller has just
// observed it at.
type SubjectQuery struct {
	Kind       string
	Repository string
	Ref        string
	Revision   string
}

func (q SubjectQuery) key() [3]string { return [3]string{q.Kind, q.Repository, q.Ref} }

// ValidateSubjectQuery applies the subject rules to the query (a blank
// revision excepted), Tier A resolve_current step 0.
func ValidateSubjectQuery(q SubjectQuery) error {
	s := &SubjectRef{Kind: q.Kind, Repository: q.Repository, Ref: q.Ref, Revision: q.Revision}
	if err := checkSubject(s); err != nil {
		return fmt.Errorf("%w: %s", ErrCurrentQueryInvalid, stripSentinel(err))
	}
	if err := checkRequiredLeaves(requiredLeaves(nil, s, nil, nil), nil, map[string]bool{"subject.revision": true}); err != nil {
		return fmt.Errorf("%w: %s", ErrCurrentQueryInvalid, stripSentinel(err))
	}
	return nil
}

func stripSentinel(err error) string {
	return strings.TrimPrefix(err.Error(), ErrEvidenceInvalid.Error()+": ")
}

// Candidate is one envelope as resolve_current sees it.
type Candidate struct {
	ID string
	// ContentKey identifies the content (everything but created_at). Tier
	// B recomputes content_hash on every read, so the recomputed hash is
	// exactly Tier A's _content_key equivalence.
	ContentKey string
	Subject    *SubjectRef
	// SubjectRedacted: the envelope declares a redacted_out gap on
	// subject, so it is not bound to a known subject.
	SubjectRedacted bool
	Authority       string
	// ObservedAt is provenance.observed_at exactly as sealed.
	ObservedAt string
	Supersedes string
	// Record is the stored record this candidate came from (nil in pure
	// tests).
	Record *Evidence
}

func (c *Candidate) rank() int { return authorityRank[c.Authority] }

// observedAtKey is Tier A's _observed_at_key: the fraction padded to six
// digits, so "...:00Z" sorts before "...:00.5Z" (raw text gets that
// backwards, '.' < 'Z').
func observedAtKey(observedAt string) string {
	if observedAt == "" {
		// Tier A ranks an envelope without provenance as (0, ""); a
		// validated subject-bound envelope always carries observed_at.
		return ""
	}
	seconds, rest, hasFraction := strings.Cut(observedAt, ".")
	if hasFraction {
		frac := strings.TrimRight(rest, "Z")
		for len(frac) < 6 {
			frac += "0"
		}
		return seconds + "." + frac
	}
	return strings.TrimRight(observedAt, "Z") + ".000000"
}

// validLink reports whether superseder's supersedes link to target counts:
// same subject key and revision, neither subject redacted, and the
// superseder's authority equal or stronger. The one predicate behind both
// resolve_current step 3 and the read-time superseded_by.
func validLink(superseder, target *Candidate) bool {
	if superseder.Supersedes == "" || superseder.Supersedes != target.ID {
		return false
	}
	if superseder.SubjectRedacted || target.SubjectRedacted {
		return false
	}
	// Supersession is about a subject: resolve_current's pool never holds
	// a subject-less envelope, so a link between two of them (every
	// pre-amendment record is one) retires nothing.
	if superseder.Subject == nil || target.Subject == nil {
		return false
	}
	if *superseder.Subject != *target.Subject {
		return false
	}
	return superseder.rank() >= target.rank()
}

// ResolveCurrent is Tier A's resolve_current. candidates must be the
// complete set for the subject key (every revision, or — equivalently —
// the complete pool at q.Revision plus any one unredacted envelope at
// another revision). It returns the state and, only for current, the
// winning candidate.
func ResolveCurrent(candidates []*Candidate, q SubjectQuery) (string, *Candidate, error) {
	// 0. A malformed argument is a caller bug, never no_evidence.
	if err := ValidateSubjectQuery(q); err != nil {
		return "", nil, err
	}
	// 1. A SHA-bound subject without its live revision is unknown.
	if q.Revision == "" && shaBoundSubjectKinds[q.Kind] {
		return CurrentStateUnknownRevision, nil, nil
	}
	// 2. Pool: same key AND same revision, never a redacted subject.
	key := q.key()
	var sameSubject, pool []*Candidate
	for _, c := range candidates {
		if c.Subject == nil || c.SubjectRedacted {
			continue
		}
		if [3]string{c.Subject.Kind, c.Subject.Repository, c.Subject.Ref} != key {
			continue
		}
		sameSubject = append(sameSubject, c)
		if c.Subject.Revision == q.Revision {
			pool = append(pool, c)
		}
	}
	// Two different contents claiming one id make every id-keyed step
	// order-dependent: fail closed before any of them. The same envelope
	// listed twice (or re-sealed at another created_at) is not a collision.
	contents := map[string]string{}
	byID := map[string]*Candidate{}
	for _, c := range pool {
		if prev, seen := contents[c.ID]; seen && prev != c.ContentKey {
			return CurrentStateAmbiguous, nil, nil
		}
		contents[c.ID] = c.ContentKey
		if _, seen := byID[c.ID]; !seen {
			byID[c.ID] = c
		}
	}
	// 3. Supersession: only inside the pool, only equal-or-stronger.
	superseded := map[string]bool{}
	for _, c := range pool {
		if target, ok := byID[c.Supersedes]; ok && validLink(c, target) {
			superseded[target.ID] = true
		}
	}
	var live []*Candidate
	for _, c := range pool {
		if !superseded[c.ID] {
			live = append(live, c)
		}
	}
	// 4. Empty pool: stale vs none. A fully superseded pool (a forged
	// cycle) is ambiguous.
	if len(live) == 0 {
		if len(pool) > 0 {
			return CurrentStateAmbiguous, nil, nil
		}
		if len(sameSubject) > 0 {
			return CurrentStateStaleRevision, nil, nil
		}
		return CurrentStateNoEvidence, nil, nil
	}
	// Authority outranks recency; among equal authority the later
	// observation wins.
	type rankKey struct {
		authority int
		observed  string
	}
	rankOf := func(c *Candidate) rankKey { return rankKey{c.rank(), observedAtKey(c.ObservedAt)} }
	less := func(a, b rankKey) bool {
		if a.authority != b.authority {
			return a.authority < b.authority
		}
		return a.observed < b.observed
	}
	top := rankOf(live[0])
	for _, c := range live[1:] {
		if r := rankOf(c); less(top, r) {
			top = r
		}
	}
	// 5. More than one distinct envelope at the top -> ambiguous.
	winners := map[string]*Candidate{}
	for _, c := range live {
		if rankOf(c) == top {
			if _, seen := winners[c.ID]; !seen {
				winners[c.ID] = c
			}
		}
	}
	if len(winners) != 1 {
		return CurrentStateAmbiguous, nil, nil
	}
	for _, w := range winners {
		return CurrentStateCurrent, w, nil
	}
	return CurrentStateAmbiguous, nil, nil // unreachable
}
