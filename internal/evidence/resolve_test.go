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

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ResolveCurrent is a port of Tier A's resolve_current (ADR 018 Amendment
// 2); these cases mirror tests/test_execution_evidence.py's T16
// resolve_current tests one for one.

const testRepo = "mctlhq/mctl-agents"

var prQuery = SubjectQuery{Kind: "pull_request", Repository: testRepo, Ref: "524", Revision: testSHA1}

type candOpt func(c *Candidate)

func at(observedAt string) candOpt        { return func(c *Candidate) { c.ObservedAt = observedAt } }
func by(authority string) candOpt         { return func(c *Candidate) { c.Authority = authority } }
func rev(revision string) candOpt         { return func(c *Candidate) { c.Subject.Revision = revision } }
func supersedes(id string) candOpt        { return func(c *Candidate) { c.Supersedes = id } }
func content(key string) candOpt          { return func(c *Candidate) { c.ContentKey = key } }
func redactedSubject() candOpt            { return func(c *Candidate) { c.SubjectRedacted = true } }
func subjectOf(s SubjectRef) candOpt      { return func(c *Candidate) { c.Subject = &s } }
func withoutSubject() candOpt             { return func(c *Candidate) { c.Subject = nil } }
func observedAtDefault() string           { return "2026-10-04T10:00:00Z" }
func evID(n string) string                { return "ev-" + strings.Repeat("0", 16-len(n)) + n }
func cands(cs ...*Candidate) []*Candidate { return cs }

func cand(id string, opts ...candOpt) *Candidate {
	c := &Candidate{
		ID: evID(id), ContentKey: "content-" + id,
		Subject:   &SubjectRef{Kind: "pull_request", Repository: testRepo, Ref: "524", Revision: testSHA1},
		Authority: "observed", ObservedAt: observedAtDefault(),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func resolve(t *testing.T, candidates []*Candidate, q SubjectQuery) (string, string) {
	t.Helper()
	state, winner, err := ResolveCurrent(candidates, q)
	if err != nil {
		t.Fatalf("ResolveCurrent: %v", err)
	}
	if (state == CurrentStateCurrent) != (winner != nil) {
		t.Fatalf("state %s with winner %v: current must carry exactly one envelope", state, winner)
	}
	if winner == nil {
		return state, ""
	}
	return state, winner.ID
}

func wantState(t *testing.T, gotState, gotID, wantState, wantID string) {
	t.Helper()
	if gotState != wantState || gotID != wantID {
		t.Fatalf("got (%s, %s), want (%s, %s)", gotState, gotID, wantState, wantID)
	}
}

func TestResolveCurrentWithoutALiveRevisionIsUnknown(t *testing.T) {
	q := prQuery
	q.Revision = ""
	s, id := resolve(t, cands(cand("1")), q)
	wantState(t, s, id, CurrentStateUnknownRevision, "")
	for _, kind := range []string{"branch", "release"} {
		s, id = resolve(t, nil, SubjectQuery{Kind: kind, Repository: testRepo, Ref: "main"})
		wantState(t, s, id, CurrentStateUnknownRevision, "")
	}
}

func TestResolveCurrentNeverReturnsSHA1EvidenceForSHA2(t *testing.T) {
	q := prQuery
	q.Revision = testSHA2
	s, id := resolve(t, cands(cand("1")), q)
	wantState(t, s, id, CurrentStateStaleRevision, "")
	s, id = resolve(t, nil, q)
	wantState(t, s, id, CurrentStateNoEvidence, "")
	// Another subject key is neither current nor stale.
	s, id = resolve(t, cands(cand("1", subjectOf(SubjectRef{Kind: "pull_request", Repository: testRepo, Ref: "525", Revision: testSHA1}))), prQuery)
	wantState(t, s, id, CurrentStateNoEvidence, "")
	s, id = resolve(t, cands(cand("1", withoutSubject())), prQuery)
	wantState(t, s, id, CurrentStateNoEvidence, "")
}

func TestResolveCurrentDropsASupersededEnvelope(t *testing.T) {
	// Supersession, not recency: the superseding envelope wins even with
	// an earlier observed_at.
	old := cand("1", at("2026-10-04T10:00:05Z"))
	repl := cand("2", at("2026-10-04T10:00:00Z"), supersedes(old.ID))
	s, id := resolve(t, cands(old, repl), prQuery)
	wantState(t, s, id, CurrentStateCurrent, repl.ID)
	s, id = resolve(t, cands(repl, old), prQuery)
	wantState(t, s, id, CurrentStateCurrent, repl.ID)
}

func TestResolveCurrentSupersedesWithEqualOrStrongerAuthority(t *testing.T) {
	old := cand("1", by("derived"), at("2026-10-04T10:00:05Z"))
	for _, authority := range []string{"derived", "observed"} {
		repl := cand("2", by(authority), at("2026-10-04T10:00:00Z"), supersedes(old.ID))
		s, id := resolve(t, cands(old, repl), prQuery)
		wantState(t, s, id, CurrentStateCurrent, repl.ID)
	}
}

func TestResolveCurrentIgnoresSupersessionFromAnotherRevision(t *testing.T) {
	old := cand("1")
	other := cand("2", rev(testSHA2), at("2026-10-04T11:00:00Z"), supersedes(old.ID))
	s, id := resolve(t, cands(old, other), prQuery)
	wantState(t, s, id, CurrentStateCurrent, old.ID)
}

func TestResolveCurrentNeverLetsAWeakerAuthoritySupersedeAStrongerOne(t *testing.T) {
	obs := cand("1")
	claim := cand("2", by("asserted"), at("2026-10-04T11:00:00Z"), supersedes(obs.ID))
	s, id := resolve(t, cands(obs, claim), prQuery)
	wantState(t, s, id, CurrentStateCurrent, obs.ID)
}

func TestResolveCurrentRanksAuthorityAboveRecency(t *testing.T) {
	obs := cand("1")
	claim := cand("2", by("asserted"), at("2026-10-05T10:00:00Z"))
	derived := cand("3", by("derived"), at("2026-10-05T09:00:00Z"))
	s, id := resolve(t, cands(claim, derived, obs), prQuery)
	wantState(t, s, id, CurrentStateCurrent, obs.ID)
	s, id = resolve(t, cands(claim, derived), prQuery)
	wantState(t, s, id, CurrentStateCurrent, derived.ID)
}

func TestResolveCurrentPrefersTheLaterObservationAtEqualAuthority(t *testing.T) {
	a := cand("1", at("2026-10-04T10:00:00Z"))
	b := cand("2", at("2026-10-04T10:00:01Z"))
	s, id := resolve(t, cands(b, a), prQuery)
	wantState(t, s, id, CurrentStateCurrent, b.ID)
	// The fraction is normalized: 10:00:00.5Z is later than 10:00:00Z,
	// although '.' < 'Z' as raw text.
	c := cand("3", at("2026-10-04T10:00:01.5Z"))
	s, id = resolve(t, cands(c, b), prQuery)
	wantState(t, s, id, CurrentStateCurrent, c.ID)
	s, id = resolve(t, cands(b, c), prQuery)
	wantState(t, s, id, CurrentStateCurrent, c.ID)
	// .5 and .500000 are the same instant: a tie, not a pick.
	d := cand("4", at("2026-10-04T10:00:01.500000Z"))
	s, id = resolve(t, cands(c, d), prQuery)
	wantState(t, s, id, CurrentStateAmbiguous, "")
}

func TestResolveCurrentReportsATieAsAmbiguous(t *testing.T) {
	a, b := cand("1"), cand("2")
	s, id := resolve(t, cands(a, b), prQuery)
	wantState(t, s, id, CurrentStateAmbiguous, "")
	s, id = resolve(t, cands(b, a), prQuery)
	wantState(t, s, id, CurrentStateAmbiguous, "")
}

func TestResolveCurrentTreatsADuplicateListingAsOneEnvelope(t *testing.T) {
	a := cand("1")
	again := cand("1")
	s, id := resolve(t, cands(a, again), prQuery)
	wantState(t, s, id, CurrentStateCurrent, a.ID)
}

func TestResolveCurrentTreatsTwoContentsUnderOneIDAsAmbiguous(t *testing.T) {
	a := cand("1")
	forged := cand("1", content("forged"), at("2026-10-04T12:00:00Z"))
	s, id := resolve(t, cands(a, forged), prQuery)
	wantState(t, s, id, CurrentStateAmbiguous, "")
	// Through supersession too, in either order: a forged id never lets
	// list order decide.
	repl := cand("2", supersedes(a.ID), at("2026-10-04T11:00:00Z"))
	for _, order := range [][]*Candidate{{a, forged, repl}, {repl, forged, a}, {forged, repl, a}} {
		s, id = resolve(t, order, prQuery)
		wantState(t, s, id, CurrentStateAmbiguous, "")
	}
}

func TestResolveCurrentReportsAFullySupersededPoolAsAmbiguous(t *testing.T) {
	a := cand("1", supersedes(evID("2")))
	b := cand("2", supersedes(evID("1")))
	s, id := resolve(t, cands(a, b), prQuery)
	wantState(t, s, id, CurrentStateAmbiguous, "")
}

func TestResolveCurrentNeverPoolsARedactedSubject(t *testing.T) {
	red := cand("1", redactedSubject())
	s, id := resolve(t, cands(red), prQuery)
	wantState(t, s, id, CurrentStateNoEvidence, "")
	// Nor counts it as evidence at another revision.
	q := prQuery
	q.Revision = testSHA2
	s, id = resolve(t, cands(red), q)
	wantState(t, s, id, CurrentStateNoEvidence, "")
	// A redacted envelope cannot retire an unredacted one either.
	ok := cand("2")
	red2 := cand("3", redactedSubject(), supersedes(ok.ID), at("2026-10-04T11:00:00Z"))
	s, id = resolve(t, cands(ok, red2), prQuery)
	wantState(t, s, id, CurrentStateCurrent, ok.ID)
}

func TestResolveCurrentStaleRevisionNeedsUnredactedEvidenceElsewhere(t *testing.T) {
	q := prQuery
	q.Revision = testSHA2
	s, id := resolve(t, cands(cand("1"), cand("2", redactedSubject())), q)
	wantState(t, s, id, CurrentStateStaleRevision, "")
}

func TestResolveCurrentForUnversionedAndVersionedIssues(t *testing.T) {
	issue := SubjectRef{Kind: "issue", Repository: testRepo, Ref: "199"}
	unversioned := cand("1", subjectOf(issue))
	versioned := issue
	versioned.Revision = "2026-10-04T10:00:00Z"
	tok := cand("2", subjectOf(versioned))

	s, id := resolve(t, cands(unversioned, tok), SubjectQuery{Kind: "issue", Repository: testRepo, Ref: "199"})
	wantState(t, s, id, CurrentStateCurrent, unversioned.ID)
	s, id = resolve(t, cands(unversioned, tok), SubjectQuery{Kind: "issue", Repository: testRepo, Ref: "199", Revision: versioned.Revision})
	wantState(t, s, id, CurrentStateCurrent, tok.ID)
	s, id = resolve(t, cands(tok), SubjectQuery{Kind: "issue", Repository: testRepo, Ref: "199"})
	wantState(t, s, id, CurrentStateStaleRevision, "")
}

func TestResolveCurrentForAWorkItemSubject(t *testing.T) {
	wi := SubjectRef{Kind: "work_item", Ref: "wi_abc"}
	c := cand("1", subjectOf(wi))
	s, id := resolve(t, cands(c), SubjectQuery{Kind: "work_item", Ref: "wi_abc"})
	wantState(t, s, id, CurrentStateCurrent, c.ID)
}

func TestResolveCurrentRejectsAMalformedArgument(t *testing.T) {
	for name, q := range map[string]SubjectQuery{
		"abbreviated SHA":         {Kind: "pull_request", Repository: testRepo, Ref: "524", Revision: testSHA1[:7]},
		"uppercase SHA":           {Kind: "pull_request", Repository: testRepo, Ref: "524", Revision: strings.ToUpper(testSHA1)},
		"unknown kind":            {Kind: "commit", Repository: testRepo, Ref: "524", Revision: testSHA1},
		"blank kind":              {Repository: testRepo, Ref: "524", Revision: testSHA1},
		"blank ref":               {Kind: "pull_request", Repository: testRepo, Revision: testSHA1},
		"PR ref not a number":     {Kind: "pull_request", Repository: testRepo, Ref: "pr-524", Revision: testSHA1},
		"missing repository":      {Kind: "pull_request", Ref: "524", Revision: testSHA1},
		"malformed repository":    {Kind: "pull_request", Repository: "mctl-agents", Ref: "524", Revision: testSHA1},
		"repository path segment": {Kind: "branch", Repository: "mctlhq/..", Ref: "main", Revision: testSHA1},
		"branch path fragment":    {Kind: "branch", Repository: testRepo, Ref: "a/../b", Revision: testSHA1},
		"issue token malformed":   {Kind: "issue", Repository: testRepo, Ref: "1", Revision: "has space"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ResolveCurrent(cands(cand("1")), q)
			if !errors.Is(err, ErrCurrentQueryInvalid) {
				t.Fatalf("ResolveCurrent(%+v) = %v, want ErrCurrentQueryInvalid", q, err)
			}
		})
	}
}

// candidateFromFixture validates a testdata envelope and returns its
// resolve_current view, the way Store.Current builds one from a row.
func candidateFromFixture(t *testing.T, name string) *Candidate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a fixed testdata fixture
	if err != nil {
		t.Fatal(err)
	}
	p, hash, id, err := Validate(IngestInput{EnvelopeBytes: raw})
	if err != nil {
		t.Fatalf("Validate(%s): %v", name, err)
	}
	e := &Evidence{ID: id, ContentHash: hash, Subject: p.a2.subject, Authority: p.a2.provenance.Authority,
		Supersedes: p.a2.provenance.Supersedes, observedAtRaw: p.a2.provenance.ObservedAt,
		subjectRedacted: p.a2.subjectRedacted()}
	return e.candidate()
}

// Tier A T16: resolve_current over the golden supersession pair at the
// fixture's SHA returns the superseding envelope, in either order.
func TestResolveCurrentOverTheGoldenSupersessionPair(t *testing.T) {
	orig := candidateFromFixture(t, "shepherd-pr-evidence.json")
	repl := candidateFromFixture(t, "shepherd-pr-superseding-evidence.json")
	if repl.Supersedes != orig.ID {
		t.Fatalf("fixture: %s supersedes %q, want %s", repl.ID, repl.Supersedes, orig.ID)
	}
	q := SubjectQuery{Kind: "pull_request", Repository: testRepo, Ref: "524", Revision: testSHA1}
	for _, order := range [][]*Candidate{{orig, repl}, {repl, orig}} {
		s, id := resolve(t, order, q)
		wantState(t, s, id, CurrentStateCurrent, "ev-5a7500c45dd74b8b")
	}
	s, id := resolve(t, cands(orig), q)
	wantState(t, s, id, CurrentStateCurrent, "ev-df6d015f8ddf64ac")
	if !validLink(repl, orig) {
		t.Fatal("validLink(superseding, original) = false, want true")
	}
}
