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
	"context"
	"crypto/sha1" //nolint:gosec // test-only: derives a unique, well-formed 40-hex git-style id
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// ADR 018 Amendment 2, Tier B checklist items 4-8, against Postgres.

// a2Spec describes one subject-bound test envelope.
type a2Spec struct {
	kind, repo, ref, revision string
	authority, observedAt     string
	supersedes                string
	workItemID                string
	// declareSubjectRedaction adds a required redacted_out gap on subject
	// (the declarative excusal: such an envelope is never a candidate).
	declareSubjectRedaction bool
}

// uniqueSubject returns a PR subject no other test (or run) uses.
func uniqueSubject() a2Spec {
	return a2Spec{kind: "pull_request", repo: "mctlhq/t" + uniqueSuffix(), ref: "1", revision: uniqueSHA(),
		authority: "observed", observedAt: "2026-10-04T10:00:00Z"}
}

func uniqueSHA() string {
	sum := sha1.Sum([]byte(uniqueSuffix())) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

func a2Envelope(t *testing.T, s a2Spec) []byte {
	t.Helper()
	m := a2Base()
	exec := sub(m, "execution")
	exec["trace_id"] = "trace-" + uniqueSuffix()
	exec["work_item_id"] = s.workItemID
	m["subject"] = map[string]any{"kind": s.kind, "repository": s.repo, "ref": s.ref, "revision": s.revision}
	m["provenance"] = map[string]any{"authority": s.authority, "observed_at": s.observedAt, "supersedes": s.supersedes}
	if s.declareSubjectRedaction {
		m["gaps"] = []any{map[string]any{"block": "subject", "code": "redacted_out", "required": true}}
	}
	return sealMap(t, m)
}

func mustIngest(t *testing.T, s *Store, env []byte) *Evidence {
	t.Helper()
	rec, _, err := s.Ingest(context.Background(), IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return rec
}

func (s a2Spec) query() SubjectQuery {
	return SubjectQuery{Kind: s.kind, Repository: s.repo, Ref: s.ref, Revision: s.revision}
}

func TestStoreA2IngestWritesImmutableSubjectColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	spec := uniqueSubject()
	spec.observedAt = "2026-10-04T10:00:00.25Z"
	rec := mustIngest(t, s, a2Envelope(t, spec))

	got, err := s.Get(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	wantSubject := SubjectRef{Kind: spec.kind, Repository: spec.repo, Ref: spec.ref, Revision: spec.revision}
	if got.Subject == nil || *got.Subject != wantSubject {
		t.Errorf("Subject = %+v, want %+v", got.Subject, wantSubject)
	}
	wantAt := time.Date(2026, 10, 4, 10, 0, 0, 250_000_000, time.UTC)
	if got.Authority != "observed" || got.ObservedAt == nil || !got.ObservedAt.Equal(wantAt) || got.Supersedes != "" {
		t.Errorf("provenance = (%q, %v, %q), want (observed, %v, \"\")", got.Authority, got.ObservedAt, got.Supersedes, wantAt)
	}

	var kind, repo, ref, revision, authority, supersedes string
	var observedAt *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT subject_kind, subject_repository, subject_ref, subject_revision,
		authority, observed_at, supersedes FROM execution_evidence WHERE id=$1`, rec.ID).
		Scan(&kind, &repo, &ref, &revision, &authority, &observedAt, &supersedes); err != nil {
		t.Fatal(err)
	}
	if kind != spec.kind || repo != spec.repo || ref != spec.ref || revision != spec.revision ||
		authority != "observed" || observedAt == nil || !observedAt.Equal(wantAt) || supersedes != "" {
		t.Errorf("columns = (%s %s %s %s %s %v %q)", kind, repo, ref, revision, authority, observedAt, supersedes)
	}

	// The columns are as immutable as the rest of the row.
	if _, err := s.pool.Exec(ctx, `UPDATE execution_evidence SET subject_revision=$2 WHERE id=$1`, rec.ID, uniqueSHA()); err == nil {
		t.Fatal("UPDATE of subject_revision succeeded, want the immutability trigger to refuse it")
	}
}

// Backward compatibility: a pre-amendment envelope stores default columns
// and serializes exactly the pre-amendment record keys.
func TestStoreA2LegacyRecordIsUnchanged(t *testing.T) {
	s := newTestStore(t)
	rec := mustIngest(t, s, uniqueEnvelope(t, "wi_test-legacy-"+uniqueSuffix(), ""))
	got, err := s.Get(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"subject", "authority", "observed_at", "supersedes", "superseded_by"} {
		if _, present := keys[k]; present {
			t.Errorf("legacy record serializes %q: %s", k, raw)
		}
	}
	// The golden legacy fixtures still ingest.
	for _, name := range []string{"investigator-evidence.json", "implementer-evidence.json", "shepherd-evidence.json"} {
		env, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a fixed testdata fixture
		if err != nil {
			t.Fatal(err)
		}
		mustIngest(t, s, env)
	}
}

// The two Amendment 2 golden vectors ingest, in either order, and the
// superseding one is read back as superseded_by on the original.
func TestStoreA2GoldenPairIngestsAndLinks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"shepherd-pr-superseding-evidence.json", "shepherd-pr-evidence.json"} {
		env, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a fixed testdata fixture
		if err != nil {
			t.Fatal(err)
		}
		mustIngest(t, s, env)
	}
	orig, err := s.Get(ctx, "ev-df6d015f8ddf64ac")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(orig.SupersededBy, "ev-5a7500c45dd74b8b") {
		t.Errorf("SupersededBy = %v, want it to contain ev-5a7500c45dd74b8b", orig.SupersededBy)
	}
}

func TestStoreA2SupersedesAtIngest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := uniqueSubject()
	target := mustIngest(t, s, a2Envelope(t, base))

	ingest := func(spec a2Spec) error {
		_, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: a2Envelope(t, spec), IngestedBy: "test:writer"})
		return err
	}
	invalidLinks := map[string]func(a2Spec) a2Spec{
		"another revision":   func(x a2Spec) a2Spec { x.revision = uniqueSHA(); return x },
		"another ref":        func(x a2Spec) a2Spec { x.ref = "2"; return x },
		"another repository": func(x a2Spec) a2Spec { x.repo = "mctlhq/other" + uniqueSuffix(); return x },
		"another kind":       func(x a2Spec) a2Spec { x.kind = "branch"; x.ref = "main"; return x },
		"weaker authority":   func(x a2Spec) a2Spec { x.authority = "asserted"; return x },
	}
	for name, mutate := range invalidLinks {
		spec := mutate(base)
		spec.supersedes = target.ID
		spec.observedAt = "2026-10-04T11:00:00Z"
		if err := ingest(spec); !errors.Is(err, ErrEvidenceSupersedesInvalid) {
			t.Errorf("%s: Ingest = %v, want ErrEvidenceSupersedesInvalid", name, err)
		}
	}

	// Equal authority, same subject and revision: accepted, and visible as
	// superseded_by on the target.
	valid := base
	valid.supersedes = target.ID
	valid.observedAt = "2026-10-04T11:00:00Z"
	repl := mustIngest(t, s, a2Envelope(t, valid))
	got, err := s.Get(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.SupersededBy, []string{repl.ID}) {
		t.Errorf("SupersededBy = %v, want [%s]", got.SupersededBy, repl.ID)
	}

	// A stronger authority may supersede a weaker one.
	weak := base
	weak.authority = "derived"
	weak.revision = uniqueSHA()
	weakRec := mustIngest(t, s, a2Envelope(t, weak))
	strong := weak
	strong.authority = "observed"
	strong.supersedes = weakRec.ID
	mustIngest(t, s, a2Envelope(t, strong))

	// A target that does not exist (yet) is accepted: the producer never
	// blocks on ordering.
	dangling := base
	dangling.supersedes = "ev-00000000deadbeef"
	dangling.observedAt = "2026-10-04T12:00:00Z"
	mustIngest(t, s, a2Envelope(t, dangling))
}

// superseded_by lists valid links only: a link stored before its target
// existed, about another revision, is never served.
func TestStoreA2SupersededByListsValidLinksOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := uniqueSubject()
	targetEnv := a2Envelope(t, base)
	_, _, targetID, err := Validate(IngestInput{EnvelopeBytes: targetEnv})
	if err != nil {
		t.Fatal(err)
	}
	// Ingested first, while the target is absent: accepted as dangling.
	other := base
	other.revision = uniqueSHA()
	other.supersedes = targetID
	mustIngest(t, s, a2Envelope(t, other))
	mustIngest(t, s, targetEnv)

	got, err := s.Get(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SupersededBy) != 0 {
		t.Fatalf("SupersededBy = %v, want none (the only link is about another revision)", got.SupersededBy)
	}
}

// Every CHECK constraint refuses a row that violates it, and accepts the
// same row with the violation removed (raw INSERTs, bypassing Validate).
func TestStoreA2CheckConstraints(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	type row struct {
		kind, repo, ref, revision, authority string
		observedAt                           *time.Time
		supersedes                           string
	}
	now := time.Now().UTC()
	valid := row{"pull_request", "mctlhq/x", "1", uniqueSHA(), "observed", &now, ""}
	insert := func(r row, id string) error {
		_, err := s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceRowColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			id, "sha256:"+uniqueSHA()+uniqueSHA()[:24], APIVersionV1Alpha1, []byte("{}"), "we_check", "", "", "",
			now, "test:check", "", now, r.kind, r.repo, r.ref, r.revision, r.authority, r.observedAt, r.supersedes)
		if err == nil {
			t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, id) })
		}
		return err
	}
	newID := func() string { return "ev-" + uniqueSHA()[:16] }
	if err := insert(valid, newID()); err != nil {
		t.Fatalf("valid row refused: %v", err)
	}
	selfID := newID()
	cases := map[string]struct {
		r  row
		id string
	}{
		"authority vocabulary":     {func() row { r := valid; r.authority = "verified"; return r }(), ""},
		"supersedes shape":         {func() row { r := valid; r.supersedes = "ev-XYZ"; return r }(), ""},
		"supersedes self":          {func() row { r := valid; r.supersedes = selfID; return r }(), selfID},
		"subject needs authority":  {func() row { r := valid; r.authority = ""; r.observedAt = nil; return r }(), ""},
		"subject needs observed":   {func() row { r := valid; r.observedAt = nil; return r }(), ""},
		"PR revision is a SHA":     {func() row { r := valid; r.revision = "abc"; return r }(), ""},
		"PR revision never blank":  {func() row { r := valid; r.revision = ""; return r }(), ""},
		"branch revision is a SHA": {func() row { r := valid; r.kind, r.ref, r.revision = "branch", "main", ""; return r }(), ""},
		"subject kind vocabulary":  {func() row { r := valid; r.kind = "commit"; return r }(), ""},
		"PR ref is a number":       {func() row { r := valid; r.ref = ""; return r }(), ""},
		"issue ref is a number":    {func() row { r := valid; r.kind, r.ref, r.revision = "issue", "x", ""; return r }(), ""},
		"no subject columns without a kind": {func() row {
			r := valid
			r.kind = ""
			return r
		}(), ""},
		"provenance is whole": {func() row {
			r := valid
			r.kind, r.repo, r.ref, r.revision = "", "", "", ""
			r.observedAt = nil
			return r
		}(), ""},
	}
	for name, c := range cases {
		id := c.id
		if id == "" {
			id = newID()
		}
		if err := insert(c.r, id); err == nil {
			t.Errorf("%s: violating row accepted", name)
		}
	}
	// The ADR-sanctioned exception: a blank repository/ref on a
	// non-numbered subject (the redaction excusal) is storable.
	excused := valid
	excused.kind, excused.ref, excused.repo = "branch", "", ""
	if err := insert(excused, newID()); err != nil {
		t.Errorf("redaction-excused row refused: %v", err)
	}
}

// A row whose subject/provenance columns disagree with its envelope is
// corrupt: refused on read, never served from either side.
func TestStoreA2ColumnsMustMatchTheEnvelope(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	spec := uniqueSubject()
	env := a2Envelope(t, spec)
	_, hash, id, err := Validate(IngestInput{EnvelopeBytes: env})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	observed := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	_, err = s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceRowColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		id, hash, APIVersionV1Alpha1, env, "we_01J8ZQK7SHEP0000000000000", "ex-1122334455667788", "", "",
		now, "test:planted", "", now, spec.kind, spec.repo, "2", spec.revision, "observed", observed, "")
	if err != nil {
		t.Fatalf("plant: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, id) })
	if _, err := s.Get(ctx, id); err == nil || errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("Get(columns disagree with envelope) = %v, want a corruption error", err)
	}
}

func TestStoreA2CurrentStates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	current := func(q SubjectQuery) *CurrentResult {
		t.Helper()
		res, err := s.Current(ctx, q)
		if err != nil {
			t.Fatalf("Current(%+v): %v", q, err)
		}
		if (res.State == CurrentStateCurrent) != (res.Evidence != nil) {
			t.Fatalf("state %s with evidence %v", res.State, res.Evidence)
		}
		return res
	}
	base := uniqueSubject()
	if got := current(base.query()).State; got != CurrentStateNoEvidence {
		t.Fatalf("fresh subject: %s, want no_evidence", got)
	}
	blank := base.query()
	blank.Revision = ""
	if got := current(blank).State; got != CurrentStateUnknownRevision {
		t.Fatalf("blank revision: %s, want unknown_revision", got)
	}

	first := mustIngest(t, s, a2Envelope(t, base))
	res := current(base.query())
	if res.State != CurrentStateCurrent || res.Evidence.ID != first.ID {
		t.Fatalf("one envelope: (%s, %v), want current %s", res.State, res.Evidence, first.ID)
	}
	other := base.query()
	other.Revision = uniqueSHA()
	if got := current(other).State; got != CurrentStateStaleRevision {
		t.Fatalf("other revision: %s, want stale_revision", got)
	}

	// Authority outranks recency: a newer assertion does not displace it.
	claim := base
	claim.authority, claim.observedAt = "asserted", "2026-10-05T10:00:00Z"
	mustIngest(t, s, a2Envelope(t, claim))
	if res := current(base.query()); res.State != CurrentStateCurrent || res.Evidence.ID != first.ID {
		t.Fatalf("after a newer assertion: (%s, %v), want current %s", res.State, res.Evidence, first.ID)
	}

	// A tie at the top is ambiguous.
	tie := base
	mustIngest(t, s, a2Envelope(t, tie))
	if got := current(base.query()).State; got != CurrentStateAmbiguous {
		t.Fatalf("tie: %s, want ambiguous", got)
	}

	// Supersession (not recency) retires an envelope: the replacement wins
	// although it observed earlier, and is served as superseded_by.
	tieless := uniqueSubject()
	a := mustIngest(t, s, a2Envelope(t, tieless))
	b := tieless
	b.supersedes, b.observedAt = a.ID, "2026-10-04T09:00:00Z"
	bRec := mustIngest(t, s, a2Envelope(t, b))
	res = current(tieless.query())
	if res.State != CurrentStateCurrent || res.Evidence.ID != bRec.ID {
		t.Fatalf("superseded: (%s, %v), want current %s", res.State, res.Evidence, bRec.ID)
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.SupersededBy, []string{bRec.ID}) {
		t.Fatalf("SupersededBy = %v, want [%s]", got.SupersededBy, bRec.ID)
	}
}

func TestStoreA2CurrentRejectsAMalformedQuery(t *testing.T) {
	s := newTestStore(t)
	q := uniqueSubject().query()
	q.Revision = q.Revision[:12]
	if _, err := s.Current(context.Background(), q); !errors.Is(err, ErrCurrentQueryInvalid) {
		t.Fatalf("Current(abbreviated SHA) = %v, want ErrCurrentQueryInvalid", err)
	}
}

// A redacted-subject envelope is never current and never makes a subject
// stale.
func TestStoreA2CurrentExcludesRedactedSubjects(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	spec := a2Spec{kind: "work_item", ref: "wi_" + uniqueSuffix(), authority: "observed",
		observedAt: "2026-10-04T10:00:00Z", declareSubjectRedaction: true}
	mustIngest(t, s, a2Envelope(t, spec))
	for _, q := range []SubjectQuery{spec.query(), {Kind: "work_item", Ref: spec.ref, Revision: "v2"}} {
		res, err := s.Current(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CurrentStateNoEvidence {
			t.Errorf("Current(%+v) = %s, want no_evidence", q, res.State)
		}
	}
	// The stale witness must be an UNREDACTED envelope: a newer redacted
	// one at another revision is skipped, not taken as the witness.
	older := a2Spec{kind: "work_item", ref: spec.ref, revision: "v1", authority: "observed",
		observedAt: "2026-10-01T10:00:00Z"}
	mustIngest(t, s, a2Envelope(t, older))
	newerRedacted := older
	newerRedacted.revision, newerRedacted.observedAt, newerRedacted.declareSubjectRedaction = "v3", "2026-10-05T10:00:00Z", true
	mustIngest(t, s, a2Envelope(t, newerRedacted))
	res, err := s.Current(ctx, SubjectQuery{Kind: "work_item", Ref: spec.ref, Revision: "v9"})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != CurrentStateStaleRevision {
		t.Errorf("Current(other revision) = %s, want stale_revision", res.State)
	}

	plain := spec
	plain.declareSubjectRedaction = false
	rec := mustIngest(t, s, a2Envelope(t, plain))
	res, err = s.Current(ctx, spec.query())
	if err != nil {
		t.Fatal(err)
	}
	if res.State != CurrentStateCurrent || res.Evidence.ID != rec.ID {
		t.Errorf("Current = (%s, %v), want current %s", res.State, res.Evidence, rec.ID)
	}
}

// Could not observe is never observed absent: a pool over the cap, and a
// corrupt row in the pool or in the stale witness, are errors.
func TestStoreA2CurrentFailsClosed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	spec := uniqueSubject()
	for range 3 {
		mustIngest(t, s, a2Envelope(t, spec))
	}
	_, err := withPoolCap(2, func() (*CurrentResult, error) { return s.Current(ctx, spec.query()) })
	if !errors.Is(err, ErrCurrentPoolTooLarge) {
		t.Fatalf("Current(pool over cap) = %v, want ErrCurrentPoolTooLarge", err)
	}
	if res, err := s.Current(ctx, spec.query()); err != nil || res.State != CurrentStateAmbiguous {
		t.Fatalf("Current(pool within cap) = (%v, %v), want ambiguous", res, err)
	}

	plantCorrupt := func(spec a2Spec) {
		t.Helper()
		env := a2Envelope(t, spec)
		_, hash, id, err := Validate(IngestInput{EnvelopeBytes: env})
		if err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte{}, env...)
		tampered = []byte(string(tampered[:len(tampered)-1]) + `,"gaps":[{"block":"usage","code":"not_produced","required":false}]}`)
		now := time.Now().UTC()
		observed := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
		if _, err := s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceRowColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			id, hash, APIVersionV1Alpha1, tampered, "we_01J8ZQK7SHEP0000000000000", "ex-1122334455667788", "", "",
			now, "test:planted", "", now, spec.kind, spec.repo, spec.ref, spec.revision, "observed", observed, ""); err != nil {
			t.Fatalf("plant: %v", err)
		}
		t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, id) })
	}

	// Corrupt row in the pool.
	corrupt := uniqueSubject()
	plantCorrupt(corrupt)
	if res, err := s.Current(ctx, corrupt.query()); err == nil {
		t.Fatalf("Current(corrupt pool row) = %+v, want an error", res)
	}
	// Corrupt row as the only other-revision evidence: not no_evidence.
	q := corrupt.query()
	q.Revision = uniqueSHA()
	if res, err := s.Current(ctx, q); err == nil {
		t.Fatalf("Current(corrupt stale witness) = %+v, want an error", res)
	}
}

func TestStoreA2ListSubjectFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := uniqueSubject()
	b := a
	b.revision = uniqueSHA()
	recA := mustIngest(t, s, a2Envelope(t, a))
	recB := mustIngest(t, s, a2Envelope(t, b))

	res, err := s.List(ctx, Filter{SubjectKind: a.kind, SubjectRepository: a.repo, SubjectRef: a.ref})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 2 || !containsID(res.Evidence, recA.ID) || !containsID(res.Evidence, recB.ID) {
		t.Fatalf("subject filter: %d records, want both", len(res.Evidence))
	}
	res, err = s.List(ctx, Filter{SubjectRepository: a.repo, SubjectRevision: b.revision})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].ID != recB.ID {
		t.Fatalf("revision filter: %v, want only %s", res.Evidence, recB.ID)
	}
	res, err = s.ByWorkItem(ctx, "wi_none-"+uniqueSuffix(), Filter{SubjectRepository: a.repo})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 0 {
		t.Fatalf("work-item scope ignored: %d records", len(res.Evidence))
	}
}

func TestStoreA2CurrentForWorkItemNeedsTheWholePoolVisible(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mine := "wi_mine-" + uniqueSuffix()
	spec := uniqueSubject()
	spec.workItemID = mine
	rec := mustIngest(t, s, a2Envelope(t, spec))
	res, err := s.CurrentForWorkItem(ctx, spec.query(), mine)
	if err != nil || res.State != CurrentStateCurrent || res.Evidence.ID != rec.ID {
		t.Fatalf("CurrentForWorkItem(own) = (%+v, %v), want current %s", res, err, rec.ID)
	}
	if _, err := s.CurrentForWorkItem(ctx, spec.query(), "wi_other-"+uniqueSuffix()); !errors.Is(err, ErrCurrentNotVisible) {
		t.Fatalf("CurrentForWorkItem(other item) = %v, want ErrCurrentNotVisible", err)
	}
	// Another work item's envelope in the pool makes the answer depend on
	// evidence the caller may not see: refused, not resolved over a part.
	theirs := spec
	theirs.workItemID = "wi_theirs-" + uniqueSuffix()
	theirs.observedAt = "2026-10-04T11:00:00Z"
	mustIngest(t, s, a2Envelope(t, theirs))
	if _, err := s.CurrentForWorkItem(ctx, spec.query(), mine); !errors.Is(err, ErrCurrentNotVisible) {
		t.Fatalf("CurrentForWorkItem(mixed pool) = %v, want ErrCurrentNotVisible", err)
	}
}

// superseded_by never discloses another work item's evidence on the
// work-item read: the link still marks the record superseded (a retired
// record must not read as live), but only the admin read lists the id.
func TestStoreA2SupersededByIsWorkItemScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mine := "wi_mine-" + uniqueSuffix()
	spec := uniqueSubject()
	spec.workItemID = mine
	target := mustIngest(t, s, a2Envelope(t, spec))
	theirs := spec
	theirs.workItemID = "wi_theirs-" + uniqueSuffix()
	theirs.supersedes = target.ID
	theirs.observedAt = "2026-10-04T11:00:00Z"
	foreign := mustIngest(t, s, a2Envelope(t, theirs))

	scoped, err := s.ByWorkItem(ctx, mine, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.Evidence) != 1 {
		t.Fatalf("ByWorkItem: %d records, want 1", len(scoped.Evidence))
	}
	if got := scoped.Evidence[0]; !got.Superseded || len(got.SupersededBy) != 0 {
		t.Fatalf("work-item read: superseded=%v superseded_by=%v, want true and no foreign ids", got.Superseded, got.SupersededBy)
	}
	admin, err := s.Get(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Superseded || !slices.Equal(admin.SupersededBy, []string{foreign.ID}) {
		t.Fatalf("admin read: superseded=%v superseded_by=%v, want true [%s]", admin.Superseded, admin.SupersededBy, foreign.ID)
	}

	// A superseder in the same work item is listed on the scoped read.
	own := spec
	own.supersedes = target.ID
	own.observedAt = "2026-10-04T12:00:00Z"
	ownRec := mustIngest(t, s, a2Envelope(t, own))
	scoped, err = s.ByWorkItem(ctx, mine, Filter{SubjectRevision: spec.revision})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range scoped.Evidence {
		if e.ID == target.ID && !slices.Equal(e.SupersededBy, []string{ownRec.ID}) {
			t.Fatalf("work-item read: superseded_by=%v, want only [%s]", e.SupersededBy, ownRec.ID)
		}
	}
}

// The stale-witness scan is bounded like the pool: past the cap without an
// unredacted witness it fails closed instead of answering no_evidence.
func TestStoreA2StaleWitnessScanIsBounded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ref := "wi_" + uniqueSuffix()
	for _, revision := range []string{"v1", "v2"} {
		mustIngest(t, s, a2Envelope(t, a2Spec{kind: "work_item", ref: ref, revision: revision, authority: "observed",
			observedAt: "2026-10-04T10:00:00Z", declareSubjectRedaction: true}))
	}
	q := SubjectQuery{Kind: "work_item", Ref: ref, Revision: "v9"}
	_, err := withPoolCap(1, func() (*CurrentResult, error) { return s.Current(ctx, q) })
	if !errors.Is(err, ErrCurrentPoolTooLarge) {
		t.Fatalf("Current(witness scan over cap) = %v, want ErrCurrentPoolTooLarge", err)
	}
	if res, err := s.Current(ctx, q); err != nil || res.State != CurrentStateNoEvidence {
		t.Fatalf("Current(within cap) = (%v, %v), want no_evidence", res, err)
	}
}

// withPoolCap runs fn with maxCurrentPool overridden, restoring it even if
// fn panics.
func withPoolCap(limit int, fn func() (*CurrentResult, error)) (*CurrentResult, error) {
	prev := maxCurrentPool
	maxCurrentPool = limit
	defer func() { maxCurrentPool = prev }()
	return fn()
}

// A provenance-only (subject-less) envelope naming a legacy record never
// marks it superseded: supersession is about a subject.
func TestStoreA2SubjectlessLinkRetiresNothing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	legacy := mustIngest(t, s, uniqueEnvelope(t, "wi_test-legacy-"+uniqueSuffix(), ""))
	m := a2Base()
	delete(m, "subject")
	sub(m, "execution")["trace_id"] = "trace-" + uniqueSuffix()
	m["provenance"] = map[string]any{"authority": "asserted", "observed_at": "2026-10-05T10:00:00Z", "supersedes": legacy.ID}
	mustIngest(t, s, sealMap(t, m))
	got, err := s.Get(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Superseded || len(got.SupersededBy) != 0 {
		t.Fatalf("legacy record: superseded=%v superseded_by=%v, want untouched", got.Superseded, got.SupersededBy)
	}
}

// superseded_by is bounded: past the cap the read fails closed instead of
// serializing an unbounded (or silently truncated) list.
func TestStoreA2SupersededByIsBounded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	spec := uniqueSubject()
	target := mustIngest(t, s, a2Envelope(t, spec))
	for _, at := range []string{"2026-10-04T11:00:00Z", "2026-10-04T12:00:00Z"} {
		repl := spec
		repl.supersedes, repl.observedAt = target.ID, at
		mustIngest(t, s, a2Envelope(t, repl))
	}
	_, err := withPoolCap(1, func() (*CurrentResult, error) {
		_, err := s.Get(ctx, target.ID)
		return nil, err
	})
	if !errors.Is(err, ErrCurrentPoolTooLarge) {
		t.Fatalf("Get(fan-in over cap) = %v, want ErrCurrentPoolTooLarge", err)
	}
	if got, err := s.Get(ctx, target.ID); err != nil || len(got.SupersededBy) != 2 {
		t.Fatalf("Get(within cap) = (%v, %v), want two superseders", got, err)
	}
}

// A corrupt stored row is a server fault: its error must never carry
// ErrEvidenceInvalid, which the HTTP layer answers as a client 400.
func TestStoreA2CorruptStoredRowIsNotAClientError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	spec := uniqueSubject()
	spec.observedAt = "2026-02-30T10:00:00Z" // pattern-valid, impossible instant
	env := a2Envelope(t, spec)
	p, err := parseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalContentJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	hash := ContentHash(canonical)
	id := EvidenceIDFor(hash)
	now := time.Now().UTC()
	if _, err := s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceRowColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		id, hash, APIVersionV1Alpha1, env, "we_01J8ZQK7SHEP0000000000000", "ex-1122334455667788", "", "",
		now, "test:planted", "", now, spec.kind, spec.repo, spec.ref, spec.revision, "observed", now, ""); err != nil {
		t.Fatalf("plant: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, id) })
	_, err = s.Get(ctx, id)
	if err == nil || errors.Is(err, ErrEvidenceInvalid) || errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("Get(corrupt row) = %v, want a server-side error (not invalid, not not-found)", err)
	}
}
