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

package securityfindings

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// fakeWorkItems answers the WorkItem lookup from a map.
type fakeWorkItems map[string]string // id -> tenant

func (f fakeWorkItems) Get(_ context.Context, id string) (*workitems.WorkItem, error) {
	tenant, ok := f[id]
	if !ok {
		return nil, workitems.ErrNotFound
	}
	return &workitems.WorkItem{ID: id, Tenant: tenant}, nil
}

func (f fakeWorkItems) add(tenant string) string {
	id := workitems.WorkItemIDPrefix + uuid.NewString()
	f[id] = tenant
	return id
}

var (
	sharedOnce  sync.Once
	sharedStore *Store
	sharedItems = fakeWorkItems{}
	sharedErr   error
)

// newTestStore connects to the Postgres that .github/workflows/validate.yml
// runs as a service for the `test` job (TEST_DATABASE_URL). It skips on a
// laptop without one, the pattern internal/evidence uses. One store serves
// the whole test binary; every test works in its own tenant.
func newTestStore(t *testing.T) (*Store, fakeWorkItems) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed security findings store test")
	}
	sharedOnce.Do(func() {
		sharedStore, sharedErr = NewStore(context.Background(), connStr, WithWorkItems(sharedItems))
	})
	if sharedErr != nil {
		t.Fatalf("NewStore: %v", sharedErr)
	}
	return sharedStore, sharedItems
}

func newTenant() string { return "t-" + uuid.NewString()[:8] }

var (
	ctx    = context.Background()
	human  = Actor{Principal: "github:alice", PrincipalID: "prn_alice", Source: "api"}
	runner = Actor{Principal: "agent:remediator", Source: "agent:remediator"}
)

func digest(c byte) string { return "sha256:" + hex64(c) }

func provider(ref string, max Strength, tenant string) ProviderContext {
	return ProviderContext{Ref: ref, MaxStrength: max, Tenants: []string{tenant}, PrincipalID: "prn_" + ref}
}

// dep is a dependency observation of cve in repo.
func dep(tenant, cve, repo string) ObservationInput {
	return ObservationInput{Tenant: tenant, Identity: cve,
		Subject: Subject{Repository: repo, PackagePURL: "pkg:golang/example.com/lib@1.0.0"}}
}

func mustIngest(t *testing.T, s *Store, pc ProviderContext, delivery string, items ...ObservationInput) []ItemResult {
	t.Helper()
	res, err := s.IngestBatch(ctx, pc, Batch{DeliveryID: delivery, Observations: items})
	if err != nil {
		t.Fatalf("IngestBatch: %v", err)
	}
	return res
}

func mustOccurrence(t *testing.T, s *Store, tenant, id string) *Occurrence {
	t.Helper()
	o, err := s.GetOccurrence(ctx, Visibility{Tenants: []string{tenant}}, id)
	if err != nil {
		t.Fatalf("GetOccurrence: %v", err)
	}
	return o
}

var cveSeq = time.Now().UnixNano() % 100000000

// cveID returns a distinct, valid CVE id per call.
func cveID() string {
	cveSeq++
	return fmt.Sprintf("CVE-2024-%d", 1000000+cveSeq)
}

func TestSchemaAppliesTwice(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		t.Fatalf("second schema application: %v", err)
	}
	// Immutable tables refuse UPDATE.
	tenant := newTenant()
	r := mustIngest(t, s, provider("trivy", StrengthScannerRerunExactRevision, tenant), "", dep(tenant, cveID(), "o/r"))[0]
	for _, q := range []string{
		`UPDATE security_observations SET claimed_action = 'absent' WHERE id = '` + r.ObservationID + `'`,
		`UPDATE security_occurrence_events SET reason = 'x' WHERE occurrence_id = '` + r.OccurrenceID + `'`,
	} {
		if _, err := s.pool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s: want immutable error, got %v", q, err)
		}
	}
}

// T1: the same CVE in two repositories is one finding with two independent
// occurrences.
func TestSameCVETwoRepositories(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	cve := cveID()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	res := mustIngest(t, s, pc, "d1", dep(tenant, cve, "o/a"), dep(tenant, cve, "o/b"))
	if res[0].FindingID != res[1].FindingID || res[0].OccurrenceID == res[1].OccurrenceID {
		t.Fatalf("want one finding, two occurrences: %+v", res)
	}
	start(t, s, res[0].OccurrenceID, wi.add(tenant))
	if got := mustOccurrence(t, s, tenant, res[0].OccurrenceID).State; got != StateFixing {
		t.Errorf("first occurrence state %s", got)
	}
	if got := mustOccurrence(t, s, tenant, res[1].OccurrenceID).State; got != StateOpen {
		t.Errorf("second occurrence must stay open, got %s", got)
	}
}

// T2-T4: artifact, location and source-vs-deployed differences make distinct
// occurrences.
func TestDistinctSubjectsDistinctOccurrences(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	cve := cveID()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	withDigest := func(d string) ObservationInput {
		o := dep(tenant, cve, "o/a")
		o.Subject.ArtifactDigest = d
		return o
	}
	res := mustIngest(t, s, pc, "", withDigest(digest('a')), withDigest(digest('b')), dep(tenant, cve, "o/a"))
	if res[0].OccurrenceID == res[1].OccurrenceID || res[0].OccurrenceID == res[2].OccurrenceID || res[1].OccurrenceID == res[2].OccurrenceID {
		t.Errorf("T2/T4: artifact and source states must be distinct occurrences: %+v", res)
	}
	rule := func(loc string) ObservationInput {
		return ObservationInput{Tenant: tenant, Identity: "go/sql-injection",
			Subject: Subject{Repository: "o/a", Path: "db.go", Location: loc}}
	}
	cq := provider("codeql", StrengthProviderClaim, tenant)
	r2 := mustIngest(t, s, cq, "", rule("10:12"), rule("40:41"))
	if r2[0].FindingID != r2[1].FindingID || r2[0].OccurrenceID == r2[1].OccurrenceID {
		t.Errorf("T3: same rule, different locations: %+v", r2)
	}
}

// T5: two providers, same canonical identity and subject: one occurrence.
func TestCrossProviderDedup(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	cve := cveID()
	tr := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	db := provider("dependabot", StrengthProviderClaim, tenant)
	a := mustIngest(t, s, tr, "", dep(tenant, cve, "o/a"))[0]
	b := mustIngest(t, s, db, "", dep(tenant, strings.ToLower(cve), "https://github.com/O/a.git"))[0]
	if a.OccurrenceID != b.OccurrenceID || b.Status != ItemCreated {
		t.Fatalf("want one occurrence: %+v %+v", a, b)
	}
	o := mustOccurrence(t, s, tenant, a.OccurrenceID)
	if len(o.Observations) != 2 || o.Observations[0].ProviderRef == o.Observations[1].ProviderRef {
		t.Errorf("want two observations from two providers: %+v", o.Observations)
	}
}

// T6: a batch of three findings under one delivery id records three; the
// redelivery is three duplicates and writes nothing.
func TestBatchDeliveryAndRedelivery(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	items := []ObservationInput{dep(tenant, cveID(), "o/a"), dep(tenant, cveID(), "o/b"), dep(tenant, cveID(), "o/c")}
	first := mustIngest(t, s, pc, "delivery-1", items...)
	ids := map[string]bool{}
	for _, r := range first {
		if r.Status != ItemCreated {
			t.Fatalf("want created: %+v", first)
		}
		ids[r.OccurrenceID] = true
	}
	if len(ids) != 3 {
		t.Fatalf("want 3 occurrences, got %d", len(ids))
	}
	count := func() (events int) {
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_occurrence_events e
			JOIN security_occurrences o ON o.id = e.occurrence_id WHERE o.tenant = $1`, tenant).Scan(&events); err != nil {
			t.Fatal(err)
		}
		return events
	}
	before := count()
	again := mustIngest(t, s, pc, "delivery-1", items...)
	for i, r := range again {
		if r.Status != ItemDuplicate || r.ObservationID != first[i].ObservationID {
			t.Errorf("item %d: want duplicate of %s, got %+v", i, first[i].ObservationID, r)
		}
	}
	if after := count(); after != before {
		t.Errorf("a redelivery must write no events: %d -> %d", before, after)
	}
	var rows int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_observations WHERE tenant = $1`, tenant).Scan(&rows); err != nil || rows != 3 {
		t.Errorf("want 3 observation rows, got %d %v", rows, err)
	}
}

// T7: a weak subject is rejected without dropping the rest of the batch; a
// tenant outside the provider's configuration is rejected too.
func TestWeakSubjectAndTenantRejected(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	weak := ObservationInput{Tenant: tenant, Identity: cveID(), Subject: Subject{Repository: "o/a"}}
	other := dep(newTenant(), cveID(), "o/a")
	res := mustIngest(t, s, pc, "", weak, dep(tenant, cveID(), "o/a"), other)
	if res[0].Status != ItemRejected || res[0].Code != CodeSubjectTooWeak {
		t.Errorf("weak: %+v", res[0])
	}
	if res[1].Status != ItemCreated {
		t.Errorf("later item must still succeed: %+v", res[1])
	}
	if res[2].Status != ItemRejected || res[2].Code != CodeTenantDenied {
		t.Errorf("foreign tenant: %+v", res[2])
	}
}

// T8: aliases resolving to two findings are rejected and nothing merges.
func TestAliasConflict(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	cve := cveID()
	ghsa := "GHSA-" + strings.ToLower(uuid.NewString()[:4]) + "-abcd-wxyz"
	a := mustIngest(t, s, pc, "", dep(tenant, cve, "o/a"))[0]
	b := mustIngest(t, s, pc, "", dep(tenant, ghsa, "o/a"))[0]
	if a.FindingID == b.FindingID {
		t.Fatal("separate identities start as separate findings")
	}
	link := dep(tenant, cve, "o/linked")
	link.Aliases = []string{ghsa}
	r := mustIngest(t, s, pc, "", link)[0]
	if r.Status != ItemRejected || r.Code != CodeAliasConflict {
		t.Fatalf("want finding_alias_conflict, got %+v", r)
	}
	var n int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM security_findings WHERE tenant = $1`, tenant).Scan(&n)
	if n != 2 {
		t.Errorf("nothing may merge: %d findings", n)
	}
	// A later observation of the same CVE lands on the existing finding.
	if r := mustIngest(t, s, pc, "", dep(tenant, cve, "o/zzz"))[0]; r.FindingID != a.FindingID {
		t.Errorf("same CVE resolves to the same finding: %+v", r)
	}
}

// openWithWork returns an open occurrence and a WorkItem in its tenant.
func openWithWork(t *testing.T, s *Store, wi fakeWorkItems, pc ProviderContext, tenant string) (ItemResult, string) {
	t.Helper()
	r := mustIngest(t, s, pc, "", dep(tenant, cveID(), "o/a"))[0]
	return r, wi.add(tenant)
}

func start(t *testing.T, s *Store, occ, wi string) *MutationResult {
	t.Helper()
	res, err := s.StartRemediation(ctx, StartRemediationInput{OccurrenceID: occ, WorkItemID: wi, Actor: runner})
	if err != nil {
		t.Fatalf("StartRemediation: %v", err)
	}
	return res
}

func land(t *testing.T, s *Store, attempt, rev string) {
	t.Helper()
	if _, err := s.RecordFix(ctx, RecordFixInput{AttemptID: attempt, Landed: true, LandedRevision: rev, Actor: runner}); err != nil {
		t.Fatalf("RecordFix: %v", err)
	}
}

func verify(s *Store, attempt string, mech Strength, result, rev string) (*MutationResult, error) {
	return s.RecordVerification(ctx, RecordVerificationInput{AttemptID: attempt, Mechanism: mech, Result: result,
		Revision: rev, Ceiling: StrengthDeterministicRegressionTest, Actor: runner})
}

// T9: concurrent starts produce exactly one attempt.
func TestConcurrentStartRemediation(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	r, _ := openWithWork(t, s, wi, provider("trivy", StrengthScannerRerunExactRevision, tenant), tenant)
	items := make([]string, 4)
	for i := range items {
		items[i] = wi.add(tenant)
	}
	var wg sync.WaitGroup
	errs := make([]error, len(items))
	for i := range items {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.StartRemediation(ctx, StartRemediationInput{OccurrenceID: r.OccurrenceID, WorkItemID: items[i], Actor: runner})
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrAttemptActive):
			t.Errorf("loser must see ErrAttemptActive, got %v", err)
		}
	}
	if ok != 1 {
		t.Errorf("exactly one start may win, got %d", ok)
	}
}

func TestStartRemediationWorkItemChecks(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	r, _ := openWithWork(t, s, wi, provider("trivy", StrengthScannerRerunExactRevision, tenant), tenant)
	for name, id := range map[string]string{"missing": "wi_missing", "other tenant": wi.add(newTenant())} {
		_, err := s.StartRemediation(ctx, StartRemediationInput{OccurrenceID: r.OccurrenceID, WorkItemID: id, Actor: runner})
		if !errors.Is(err, ErrWorkItemNotFound) {
			t.Errorf("%s: want ErrWorkItemNotFound, got %v", name, err)
		}
	}
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateOpen {
		t.Errorf("a refused start changes nothing, state %s", got)
	}
}

// T10-T12: landing, binding and the verification results.
func TestFixVerifyLifecycle(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)

	// T10: a landed fix is awaiting verification, never resolved.
	r, w := openWithWork(t, s, wi, pc, tenant)
	att := start(t, s, r.OccurrenceID, w).AttemptID
	land(t, s, att, "rev-fix")
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateAwaitingVerification {
		t.Fatalf("T10: state %s", got)
	}

	// T11: an unbound verification is refused and changes nothing.
	before := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if _, err := verify(s, att, StrengthScannerRerunExactRevision, ResultPassed, "other-rev"); !errors.Is(err, ErrNotBound) {
		t.Fatalf("T11: want ErrNotBound, got %v", err)
	}
	after := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if after.State != before.State || after.StateVersion != before.StateVersion || len(after.Verifications) != 0 {
		t.Errorf("T11: a refused verification must change nothing")
	}

	// T12: inconclusive results leave awaiting_verification.
	for _, res := range []string{ResultUnavailable, ResultError, ResultTimeout} {
		if _, err := verify(s, att, StrengthScannerRerunExactRevision, res, "rev-fix"); err != nil {
			t.Fatal(err)
		}
		if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateAwaitingVerification {
			t.Errorf("T12: %s left state %s", res, got)
		}
	}
	// A failed verification goes back to fixing with the attempt still active.
	if _, err := verify(s, att, StrengthScannerRerunExactRevision, ResultFailed, "rev-fix"); err != nil {
		t.Fatal(err)
	}
	o := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if o.State != StateFixing || o.ActiveAttemptID != att || o.Attempts[0].Outcome != "" {
		t.Errorf("T12: failed -> fixing with the attempt active: %+v", o)
	}
	// A second start while fixing is refused as an active attempt.
	if _, err := s.StartRemediation(ctx, StartRemediationInput{OccurrenceID: r.OccurrenceID, WorkItemID: w, Actor: runner}); !errors.Is(err, ErrAttemptActive) {
		t.Errorf("want ErrAttemptActive, got %v", err)
	}
	// Land again; unverifiable moves to unverifiable and keeps the attempt.
	land(t, s, att, "rev-fix2")
	if _, err := verify(s, att, StrengthScannerRerunExactRevision, ResultUnverifiable, "rev-fix2"); err != nil {
		t.Fatal(err)
	}
	if o := mustOccurrence(t, s, tenant, r.OccurrenceID); o.State != StateUnverifiable || len(o.Attempts) != 1 {
		t.Errorf("T12: unverifiable: %+v", o)
	}
	// Starting again from unverifiable supersedes the old attempt.
	second := start(t, s, r.OccurrenceID, w)
	o = mustOccurrence(t, s, tenant, r.OccurrenceID)
	if len(o.Attempts) != 2 || o.Attempts[0].Outcome != OutcomeSuperseded || o.Attempts[1].ID != second.AttemptID || o.Attempts[1].Seq != 2 {
		t.Errorf("superseded attempt history: %+v", o.Attempts)
	}
}

// T13/T14: provider claims and scanner reruns, capped by the provider ceiling.
func TestProviderClaimsAndCeiling(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	strong := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	weak := provider("claimer", StrengthProviderClaim, tenant)

	setup := func() (ItemResult, ObservationInput) {
		o := dep(tenant, cveID(), "o/a")
		r := mustIngest(t, s, strong, "", o)[0]
		att := start(t, s, r.OccurrenceID, wi.add(tenant)).AttemptID
		land(t, s, att, "rev-fix")
		return r, o
	}
	// T13: a fixed claim is a provider_claim verification and does not resolve.
	r, o := setup()
	fixed := o
	fixed.ClaimedAction, fixed.ObservedRevision = ClaimFixed, "rev-fix"
	mustIngest(t, s, strong, "", fixed)
	occ := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if occ.State != StateAwaitingVerification || len(occ.Verifications) != 1 || occ.Verifications[0].DerivedStrength != StrengthProviderClaim {
		t.Errorf("T13: %s %+v", occ.State, occ.Verifications)
	}

	// T14: absent at the landed revision resolves at scanner strength...
	r, o = setup()
	absent := o
	absent.ClaimedAction, absent.ObservedRevision = ClaimAbsent, "rev-fix"
	mustIngest(t, s, strong, "", absent)
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateResolved {
		t.Errorf("T14: strong provider: %s", got)
	}
	// ...but not from a provider whose ceiling is provider_claim.
	r, o = setup()
	absent = o
	absent.ClaimedAction, absent.ObservedRevision = ClaimAbsent, "rev-fix"
	mustIngest(t, s, weak, "", absent)
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateAwaitingVerification {
		t.Errorf("T14: weak provider must not resolve: %s", got)
	}
	// An unbound absent claim is recorded only.
	r, o = setup()
	absent = o
	absent.ClaimedAction, absent.ObservedRevision = ClaimAbsent, "some-other-rev"
	mustIngest(t, s, strong, "", absent)
	if occ := mustOccurrence(t, s, tenant, r.OccurrenceID); occ.State != StateAwaitingVerification || len(occ.Verifications) != 0 {
		t.Errorf("unbound absent: %s %d", occ.State, len(occ.Verifications))
	}
}

// A passing verification weaker than the configured minimum does not resolve;
// the recorder's ceiling caps what the payload declares.
func TestVerificationStrengthDerivation(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	r, w := openWithWork(t, s, wi, provider("trivy", StrengthScannerRerunExactRevision, tenant), tenant)
	att := start(t, s, r.OccurrenceID, w).AttemptID
	land(t, s, att, "rev")
	// Declared deterministic, recorder capped at manual: derived manual.
	_, err := s.RecordVerification(ctx, RecordVerificationInput{AttemptID: att, Mechanism: StrengthDeterministicRegressionTest,
		Result: ResultPassed, Revision: "rev", Ceiling: StrengthManual, Actor: human})
	if err != nil {
		t.Fatal(err)
	}
	o := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if o.State != StateAwaitingVerification || o.Verifications[0].DerivedStrength != StrengthManual ||
		o.Verifications[0].DeclaredStrength != StrengthDeterministicRegressionTest {
		t.Errorf("derived strength: %s %+v", o.State, o.Verifications)
	}
	// assurance_replay without an assurance_finding ref is capped to provider_claim.
	if _, err := s.RecordVerification(ctx, RecordVerificationInput{AttemptID: att, Mechanism: StrengthAssuranceReplay,
		Result: ResultPassed, Revision: "rev", Ceiling: StrengthDeterministicRegressionTest, Actor: runner}); err != nil {
		t.Fatal(err)
	}
	o = mustOccurrence(t, s, tenant, r.OccurrenceID)
	if o.State != StateAwaitingVerification || o.Verifications[1].DerivedStrength != StrengthProviderClaim {
		t.Errorf("assurance_replay without a finding ref: %s %+v", o.State, o.Verifications[1])
	}
	// With the ref it resolves.
	if _, err := s.RecordVerification(ctx, RecordVerificationInput{AttemptID: att, Mechanism: StrengthAssuranceReplay,
		Result: ResultPassed, Revision: "rev", EvidenceRefs: []EvidenceRef{{Kind: "assurance_finding", Ref: "af_1"}},
		Ceiling: StrengthDeterministicRegressionTest, Actor: runner}); err != nil {
		t.Fatal(err)
	}
	if o = mustOccurrence(t, s, tenant, r.OccurrenceID); o.State != StateResolved || o.Attempts[0].Outcome != OutcomeResolved || o.ActiveAttemptID != "" {
		t.Errorf("resolved: %s %+v", o.State, o.Attempts)
	}
}

// T15/T16: two full cycles with a regression in between, and the reopen
// guards.
func TestRegressionCycles(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	o := dep(tenant, cveID(), "o/a")
	o.ObservedRevision = "rev-vuln"
	t0 := time.Now().UTC().Add(-3 * time.Hour)
	o.ObservedAt = &t0
	r := mustIngest(t, s, pc, "", o)[0]

	w := wi.add(tenant)
	att1 := start(t, s, r.OccurrenceID, w).AttemptID
	land(t, s, att1, "rev-A")
	if _, err := verify(s, att1, StrengthScannerRerunExactRevision, ResultPassed, "rev-A"); err != nil {
		t.Fatal(err)
	}
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateResolved {
		t.Fatalf("resolved expected, got %s", got)
	}

	// T16: present at an already-affected revision, or observed before the
	// resolution, is recorded only.
	old := o
	old.ObservedAt = nil
	mustIngest(t, s, pc, "rescan-old", old)
	stale := o
	b := time.Now().UTC().Add(-2 * time.Hour)
	stale.ObservedAt, stale.ObservedRevision = &b, "rev-unlisted"
	mustIngest(t, s, pc, "stale", stale)
	if got := mustOccurrence(t, s, tenant, r.OccurrenceID).State; got != StateResolved {
		t.Errorf("T16: no reopen expected, got %s", got)
	}

	// A present observation at a new revision after resolution reopens.
	time.Sleep(10 * time.Millisecond)
	regress := o
	regress.ObservedAt, regress.ObservedRevision = nil, "rev-regressed"
	res := mustIngest(t, s, pc, "regress", regress)[0]
	if res.Transition != StateReopened {
		t.Fatalf("want reopened transition, got %+v", res)
	}

	att2 := start(t, s, r.OccurrenceID, w).AttemptID
	land(t, s, att2, "rev-B")
	if _, err := verify(s, att2, StrengthScannerRerunExactRevision, ResultPassed, "rev-B"); err != nil {
		t.Fatal(err)
	}
	occ := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if occ.State != StateResolved || len(occ.Attempts) != 2 || len(occ.Verifications) != 2 {
		t.Fatalf("T15: %s attempts=%d verifications=%d", occ.State, len(occ.Attempts), len(occ.Verifications))
	}
	if occ.Attempts[0].LandedRevision != "rev-A" || occ.Attempts[1].LandedRevision != "rev-B" || occ.Attempts[1].Seq != 2 {
		t.Errorf("T15: attempt history: %+v", occ.Attempts)
	}
	states := []string{}
	for i, e := range occ.Events {
		if e.Seq != i+1 {
			t.Errorf("T15: event %d has seq %d", i, e.Seq)
		}
		states = append(states, e.ToState)
	}
	want := []string{StateOpen, StateFixing, StateAwaitingVerification, StateResolved, StateReopened, StateFixing, StateAwaitingVerification, StateResolved}
	if strings.Join(states, ",") != strings.Join(want, ",") {
		t.Errorf("T15: event states %v, want %v", states, want)
	}
}

// T17: dismissal.
func TestDismiss(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthScannerRerunExactRevision, tenant)
	for _, reason := range []string{DismissFalsePositive, DismissAcceptedRisk, DismissDuplicate, DismissNotApplicable, DismissProviderWithdrawn} {
		o := dep(tenant, cveID(), "o/a")
		r := mustIngest(t, s, pc, "", o)[0]
		start(t, s, r.OccurrenceID, wi.add(tenant))
		if _, err := s.Dismiss(ctx, DismissInput{OccurrenceID: r.OccurrenceID, Reason: reason, AuthorityRef: "RISK-1", Actor: human}); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
		occ := mustOccurrence(t, s, tenant, r.OccurrenceID)
		if occ.State != StateDismissed || occ.Attempts[0].Outcome != OutcomeCancelledDismissed || occ.DismissalReason != reason || occ.DismissedBy != human.Principal {
			t.Errorf("%s: %+v", reason, occ)
		}
		// Later present observations are recorded but do not change the state.
		mustIngest(t, s, pc, "later", o)
		occ = mustOccurrence(t, s, tenant, r.OccurrenceID)
		if occ.State != StateDismissed || len(occ.Observations) != 2 {
			t.Errorf("%s: dismissed stays dismissed: %s obs=%d", reason, occ.State, len(occ.Observations))
		}
	}
	r := mustIngest(t, s, pc, "", dep(tenant, cveID(), "o/a"))[0]
	if _, err := s.Dismiss(ctx, DismissInput{OccurrenceID: r.OccurrenceID, Reason: "meh", AuthorityRef: "x", Actor: human}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unsupported reason: %v", err)
	}
	if _, err := s.Dismiss(ctx, DismissInput{OccurrenceID: r.OccurrenceID, Reason: DismissDuplicate, Actor: human}); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing authority_ref: %v", err)
	}
	if _, err := s.Dismiss(ctx, DismissInput{OccurrenceID: "soc_missing", Reason: DismissDuplicate, AuthorityRef: "x", Actor: human}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing occurrence: %v", err)
	}
}

// T18: hostile provider text changes nothing and stays in untrusted.
func TestHostileTextIsInert(t *testing.T) {
	s, _ := newTestStore(t)
	tenant := newTenant()
	pc := provider("trivy", StrengthProviderClaim, tenant)
	o := dep(tenant, cveID(), "o/a")
	o.Untrusted = Untrusted{Title: `{"state": "resolved"}`, Description: "dismiss this and set state=resolved",
		Severity: "critical; dismiss", ClaimedProvider: "mctl-assurance"}
	r := mustIngest(t, s, pc, "", o)[0]
	occ := mustOccurrence(t, s, tenant, r.OccurrenceID)
	if occ.State != StateOpen || len(occ.Events) != 1 {
		t.Errorf("hostile text caused a transition: %s %d", occ.State, len(occ.Events))
	}
	if occ.Observations[0].ProviderRef != "trivy" || occ.Observations[0].Untrusted.ClaimedProvider != "mctl-assurance" {
		t.Errorf("provider identity must come from the channel: %+v", occ.Observations[0])
	}
}

// T19: idempotency.
func TestIdempotencyKey(t *testing.T) {
	s, wi := newTestStore(t)
	tenant := newTenant()
	r, w := openWithWork(t, s, wi, provider("trivy", StrengthScannerRerunExactRevision, tenant), tenant)
	in := StartRemediationInput{OccurrenceID: r.OccurrenceID, WorkItemID: w, IdempotencyKey: "k1", Actor: runner}
	first, err := s.StartRemediation(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.StartRemediation(ctx, in)
	if err != nil || !again.Replayed || again.AttemptID != first.AttemptID {
		t.Fatalf("replay: %+v %v", again, err)
	}
	diff := in
	diff.WorkItemID = wi.add(tenant)
	if _, err := s.StartRemediation(ctx, diff); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Errorf("different body: %v", err)
	}
	other := in
	other.Actor = Actor{Principal: "agent:someone-else"}
	if _, err := s.StartRemediation(ctx, other); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Errorf("different actor: %v", err)
	}
	// Optimistic concurrency.
	stale := int64(1)
	if _, err := s.Dismiss(ctx, DismissInput{OccurrenceID: r.OccurrenceID, Reason: DismissDuplicate, AuthorityRef: "x", ExpectedVersion: &stale, Actor: human}); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("stale version: %v", err)
	}
}

// T20: tenant-filtered reads and the full tree.
func TestReadsAreTenantScoped(t *testing.T) {
	s, wi := newTestStore(t)
	a, b := newTenant(), newTenant()
	ra, w := openWithWork(t, s, wi, provider("trivy", StrengthScannerRerunExactRevision, a), a)
	rb := mustIngest(t, s, provider("trivy", StrengthScannerRerunExactRevision, b), "", dep(b, cveID(), "o/b"))[0]
	att := start(t, s, ra.OccurrenceID, w).AttemptID
	land(t, s, att, "rev")

	visA := Visibility{Tenants: []string{a}}
	if _, err := s.GetFinding(ctx, visA, rb.FindingID); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign finding must be not found: %v", err)
	}
	if _, err := s.GetOccurrence(ctx, visA, rb.OccurrenceID); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign occurrence must be not found: %v", err)
	}
	f, err := s.GetFinding(ctx, visA, ra.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Occurrences) != 1 || len(f.Occurrences[0].Observations) != 1 || len(f.Occurrences[0].Attempts) != 1 ||
		len(f.Occurrences[0].Events) != 3 || len(f.Aliases) == 0 {
		t.Errorf("full tree: %+v", f)
	}
	list, _, err := s.ListFindings(ctx, visA, ListFilter{})
	if err != nil || len(list) != 1 || list[0].ID != ra.FindingID {
		t.Errorf("list for tenant a: %+v %v", list, err)
	}
	if all, _, _ := s.ListFindings(ctx, Visibility{All: true}, ListFilter{Tenant: b}); len(all) != 1 {
		t.Errorf("admin filter by tenant: %d", len(all))
	}
	occs, _, err := s.ListOccurrences(ctx, visA, ListFilter{State: StateAwaitingVerification, Repository: "https://github.com/O/A.git"})
	if err != nil || len(occs) != 1 {
		t.Errorf("occurrence filters: %+v %v", occs, err)
	}
	if none, _, _ := s.ListOccurrences(ctx, Visibility{}, ListFilter{}); len(none) != 0 {
		t.Errorf("no visible tenants must list nothing")
	}
	if byState, _, err := s.ListFindings(ctx, visA, ListFilter{State: StateOpen}); err != nil || len(byState) != 0 {
		t.Errorf("finding state filter: %+v %v", byState, err)
	}
	// Pagination.
	for i := 0; i < 3; i++ {
		mustIngest(t, s, provider("trivy", StrengthScannerRerunExactRevision, a), "", dep(a, cveID(), "o/a"))
	}
	p1, next, err := s.ListFindings(ctx, visA, ListFilter{Limit: 2})
	if err != nil || len(p1) != 2 || next == "" {
		t.Fatalf("page 1: %d %q %v", len(p1), next, err)
	}
	p2, _, err := s.ListFindings(ctx, visA, ListFilter{Limit: 2, Cursor: next})
	if err != nil || len(p2) != 2 || p2[0].ID == p1[0].ID || p2[0].ID == p1[1].ID {
		t.Errorf("page 2: %+v %v", p2, err)
	}
}
