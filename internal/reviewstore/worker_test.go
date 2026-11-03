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

package reviewstore

// Worker receipt ingestion (mctl-api#917), tests T1 and T5-T14 of the
// proposal against SubmitWorker with a fake provenance lookup. Every refusal
// asserts the typed error AND that nothing was written to review_receipts or
// review_nonce_consumptions for that request.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/executionprovenance"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const reviewerActor = "agent:review-worker"

// workerAuthor is the authoring execution every worker request in this file
// names; newTestStore's fixture holds its provenance.
var workerAuthor = "we_" + strings.Repeat("a", 16)

// reviewerExec returns a distinct, well-formed work-item execution id.
func reviewerExec() string {
	return "we_" + uuid.NewString()
}

// workerEnv is a store plus the fake provenance it reads, so a test can add
// reviewer executions.
type workerEnv struct {
	t  *testing.T
	s  *Store
	fp *fakeProvenance
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	s, _ := newTestStore(t, Config{PoolMax: 1 << 30})
	fp, _, _ := provFixtureFor(workerAuthor)
	s.SetProvenance(fp)
	return &workerEnv{t: t, s: s, fp: fp}
}

// addReviewer records provenance for a reviewer execution: its own attempt
// and lineage, attached by the platform acting directly unless direct is
// false.
func (e *workerEnv) addReviewer(direct bool, path string) string {
	id := reviewerExec()
	e.fp.recs[id] = &workitems.Provenance{
		ExecutionID: id, AttemptID: executionprovenance.AttemptID("temporal", "run-"+id),
		LineageRoot: executionprovenance.LineageRoot(id), AttachPath: path, AttachedDirectService: direct,
	}
	return id
}

// ingestWorker seals and ingests a worker request for subj and returns it.
// Its rows are removed at cleanup so that tests asserting an empty nonce
// table elsewhere in the package keep holding.
func (e *workerEnv) ingestWorker(subj reviewreceipts.ReviewSubject, authors ...string) reviewreceipts.ReviewRequest {
	e.t.Helper()
	req, err := reviewreceipts.SealRequest(reviewreceipts.SealRequestInput{
		Subject: subj, Mode: reviewreceipts.ModeWorker, Nonce: "nonce-" + uuid.NewString(),
		AuthorActors:         authors,
		AuthoringExecutionID: workerAuthor, CreatedAt: "2026-01-01T00:00:00Z",
		AuthoringAttemptIDs:  []string{executionprovenance.AttemptID("argo", "wf-author")},
		AuthoringLineageRoot: executionprovenance.LineageRoot(workerAuthor),
	})
	if err != nil {
		e.t.Fatalf("SealRequest: %v", err)
	}
	raw, err := json.Marshal(req.Dict())
	if err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.s.IngestRequest(context.Background(), raw, Actor{Name: "svc"}); err != nil {
		e.t.Fatalf("IngestRequest: %v", err)
	}
	e.cleanupRequest(req.RequestID)
	return req
}

func (e *workerEnv) cleanupRequest(id string) {
	e.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = e.s.pool.Exec(ctx, `DELETE FROM review_nonce_consumptions WHERE request_id = $1`, id)
		_, _ = e.s.pool.Exec(ctx, `DELETE FROM review_receipts WHERE request_id = $1`, id)
	})
}

// rows counts what is stored for one request in both tables.
func (e *workerEnv) rows(requestID string) (receipts, consumptions int) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.s.pool.QueryRow(ctx, `SELECT count(*) FROM review_receipts WHERE request_id = $1`, requestID).Scan(&receipts); err != nil {
		e.t.Fatal(err)
	}
	if err := e.s.pool.QueryRow(ctx, `SELECT count(*) FROM review_nonce_consumptions WHERE request_id = $1`, requestID).Scan(&consumptions); err != nil {
		e.t.Fatal(err)
	}
	return receipts, consumptions
}

// assertNothingStored is the "zero rows" half of every refusal.
func (e *workerEnv) assertNothingStored(requestID string) {
	e.t.Helper()
	if r, c := e.rows(requestID); r != 0 || c != 0 {
		e.t.Fatalf("refusal wrote %d receipt(s) and %d nonce consumption(s), want none", r, c)
	}
}

func workerInput(req reviewreceipts.ReviewRequest) WorkerInput {
	return WorkerInput{RequestID: req.RequestID, Subject: req.Subject, Nonce: req.Nonce, Outcome: "PASS", Criteria: allMet()}
}

func reviewer(exec string) Reviewer {
	return Reviewer{Actor: Actor{Name: reviewerActor, PrincipalID: "prn_reviewer"}, ExecutionID: exec, RunID: "art_review"}
}

// typedRefusals are every typed error SubmitWorker may return. A driver
// failure must be none of them.
var typedRefusals = []error{
	ErrRunTokenUnbound, ErrRequestNotFound, ErrRequestClosed, ErrRequestModeManual, ErrBindingMismatch,
	ErrNonceMismatch, ErrExecutionUnproven, ErrProvenanceUnavailable, ErrReviewerIneligible,
	ErrReviewerNotIndependent, ErrNonceConsumed,
}

func isTypedRefusal(err error) bool {
	for _, target := range typedRefusals {
		if errors.Is(err, target) {
			return true
		}
	}
	var docErr *reviewreceipts.Error
	return errors.As(err, &docErr)
}

func uniqueSubject(prefix, digestChar string) reviewreceipts.ReviewSubject {
	return proposal(prefix+"-"+uuid.NewString()[:8], digestChar)
}

// T1: an eligible, independent reviewer run stores exactly one receipt and
// one consumption; the receipt's reviewer facts are the token execution's
// recorded provenance, and the gate under required_assurance=independent
// answers satisfied for the PASS.
func TestSubmitWorker_HappyPathSatisfiesTheIndependentGate(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	subj := uniqueSubject("w1", "1")
	req := e.ingestWorker(subj)
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)

	rc, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now())
	if err != nil {
		t.Fatalf("SubmitWorker: %v", err)
	}
	p := e.fp.recs[rev]
	got := rc.Receipt
	if got.Mode != reviewreceipts.ModeWorker || got.Assurance != reviewreceipts.AssuranceIndependent ||
		got.ReviewerActor != reviewerActor || got.ReviewerExecutionID != rev ||
		got.AttemptID != p.AttemptID || got.LineageRoot != p.LineageRoot ||
		got.RequestID != req.RequestID || got.Nonce != req.Nonce || rc.Tenant != "acme" {
		t.Fatalf("receipt = %+v (tenant %q), want worker/independent with the token execution's facts", got, rc.Tenant)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("stored %d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
	var digest, receiptID, mode, assurance, submittedBy string
	if err := e.s.pool.QueryRow(ctx, `SELECT c.nonce_sha256, c.receipt_id, r.mode, r.assurance, r.submitted_by
FROM review_nonce_consumptions c JOIN review_receipts r ON r.receipt_id = c.receipt_id
WHERE c.request_id = $1`, req.RequestID).Scan(&digest, &receiptID, &mode, &assurance, &submittedBy); err != nil {
		t.Fatal(err)
	}
	if digest != nonceDigest(req.Nonce) || receiptID != got.ReceiptID || mode != "worker" || assurance != "independent" || submittedBy != reviewerActor {
		t.Fatalf("rows = %s %s %s %s %s", digest, receiptID, mode, assurance, submittedBy)
	}

	sr, pool, err := e.s.GateInput(ctx, subj)
	if err != nil || sr == nil {
		t.Fatalf("GateInput: %v %v", sr, err)
	}
	verdict, err := reviewreceipts.EvaluateReviewGate(&subj, &sr.Request, pool, reviewreceipts.AssuranceIndependent)
	if err != nil || verdict != reviewreceipts.GateSatisfied {
		t.Fatalf("gate under independent = %s %v, want %s", verdict, err, reviewreceipts.GateSatisfied)
	}
}

// The token's execution id must be a well-formed work-item execution id
// (the `we_` prefix and the Tier B executionIDRE) before anything is read.
func TestSubmitWorker_MalformedTokenExecutionIsUnbound(t *testing.T) {
	e := newWorkerEnv(t)
	req := e.ingestWorker(uniqueSubject("wid", "2"))
	for _, id := range []string{"", "ex-0123456789abcdef", "we_NOTHEX", "we_x", "we_" + strings.Repeat("A", 16), "we_" + strings.Repeat("a", 65)} {
		// Give the malformed id an otherwise eligible record, so only the
		// shape check can refuse it.
		e.fp.recs[id] = &workitems.Provenance{ExecutionID: id, AttemptID: executionprovenance.AttemptID("temporal", "r-"+id),
			LineageRoot: executionprovenance.LineageRoot("we_" + strings.Repeat("c", 16)), AttachedDirectService: true}
		if _, err := e.s.SubmitWorker(context.Background(), workerInput(req), reviewer(id), time.Now()); !errors.Is(err, ErrRunTokenUnbound) {
			t.Errorf("execution %q: %v, want ErrRunTokenUnbound", id, err)
		}
	}
	e.assertNothingStored(req.RequestID)
}

// T5: the reviewer is the token's execution, never another eligible one.
// With A eligible the receipt names A's facts; with A ineligible the submit
// is refused even though B, eligible, exists.
func TestSubmitWorker_UsesOnlyTheTokenExecution(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	b := e.addReviewer(true, workitems.AttachPathFulfilStart)

	reqA := e.ingestWorker(uniqueSubject("w5a", "3"))
	a := e.addReviewer(true, workitems.AttachPathFulfilStart)
	rc, err := e.s.SubmitWorker(ctx, workerInput(reqA), reviewer(a), time.Now())
	if err != nil {
		t.Fatalf("SubmitWorker(A): %v", err)
	}
	pa, pb := e.fp.recs[a], e.fp.recs[b]
	if rc.Receipt.ReviewerExecutionID != a || rc.Receipt.AttemptID != pa.AttemptID || rc.Receipt.LineageRoot != pa.LineageRoot {
		t.Fatalf("receipt = %+v, want A's facts", rc.Receipt)
	}
	if rc.Receipt.ReviewerExecutionID == b || rc.Receipt.AttemptID == pb.AttemptID || rc.Receipt.LineageRoot == pb.LineageRoot {
		t.Fatalf("receipt carries B's facts: %+v", rc.Receipt)
	}

	reqB := e.ingestWorker(uniqueSubject("w5b", "4"))
	ineligibleA := e.addReviewer(false, workitems.AttachPathAttach)
	if _, err := e.s.SubmitWorker(ctx, workerInput(reqB), reviewer(ineligibleA), time.Now()); !errors.Is(err, ErrReviewerIneligible) {
		t.Fatalf("ineligible A with eligible B present: %v, want ErrReviewerIneligible", err)
	}
	e.assertNothingStored(reqB.RequestID)
}

// T6: a second valid submit for the same request is 409 nonce consumed, by
// the same reviewer or by another eligible one, and nothing new is stored.
func TestSubmitWorker_NonceReplayIsConsumed(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	req := e.ingestWorker(uniqueSubject("w6", "5"))
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)
	if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now()); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now().Add(time.Second)); !errors.Is(err, ErrNonceConsumed) {
		t.Fatalf("replay: %v, want ErrNonceConsumed", err)
	}
	other := e.addReviewer(true, workitems.AttachPathFulfilResume)
	in := workerInput(req)
	in.Outcome = "CHANGES_REQUESTED"
	in.Criteria[0].Status = "unmet"
	if _, err := e.s.SubmitWorker(ctx, in, reviewer(other), time.Now()); !errors.Is(err, ErrNonceConsumed) {
		t.Fatalf("second reviewer: %v, want ErrNonceConsumed", err)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("after replays: %d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
}

// T7: N concurrent valid submits by N distinct eligible reviewers (so their
// receipt ids differ and only the nonce can serialise them) produce exactly
// one success, N-1 nonce-consumed refusals and one consumption row.
func TestSubmitWorker_NonceRaceHasOneWinner(t *testing.T) {
	e := newWorkerEnv(t)
	req := e.ingestWorker(uniqueSubject("w7", "6"))
	const n = 8
	revs := make([]string, n)
	for i := range revs {
		revs[i] = e.addReviewer(true, workitems.AttachPathFulfilStart)
	}
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = e.s.SubmitWorker(context.Background(), workerInput(req), reviewer(revs[i]), time.Now())
		}(i)
	}
	close(start)
	wg.Wait()
	ok, consumed := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrNonceConsumed):
			consumed++
		default:
			t.Errorf("submit %d: unexpected %v", i, err)
		}
	}
	if ok != 1 || consumed != n-1 {
		t.Fatalf("%d success(es), %d consumed; want 1 and %d", ok, consumed, n-1)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("after the race: %d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
}

// T8: a nonce that is not the request's is refused before anything is read
// or written.
func TestSubmitWorker_NonceMismatch(t *testing.T) {
	e := newWorkerEnv(t)
	req := e.ingestWorker(uniqueSubject("w8", "7"))
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)
	for _, nonce := range []string{"", "nonce-wrong", req.Nonce + " ", strings.ToUpper(req.Nonce)} {
		in := workerInput(req)
		in.Nonce = nonce
		if _, err := e.s.SubmitWorker(context.Background(), in, reviewer(rev), time.Now()); !errors.Is(err, ErrNonceMismatch) {
			t.Errorf("nonce %q: %v, want ErrNonceMismatch", nonce, err)
		}
	}
	e.assertNothingStored(req.RequestID)
}

// T9: the receipt INSERT fails after the consumption INSERT (a receipt_id
// collision seeded by direct SQL): the consumption is rolled back with it and
// the error is a store failure, none of the typed refusals.
func TestSubmitWorker_ReceiptFailureRollsBackTheConsumption(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	req := e.ingestWorker(uniqueSubject("w9", "8"))
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)
	p := e.fp.recs[rev]
	// The receipt id is a digest of the content, not of the time: seal the
	// same receipt SubmitWorker will, and store it under another request so
	// this request's own rows stay countable.
	rc, err := reviewreceipts.SealReceipt(req, reviewreceipts.SealReceiptInput{
		Outcome: "PASS", Criteria: allMet(), ReviewerActor: reviewerActor,
		ReviewerExecutionID: rev, AttemptID: p.AttemptID, LineageRoot: p.LineageRoot,
		CreatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := marshalDict(rc.Dict())
	if err != nil {
		t.Fatal(err)
	}
	host := e.ingestWorker(uniqueSubject("w9host", "9"))
	if _, err := e.s.pool.Exec(ctx, `INSERT INTO review_receipts (receipt_id, request_id, content_hash, document, mode, assurance, tenant, submitted_by, submitted_at)
VALUES ($1, $2, $3, $4, 'worker', 'independent', 'acme', 'seed', now())`, rc.ReceiptID, host.RequestID, rc.ContentHash, doc); err != nil {
		t.Fatalf("seed colliding receipt: %v", err)
	}
	t.Cleanup(func() {
		_, _ = e.s.pool.Exec(context.Background(), `DELETE FROM review_receipts WHERE receipt_id = $1`, rc.ReceiptID)
	})

	_, err = e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now())
	if err == nil || isTypedRefusal(err) {
		t.Fatalf("SubmitWorker with a colliding receipt: %v, want an untyped store failure", err)
	}
	e.assertNothingStored(req.RequestID)
	// The nonce is not burnt: once the collision is gone the reviewer can
	// still answer.
	if _, err := e.s.pool.Exec(ctx, `DELETE FROM review_receipts WHERE receipt_id = $1`, rc.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now()); err != nil {
		t.Fatalf("submit after the collision is gone: %v", err)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("%d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
}

// T10 (fake provenance): every execution not attached by the platform
// acting directly is ineligible, whatever its path, and a legacy-shaped
// record ("" / false) is too.
func TestSubmitWorker_IneligibleAttachers(t *testing.T) {
	e := newWorkerEnv(t)
	req := e.ingestWorker(uniqueSubject("w10", "a"))
	for _, path := range []string{workitems.AttachPathAttach, workitems.AttachPathResume,
		workitems.AttachPathFulfilStart, workitems.AttachPathFulfilResume, ""} {
		rev := e.addReviewer(false, path)
		if _, err := e.s.SubmitWorker(context.Background(), workerInput(req), reviewer(rev), time.Now()); !errors.Is(err, ErrReviewerIneligible) {
			t.Errorf("path %q, not direct service: %v, want ErrReviewerIneligible", path, err)
		}
	}
	e.assertNothingStored(req.RequestID)
}

// T11: each of the four independence facts refuses on its own; the reviewer
// is otherwise eligible.
func TestSubmitWorker_NotIndependent(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	authorAttempt := executionprovenance.AttemptID("argo", "wf-author")
	authorLineage := executionprovenance.LineageRoot(workerAuthor)

	sameAttempt := reviewerExec()
	e.fp.recs[sameAttempt] = &workitems.Provenance{ExecutionID: sameAttempt, AttemptID: authorAttempt,
		LineageRoot: executionprovenance.LineageRoot(sameAttempt), AttachedDirectService: true}
	sameLineage := reviewerExec() // resumed from the author
	e.fp.recs[sameLineage] = &workitems.Provenance{ExecutionID: sameLineage,
		AttemptID: executionprovenance.AttemptID("temporal", "run-resumed"), LineageRoot: authorLineage,
		ParentExecutionID: workerAuthor, RootExecutionID: workerAuthor, AttachedDirectService: true}

	for _, c := range []struct {
		name    string
		exec    func() string
		authors []string
		actor   string
	}{
		{"reviewer is the authoring execution", func() string {
			// The author's own record, made eligible, so only independence
			// can refuse it.
			p := *e.fp.recs[workerAuthor]
			p.AttachedDirectService = true
			e.fp.recs[workerAuthor] = &p
			return workerAuthor
		}, nil, reviewerActor},
		{"reviewer attempt is an authoring attempt", func() string { return sameAttempt }, nil, reviewerActor},
		{"reviewer lineage is the authoring lineage", func() string { return sameLineage }, nil, reviewerActor},
		{"reviewer actor is an author", func() string { return e.addReviewer(true, workitems.AttachPathFulfilStart) },
			[]string{"agent:implementer", reviewerActor}, reviewerActor},
		{"reviewer actor is an author, case-insensitively", func() string { return e.addReviewer(true, workitems.AttachPathFulfilStart) },
			[]string{"Agent:Review-Worker"}, reviewerActor},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := e.ingestWorker(uniqueSubject("w11", "b"), c.authors...)
			rv := reviewer(c.exec())
			rv.Actor.Name = c.actor
			if _, err := e.s.SubmitWorker(ctx, workerInput(req), rv, time.Now()); !errors.Is(err, ErrReviewerNotIndependent) {
				t.Fatalf("%v, want ErrReviewerNotIndependent", err)
			}
			e.assertNothingStored(req.RequestID)
		})
	}
}

// failNonceInsertFor makes the nonce consumption INSERT of one request fail
// in the database, so the store's own error path is exercised. The trigger
// fires only for that request.
func (e *workerEnv) failNonceInsertFor(requestID string) {
	e.t.Helper()
	ctx := context.Background()
	name := "t917_" + strings.TrimPrefix(requestID, "rr_")
	for _, q := range []string{
		`CREATE OR REPLACE FUNCTION ` + name + `() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected evidence DB failure'; END; $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON review_nonce_consumptions FOR EACH ROW WHEN (NEW.request_id = '` + requestID + `') EXECUTE FUNCTION ` + name + `()`,
	} {
		if _, err := e.s.pool.Exec(ctx, q); err != nil {
			e.t.Fatal(err)
		}
	}
	e.t.Cleanup(func() {
		_, _ = e.s.pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+name+` ON review_nonce_consumptions`)
		_, _ = e.s.pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+name+`()`)
	})
}

// T12: fail closed. A provenance read error and an unwired provenance store
// are ErrProvenanceUnavailable (never absent, never ineligible), a database
// error on the nonce insert is an untyped store failure, and an execution
// with no record is ErrExecutionUnproven. Nothing is stored in any case.
func TestSubmitWorker_FailsClosed(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)

	req := e.ingestWorker(uniqueSubject("w12", "c"))
	e.s.SetProvenance(&fakeProvenance{readErr: errors.New("db down")})
	_, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now())
	if !errors.Is(err, ErrProvenanceUnavailable) || errors.Is(err, workitems.ErrProvenanceAbsent) || errors.Is(err, ErrExecutionUnproven) {
		t.Fatalf("lookup error: %v, want ErrProvenanceUnavailable only", err)
	}
	e.s.SetProvenance(nil)
	if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("provenance not wired: %v, want ErrProvenanceUnavailable", err)
	}
	e.s.SetProvenance(e.fp)
	if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(reviewerExec()), time.Now()); !errors.Is(err, ErrExecutionUnproven) {
		t.Fatalf("absent provenance: %v, want ErrExecutionUnproven", err)
	}
	e.failNonceInsertFor(req.RequestID)
	_, err = e.s.SubmitWorker(ctx, workerInput(req), reviewer(rev), time.Now())
	if err == nil || isTypedRefusal(err) {
		t.Fatalf("nonce insert failure: %v, want an untyped store failure", err)
	}
	e.assertNothingStored(req.RequestID)
}

// T13: request state. Unknown, closed by ttl, closed by supersession, a
// manual-mode request and a binding mismatch are each refused.
func TestSubmitWorker_RequestState(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	rev := e.addReviewer(true, workitems.AttachPathFulfilStart)

	if _, err := e.s.SubmitWorker(ctx, WorkerInput{RequestID: "rr_0000000000000000", Subject: proposal("none", "d")}, reviewer(rev), time.Now()); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("unknown request: %v, want ErrRequestNotFound", err)
	}

	// Superseded: a newer request for the same identity with another binding.
	slug := "w13-" + uuid.NewString()[:8]
	old := e.ingestWorker(proposal(slug, "d"))
	e.ingestWorker(proposal(slug, "e"))
	if _, err := e.s.SubmitWorker(ctx, workerInput(old), reviewer(rev), time.Now()); !errors.Is(err, ErrRequestClosed) {
		t.Fatalf("superseded: %v, want ErrRequestClosed", err)
	}
	e.assertNothingStored(old.RequestID)

	// Binding mismatch: another content digest.
	open := e.ingestWorker(uniqueSubject("w13b", "f"))
	in := workerInput(open)
	in.Subject.ContentDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := e.s.SubmitWorker(ctx, in, reviewer(rev), time.Now()); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("binding mismatch: %v, want ErrBindingMismatch", err)
	}
	e.assertNothingStored(open.RequestID)

	// Manual-mode request.
	manual, raw := sealed(t, uniqueSubject("w13m", "1"), reviewreceipts.ModeManual)
	if _, _, err := e.s.IngestRequest(ctx, raw, Actor{Name: "svc"}); err != nil {
		t.Fatal(err)
	}
	e.cleanupRequest(manual.RequestID)
	if _, err := e.s.SubmitWorker(ctx, workerInput(manual), reviewer(rev), time.Now()); !errors.Is(err, ErrRequestModeManual) {
		t.Fatalf("manual-mode request: %v, want ErrRequestModeManual", err)
	}
	e.assertNothingStored(manual.RequestID)

	// TTL: the open request, read a day and more later.
	e.s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := e.s.SubmitWorker(ctx, workerInput(open), reviewer(rev), time.Now()); !errors.Is(err, ErrRequestClosed) {
		t.Fatalf("ttl: %v, want ErrRequestClosed", err)
	}
	e.assertNothingStored(open.RequestID)
}

// T14: the manual path never writes review_nonce_consumptions, checked per
// request so it holds beside the worker tests' rows.
func TestSubmitManual_NeverConsumesTheNonce(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	subj := uniqueSubject("w14", "2")
	req, raw := sealed(t, subj, reviewreceipts.ModeManual)
	if _, _, err := e.s.IngestRequest(ctx, raw, Actor{Name: "svc"}); err != nil {
		t.Fatal(err)
	}
	e.cleanupRequest(req.RequestID)
	for i := 0; i < 2; i++ {
		in := ManualInput{RequestID: req.RequestID, Subject: subj, Outcome: "PASS", Criteria: allMet(),
			FindingsRef: reviewreceipts.ArtifactRef{Name: fmt.Sprintf("n-%d", i), Kind: "text", ContentHash: "sha256:" + strings.Repeat(fmt.Sprint(i), 64)}}
		if _, err := e.s.SubmitManual(ctx, in, Actor{Name: "github:alice"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if r, c := e.rows(req.RequestID); r != 2 || c != 0 {
		t.Fatalf("manual: %d receipt(s), %d consumption(s); want 2 and 0", r, c)
	}
}

// The schema's worker CHECK: a worker row can never be advisory, and
// applying the schema again over existing rows succeeds.
func TestWorkerIndependentCheckAndIdempotentSchema(t *testing.T) {
	e := newWorkerEnv(t)
	ctx := context.Background()
	req := e.ingestWorker(uniqueSubject("wck", "3"))
	if _, err := e.s.pool.Exec(ctx, `INSERT INTO review_receipts (receipt_id, request_id, content_hash, document, mode, assurance, tenant, submitted_by, submitted_at)
VALUES ('rc_ffffffffffff0917', $1, 'h', '\x00', 'worker', 'advisory', 'acme', 'x', now())`, req.RequestID); err == nil {
		_, _ = e.s.pool.Exec(ctx, `DELETE FROM review_receipts WHERE receipt_id = 'rc_ffffffffffff0917'`)
		t.Fatal("worker/advisory must violate review_receipts_worker_independent")
	}
	for i := 0; i < 2; i++ {
		if _, err := e.s.pool.Exec(ctx, schema); err != nil {
			t.Fatalf("schema apply %d: %v", i+1, err)
		}
	}
}
