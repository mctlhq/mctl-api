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

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
)

type fakeEvidence struct {
	tenant string
	none   bool
	err    error
}

func (f *fakeEvidence) List(_ context.Context, _ evidence.Filter) (*evidence.ListResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.none {
		return &evidence.ListResult{}, nil
	}
	return &evidence.ListResult{Evidence: []*evidence.Evidence{{Ref: &evidence.EvidenceRef{Tenant: f.tenant}}}}, nil
}

func newTestStore(t *testing.T, cfg Config) (*Store, *fakeEvidence) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed review store test")
	}
	s, err := NewStore(context.Background(), connStr, cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	ev := &fakeEvidence{tenant: "acme"}
	s.SetEvidence(ev)
	return s, ev
}

func proposal(slug, digestChar string) reviewreceipts.ReviewSubject {
	return reviewreceipts.ReviewSubject{
		Kind: reviewreceipts.SubjectProposal, Service: "mctl-api", Slug: slug,
		GitopsCommit:  strings.Repeat("a", 40),
		ContentDigest: "sha256:" + strings.Repeat(digestChar, 64),
	}
}

func sealed(t *testing.T, subj reviewreceipts.ReviewSubject, mode string) (reviewreceipts.ReviewRequest, []byte) {
	t.Helper()
	req, err := reviewreceipts.SealRequest(reviewreceipts.SealRequestInput{
		Subject: subj, Mode: mode, Nonce: "nonce-" + uuid.NewString(),
		AuthoringExecutionID: "we_" + strings.Repeat("a", 16), CreatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	raw, err := json.Marshal(req.Dict())
	if err != nil {
		t.Fatal(err)
	}
	return req, raw
}

func allMet() []reviewreceipts.Criterion {
	var out []reviewreceipts.Criterion
	for _, id := range []string{"scope_bounded", "contracts_specified", "acceptance_testable", "rollback_defined", "matches_issue"} {
		out = append(out, reviewreceipts.Criterion{ID: id, Status: "met"})
	}
	return out
}

func TestIngestReplayConflictAndErrors(t *testing.T) {
	s, ev := newTestStore(t, Config{})
	ctx := context.Background()
	slug := "s-" + uuid.NewString()[:8]
	req, raw := sealed(t, proposal(slug, "b"), reviewreceipts.ModeManual)

	got, replayed, err := s.IngestRequest(ctx, raw, Actor{Name: "svc"})
	if err != nil || replayed {
		t.Fatalf("first ingest: replayed=%v err=%v", replayed, err)
	}
	if got.Tenant != "acme" || !bytes.Equal(got.Document, raw) {
		t.Fatalf("tenant/document not preserved: %+v", got)
	}
	if _, replayed, err = s.IngestRequest(ctx, raw, Actor{Name: "svc"}); err != nil || !replayed {
		t.Fatalf("replay: replayed=%v err=%v", replayed, err)
	}
	// Same request id, different bytes.
	if _, _, err = s.IngestRequest(ctx, append([]byte(" "), raw...), Actor{}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("want ErrIdempotencyConflict, got %v", err)
	}
	// Same nonce, different request.
	dup, derr := reviewreceipts.SealRequest(reviewreceipts.SealRequestInput{
		Subject: proposal(slug+"n", "a"), Mode: reviewreceipts.ModeManual, Nonce: req.Nonce,
		AuthoringExecutionID: req.AuthoringExecutionID, CreatedAt: "2026-01-02T00:00:00Z",
	})
	if derr != nil {
		t.Fatal(derr)
	}
	rawDup, _ := json.Marshal(dup.Dict())
	if _, _, err = s.IngestRequest(ctx, rawDup, Actor{}); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("want ErrNonceReused, got %v", err)
	}
	// An unsealed document is refused.
	unsealed := req.Dict()
	delete(unsealed, "request_id")
	delete(unsealed, "content_hash")
	rawUnsealed, _ := json.Marshal(unsealed)
	if _, _, err = s.IngestRequest(ctx, rawUnsealed, Actor{}); !errors.Is(err, ErrUnsealed) {
		t.Fatalf("want ErrUnsealed, got %v", err)
	}
	_, raw2 := sealed(t, proposal(slug+"x", "c"), reviewreceipts.ModeManual)
	ev.none = true
	if _, _, err = s.IngestRequest(ctx, raw2, Actor{}); !errors.Is(err, ErrAuthoringUnresolved) {
		t.Fatalf("want ErrAuthoringUnresolved, got %v", err)
	}
	ev.none, ev.tenant = false, ""
	if _, _, err = s.IngestRequest(ctx, raw2, Actor{}); !errors.Is(err, ErrTenantUnresolved) {
		t.Fatalf("want ErrTenantUnresolved, got %v", err)
	}
	ev.err = errors.New("boom")
	if _, _, err = s.IngestRequest(ctx, raw2, Actor{}); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("want ErrEvidenceUnavailable, got %v", err)
	}
	s.SetEvidence(nil)
	if _, _, err = s.IngestRequest(ctx, raw2, Actor{}); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("unset evidence store: want ErrEvidenceUnavailable, got %v", err)
	}
}

func TestClosureAndManualSubmission(t *testing.T) {
	s, _ := newTestStore(t, Config{})
	ctx := context.Background()
	slug := "s-" + uuid.NewString()[:8]
	subj1 := proposal(slug, "d")
	req1, raw1 := sealed(t, subj1, reviewreceipts.ModeManual)
	if _, _, err := s.IngestRequest(ctx, raw1, Actor{Name: "svc"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	in := ManualInput{RequestID: req1.RequestID, Subject: subj1, Outcome: "PASS", Criteria: allMet()}
	rc, err := s.SubmitManual(ctx, in, Actor{Name: "github:alice"}, now)
	if err != nil {
		t.Fatalf("SubmitManual: %v", err)
	}
	if rc.Receipt.Mode != "manual" || rc.Receipt.Assurance != "advisory" || rc.Tenant != "acme" ||
		rc.Receipt.ReviewerActor != "github:alice" {
		t.Fatalf("unexpected receipt %+v", rc.Receipt)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM review_nonce_consumptions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("nonce consumptions: %d, %v", n, err)
	}
	// A different content digest is a mismatch.
	bad := in
	bad.Subject = proposal(slug, "e")
	if _, err := s.SubmitManual(ctx, bad, Actor{Name: "a"}, now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("want ErrBindingMismatch, got %v", err)
	}
	// A different gitops_commit is not.
	prov := subj1
	prov.GitopsCommit = strings.Repeat("f", 40)
	okIn := in
	okIn.Subject = prov
	if _, err := s.SubmitManual(ctx, okIn, Actor{Name: "a"}, now.Add(time.Second)); err != nil {
		t.Fatalf("provenance-only change must bind: %v", err)
	}
	// Unknown request.
	if _, err := s.SubmitManual(ctx, ManualInput{RequestID: "rr_0000000000000000", Subject: subj1}, Actor{}, now); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("want ErrRequestNotFound, got %v", err)
	}
	// A worker request refuses a manual receipt.
	wreq, wraw := sealed(t, proposal(slug+"w", "1"), reviewreceipts.ModeWorker)
	if _, _, err := s.IngestRequest(ctx, wraw, Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitManual(ctx, ManualInput{RequestID: wreq.RequestID, Subject: wreq.Subject, Outcome: "PASS", Criteria: allMet()}, Actor{}, now); !errors.Is(err, ErrRequestModeWorker) {
		t.Fatalf("want ErrRequestModeWorker, got %v", err)
	}
	// Supersession: same identity, new binding closes the older request.
	subj2 := proposal(slug, "9")
	req2, raw2 := sealed(t, subj2, reviewreceipts.ModeManual)
	if _, _, err := s.IngestRequest(ctx, raw2, Actor{}); err != nil {
		t.Fatal(err)
	}
	old, err := s.Request(ctx, req1.RequestID)
	if err != nil || !old.Closed || old.ClosedReason != ClosedSuperseded || old.ClosedBy != req2.RequestID {
		t.Fatalf("old request should be superseded by %s: %+v %v", req2.RequestID, old, err)
	}
	if _, err := s.SubmitManual(ctx, in, Actor{}, now); !errors.Is(err, ErrRequestClosed) {
		t.Fatalf("want ErrRequestClosed, got %v", err)
	}
	// A same-binding repeat closes nothing.
	_, raw3 := sealed(t, subj2, reviewreceipts.ModeManual)
	if _, _, err := s.IngestRequest(ctx, raw3, Actor{}); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Request(ctx, req2.RequestID)
	if err != nil || cur.Closed {
		t.Fatalf("same-binding repeat must not close: %+v %v", cur, err)
	}
	// TTL.
	s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	exp, err := s.Request(ctx, req2.RequestID)
	if err != nil || !exp.Closed || exp.ClosedReason != ClosedTTL {
		t.Fatalf("expected ttl closure: %+v %v", exp, err)
	}
}

func TestPoolBoundAndImmutability(t *testing.T) {
	s, _ := newTestStore(t, Config{PoolMax: 1 << 30})
	ctx := context.Background()
	subj := proposal("s-"+uuid.NewString()[:8], "7")
	req, raw := sealed(t, subj, reviewreceipts.ModeManual)
	if _, _, err := s.IngestRequest(ctx, raw, Actor{}); err != nil {
		t.Fatal(err)
	}
	in := ManualInput{RequestID: req.RequestID, Subject: subj, Outcome: "PASS", Criteria: allMet()}
	if _, err := s.SubmitManual(ctx, in, Actor{Name: "a"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	pool, _, err := s.Pool(ctx)
	if err != nil || len(pool) == 0 {
		t.Fatalf("pool: %d, %v", len(pool), err)
	}
	s.poolMax = len(pool) - 1
	if p, _, err := s.Pool(ctx); !errors.Is(err, ErrPoolTooLarge) || p != nil {
		t.Fatalf("want ErrPoolTooLarge with no pool, got %v %v", p, err)
	}
	// A row-level trigger never fires on an empty table, so give the nonce
	// table a row before asserting that it refuses an UPDATE.
	if _, err := s.pool.Exec(ctx, `INSERT INTO review_nonce_consumptions (nonce_sha256, request_id, receipt_id, consumed_at)
VALUES ($1, $2, 'rc_0000000000000001', now())`, strings.Repeat("0", 64), req.RequestID); err != nil {
		t.Fatalf("seed nonce consumption: %v", err)
	}
	// DELETE stays allowed; other tests assert this table is empty.
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM review_nonce_consumptions WHERE nonce_sha256 = $1`, strings.Repeat("0", 64))
	})
	for _, q := range []string{
		`UPDATE review_requests SET tenant = 'x'`,
		`UPDATE review_receipts SET tenant = 'x'`,
		`UPDATE review_nonce_consumptions SET receipt_id = 'x'`,
	} {
		if _, err := s.pool.Exec(ctx, q); err == nil {
			t.Fatalf("%q must raise", q)
		}
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO review_receipts (receipt_id, request_id, content_hash, document, mode, assurance, tenant, submitted_by, submitted_at)
VALUES ('rc_0000000000000000', $1, 'h', '\x00', 'manual', 'independent', 'acme', 'x', now())`, req.RequestID); err == nil {
		t.Fatal("manual/independent must violate the CHECK")
	}
	// A second NewStore on the same database succeeds.
	s2, err := NewStore(ctx, os.Getenv("TEST_DATABASE_URL"), Config{})
	if err != nil {
		t.Fatalf("second NewStore: %v", err)
	}
	s2.Close()
}
