package deployplan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func storedPlan(t *testing.T, s *Store, seed string) *Plan {
	t.Helper()
	p, _, err := s.Insert(context.Background(), testPlan(seed))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mctl-api#1047: one record per plan and per grant, status moves once out
// of submitting, planned fields never change, rows are never deleted.
func TestRecordStore(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p := storedPlan(t, s, "a")

	r, err := s.InsertRecord(ctx, NewRecord(p, "aar_1", "prn_owner", "prn_dev", "", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.ID, RecordIDPrefix) || r.Status != RecordSubmitting || r.Health != HealthUnknown ||
		r.PlanDigest != p.Digest || r.GitopsSHA != p.GitopsBaseSHA || r.Workflow != "" || r.ImageDigest != "" {
		t.Fatalf("inserted = %+v", r)
	}

	// One record per plan, and per grant.
	if _, err := s.InsertRecord(ctx, NewRecord(p, "aar_2", "prn_owner", "prn_dev", "", time.Now())); !errors.Is(err, ErrRecordExists) {
		t.Fatalf("second record for the plan: %v", err)
	}
	p2 := storedPlan(t, s, "c")
	if _, err := s.InsertRecord(ctx, NewRecord(p2, "aar_1", "prn_owner", "prn_dev", "", time.Now())); !errors.Is(err, ErrRecordExists) {
		t.Fatalf("second record for the grant: %v", err)
	}

	// A record must start as submitting with unknown health.
	bad := NewRecord(p2, "aar_3", "prn_owner", "prn_dev", "", time.Now())
	bad.Health = HealthHealthy
	if _, err := s.InsertRecord(ctx, bad); err == nil {
		t.Fatal("a record born healthy was stored")
	}

	// Submission: outcome rules, then exactly once.
	for name, tc := range map[string][2]string{
		"submitted without workflow": {RecordSubmitted, ""},
		"failed with workflow":       {RecordSubmitFailed, "wf-1"},
		"not an outcome":             {RecordSubmitting, ""},
	} {
		if _, err := s.SetRecordSubmission(ctx, r.ID, tc[0], tc[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	got, err := s.SetRecordSubmission(ctx, r.ID, RecordSubmitted, "wf-1")
	if err != nil || got.Status != RecordSubmitted || got.Workflow != "wf-1" {
		t.Fatalf("submitted = %+v, %v", got, err)
	}
	if _, err := s.SetRecordSubmission(ctx, r.ID, RecordSubmitFailed, ""); err == nil {
		t.Fatal("status moved twice")
	}

	// Reads.
	if g, err := s.GetRecord(ctx, r.ID); err != nil || g.Workflow != "wf-1" {
		t.Fatalf("GetRecord = %+v, %v", g, err)
	}
	if g, err := s.RecordForPlan(ctx, p.ID); err != nil || g.ID != r.ID {
		t.Fatalf("RecordForPlan = %+v, %v", g, err)
	}
	for _, f := range []func() error{
		func() error { _, err := s.GetRecord(ctx, "dep_missing"); return err },
		func() error { _, err := s.RecordForPlan(ctx, p2.ID); return err },
	} {
		if err := f(); !errors.Is(err, ErrRecordNotFound) {
			t.Errorf("missing = %v", err)
		}
	}

	// The triggers, for any writer that bypasses the store.
	refused := map[string]string{
		"planned field":      "UPDATE deploy_records SET host = 'x' WHERE id = $1",
		"grant":              "UPDATE deploy_records SET decided_by_principal_id = 'prn_x' WHERE id = $1",
		"status back":        "UPDATE deploy_records SET status = 'submitting' WHERE id = $1",
		"workflow rewritten": "UPDATE deploy_records SET workflow = 'wf-2' WHERE id = $1",
		"delete":             "DELETE FROM deploy_records WHERE id = $1",
	}
	for name, q := range refused {
		if _, err := s.pool.Exec(ctx, q, r.ID); err == nil {
			t.Errorf("%s: the trigger let it through", name)
		}
	}
	// Observed fields: written once, never rewritten.
	digest := "sha256:" + strings.Repeat("d", 64)
	for _, q := range []string{
		"UPDATE deploy_records SET image_digest = '" + digest + "' WHERE id = $1",
		"UPDATE deploy_records SET argo_revision = 'rev1' WHERE id = $1",
		"UPDATE deploy_records SET commit_sha = '" + strings.Repeat("a", 40) + "' WHERE id = $1",
		"UPDATE deploy_records SET health = 'healthy', health_url = 'https://x' WHERE id = $1",
	} {
		if _, err := s.pool.Exec(ctx, q, r.ID); err != nil {
			t.Fatalf("first write %q: %v", q, err)
		}
	}
	for name, q := range map[string]string{
		"image digest": "UPDATE deploy_records SET image_digest = 'sha256:" + strings.Repeat("e", 64) + "' WHERE id = $1",
		"argo":         "UPDATE deploy_records SET argo_revision = 'rev2' WHERE id = $1",
		"commit sha":   "UPDATE deploy_records SET commit_sha = '" + strings.Repeat("b", 40) + "' WHERE id = $1",
		"health":       "UPDATE deploy_records SET health = 'unhealthy' WHERE id = $1",
		"health url":   "UPDATE deploy_records SET health_url = 'https://y' WHERE id = $1",
	} {
		if _, err := s.pool.Exec(ctx, q, r.ID); err == nil {
			t.Errorf("%s rewritten", name)
		}
	}
	// A malformed digest is refused by the column check.
	r2, err := s.InsertRecord(ctx, NewRecord(p2, "aar_4", "prn_owner", "prn_dev", "", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET image_digest = 'latest' WHERE id = $1", r2.ID); err == nil {
		t.Error("a non-digest image_digest was stored")
	}
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET commit_sha = 'main' WHERE id = $1", r2.ID); err == nil {
		t.Error("a non-commit commit_sha was stored")
	}
}

// mctl-api#1047 slice 2a: the run result and image digest are written once,
// only on a submitted record; the workflow must be the one named before the
// submit; the reconcile queue holds exactly the records still open.
func TestRecordRunResult(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("d", 64)

	open := storedPlan(t, s, "a")
	r, err := s.InsertRecord(ctx, NewRecord(open, "aar_r1", "prn_owner", "prn_dev", "preview-deploy-aaaa0001", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if r.WorkflowRef != "preview-deploy-aaaa0001" || r.RunResult != "" {
		t.Fatalf("inserted = %+v", r)
	}
	if _, err := s.SetRunResult(ctx, r.ID, RunOutcome{Result: RunSucceeded, ImageDigest: digest}); err == nil {
		t.Fatal("a run result on a submitting record")
	}
	if _, err := s.SetRecordSubmission(ctx, r.ID, RecordSubmitted, "preview-deploy-other"); err == nil {
		t.Fatal("submitted under a name other than its ref")
	}
	legacy := storedPlan(t, s, "c")
	l, err := s.InsertRecord(ctx, NewRecord(legacy, "aar_r2", "prn_owner", "prn_dev", "", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	failed := storedPlan(t, s, "e")
	f, err := s.InsertRecord(ctx, NewRecord(failed, "aar_r3", "prn_owner", "prn_dev", "preview-deploy-aaaa0003", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRecordSubmission(ctx, f.ID, RecordSubmitFailed, ""); err != nil {
		t.Fatal(err)
	}

	queue := func() map[string]bool {
		recs, err := s.RecordsToReconcile(ctx, time.Now().Add(-time.Hour), time.Time{}, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, x := range recs {
			ids[x.ID] = true
		}
		return ids
	}
	// Submitting with a ref: open. Submitting without one (written before
	// refs existed): nothing to look up. Failed: closed.
	if q := queue(); !q[r.ID] || q[l.ID] || q[f.ID] || len(q) != 1 {
		t.Fatalf("queue = %v", q)
	}
	if _, err := s.SetRecordSubmission(ctx, r.ID, RecordSubmitted, "preview-deploy-aaaa0001"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRunResult(ctx, f.ID, RunOutcome{Result: RunFailed}); err == nil {
		t.Fatal("a run result on a failed submit")
	}
	if _, err := s.SetRunResult(ctx, r.ID, RunOutcome{Result: "maybe"}); err == nil {
		t.Fatal("an unknown run result")
	}
	if _, err := s.SetRunResult(ctx, r.ID, RunOutcome{Result: RunSucceeded, ImageDigest: "latest"}); err == nil {
		t.Fatal("a malformed digest")
	}
	if !queue()[r.ID] {
		t.Fatal("a submitted record without a result left the queue")
	}
	got, err := s.SetRunResult(ctx, r.ID, RunOutcome{Result: RunSucceeded, ImageDigest: digest})
	if err != nil || got.RunResult != RunSucceeded || got.ImageDigest != digest {
		t.Fatalf("SetRunResult = %+v, %v", got, err)
	}
	if _, err := s.SetRunResult(ctx, r.ID, RunOutcome{Result: RunFailed}); err == nil {
		t.Fatal("run result written twice")
	}
	if queue()[r.ID] {
		t.Fatal("a finished record is still queued")
	}

	// Triggers, for any writer that bypasses the store.
	for name, q := range map[string]string{
		"result rewritten": "UPDATE deploy_records SET run_result = 'failed' WHERE id = $1",
		"ref rewritten":    "UPDATE deploy_records SET workflow_ref = 'x' WHERE id = $1",
		"digest rewritten": "UPDATE deploy_records SET image_digest = 'sha256:" + strings.Repeat("e", 64) + "' WHERE id = $1",
	} {
		if _, err := s.pool.Exec(ctx, q, r.ID); err == nil {
			t.Errorf("%s: the trigger let it through", name)
		}
	}
	// f has a ref and no workflow, so only the immutability rule can refuse.
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET workflow_ref = 'x' WHERE id = $1", f.ID); err == nil {
		t.Error("workflow_ref rewritten on a record without a workflow")
	}
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET run_result = 'failed' WHERE id = $1", f.ID); err == nil {
		t.Error("a run result on a failed submit got through the trigger")
	}
	// The digest a submit_failed record never had is not filled by a result
	// either; a result keeps a digest already present.
	g := storedPlan(t, s, "f")
	gr, _ := s.InsertRecord(ctx, NewRecord(g, "aar_r4", "prn_owner", "prn_dev", "preview-deploy-aaaa0004", time.Now()))
	if _, err := s.SetRecordSubmission(ctx, gr.ID, RecordSubmitted, "preview-deploy-aaaa0004"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET image_digest = $2 WHERE id = $1", gr.ID, digest); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SetRunResult(ctx, gr.ID, RunOutcome{Result: RunSucceeded, ImageDigest: "sha256:" + strings.Repeat("9", 64)}); err != nil || got.ImageDigest != digest {
		t.Fatalf("a result replaced the recorded digest: %+v %v", got, err)
	}

	// The full outcome lands once, each field kept when already set; a
	// malformed one is refused before any write.
	h := storedPlan(t, s, "b")
	hr, _ := s.InsertRecord(ctx, NewRecord(h, "aar_r5", "prn_owner", "prn_dev", "preview-deploy-aaaa0005", time.Now()))
	if _, err := s.SetRecordSubmission(ctx, hr.ID, RecordSubmitted, "preview-deploy-aaaa0005"); err != nil {
		t.Fatal(err)
	}
	sha1, sha2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	for name, o := range map[string]RunOutcome{
		"argo not a commit": {Result: RunFailed, ArgoRevision: "main"},
		"commit too short":  {Result: RunFailed, CommitSHA: "abc"},
		"health idle":       {Result: RunSucceeded, Health: "idle"},
		"url with a path":   {Result: RunSucceeded, HealthURL: "https://x.test/a"},
		"url not https":     {Result: RunSucceeded, HealthURL: "http://x.test"},
	} {
		if _, err := s.SetRunResult(ctx, hr.ID, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	got, err = s.SetRunResult(ctx, hr.ID, RunOutcome{Result: RunFailed, ArgoRevision: sha1, CommitSHA: sha2,
		Health: HealthUnhealthy, HealthURL: "https://svc.example.test"})
	if err != nil || got.ArgoRevision != sha1 || got.CommitSHA != sha2 || got.Health != HealthUnhealthy ||
		got.HealthURL != "https://svc.example.test" || got.ImageDigest != "" {
		t.Fatalf("outcome = %+v, %v", got, err)
	}
	// No health reported: it stays unknown, never healthy.
	k := storedPlan(t, s, "d")
	kr, _ := s.InsertRecord(ctx, NewRecord(k, "aar_r6", "prn_owner", "prn_dev", "preview-deploy-aaaa0006", time.Now()))
	if _, err := s.SetRecordSubmission(ctx, kr.ID, RecordSubmitted, "preview-deploy-aaaa0006"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SetRunResult(ctx, kr.ID, RunOutcome{Result: RunSucceeded}); err != nil || got.Health != HealthUnknown {
		t.Fatalf("silent outcome health = %+v, %v", got, err)
	}
}

// The queue pages by (created_at, id), so equal timestamps are not skipped.
func TestRecordsToReconcilePages(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	at := time.Now()
	want := map[string]bool{}
	for i, seed := range []string{"1", "2", "3", "4", "5"} {
		p := storedPlan(t, s, seed)
		r, err := s.InsertRecord(ctx, NewRecord(p, "aar_p"+seed, "prn_owner", "prn_dev", "preview-deploy-0000000"+seed, at))
		if err != nil {
			t.Fatal(i, err)
		}
		want[r.ID] = true
	}
	got := map[string]bool{}
	var afterCreated time.Time
	afterID := ""
	for {
		page, err := s.RecordsToReconcile(ctx, at.Add(-time.Hour), afterCreated, afterID, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			got[r.ID] = true
		}
		if len(page) < 2 {
			break
		}
		afterCreated, afterID = page[len(page)-1].CreatedAt, page[len(page)-1].ID
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d of %d", len(got), len(want))
	}
}
