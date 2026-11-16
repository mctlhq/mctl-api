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

	r, err := s.InsertRecord(ctx, NewRecord(p, "aar_1", "prn_owner", "prn_dev", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.ID, RecordIDPrefix) || r.Status != RecordSubmitting || r.Health != HealthUnknown ||
		r.PlanDigest != p.Digest || r.GitopsSHA != p.GitopsBaseSHA || r.Workflow != "" || r.ImageDigest != "" {
		t.Fatalf("inserted = %+v", r)
	}

	// One record per plan, and per grant.
	if _, err := s.InsertRecord(ctx, NewRecord(p, "aar_2", "prn_owner", "prn_dev", time.Now())); !errors.Is(err, ErrRecordExists) {
		t.Fatalf("second record for the plan: %v", err)
	}
	p2 := storedPlan(t, s, "c")
	if _, err := s.InsertRecord(ctx, NewRecord(p2, "aar_1", "prn_owner", "prn_dev", time.Now())); !errors.Is(err, ErrRecordExists) {
		t.Fatalf("second record for the grant: %v", err)
	}

	// A record must start as submitting with unknown health.
	bad := NewRecord(p2, "aar_3", "prn_owner", "prn_dev", time.Now())
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
		"UPDATE deploy_records SET health = 'healthy', health_url = 'https://x' WHERE id = $1",
	} {
		if _, err := s.pool.Exec(ctx, q, r.ID); err != nil {
			t.Fatalf("first write %q: %v", q, err)
		}
	}
	for name, q := range map[string]string{
		"image digest": "UPDATE deploy_records SET image_digest = 'sha256:" + strings.Repeat("e", 64) + "' WHERE id = $1",
		"argo":         "UPDATE deploy_records SET argo_revision = 'rev2' WHERE id = $1",
		"health":       "UPDATE deploy_records SET health = 'unhealthy' WHERE id = $1",
		"health url":   "UPDATE deploy_records SET health_url = 'https://y' WHERE id = $1",
	} {
		if _, err := s.pool.Exec(ctx, q, r.ID); err == nil {
			t.Errorf("%s rewritten", name)
		}
	}
	// A malformed digest is refused by the column check.
	r2, err := s.InsertRecord(ctx, NewRecord(p2, "aar_4", "prn_owner", "prn_dev", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE deploy_records SET image_digest = 'latest' WHERE id = $1", r2.ID); err == nil {
		t.Error("a non-digest image_digest was stored")
	}
}
