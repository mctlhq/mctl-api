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

package alerts

import (
	"context"
	"os"
	"testing"
)

// newTestStore connects to a real Postgres instance for dedup-upsert tests.
// Skips when TEST_DATABASE_URL is unset — this repo has no Postgres service
// in CI, so these tests only run when pointed at a local/ephemeral instance
// (e.g. `docker run -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine`).
func newTestStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed alerts store test")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, "DELETE FROM alert_evidence")
		_, _ = s.pool.Exec(ctx, "DELETE FROM alerts")
		s.pool.Close()
	})

	// Isolate from any rows left by other tests/runs.
	if _, err := s.pool.Exec(ctx, "DELETE FROM alert_evidence"); err != nil {
		t.Fatalf("cleanup evidence: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM alerts"); err != nil {
		t.Fatalf("cleanup alerts: %v", err)
	}
	return s
}

func newAlert(id, fingerprint string) *Alert {
	return &Alert{
		ID:          id,
		Source:      SourceAlertManager,
		Type:        "workflow_failed",
		Tenant:      "admins",
		Service:     "mctl-agents",
		Summary:     "workflow failed",
		Severity:    SeverityWarning,
		Status:      StatusOpen,
		Fingerprint: fingerprint,
	}
}

func TestCreate_SameFingerprint_Dedups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.Create(ctx, newAlert("argo-run-1", "workflow_failed:run:foo"))
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if first.OccurrenceCount != 1 {
		t.Fatalf("expected occurrence_count=1 on first insert, got %d", first.OccurrenceCount)
	}

	second, err := s.Create(ctx, newAlert("argo-run-2", "workflow_failed:run:foo"))
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected dedup hit to return original id %q, got %q", first.ID, second.ID)
	}
	if second.OccurrenceCount != 2 {
		t.Fatalf("expected occurrence_count=2 after dedup, got %d", second.OccurrenceCount)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 row after two same-fingerprint creates, got %d", len(all))
	}
}

func TestCreate_SameFingerprint_DifferentTenants_BothPersist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a := newAlert("tenant-a-1", "workflow_failed:run:shared")
	a.Tenant = "tenant-a"
	first, err := s.Create(ctx, a)
	if err != nil {
		t.Fatalf("create tenant-a: %v", err)
	}

	b := newAlert("tenant-b-1", "workflow_failed:run:shared")
	b.Tenant = "tenant-b"
	second, err := s.Create(ctx, b)
	if err != nil {
		t.Fatalf("create tenant-b: %v", err)
	}

	if second.ID == first.ID {
		t.Fatalf("expected independent alerts for the same fingerprint under different tenants, got merged id %q", second.ID)
	}
	if first.OccurrenceCount != 1 || second.OccurrenceCount != 1 {
		t.Fatalf("expected occurrence_count=1 for both tenants' alerts (no cross-tenant merge), got %d and %d",
			first.OccurrenceCount, second.OccurrenceCount)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 independent rows across tenants sharing a fingerprint, got %d", len(all))
	}
}

func TestCreate_SameID_Retry_ReturnsExistingRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two distinct fingerprints so the retry can only be caught by the id
	// (PK) collision path, not the fingerprint dedup path.
	first, err := s.Create(ctx, newAlert("retry-1", "workflow_failed:run:x"))
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	retry := newAlert("retry-1", "workflow_failed:run:y")
	got, err := s.Create(ctx, retry)
	if err != nil {
		t.Fatalf("expected a same-id retry to be a no-op, not an error: %v", err)
	}
	if got.ID != first.ID {
		t.Fatalf("expected retry to return the existing row's id %q, got %q", first.ID, got.ID)
	}
	if got.Fingerprint != first.Fingerprint {
		t.Fatalf("expected retry to return the ORIGINAL stored row, not the retry's payload; got fingerprint %q, want %q",
			got.Fingerprint, first.Fingerprint)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 row after a same-id retry, got %d", len(all))
	}
}

func TestCreate_DifferentFingerprints_BothPersist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newAlert("argo-a-1", "workflow_failed:run:a")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := s.Create(ctx, newAlert("argo-b-1", "workflow_failed:run:b")); err != nil {
		t.Fatalf("create b: %v", err)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 independent rows for different fingerprints, got %d", len(all))
	}
}

func TestCreate_EmptyFingerprint_NeverConflicts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newAlert("manual-1", "")); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, err := s.Create(ctx, newAlert("manual-2", "")); err != nil {
		t.Fatalf("create 2: %v", err)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected empty-fingerprint alerts to always insert a new row, got %d rows", len(all))
	}
	for _, a := range all {
		if a.OccurrenceCount != 1 {
			t.Fatalf("expected occurrence_count=1 for non-deduped alert %s, got %d", a.ID, a.OccurrenceCount)
		}
	}
}

func TestResolveByFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, newAlert("argo-r-1", "workflow_failed:run:r"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	resolved, err := s.ResolveByFingerprint(ctx, "admins", "workflow_failed:run:r")
	if err != nil {
		t.Fatalf("resolve by fingerprint: %v", err)
	}
	if !resolved {
		t.Fatal("expected resolved=true for an open matching alert")
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusResolved {
		t.Fatalf("expected status=resolved, got %q", got.Status)
	}
	if got.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}

	// A second, freshly-failing occurrence with the same fingerprint must
	// open a NEW alert, not merge into the now-resolved one.
	reopened, err := s.Create(ctx, newAlert("argo-r-2", "workflow_failed:run:r"))
	if err != nil {
		t.Fatalf("create after resolve: %v", err)
	}
	if reopened.ID == created.ID {
		t.Fatal("expected a fresh alert after the prior one resolved, got the resolved id back")
	}
	if reopened.OccurrenceCount != 1 {
		t.Fatalf("expected occurrence_count=1 on the reopened alert, got %d", reopened.OccurrenceCount)
	}
}

func TestResolveByFingerprint_NoMatch_NotAnError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	resolved, err := s.ResolveByFingerprint(ctx, "admins", "workflow_failed:run:nonexistent")
	if err != nil {
		t.Fatalf("expected no error for a no-op resolve, got: %v", err)
	}
	if resolved {
		t.Fatal("expected resolved=false when no matching open alert exists")
	}
}
