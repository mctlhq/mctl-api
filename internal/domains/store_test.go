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

package domains

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

// newTestStore connects to a real Postgres instance, mirroring
// internal/alerts/store_test.go's harness. Skips when TEST_DATABASE_URL is
// unset — this repo has no Postgres service in CI.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed domains store test")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, "DELETE FROM custom_domains")
		s.pool.Close()
	})

	if _, err := s.pool.Exec(ctx, "DELETE FROM custom_domains"); err != nil {
		t.Fatalf("cleanup custom_domains: %v", err)
	}
	return s
}

func newDomain(team, service, domain string) *Domain {
	return &Domain{
		ID:                uuid.New().String(),
		Team:              team,
		Service:           service,
		Domain:            domain,
		Status:            StatusPending,
		VerificationToken: "test-token",
		CreatedBy:         "test-user",
	}
}

func TestCreate_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.Create(ctx, newDomain("labs", "genai-leader", "genai-leader.example.com"))
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	second, err := s.Create(ctx, newDomain("labs", "genai-leader", "genai-leader.example.com"))
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected idempotent create to return existing id %q, got %q", first.ID, second.ID)
	}
}

func TestCreate_CrossTeamConflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newDomain("labs", "genai-leader", "shared.example.com")); err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err := s.Create(ctx, newDomain("infra", "other-service", "shared.example.com"))
	if !errors.Is(err, ErrDomainConflict) {
		t.Fatalf("expected ErrDomainConflict, got %v", err)
	}
}

// TestCreate_LegacyMixedCaseRowIsIdempotentNotConflict pins the fix for a
// case the case-insensitivity pass elsewhere in the package missed: this is
// the one lookup Create's own idempotent-reregistration path performs, and
// AddDomain always lowercases team/service on the way in now, so an exact
// comparison against a legacy mixed-case row would 409 every
// re-registration by the row's own team, forever, instead of returning the
// existing row.
func TestCreate_LegacyMixedCaseRowIsIdempotentNotConflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	legacy := newDomain("Labs", "Svc", "legacy-reregister.example.com")
	created, err := s.Create(ctx, legacy)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Same hostname, same team/service — but lowercased, the way AddDomain
	// normalizes a real caller's input before ever reaching Create.
	again, err := s.Create(ctx, newDomain("labs", "svc", "legacy-reregister.example.com"))
	if err != nil {
		t.Fatalf("re-registration by the same team must not error, got: %v", err)
	}
	if again.ID != created.ID {
		t.Fatalf("expected the existing row back (id %q), got a different id %q", created.ID, again.ID)
	}
}

func TestListByTeam(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newDomain("labs", "svc-a", "a.example.com")); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := s.Create(ctx, newDomain("labs", "svc-b", "b.example.com")); err != nil {
		t.Fatalf("create b: %v", err)
	}
	if _, err := s.Create(ctx, newDomain("other", "svc-c", "c.example.com")); err != nil {
		t.Fatalf("create c: %v", err)
	}

	all, err := s.ListByTeam(ctx, "labs", "")
	if err != nil {
		t.Fatalf("list all for team: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 domains for team labs, got %d", len(all))
	}

	filtered, err := s.ListByTeam(ctx, "labs", "svc-a")
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Domain != "a.example.com" {
		t.Fatalf("expected exactly a.example.com, got %+v", filtered)
	}
}

// TestListByTeam_EmptyTeamReturnsEmptySliceNotNil pins the fix for a
// contract change: the Backstage proxy this store replaced always returned
// "domains":[] — never null — for a team with no rows, and a nil slice
// serializes to JSON null.
func TestListByTeam_EmptyTeamReturnsEmptySliceNotNil(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	list, err := s.ListByTeam(ctx, "no-such-team", "")
	if err != nil {
		t.Fatalf("list for empty team: %v", err)
	}
	if list == nil {
		t.Fatalf("expected a non-nil empty slice, got nil")
	}
	if len(list) != 0 {
		t.Fatalf("expected an empty result, got %+v", list)
	}
}

// TestListByTeam_MixedCaseStoredRow exercises the lower() comparison
// against a genuinely mixed-case stored row — inserted directly via Create,
// bypassing AddDomain's normalization, the same technique
// TestCreate_LegacyMixedCaseRowIsIdempotentNotConflict uses. A caller
// spelling the team/service in canonical lowercase must still find a row
// that predates AddDomain's own lowercasing.
func TestListByTeam_MixedCaseStoredRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newDomain("Labs", "Svc", "mixed-list.example.com")); err != nil {
		t.Fatalf("create: %v", err)
	}

	filtered, err := s.ListByTeam(ctx, "labs", "svc")
	if err != nil {
		t.Fatalf("list by team+service: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Domain != "mixed-list.example.com" {
		t.Fatalf("expected exactly mixed-list.example.com, got %+v", filtered)
	}

	all, err := s.ListByTeam(ctx, "labs", "")
	if err != nil {
		t.Fatalf("list by team only: %v", err)
	}
	found := false
	for _, d := range all {
		if d.Domain == "mixed-list.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mixed-list.example.com in ListByTeam(\"labs\", \"\"), got %+v", all)
	}
}

func TestGetAndGetByDomain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, newDomain("labs", "svc-a", "get.example.com"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	byID, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID.Domain != "get.example.com" {
		t.Fatalf("get by id returned wrong row: %+v", byID)
	}

	byDomain, err := s.GetByDomain(ctx, "get.example.com")
	if err != nil {
		t.Fatalf("get by domain: %v", err)
	}
	if byDomain.ID != created.ID {
		t.Fatalf("get by domain returned wrong row: %+v", byDomain)
	}

	if _, err := s.Get(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetStatusAndMarkVerified(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, newDomain("labs", "svc-a", "status.example.com"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.MarkVerified(ctx, created.ID); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	verified, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after verify: %v", err)
	}
	if verified.Status != StatusVerified || verified.VerifiedAt == nil {
		t.Fatalf("expected verified status with verified_at set, got %+v", verified)
	}

	if err := s.SetStatus(ctx, created.ID, StatusFailed, "workflow error"); err != nil {
		t.Fatalf("set status: %v", err)
	}
	failed, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after set status: %v", err)
	}
	if failed.Status != StatusFailed || failed.LastError != "workflow error" {
		t.Fatalf("expected failed status with last_error set, got %+v", failed)
	}

	if err := s.SetStatus(ctx, "does-not-exist", StatusFailed, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown id, got %v", err)
	}
}

// TestMarkVerifiedDoesNotDemoteActive pins the fix for a regression
// mctl_verify_domain would otherwise reintroduce on every routine check: it
// re-verifies every domain returned for a team/service, so an unconditional
// MarkVerified would silently demote an already-active row back to
// "verified" (and clear last_error) each time.
func TestMarkVerifiedDoesNotDemoteActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, newDomain("labs", "svc-a", "active.example.com"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetStatus(ctx, created.ID, StatusActive, ""); err != nil {
		t.Fatalf("set status active: %v", err)
	}

	if err := s.MarkVerified(ctx, created.ID); err != nil {
		t.Fatalf("mark verified on an active row must not error: %v", err)
	}

	stillActive, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after re-verify: %v", err)
	}
	if stillActive.Status != StatusActive {
		t.Fatalf("expected status to stay %q after re-verify, got %q", StatusActive, stillActive.Status)
	}
}

func TestMarkVerifiedUnknownIDIsNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.MarkVerified(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown id, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, newDomain("labs", "svc-a", "delete.example.com"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := s.Delete(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting again, got %v", err)
	}
}
