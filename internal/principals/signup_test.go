package principals

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func importTestSignup(t *testing.T, s *Store) SignupRequest {
	t.Helper()
	r := SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Applicant", Email: "test@example.com", GitHub: "test-user", Project: "Test project"}
	if err := s.ImportSignup(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSignupZeroCapacityAndImmutableRecipient(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	r := importTestSignup(t, s)
	if _, err := s.DecideSignup(ctx, r.ID, "approved", "123", "test-user", "admin", "Welcome"); !errors.Is(err, ErrSignupCapacity) {
		t.Fatalf("zero capacity: %v", err)
	}
	ok, err := s.SignupAllowed(ctx, "123")
	if err != nil || ok {
		t.Fatalf("unexpected authority: %v %v", ok, err)
	}
	r.Email = "other@example.com"
	if err := s.ImportSignup(ctx, r); !errors.Is(err, ErrSignupConflict) {
		t.Fatalf("recipient overwrite: %v", err)
	}
	d, err := s.DecideSignup(ctx, r.ID, "rejected", "", "", "admin", "Pilot full")
	if err != nil || d.Request.Email != "test@example.com" || !d.NotificationPending {
		t.Fatalf("rejection: %+v %v", d, err)
	}
}
func TestSignupConcurrentApprovalsReserveExactlyOneSlot(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed funded resource budget"); err != nil {
		t.Fatal(err)
	}
	requests := make([]SignupRequest, 12)
	for i := range requests {
		requests[i] = importTestSignup(t, s)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i, r := range requests {
		wg.Add(1)
		go func(i int, r SignupRequest) {
			defer wg.Done()
			_, err := s.DecideSignup(ctx, r.ID, "approved", fmt.Sprint(1000+i), "test-user", "admin", "Welcome")
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrSignupCapacity) {
				t.Errorf("decision: %v", err)
			}
		}(i, r)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("approved %d for one slot", accepted.Load())
	}
	c, err := s.SignupCapacity(ctx)
	if err != nil || c.Used != 1 || c.Available != 0 {
		t.Fatalf("capacity: %+v %v", c, err)
	}
	if err = s.SetSignupCapacity(ctx, 0, "admin", "Reduce below reserved slot"); !errors.Is(err, ErrSignupCapacity) {
		t.Fatalf("shrank used budget: %v", err)
	}
}
func TestSignupClaimRetryExpiryAndDeliveryLease(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	r := importTestSignup(t, s)
	principal, err := s.Provision(ctx, github(123, "test-user"))
	if err != nil {
		t.Fatal(err)
	}
	_ = principal
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed funded resource budget"); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := s.DecideSignup(ctx, r.ID, "approved", "123", "test-user", "admin", "Welcome"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClaimSignup(ctx, "123", "test-team", principal.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimSignup(ctx, "123", "test-team", principal.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimSignup(ctx, "123", "other-team", principal.ID); !errors.Is(err, ErrSignupConflict) {
		t.Fatalf("second workspace: %v", err)
	}
	lease := uuid.NewString()
	if _, err := s.LeaseSignupDelivery(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LeaseSignupDelivery(ctx, uuid.NewString()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("parallel delivery: %v", err)
	}
	if err := s.AckSignupDelivery(ctx, r.ID, uuid.NewString(), "email-id"); err == nil {
		t.Fatal("wrong lease acknowledged")
	}
	if err := s.AckSignupDelivery(ctx, r.ID, lease, "email-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE signup_requests SET expires_at=now()-interval '1 day' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SignupAllowed(ctx, "123"); err != nil || !ok {
		t.Fatalf("claimed workspace lost access on invitation expiry: %v %v", ok, err)
	}
}
func TestSignupExpiredUnusedApprovalReleasesBudget(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	r := importTestSignup(t, s)
	principal, err := s.Provision(ctx, github(123, "test-user"))
	if err != nil {
		t.Fatal(err)
	}
	_ = principal
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed funded resource budget"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideSignup(ctx, r.ID, "approved", "123", "test-user", "admin", "Welcome"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE signup_requests SET expires_at=now()-interval '1 day' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SignupAllowed(ctx, "123"); err != nil || ok {
		t.Fatalf("expired authority: %v %v", ok, err)
	}
	next := importTestSignup(t, s)
	if _, err := s.DecideSignup(ctx, next.ID, "approved", "456", "test-user", "admin", "Welcome"); err != nil {
		t.Fatalf("expired reservation not released: %v", err)
	}
}

func TestSignupGrandfatherSnapshotRunsOnce(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if _, err := s.Provision(ctx, github(8877001, "old-customer")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM signup_legacy_github;DELETE FROM signup_admission_cutover`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, signupSchema); err != nil {
		t.Fatal(err)
	}
	if old, err := s.SignupGrandfathered(ctx, "8877001"); err != nil || !old {
		t.Fatalf("existing customer lost admission: %v %v", old, err)
	}
	if _, err := s.Provision(ctx, github(8877002, "new-customer")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, signupSchema); err != nil {
		t.Fatal(err)
	}
	if newCustomer, err := s.SignupGrandfathered(ctx, "8877002"); err != nil || newCustomer {
		t.Fatalf("restart grandfathered new customer: %v %v", newCustomer, err)
	}
}
func TestPublicSignupClaimsRemainBoundedUnderConcurrency(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	zeroPrincipal, err := s.Provision(ctx, github(7788000, "public-customer0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimPublicSignup(ctx, "7788000", "public-0", zeroPrincipal.ID); !errors.Is(err, ErrSignupCapacity) {
		t.Fatalf("public zero budget: %v", err)
	}

	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed resource budget"); err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		id := fmt.Sprint(7788000 + n)
		principal, err := s.Provision(ctx, github(int64(7788000+n), "public-customer"+fmt.Sprint(n)))
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(id, pid, tenant string) {
			defer wg.Done()
			err := s.ClaimPublicSignup(ctx, id, tenant, pid)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrSignupCapacity) {
				t.Errorf("public admission: %v", err)
			}
		}(id, principal.ID, "public-"+fmt.Sprint(n))
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("public claims %d for one slot", accepted.Load())
	}
	capacity, err := s.SignupCapacity(ctx)
	if err != nil || capacity.Used != 1 || capacity.Available != 0 {
		t.Fatalf("capacity %+v %v", capacity, err)
	}
}

func TestSignupConcurrentTenantConflictKeepsTheLoserRetryable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if err := s.SetSignupCapacity(ctx, 2, "admin", "Reviewed resource budget"); err != nil {
		t.Fatal(err)
	}
	pids := make([]string, 2)
	for n := 0; n < 2; n++ {
		number := int64(9977000 + n)
		principal, err := s.Provision(ctx, github(number, fmt.Sprint("tenant-racer", n)))
		if err != nil {
			t.Fatal(err)
		}
		pids[n] = principal.ID
		r := importTestSignup(t, s)
		if _, err := s.DecideSignup(ctx, r.ID, "approved", fmt.Sprint(number), "test-user", "admin", "Welcome"); err != nil {
			t.Fatal(err)
		}
	}
	results := make([]error, 2)
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			results[n] = s.ClaimSignup(ctx, fmt.Sprint(9977000+n), "shared-team", pids[n])
		}(n)
	}
	wg.Wait()
	accepted, conflicted := 0, 0
	for n, err := range results {
		if err == nil {
			accepted++
			continue
		}
		if !errors.Is(err, ErrSignupConflict) {
			t.Fatalf("expected semantic conflict: %v", err)
		}
		conflicted++
		if err := s.ClaimSignup(ctx, fmt.Sprint(9977000+n), "other-team", pids[n]); err != nil {
			t.Fatalf("name loser cannot retry: %v", err)
		}
	}
	if accepted != 1 || conflicted != 1 {
		t.Fatalf("accepted=%d conflicts=%d", accepted, conflicted)
	}
	capacity, err := s.SignupCapacity(ctx)
	if err != nil || capacity.Used != 2 {
		t.Fatalf("capacity %+v %v", capacity, err)
	}
}
