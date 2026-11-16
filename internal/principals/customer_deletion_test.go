// Copyright 2026 MCTL Authors
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

package principals

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCustomerDeletionRemovesOldIdentityAndPermitsFreshSubject(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	sid, err := surfaceid.NewStore(ctx, os.Getenv("TEST_DATABASE_URL"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sid.Close()
	refresh, err := refreshstore.NewPostgresStore(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	old := customer("delete-old", 730001, "delete-customer")
	p, err := s.ResolveCustomer(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := refresh.Insert("deletion-test-token-"+p.ID, "test-client", refreshstore.Session{PrincipalID: p.ID}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sid.SetMirror(s)
	redeem := func(holder, subject, externalID string) *surfaceid.Link {
		challenge, err := sid.CreateChallenge(ctx, holder, subject, surfaceid.SurfaceTelegram)
		if err != nil {
			t.Fatal(err)
		}
		linked, err := sid.Redeem(ctx, surfaceid.SurfaceTelegram, challenge.Code, externalID)
		if err != nil {
			t.Fatal(err)
		}
		return linked
	}
	redeem(p.ID, "oidc:delete-customer", "7300011")
	revoked := redeem("github:delete-customer", "", "7300012")
	if _, err := sid.Revoke(ctx, revoked.ID, "github:delete-customer", false); err != nil {
		t.Fatal(err)
	}
	other, err := s.Provision(ctx, github(730099, "other-customer"))
	if err != nil {
		t.Fatal(err)
	}
	redeem("github:other-customer", "", "7300991")
	late, err := sid.CreateChallenge(ctx, p.ID, "oidc:delete-customer", surfaceid.SurfaceTelegram)
	if err != nil {
		t.Fatal(err)
	}

	// Two replicas may both have cached the active identity and local JWT.
	replica := NewResolver(s, nil, false)
	if _, err := replica.ResolvePrincipal(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := replica.CheckPrincipal(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	signup := importTestSignup(t, s)
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed test capacity"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideSignup(ctx, signup.ID, "approved", "730001", "delete-customer", "admin", "Welcome"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimSignup(ctx, auth.ProviderGitHub, "730001", "delete-test", p.ID); err != nil {
		t.Fatal(err)
	}
	d, err := s.PrepareCustomerDeletion(ctx, "delete-test", p.ID, old.Issuer, "admin-approval")
	if err != nil {
		t.Fatal(err)
	}
	if d.Subject != old.Subject || d.GitHubID != "730001" || d.Status != "prepared" {
		t.Fatalf("wrong frozen manifest: %+v", d)
	}
	if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err == nil {
		t.Fatal("completion before begin was accepted")
	}
	if frozen, err := s.CustomerTenantDeletionPending(ctx, d.Tenant); err != nil || !frozen {
		t.Fatalf("tenant name was not frozen: %v %v", frozen, err)
	}
	pending, err := s.CustomerDeletionPending(ctx, auth.ProviderGitHub, d.GitHubID)
	if err != nil || !pending {
		t.Fatalf("pending=%v error=%v", pending, err)
	}
	// The approved prepared intent already fences customer actions, even if
	// workflow submission fails or begin is queued. It cannot create a new
	// workspace after an ordinary removal of the original workspace.
	if err := replica.CheckPrincipal(ctx, p.ID); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("prepared intent still permits API actions: %v", err)
	}
	if err := replica.CheckHumanPrincipal(ctx, p.ID); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("prepared human still acts: %v", err)
	}
	if _, err := replica.ResolvePrincipal(ctx, old); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("prepared subject signs in: %v", err)
	}
	// An already-issued challenge can redeem while the workflow is queued.
	if _, err := sid.Redeem(ctx, surfaceid.SurfaceTelegram, late.Code, "7300013"); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.ResolvePrincipal(ctx, old); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("cached old customer survived cross-replica deletion: %v", err)
	}
	if err := replica.CheckPrincipal(ctx, p.ID); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("cached local token survived cross-replica deletion: %v", err)
	}
	if err := replica.CheckHumanPrincipal(ctx, p.ID); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("human-only checker bypassed cross-replica deletion: %v", err)
	}
	if _, err := s.ResolveCustomer(ctx, old); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("old subject accepted during deletion: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE principals SET status='active' WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err == nil {
		t.Fatal("reactivated principal reported removed")
	}
	if manifest, err := s.CustomerDeletion(ctx, d.Tenant, p.ID); err != nil || manifest.Status != "deleting" {
		t.Fatalf("failed cleanup changed manifest: %+v %v", manifest, err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE principals SET status='disabled' WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.SignupAllowed(ctx, "730001"); err != nil || allowed {
		t.Fatalf("deletion retained invitation authority: %v %v", allowed, err)
	}
	if capacity, err := s.SignupCapacity(ctx); err != nil || capacity.Used != 0 {
		t.Fatalf("deletion retained reserved slot: %+v %v", capacity, err)
	}

	if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
		t.Fatal("retry:", err)
	}
	if _, err := s.ResolveCustomer(ctx, old); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("old subject recreated after deletion: %v", err)
	}
	if pending, err := s.CustomerTenantDeletionPending(ctx, d.Tenant); err != nil || !pending {
		t.Fatalf("name unfrozen before portal release acknowledgment: %v %v", pending, err)
	}
	if err := s.ReleaseCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.ResolveCustomer(ctx, customer("delete-new", 730001, "delete-customer"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ID == p.ID {
		t.Fatal("recreated customer inherited the old principal")
	}
	pending, err = s.CustomerDeletionPending(ctx, auth.ProviderGitHub, d.GitHubID)
	if err != nil || pending {
		t.Fatalf("completed deletion still blocks fresh signup: %v %v", pending, err)
	}
	if frozen, err := s.CustomerTenantDeletionPending(ctx, d.Tenant); err != nil || frozen {
		t.Fatalf("completed deletion still freezes name: %v %v", frozen, err)
	}
	var remaining int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens WHERE principal_id=$1`, p.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("old refresh sessions: %d %v", remaining, err)
	}
	for _, table := range []string{"surface_identity_challenges", "surface_identity_links"} {
		var total, unrelated int
		if err := s.pool.QueryRow(ctx, "SELECT count(*),count(*) FILTER (WHERE principal='github:other-customer') FROM "+table).Scan(&total, &unrelated); err != nil || total != 1 || unrelated != 1 {
			t.Fatalf("%s cleanup isolation: total=%d unrelated=%d err=%v", table, total, unrelated, err)
		}
	}
	ids, err := s.Identities(ctx, p.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("old identities remain: %v %v", ids, err)
	}
	if ids, err := s.Identities(ctx, other.ID); err != nil || len(ids) != 2 {
		t.Fatalf("unrelated surface identity affected: %+v %v", ids, err)
	}
	redeem(fresh.ID, "oidc:delete-customer", "7300011")
	if owner, revoked, found := telegramIdentity(t, s, "7300011"); !found || revoked || owner != fresh.ID {
		t.Fatalf("fresh account could not reuse erased surface link: %s %v %v", owner, revoked, found)
	}

}

func TestCustomerDeletionRefusesUnrelatedAndRevokedIdentities(t *testing.T) {
	for _, mutation := range []string{"third-identity", "revoked"} {
		t.Run(mutation, func(t *testing.T) {
			s := newStoreForTest(t)
			ctx := context.Background()
			id := customer("mixed-old", 730002, "mixed-customer")
			p, err := s.ResolveCustomer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "third-identity" {
				_, err = s.LinkIdentity(ctx, p.ID, auth.Identity{Provider: "dex", Issuer: "https://staff.example", Subject: "staff", Kind: auth.KindHuman})
			} else {
				_, err = s.pool.Exec(ctx, `UPDATE external_identities SET revoked_at=now() WHERE principal_id=$1 AND provider='zitadel'`, p.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.PrepareCustomerDeletion(ctx, "mixed-test", p.ID, id.Issuer, "admin"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe target accepted: %v", err)
			}
			var count int
			if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM customer_deletions`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("refused target left a deletion manifest")
			}
		})
	}
}

func TestCustomerDeletionPendingReadFailureIsUnknown(t *testing.T) {
	s := newStoreForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CustomerDeletionPending(ctx, auth.ProviderGitHub, "730003"); err == nil {
		t.Fatal("failed read reported a clean absence")
	}
}

func TestCustomerDeletionLockDoesNotBorrowAuthenticationPool(t *testing.T) {
	s := newStoreForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := s.pool.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	s.pool.Close()
	s.pool = pool
	other, err := NewStore(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	err = s.WithCustomerDeletionLock(ctx, "lock-test", "customer", func(runCtx context.Context) error {
		var n int
		if err := s.pool.QueryRow(runCtx, "SELECT 1").Scan(&n); err != nil {
			return err
		}
		for _, principal := range []string{"customer", "replacement-customer"} {
			ran := false
			if err := other.WithCustomerDeletionLock(runCtx, "lock-test", principal, func(context.Context) error { ran = true; return nil }); err == nil || ran {
				return errors.New("another principal or replica entered the locked tenant stage")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.WithCustomerDeletionLock(ctx, "lock-test", "customer", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
}

func TestCustomerDeletionLockLossCancelsStages(t *testing.T) {
	s := newStoreForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.WithCustomerDeletionLock(ctx, "lost-lock", "customer", func(runCtx context.Context) error {
		var terminated bool
		if err := s.pool.QueryRow(runCtx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mctl-customer-deletion-lock' AND pid<>pg_backend_pid()").Scan(&terminated); err != nil {
			return err
		}
		if !terminated {
			return errors.New("lock session not terminated")
		}
		<-runCtx.Done()
		return runCtx.Err()
	})
	if err == nil || !strings.Contains(err.Error(), "lock session lost") {
		t.Fatalf("lost session did not fail cleanup: %v", err)
	}
}

func TestCustomerDeletionApprovalRechecksIdentityAfterExternalObservation(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.ResolveCustomer(ctx, customer("approval-race", 730003, "race-customer"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PrepareCustomerDeletion(ctx, "race-tenant", p.ID, "https://auth.mctl.ai", "admin", func(*CustomerDeletion) error {
		_, err := s.LinkIdentity(ctx, p.ID, auth.Identity{Provider: "dex", Issuer: "https://staff.example", Subject: "race", Kind: auth.KindHuman})
		return err
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed identity accepted: %v", err)
	}
}

func TestPreparedCustomerDeletionCancellationRestoresExistingIdentity(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	id := customer("cancel-old", 730004, "cancel-customer")
	p, err := s.ResolveCustomer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	replica := NewResolver(s, nil, false)
	if err := replica.CheckPrincipal(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "cancel-test", p.ID, id.Issuer, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveCustomer(ctx, id); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("direct customer resolution bypassed prepared fence: %v", err)
	}
	if err := s.CancelCustomerDeletion(ctx, "cancel-test", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCustomerDeletion(ctx, "cancel-test", p.ID); err == nil {
		t.Fatal("queued begin survived cancellation")
	}
	if err := replica.CheckPrincipal(ctx, p.ID); err != nil {
		t.Fatalf("cancelled customer still denied: %v", err)
	}
	if linked, err := s.ResolveCustomer(ctx, id); err != nil || linked.ID != p.ID {
		t.Fatalf("cancel changed original identity: %+v %v", linked, err)
	}
	if pending, err := s.CustomerDeletionPending(ctx, auth.ProviderGitHub, "730004"); err != nil || pending {
		t.Fatalf("cancelled customer signup still fenced: %v %v", pending, err)
	}
	if receipt, err := s.CustomerDeletion(ctx, "cancel-test", p.ID); err != nil || !receipt.Cancelled || receipt.Login != "cancel-customer" {
		t.Fatalf("cancellation lost exact target receipt: %+v %v", receipt, err)
	}
	if pending, err := s.CustomerTenantDeletionPending(ctx, "cancel-test"); err != nil || !pending {
		t.Fatalf("name released before portal cancel acknowledgment: %v %v", pending, err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "cancel-test", p.ID, id.Issuer, "admin"); err == nil {
		t.Fatal("cancel receipt reused as a new deletion intent")
	}
	if err := s.FinishCustomerCancellation(ctx, "cancel-test", p.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.CustomerTenantDeletionPending(ctx, "cancel-test"); err != nil || pending {
		t.Fatalf("acknowledged cancellation still freezes name: %v %v", pending, err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "cancel-test", p.ID, id.Issuer, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCustomerDeletion(ctx, "cancel-test", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelCustomerDeletion(ctx, "cancel-test", p.ID); err == nil {
		t.Fatal("begun deletion cancelled")
	}
	if err := replica.CheckPrincipal(ctx, p.ID); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("begun principal restored: %v", err)
	}
}

func TestCustomerDeletionBeginRefusesIdentityMovedByAdministrator(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	id := customer("merge-before-begin", 730005, "merge-customer")
	source, err := s.ResolveCustomer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "merge-before-begin", source.ID, id.Issuer, "admin"); err != nil {
		t.Fatal(err)
	}
	target, err := s.Provision(ctx, auth.Identity{Provider: "zitadel", Issuer: "https://staff.example.test", Subject: "different-account", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergePrincipals(ctx, source.ID, target.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCustomerDeletion(ctx, "merge-before-begin", source.ID); err == nil {
		t.Fatal("deletion began against identities now owned by another principal")
	}
	if d, err := s.CustomerDeletion(ctx, "merge-before-begin", source.ID); err != nil || d.Status != "prepared" {
		t.Fatalf("identity drift advanced deletion: %+v %v", d, err)
	}
	if p, err := s.Get(ctx, target.ID); err != nil || p.Status != StatusActive {
		t.Fatalf("merged target affected: %+v %v", p, err)
	}
	if err := s.CancelCustomerDeletion(ctx, "merge-before-begin", source.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishCustomerCancellation(ctx, "merge-before-begin", source.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledReceiptDoesNotOccupyActiveGitHubIndex(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	id := customer("cancel-index", 730006, "index-customer")
	p, err := s.ResolveCustomer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the pre-migration index, then exercise the real startup migration.
	if _, err := s.pool.Exec(ctx, `CREATE UNIQUE INDEX customer_deletion_pending_github ON customer_deletions(github_id) WHERE status<>'complete'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "cancel-index-a", p.ID, id.Issuer, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelCustomerDeletion(ctx, "cancel-index-a", p.ID); err != nil {
		t.Fatal(err)
	}
	upgraded, err := NewStore(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if _, err := upgraded.PrepareCustomerDeletion(ctx, "cancel-index-b", p.ID, id.Issuer, "admin"); err != nil {
		t.Fatalf("cancel receipt occupied active GitHub uniqueness: %v", err)
	}
	if err := s.FinishCustomerCancellation(ctx, "cancel-index-a", p.ID); err != nil {
		t.Fatal(err)
	}
	if blocked, err := s.CustomerPrincipalDeleted(ctx, p.ID); err != nil || !blocked {
		t.Fatal("old cancellation erased the new intent fence")
	}
	if pending, err := s.CustomerTenantDeletionPending(ctx, "cancel-index-a"); err != nil || pending {
		t.Fatal("old name not released after acknowledgment")
	}
	if pending, err := s.CustomerTenantDeletionPending(ctx, "cancel-index-b"); err != nil || !pending {
		t.Fatal("new intent name fence lost")
	}
}

func TestCustomerDeletionPrepareStorageFailureIsUnknown(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	id := customer("storage-unknown", 730007, "unknown-customer")
	p, err := s.ResolveCustomer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.PrepareCustomerDeletion(cancelled, "storage-unknown", p.ID, id.Issuer, "admin"); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("unreadable preparation classified as observed conflict: %v", err)
	}
}

// Each optional store can be disabled or use another database independently.
func TestCustomerDeletionFinishesWithoutOptionalStoreTables(t *testing.T) {
	for mask := 1; mask < 8; mask++ {
		t.Run(fmt.Sprintf("absent-%d", mask), func(t *testing.T) {
			s := newStoreForTest(t)
			ctx := context.Background()
			sid, err := surfaceid.NewStore(ctx, os.Getenv("TEST_DATABASE_URL"), 0)
			if err != nil {
				t.Fatal(err)
			}
			sid.Close()
			if _, err := refreshstore.NewPostgresStore(ctx, os.Getenv("TEST_DATABASE_URL")); err != nil {
				t.Fatal(err)
			}
			// Preserve shared fixture tables and their data. Tests using this DB
			// run serially; cleanup restores the names even when an assertion fails.
			for i, table := range []string{"surface_identity_links", "surface_identity_challenges", "oauth_refresh_tokens"} {
				if mask&(1<<i) == 0 {
					continue
				}
				if _, err := s.pool.Exec(ctx, "ALTER TABLE "+table+" RENAME TO deletion_fixture_"+table); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := s.pool.Exec(ctx, "ALTER TABLE deletion_fixture_"+table+" RENAME TO "+table); err != nil {
						t.Error(err)
					}
				})
			}
			old := customer("optional-old", 739001, "optional-customer")
			p, err := s.ResolveCustomer(ctx, old)
			if err != nil {
				t.Fatal(err)
			}
			d, err := s.PrepareCustomerDeletion(ctx, "optional-test", p.ID, old.Issuer, "admin")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.BeginCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.FinishCustomerDeletion(ctx, d.Tenant, p.ID); err != nil {
				t.Fatalf("retry: %v", err)
			}
			d, err = s.CustomerDeletion(ctx, d.Tenant, p.ID)
			if err != nil || d.Status != "complete" {
				t.Fatalf("completion: %+v %v", d, err)
			}
			fresh, err := s.ResolveCustomer(ctx, customer("optional-new", 739001, "optional-customer"))
			if err != nil || fresh.ID == p.ID {
				t.Fatalf("fresh signup: %+v %v", fresh, err)
			}
		})
	}
}

// mctl-api#1079: a Google customer is deleted by its Google subject. The
// manifest names no GitHub account, the re-registration fence and the
// signup release are keyed on the subject, and a GitHub customer whose id
// has the same digits is a different customer throughout.
func TestCustomerDeletionOfAGoogleCustomer(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	const sub = "7300551234"
	gc := googleCustomer("delete-google", sub)
	p, err := s.ResolveCustomer(ctx, gc)
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.ResolveCustomer(ctx, customer("delete-same-digits", 7300551234, "same-digits"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSignupCapacity(ctx, 3, "admin", "Reviewed test capacity"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimPublicSignup(ctx, auth.ProviderGoogle, sub, "delete-google", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimPublicSignup(ctx, auth.ProviderGitHub, sub, "keep-github", same.ID); err != nil {
		t.Fatal(err)
	}

	d, err := s.PrepareCustomerDeletion(ctx, "delete-google", p.ID, gc.Issuer, "admin-approval")
	if err != nil {
		t.Fatal(err)
	}
	if d.GoogleSub != sub || d.GitHubID != "" || d.Login != "" || d.Subject != gc.Subject {
		t.Fatalf("wrong frozen Google manifest: %+v", d)
	}
	stored, err := s.CustomerDeletion(ctx, "delete-google", p.ID)
	if err != nil || *stored != *d {
		t.Fatalf("stored manifest %+v (%v), want %+v", stored, err, d)
	}
	for _, tc := range []struct {
		provider, subject string
		want              bool
	}{
		{auth.ProviderGoogle, sub, true},
		{auth.ProviderGitHub, sub, false},
	} {
		pending, err := s.CustomerDeletionPending(ctx, tc.provider, tc.subject)
		if err != nil || pending != tc.want {
			t.Fatalf("%s %s pending=%v (%v), want %v", tc.provider, tc.subject, pending, err, tc.want)
		}
	}
	for _, bad := range [][2]string{{auth.ProviderGoogle, "abc"}, {auth.ProviderGoogle, ""}, {"gitlab", sub}, {auth.ProviderGitHub, ""}, {auth.ProviderGitHub, "google:" + sub}} {
		if _, err := s.CustomerDeletionPending(ctx, bad[0], bad[1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("pending(%q,%q) = %v, want ErrInvalid", bad[0], bad[1], err)
		}
	}
	// One active deletion per Google customer, as for GitHub.
	if _, err := s.PrepareCustomerDeletion(ctx, "delete-google-2", p.ID, gc.Issuer, "admin-approval"); err == nil {
		t.Fatal("a second active deletion of the same Google customer was accepted")
	}
	// The GitHub customer with the same digits is deletable alongside.
	other, err := s.PrepareCustomerDeletion(ctx, "keep-github", same.ID, gc.Issuer, "admin-approval")
	if err != nil {
		t.Fatalf("GitHub customer with the same digits: %v", err)
	}
	if other.GitHubID != sub || other.GoogleSub != "" || other.Login != "same-digits" {
		t.Fatalf("wrong GitHub manifest: %+v", other)
	}
	if err := s.CancelCustomerDeletion(ctx, "keep-github", same.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.BeginCustomerDeletion(ctx, "delete-google", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishCustomerDeletion(ctx, "delete-google", p.ID); err != nil {
		t.Fatal(err)
	}
	var googleStatus, githubStatus string
	if err := s.pool.QueryRow(ctx, `SELECT status FROM signup_requests WHERE tenant='delete-google'`).Scan(&googleStatus); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT status FROM signup_requests WHERE tenant='keep-github'`).Scan(&githubStatus); err != nil {
		t.Fatal(err)
	}
	if googleStatus != "released" || githubStatus != "claimed" {
		t.Fatalf("signup statuses google=%s github=%s, want released and claimed", googleStatus, githubStatus)
	}
	if _, err := s.Get(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Google principal survived: %v", err)
	}
	// Still fenced until the portal releases it, then free.
	if pending, err := s.CustomerDeletionPending(ctx, auth.ProviderGoogle, sub); err != nil || !pending {
		t.Fatalf("unreleased Google deletion pending=%v (%v)", pending, err)
	}
	if err := s.ReleaseCustomerDeletion(ctx, "delete-google", p.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.CustomerDeletionPending(ctx, auth.ProviderGoogle, sub); err != nil || pending {
		t.Fatalf("released Google deletion pending=%v (%v)", pending, err)
	}
}

// A principal holding both a GitHub and a Google identity, or a Google
// identity that is not a valid subject, is no customer to delete.
func TestCustomerDeletionRefusesMixedOrMalformedGoogleIdentities(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	gc := googleCustomer("delete-mixed", "7300661234")
	p, err := s.ResolveCustomer(ctx, gc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO external_identities (id,principal_id,provider,issuer,subject,display,verified_at) VALUES ('mixed-gh',$1,'github','','7300661235','mixed',now())`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "delete-mixed", p.ID, gc.Issuer, "admin-approval"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mixed principal: %v, want ErrInvalid", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM external_identities WHERE id='mixed-gh'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE external_identities SET subject='not-a-sub' WHERE principal_id=$1 AND provider='google'`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "delete-mixed", p.ID, gc.Issuer, "admin-approval"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed Google subject: %v, want ErrInvalid", err)
	}
}

// A surface may not be named after the Google provider: a mirrored
// (google, ”, x) identity would be a Google customer key.
func TestSurfaceCannotTakeTheGoogleProviderName(t *testing.T) {
	if !reservedProvider(auth.ProviderGoogle) {
		t.Fatal("google is not a reserved provider name")
	}
}

// Begin re-reads the identities: a Google subject swapped after approval is
// refused, and a GitHub customer still needs its login.
func TestCustomerDeletionBeginRefusesAChangedGoogleSubjectAndGitHubNeedsALogin(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	gc := googleCustomer("delete-swap", "7300771234")
	p, err := s.ResolveCustomer(ctx, gc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "delete-swap", p.ID, gc.Issuer, "admin-approval"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE external_identities SET subject='7300771299' WHERE principal_id=$1 AND provider='google'`, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCustomerDeletion(ctx, "delete-swap", p.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("begin after the Google subject changed: %v, want ErrInvalid", err)
	}

	cc := customer("delete-nologin", 7300781234, "no-login")
	q, err := s.ResolveCustomer(ctx, cc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE external_identities SET display='' WHERE principal_id=$1 AND provider='github'`, q.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareCustomerDeletion(ctx, "delete-nologin", q.ID, cc.Issuer, "admin-approval"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("GitHub customer without a login: %v, want ErrInvalid", err)
	}
}
