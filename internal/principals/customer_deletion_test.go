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
	for _, holder := range []string{p.ID, "github:delete-customer", "github:other-customer"} {
		if _, err := s.pool.Exec(ctx, `INSERT INTO surface_identity_challenges(id,code_hash,principal,surface,created_at,expires_at) VALUES($1,$1,$1,'telegram',now(),now()+interval '1 hour')`, holder); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO surface_identity_links(id,surface,external_id,principal,challenge_id,created_at) VALUES($1,'telegram',$1,$1,$1,now())`, holder); err != nil {
			t.Fatal(err)
		}
	}
	// Two replicas may both have cached the active identity and local JWT.
	replica := NewResolver(s, nil, false)
	if _, err := replica.ResolvePrincipal(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := replica.CheckPrincipal(ctx, p.ID); err != nil {
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
	pending, err := s.CustomerDeletionPending(ctx, d.GitHubID)
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
	pending, err = s.CustomerDeletionPending(ctx, d.GitHubID)
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
	if _, err := s.CustomerDeletionPending(ctx, "730003"); err == nil {
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
	if pending, err := s.CustomerDeletionPending(ctx, "730004"); err != nil || pending {
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
