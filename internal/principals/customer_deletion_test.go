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
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
	"os"
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
	if err := refresh.Insert("deletion-test-token", "test-client", refreshstore.Session{PrincipalID: p.ID}, time.Now().Add(time.Hour)); err != nil {
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
	pending, err := s.CustomerDeletionPending(ctx, d.GitHubID)
	if err != nil || !pending {
		t.Fatalf("pending=%v error=%v", pending, err)
	}
	// Two replicas may both have cached the active identity and local JWT.
	replica := NewResolver(s, nil, false)
	if _, err := replica.ResolvePrincipal(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := replica.CheckPrincipal(ctx, p.ID); err != nil {
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
	if _, err := s.ResolveCustomer(ctx, old); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("old subject accepted during deletion: %v", err)
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
	var remaining int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens WHERE principal_id=$1`, p.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("old refresh sessions: %d %v", remaining, err)
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
			s.pool.QueryRow(ctx, `SELECT count(*) FROM customer_deletions`).Scan(&count)
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
