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

package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const deletionPID = "prn_01M45DR1GWC87109EH88VBJX25"
const deletionAdmin = "prn_01M45DR1GWC87109EH88VBJX26"

type deletionReader struct {
	GitReader
	tenants []gitops.Tenant
	err     error
}

func (r *deletionReader) ListTenantsStrict() ([]gitops.Tenant, error) { return r.tenants, r.err }
func (r *deletionReader) TenantExists(name string) (bool, error) {
	for i := range r.tenants {
		t := &r.tenants[i]
		if t.Name == name {
			return true, r.err
		}
	}
	return false, r.err
}

type deletionStore struct {
	job                *principals.CustomerDeletion
	prepared, finished int
}

func (s *deletionStore) WithCustomerDeletionLock(_ context.Context, _, _ string, fn func() error) error {
	return fn()
}
func (s *deletionStore) CustomerDeletion(context.Context, string, string) (*principals.CustomerDeletion, error) {
	if s.job == nil {
		return nil, pgx.ErrNoRows
	}
	d := *s.job
	return &d, nil
}
func (s *deletionStore) PrepareCustomerDeletion(_ context.Context, tenant, pid, issuer, actor string, checks ...func(*principals.CustomerDeletion) error) (*principals.CustomerDeletion, error) {
	d := &principals.CustomerDeletion{Tenant: tenant, PrincipalID: pid, Issuer: issuer, Subject: "7001", GitHubID: "123", Login: "alice", Actor: actor, Status: "prepared"}
	for _, check := range checks {
		if err := check(d); err != nil {
			return nil, err
		}
	}
	s.job = d
	s.prepared++
	return d, nil
}
func (s *deletionStore) BeginCustomerDeletion(context.Context, string, string) error {
	s.job.Status = "deleting"
	return nil
}
func (s *deletionStore) FinishCustomerDeletion(context.Context, string, string) error {
	s.job.Status = "complete"
	s.finished++
	return nil
}

func deletionFixture() (*Handlers, *deletionReader, *deletionStore, *[]string, *string) {
	reader := &deletionReader{tenants: []gitops.Tenant{{Name: "acme", Members: []gitops.TenantMember{{UserID: "alice", PrincipalID: deletionPID, Role: "owner"}}}}}
	store := &deletionStore{}
	calls := []string{}
	fail := ""
	step := func(name string) func(context.Context, *principals.CustomerDeletion) error {
		return func(context.Context, *principals.CustomerDeletion) error {
			calls = append(calls, name)
			if fail == name {
				return errors.New("provider unavailable")
			}
			return nil
		}
	}
	h := &Handlers{opts: Options{GitReader: reader, AdminPrincipals: map[string]bool{deletionAdmin: true}, CustomerDeletion: &CustomerDeletionOptions{
		Store: store, Issuer: "https://auth.mctl.ai", VerifyCustomer: step("verify"), DeleteCustomer: step("zitadel"), RevokeSiteSessions: step("site"), CleanPortal: step("portal"), FreezePortal: step("freeze"), ReleasePortal: step("release"),
		CheckPlatformGone: func(context.Context, string) error {
			calls = append(calls, "platform")
			if fail == "platform" {
				return errors.New("unreadable")
			}
			return nil
		},
		RevokeSessions: func(string, string) (int64, error) { calls = append(calls, "refresh"); return 1, nil }, ForgetPrincipals: func(...string) {},
	}}}
	return h, reader, store, &calls, &fail
}

func prepareDeletion(t *testing.T, h *Handlers, user *auth.User) (bool, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	r := asUser(httptest.NewRequest("POST", "/", nil), user)
	ok := h.prepareCustomerAccountDeletion(w, r, map[string]string{"tenant_name": "acme", "delete_customer_account": "true", "customer_principal_id": deletionPID})
	return ok, w
}

func TestCustomerDeletionRequiresDirectAdminAndExclusiveOwnership(t *testing.T) {
	for _, kind := range []string{"member", "service", "other-principal-membership", "other-login-membership", "multiple-members", "unreadable", "IdP-unreadable"} {
		t.Run(kind, func(t *testing.T) {
			h, reader, store, _, fail := deletionFixture()
			user := userWithPrincipal(t, "admin", []string{"admins"}, deletionAdmin)
			switch kind {
			case "member":
				user = userWithPrincipal(t, "alice", nil, deletionPID)
			case "service":
				user = auth.NewServiceUser()
			case "other-principal-membership":
				reader.tenants = append(reader.tenants, gitops.Tenant{Name: "other", Members: []gitops.TenantMember{{PrincipalID: deletionPID, Role: "developer"}}})
			case "other-login-membership":
				reader.tenants = append(reader.tenants, gitops.Tenant{Name: "staff", Members: []gitops.TenantMember{{UserID: "ALICE", Role: "owner"}}})
			case "multiple-members":
				reader.tenants[0].Members = append(reader.tenants[0].Members, gitops.TenantMember{UserID: "bob", Role: "viewer"})
			case "unreadable":
				reader.err = errors.New("later tenant unreadable")
			case "IdP-unreadable":
				*fail = "verify"
			}
			ok, w := prepareDeletion(t, h, user)
			if ok || w.Code < 400 || store.prepared != 0 {
				t.Fatalf("unsafe deletion prepared: %v HTTP %d writes %d", ok, w.Code, store.prepared)
			}
			if (kind == "unreadable" || kind == "IdP-unreadable") && w.Code != 503 {
				t.Fatalf("unknown observation must be 503, got %d", w.Code)
			}
		})
	}
}

func TestCustomerDeletionStopsAndResumesWithoutRepeatingCompletedTeardown(t *testing.T) {
	h, reader, store, calls, fail := deletionFixture()
	admin := userWithPrincipal(t, "admin", []string{"admins"}, deletionAdmin)
	if ok, w := prepareDeletion(t, h, admin); !ok {
		t.Fatal(w.Body.String())
	}
	params := map[string]string{"tenant": "acme", "principal": deletionPID, "stage": "begin"}
	if w := callAs(h, admin, "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 403 {
		t.Fatal("human reached workflow callback")
	}
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	reader.tenants = nil
	params["stage"] = "complete"
	*fail = "site"
	*calls = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 503 {
		t.Fatal("partial cleanup accepted")
	}
	if store.finished != 0 || store.job.Status != "deleting" {
		t.Fatal("partial cleanup purged principal")
	}
	if !reflect.DeepEqual(*calls, []string{"platform", "zitadel", "site"}) {
		t.Fatalf("wrong order: %v", *calls)
	}
	*fail = ""
	*calls = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if store.finished != 1 || store.job.Status != "complete" {
		t.Fatal("cleanup did not complete")
	}
	*calls = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if !reflect.DeepEqual(*calls, []string{"release"}) || store.finished != 1 {
		t.Fatal("completed retry repeated destructive work")
	}
}

func TestCustomerDeletionResumeNeverDeletesAReplacementWorkspace(t *testing.T) {
	h, reader, store, calls, _ := deletionFixture()
	store.job = &principals.CustomerDeletion{Tenant: "acme", PrincipalID: deletionPID, Login: "alice", Status: "deleting"}
	reader.tenants[0].Members = []gitops.TenantMember{{UserID: "bob", PrincipalID: deletionAdmin, Role: "owner"}}
	admin := userWithPrincipal(t, "admin", []string{"admins"}, deletionAdmin)
	if ok, _ := prepareDeletion(t, h, admin); ok {
		t.Fatal("replacement workspace accepted")
	}
	if len(*calls) != 0 {
		t.Fatal("replacement workspace mutated")
	}
}
