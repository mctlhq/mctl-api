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
	"github.com/mctlhq/mctl-api/internal/audit"
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
	releaseErr             error
	releaseCalls, released int
	readErr                error
	job                    *principals.CustomerDeletion
	prepared, finished     int
}

func (s *deletionStore) ReleaseCustomerDeletion(context.Context, string, string) error {
	s.releaseCalls++
	if s.releaseErr != nil {
		return s.releaseErr
	}
	s.released++
	return nil
}

func (s *deletionStore) WithCustomerDeletionLock(ctx context.Context, _, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}
func (s *deletionStore) CustomerDeletion(context.Context, string, string) (*principals.CustomerDeletion, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
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

func TestCustomerDeletionResourceGuardRefusesReplacementAndCompletedReplay(t *testing.T) {
	h, reader, store, calls, _ := deletionFixture()
	admin := userWithPrincipal(t, "admin", []string{"admins"}, deletionAdmin)
	if ok, w := prepareDeletion(t, h, admin); !ok {
		t.Fatal(w.Body.String())
	}
	params := map[string]string{"tenant": "acme", "principal": deletionPID, "stage": "begin"}
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	params["stage"] = "resources"
	*calls = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if len(*calls) != 0 {
		t.Fatal("resource guard called external cleanup")
	}
	reader.tenants[0].Members[0].PrincipalID = deletionAdmin
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code == 200 {
		t.Fatal("replacement workspace passed old resource guard")
	}
	store.job.Status = "complete"
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 409 {
		t.Fatalf("completed deletion replayed resource removal: %d", w.Code)
	}
}

func TestCustomerDeletionNameFreezeCoversAdministratorCreation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending bool
		err     error
		status  int
	}{
		{"pending", true, nil, 409}, {"unknown", false, errors.New("database unavailable"), 503}, {"clear", false, nil, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{opts: Options{CustomerTenantDeletionPending: func(_ context.Context, name string) (bool, error) {
				if name != "acme" {
					t.Fatal("wrong name")
				}
				return tc.pending, tc.err
			}}}
			r := httptest.NewRequest("POST", "/", nil)
			w := httptest.NewRecorder()
			allowed := h.guardCustomerTenantCreation(w, r, "create-tenant", map[string]string{"tenant_name": "acme"})
			if allowed != (tc.status == 200) || w.Code != tc.status {
				t.Fatalf("allowed=%v status=%d", allowed, w.Code)
			}
		})
	}
}

func TestCustomerDeletionUnreadableManifestIsRetryable(t *testing.T) {
	h, _, store, _, _ := deletionFixture()
	store.readErr = errors.New("database unavailable")
	params := map[string]string{"tenant": "acme", "principal": deletionPID, "stage": "begin"}
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 503 {
		t.Fatalf("unknown read returned %d", w.Code)
	}
	store.readErr = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 409 {
		t.Fatalf("absent manifest returned %d", w.Code)
	}
}
func TestCustomerDeletionRefusalsAreAudited(t *testing.T) {
	h, _, _, _, _ := deletionFixture()
	logger := audit.NewLogger()
	h.opts.AuditLog = logger
	if ok, _ := prepareDeletion(t, h, userWithPrincipal(t, "alice", nil, deletionPID)); ok {
		t.Fatal("non-admin allowed")
	}
	entries := logger.List(10)
	if len(entries) != 1 || entries[0].Status != "denied" || entries[0].Parameters["principal_id"] != deletionPID {
		t.Fatalf("missing refusal audit: %+v", entries)
	}
}

func TestPreparedCustomerDeletionResumesAfterOrdinaryWorkspaceRemoval(t *testing.T) {
	h, reader, store, calls, _ := deletionFixture()
	admin := userWithPrincipal(t, "admin", []string{"admins"}, deletionAdmin)
	if ok, w := prepareDeletion(t, h, admin); !ok {
		t.Fatal(w.Body.String())
	}
	reader.tenants = nil
	*calls = nil
	if ok, w := prepareDeletion(t, h, admin); !ok {
		t.Fatalf("prepared recovery refused: %s", w.Body.String())
	}
	if store.prepared != 1 || !reflect.DeepEqual(*calls, []string{"freeze"}) {
		t.Fatalf("approved target recaptured: %d %v", store.prepared, *calls)
	}
	reader.err = errors.New("GitOps unreadable")
	if ok, w := prepareDeletion(t, h, admin); ok || w.Code != 503 {
		t.Fatalf("unknown treated as absent: %v %d", ok, w.Code)
	}
	reader.err = nil
	reader.tenants = []gitops.Tenant{{Name: "acme", Members: []gitops.TenantMember{{PrincipalID: deletionAdmin, Role: "owner"}}}}
	if ok, w := prepareDeletion(t, h, admin); ok || w.Code != 409 {
		t.Fatalf("replacement owner accepted: %v %d", ok, w.Code)
	}
}

func TestCustomerDeletionRecordsReleaseOnlyAfterPortalAcknowledgment(t *testing.T) {
	h, _, store, calls, fail := deletionFixture()
	store.job = &principals.CustomerDeletion{Tenant: "acme", PrincipalID: deletionPID, Login: "alice", Status: "complete"}
	params := map[string]string{"tenant": "acme", "principal": deletionPID, "stage": "complete"}
	*fail = "release"
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 503 {
		t.Fatal(w.Body.String())
	}
	if store.releaseCalls != 0 {
		t.Fatal("recorded release before portal acknowledgment")
	}
	*fail = ""
	store.releaseErr = errors.New("ledger unavailable")
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 503 {
		t.Fatal(w.Body.String())
	}
	if store.released != 0 {
		t.Fatal("failed durable acknowledgment reported released")
	}
	store.releaseErr = nil
	*calls = nil
	if w := callAs(h, auth.NewServiceUser(), "POST", "/", params, h.AdvanceCustomerDeletion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if store.released != 1 || store.finished != 0 || !reflect.DeepEqual(*calls, []string{"release"}) {
		t.Fatalf("completed recovery repeated cleanup: %d %d %v", store.released, store.finished, *calls)
	}
}
