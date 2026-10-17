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
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/principals"
)

var errCustomerDeletionUnobserved = errors.New("customer deletion observation unavailable")

var customerDeletionTenantName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type CustomerDeletionStore interface {
	WithCustomerDeletionLock(context.Context, string, string, func() error) error

	PrepareCustomerDeletion(context.Context, string, string, string, string, ...func(*principals.CustomerDeletion) error) (*principals.CustomerDeletion, error)
	CustomerDeletion(context.Context, string, string) (*principals.CustomerDeletion, error)
	BeginCustomerDeletion(context.Context, string, string) error
	FinishCustomerDeletion(context.Context, string, string) error
}

// CustomerDeletionOptions is deliberately opt-in. Missing providers refuse the
// complete-account option before a workspace deletion is submitted.
type CustomerDeletionOptions struct {
	Store              CustomerDeletionStore
	Issuer             string
	VerifyCustomer     func(context.Context, *principals.CustomerDeletion) error
	DeleteCustomer     func(context.Context, *principals.CustomerDeletion) error
	RevokeSiteSessions func(context.Context, *principals.CustomerDeletion) error
	CleanPortal        func(context.Context, *principals.CustomerDeletion) error
	FreezePortal       func(context.Context, *principals.CustomerDeletion) error
	ReleasePortal      func(context.Context, *principals.CustomerDeletion) error
	CheckPlatformGone  func(context.Context, string) error
	RevokeSessions     func(string, string) (int64, error)
	ForgetPrincipals   func(...string)
}

func (o *CustomerDeletionOptions) configured() bool {
	return o != nil && o.Store != nil && o.Issuer != "" && o.VerifyCustomer != nil && o.DeleteCustomer != nil &&
		o.FreezePortal != nil && o.ReleasePortal != nil && o.RevokeSiteSessions != nil && o.CleanPortal != nil && o.CheckPlatformGone != nil && o.RevokeSessions != nil && o.ForgetPrincipals != nil
}

// customerMemberships uses a complete directory read and checks every tenant's
// parse result. An unreadable later tenant must not become "no other access".
func (h *Handlers) customerMemberships(tenant, pid, login string, requireOwner bool) error {
	strict, ok := h.opts.GitReader.(interface {
		ListTenantsStrict() ([]gitops.Tenant, error)
	})
	if !ok {
		return fmt.Errorf("%w: strict tenant reader", errCustomerDeletionUnobserved)
	}
	tenants, err := strict.ListTenantsStrict()
	if err != nil {
		return fmt.Errorf("%w: tenant listing", errCustomerDeletionUnobserved)
	}
	found := false
	for _, t := range tenants {
		if err := t.PrincipalKeysErr(); err != nil {
			return fmt.Errorf("%w: tenant membership parsing", errCustomerDeletionUnobserved)
		}
		all := append([]gitops.TenantMember{}, t.Members...)
		for _, team := range t.Teams {
			all = append(all, team.Members...)
		}
		for _, m := range all {
			if m.PrincipalID == pid || (login != "" && strings.EqualFold(m.UserID, login)) {
				if !requireOwner || t.Name != tenant || len(t.Teams) != 0 || len(t.Members) != 1 || m.PrincipalID != pid || m.Role != "owner" {
					return fmt.Errorf("customer has other or ambiguous access")
				}
				found = true
			}
		}
	}
	if requireOwner && !found {
		return fmt.Errorf("exclusive principal-keyed owner not observed")
	}
	return nil
}

func (h *Handlers) prepareCustomerAccountDeletion(w http.ResponseWriter, r *http.Request, input map[string]string) bool {
	if input["delete_customer_account"] != "true" {
		if input["customer_principal_id"] != "" {
			writeError(w, 400, "customer_principal_id requires delete_customer_account=true")
			return false
		}
		return true
	}
	u := auth.UserFromContext(r.Context())
	if u == nil || !isHumanAdmin(u) || u.IsAgent() || u.ViaPrincipalID() != "" || u.PrincipalID() == "" {
		writeError(w, 403, "complete customer deletion requires a direct human platform administrator")
		return false
	}
	pid := input["customer_principal_id"]
	if !auth.ValidPrincipalID(pid) || pid == u.PrincipalID() || h.opts.AdminPrincipals[pid] {
		writeError(w, 400, "invalid or protected customer principal")
		return false
	}
	o := h.opts.CustomerDeletion
	if !o.configured() {
		writeError(w, 503, "complete customer deletion is not configured")
		return false
	}
	tenant := input["tenant_name"]
	previous, readErr := o.Store.CustomerDeletion(r.Context(), tenant, pid)
	if readErr != nil && !errors.Is(readErr, pgx.ErrNoRows) {
		writeError(w, 503, "customer deletion state could not be read")
		return false
	}
	if previous != nil && previous.Status == "complete" {
		if err := o.ReleasePortal(r.Context(), previous); err != nil {
			writeError(w, 503, "customer deletion is awaiting portal release")
			return false
		}
		writeJSON(w, 200, map[string]string{"status": "complete", "tenant": tenant, "principal_id": pid})
		return false
	}
	var d *principals.CustomerDeletion
	if previous != nil && previous.Status == "deleting" {
		exists, err := h.opts.GitReader.TenantExists(tenant)
		if err != nil || h.customerMemberships(tenant, pid, previous.Login, exists) != nil {
			writeError(w, 409, "customer ownership or absence could not be verified")
			return false
		}
		d = previous
	} else {
		var err error
		d, err = o.Store.PrepareCustomerDeletion(r.Context(), tenant, pid, o.Issuer, u.PrincipalID(), func(target *principals.CustomerDeletion) error {
			if err := h.customerMemberships(target.Tenant, target.PrincipalID, target.Login, true); err != nil {
				return err
			}
			if err := o.VerifyCustomer(r.Context(), target); err != nil {
				return fmt.Errorf("%w: IdP identity", errCustomerDeletionUnobserved)
			}
			return nil
		})
		if err != nil {
			status := 409
			if errors.Is(err, errCustomerDeletionUnobserved) {
				status = 503
			}
			writeError(w, status, "exclusive customer identity and ownership could not be verified")
			return false
		}
	}
	if err := o.FreezePortal(r.Context(), d); err != nil {
		writeError(w, 503, "portal customer deletion freeze could not be verified")
		return false
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "customer.delete.prepare", Status: "succeeded", RiskLevel: "high", Parameters: map[string]string{"tenant": d.Tenant, "principal_id": d.PrincipalID}})
	return true
}

// AdvanceCustomerDeletion is a platform-workflow callback, not a surface or
// delegated-human route. The target comes from the frozen approval manifest.
func (h *Handlers) AdvanceCustomerDeletion(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil || !u.IsService() {
		writeError(w, 403, "platform workflow principal required")
		return
	}
	o := h.opts.CustomerDeletion
	if !o.configured() {
		writeError(w, 503, "customer deletion is not configured")
		return
	}
	tenant, pid, stage := chi.URLParam(r, "tenant"), chi.URLParam(r, "principal"), chi.URLParam(r, "stage")
	if !customerDeletionTenantName.MatchString(tenant) || !auth.ValidPrincipalID(pid) || (stage != "begin" && stage != "complete") {
		writeError(w, 400, "invalid deletion target or stage")
		return
	}
	d, err := o.Store.CustomerDeletion(r.Context(), tenant, pid)
	if err != nil {
		writeError(w, 409, "approved customer deletion manifest unavailable")
		return
	}
	if d.Status == "complete" {
		if err := o.ReleasePortal(r.Context(), d); err != nil {
			writeError(w, 503, "portal release incomplete")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "complete"})
		return
	}
	if h.opts.AdminPrincipals[pid] {
		writeError(w, 409, "principal became protected")
		return
	}
	phase := stage
	run := func() error {
		if stage == "begin" {
			exists, err := h.opts.GitReader.TenantExists(tenant)
			if err != nil {
				return err
			}
			if err := h.customerMemberships(tenant, pid, d.Login, exists); err != nil {
				return err
			}
			if d.Status == "prepared" {
				if err := o.VerifyCustomer(r.Context(), d); err != nil {
					return err
				}
			}

			if err := o.Store.BeginCustomerDeletion(r.Context(), tenant, pid); err != nil {
				return err
			}
			o.ForgetPrincipals(pid)
			_, err = o.RevokeSessions(pid, "customer_account_deleted")
			return err
		}
		if d.Status != "deleting" {
			return errors.New("account deletion has not begun")
		}
		if err := h.customerMemberships(tenant, pid, d.Login, false); err != nil {
			return err
		}
		if exists, err := h.opts.GitReader.TenantExists(tenant); err != nil || exists {
			return errors.New("GitOps tenant absence not confirmed")
		}
		phase = "platform"
		if err := o.CheckPlatformGone(r.Context(), tenant); err != nil {
			return fmt.Errorf("platform postcondition: %w", err)
		}
		phase = "zitadel"
		if err := o.DeleteCustomer(r.Context(), d); err != nil {
			return fmt.Errorf("IdP deletion: %w", err)
		}
		phase = "site-sessions"
		if err := o.RevokeSiteSessions(r.Context(), d); err != nil {
			return fmt.Errorf("site session revocation: %w", err)
		}
		phase = "portal"
		if err := o.CleanPortal(r.Context(), d); err != nil {
			return fmt.Errorf("portal cleanup: %w", err)
		}
		if _, err := o.RevokeSessions(pid, "customer_account_deleted"); err != nil {
			return err
		}
		phase = "principal"
		if err := o.Store.FinishCustomerDeletion(r.Context(), tenant, pid); err != nil {
			return err
		}
		o.ForgetPrincipals(pid)
		phase = "portal-release"
		return o.ReleasePortal(r.Context(), d)
	}
	err = o.Store.WithCustomerDeletionLock(r.Context(), tenant, pid, func() error {
		fresh, err := o.Store.CustomerDeletion(r.Context(), tenant, pid)
		if err != nil {
			return err
		}
		if fresh.Status == "complete" {
			return o.ReleasePortal(r.Context(), fresh)
		}
		d = fresh
		return run()
	})
	status := "succeeded"
	if err != nil {
		status = "failed"
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "customer.delete." + stage, Status: status, RiskLevel: "high", Parameters: map[string]string{"tenant": tenant, "principal_id": pid}})
	if err != nil {
		writeErrorCode(w, 503, "customer_deletion_incomplete", "Customer deletion incomplete; retry", map[string]interface{}{"stage": phase})
		return
	}
	writeJSON(w, 200, map[string]string{"stage": stage, "status": "succeeded"})
}
