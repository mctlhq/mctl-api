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

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Tenant member principal-key plan (mctl-api#377 A5).
//
// Before principal mode, every GitOps member entry needs a principalId. This
// endpoint proposes one per entry and changes nothing: no principal is
// provisioned, no file is written. A human reviews the output and turns it
// into an mctl-gitops PR. A login is resolved through the live GitHub
// identity (its numeric id, as GitHub reports it now), never through the
// login string alone, since a login can be renamed and then reused.
//
// The plan is complete only when nothing blocks it: every entry keyed or
// with a proposal, no unreadable tenant, no invalid key. An entry that
// cannot be resolved is a blocker, never a skip.

// MemberKeyPlanStore is the read-only part of the principal store the plan
// uses.
type MemberKeyPlanStore interface {
	LookupIdentity(ctx context.Context, provider, issuer, subject string) (*principals.Principal, bool, error)
	Get(ctx context.Context, id string) (*principals.Principal, error)
}

// MemberKeyPlanOptions wires the plan. Nil (or any nil field) makes the
// endpoint 503.
type MemberKeyPlanOptions struct {
	Entries interface {
		AllMemberEntries() (gitops.MemberEntries, error)
	}
	Store    MemberKeyPlanStore
	GitHubID principals.GitHubIDLookup
}

// Entry statuses. keyed and propose are fine; the rest block the plan.
const (
	planKeyed      = "keyed"      // principalId present and its principal active
	planPropose    = "propose"    // no principalId yet; ProposedPrincipalID is the one to add
	planUnresolved = "unresolved" // no principal can be named for it; Reason says why
	planMismatch   = "mismatch"   // principalId and userId name different principals
	planInvalid    = "invalid"    // principalId is malformed
	// planUnverified: principalId names an active principal, but userId
	// beside it could not be resolved, so the two were never checked
	// against each other. A transient GitHub failure costs a retry, never a
	// silent pass for a key that may belong to someone else.
	planUnverified = "unverified"
)

type memberKeyPlanEntry struct {
	gitops.MemberEntry
	Status              string `json:"status"`
	ProposedPrincipalID string `json:"proposedPrincipalId,omitempty"`
	// LoginPrincipalID is the principal userId resolves to, when it does.
	LoginPrincipalID string `json:"loginPrincipalId,omitempty"`
	GitHubID         int64  `json:"githubId,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Detail           string `json:"detail,omitempty"`
}

type memberKeyPlan struct {
	Complete          bool                 `json:"complete"`
	Blockers          int                  `json:"blockers"`
	Counts            map[string]int       `json:"counts"`
	Entries           []memberKeyPlanEntry `json:"entries"`
	UnreadableTenants []string             `json:"unreadableTenants"`
	KeyErrors         map[string]string    `json:"keyErrors"`
}

// loginResolution is what one login resolved to; cached per plan, since a
// login usually appears in several entries.
type loginResolution struct {
	principalID string
	githubID    int64
	reason      string // empty when principalID is set
	detail      string
}

// TenantMemberPrincipalPlan handles GET
// /api/v1/admin/tenant-members/principal-plan.
func (h *Handlers) TenantMemberPrincipalPlan(w http.ResponseWriter, r *http.Request) {
	if !isHumanAdmin(auth.UserFromContext(r.Context())) {
		writeError(w, http.StatusForbidden, "only a platform admin acting directly may read the member key plan")
		return
	}
	o := h.opts.MemberKeyPlan
	if o == nil || o.Entries == nil || o.Store == nil || o.GitHubID == nil {
		writeError(w, http.StatusServiceUnavailable, "member key plan not configured")
		return
	}
	all, err := o.Entries.AllMemberEntries()
	if err != nil {
		// Not "no entries": the checkout could not be read.
		writeError(w, http.StatusServiceUnavailable, "gitops checkout unavailable; try again later")
		return
	}
	writeJSON(w, http.StatusOK, buildMemberKeyPlan(r.Context(), o, all))
}

func buildMemberKeyPlan(ctx context.Context, o *MemberKeyPlanOptions, all gitops.MemberEntries) memberKeyPlan {
	plan := memberKeyPlan{
		Counts:            map[string]int{},
		Entries:           make([]memberKeyPlanEntry, 0, len(all.Entries)),
		UnreadableTenants: append([]string{}, all.Unreadable...),
		KeyErrors:         all.KeyErrors,
	}
	if plan.KeyErrors == nil {
		plan.KeyErrors = map[string]string{}
	}
	// GitHub logins are case-insensitive: one lookup per login, however
	// it is spelled.
	logins := map[string]loginResolution{}
	resolve := func(login string) loginResolution {
		key := strings.ToLower(login)
		if res, ok := logins[key]; ok {
			return res
		}
		res := resolveLoginPrincipal(ctx, o, login)
		logins[key] = res
		return res
	}
	keyErrorShown := map[string]bool{} // tenant -> an entry already is its key error
	for _, e := range all.Entries {
		pe := planMemberEntry(ctx, o, e, resolve)
		plan.Counts[pe.Status]++
		if pe.Status != planKeyed && pe.Status != planPropose {
			plan.Blockers++
			if pe.Status == planInvalid {
				keyErrorShown[e.Tenant] = true
			}
		}
		plan.Entries = append(plan.Entries, pe)
	}
	// A key error is one more thing to fix unless an entry already is that
	// error (an entry naming nobody, a malformed key). A duplicate key shows
	// on no entry, and an unrelated blocker in the same tenant does not
	// stand in for it.
	plan.Blockers += len(plan.UnreadableTenants)
	for tenant := range plan.KeyErrors {
		if !keyErrorShown[tenant] {
			plan.Blockers++
		}
	}
	plan.Complete = plan.Blockers == 0
	return plan
}

func planMemberEntry(ctx context.Context, o *MemberKeyPlanOptions, e gitops.MemberEntry, resolve func(string) loginResolution) memberKeyPlanEntry {
	pe := memberKeyPlanEntry{MemberEntry: e}
	var login loginResolution
	if e.UserID != "" {
		login = resolve(e.UserID)
		pe.GitHubID = login.githubID
		pe.LoginPrincipalID = login.principalID
	}

	if e.PrincipalID == "" {
		if e.UserID == "" {
			// The parser already refuses this tenant; say so per entry too.
			pe.Status, pe.Reason = planInvalid, "no_key"
			return pe
		}
		if login.principalID == "" {
			pe.Status, pe.Reason, pe.Detail = planUnresolved, login.reason, login.detail
			return pe
		}
		pe.Status, pe.ProposedPrincipalID = planPropose, login.principalID
		return pe
	}

	if !gitops.ValidPrincipalID(e.PrincipalID) {
		pe.Status, pe.Reason = planInvalid, "malformed_principal_id"
		return pe
	}
	p, err := o.Store.Get(ctx, e.PrincipalID)
	switch {
	case errors.Is(err, principals.ErrNotFound):
		pe.Status, pe.Reason = planUnresolved, "principal_not_found"
		return pe
	case err != nil:
		pe.Status, pe.Reason = planUnresolved, "store_error"
		return pe
	case p.Status != principals.StatusActive:
		pe.Status, pe.Reason = planUnresolved, "principal_disabled"
		return pe
	}
	if login.principalID != "" && login.principalID != e.PrincipalID {
		pe.Status, pe.Reason = planMismatch, "login_names_another_principal"
		return pe
	}
	if e.UserID != "" && login.principalID == "" {
		pe.Status, pe.Reason, pe.Detail = planUnverified, "login_unverified", login.reason
		return pe
	}
	pe.Status = planKeyed
	return pe
}

// resolveLoginPrincipal maps a GitHub login to its principal through the
// numeric id GitHub reports for it now.
func resolveLoginPrincipal(ctx context.Context, o *MemberKeyPlanOptions, login string) loginResolution {
	id, err := o.GitHubID(ctx, login)
	if err != nil {
		return loginResolution{reason: "github_lookup_failed", detail: err.Error()}
	}
	res := loginResolution{githubID: id}
	p, revoked, err := o.Store.LookupIdentity(ctx, auth.ProviderGitHub, "", strconv.FormatInt(id, 10))
	switch {
	case errors.Is(err, principals.ErrNotFound):
		res.reason = "no_linked_identity"
	case err != nil:
		res.reason = "store_error"
	case revoked:
		res.reason = "identity_revoked"
	case p.Status != principals.StatusActive:
		res.reason = "principal_disabled"
	default:
		res.principalID = p.ID
	}
	return res
}
