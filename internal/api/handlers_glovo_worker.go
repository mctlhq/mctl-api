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
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/wire"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The worker routes hold only a gcn_ id. Each handler starts with the one
// by-id read without an owner predicate (a worker-only store read), takes the
// write-once Owner and the version from it, and passes them to the locked
// store primitives, which re-check under L1 and L2. The read takes no lock and
// is not an authority. Nothing here reads glovo_connections with raw SQL.

// glovoWorkerActor is the audit actor of every worker call.
var glovoWorkerActor = glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker}

// glovoConnectionTTL is the synthetic lifetime given to an activated connection.
const glovoConnectionTTL = 24 * time.Hour

// requireGlovoWorker admits only the Glovo worker principal: not an admin, not
// the service token, not a bridge provider, not a Glovo-audience token.
func (h *Handlers) requireGlovoWorker(w http.ResponseWriter, r *http.Request, route string) bool {
	if user := auth.UserFromContext(r.Context()); user == nil || !user.IsGlovoWorker() {
		glovoRefuse(w, route, glovo.Refuse(glovo.CodeNotAuthorized))
		return false
	}
	return true
}

// glovoRederiveOwner re-reads, on every call, whether the owner is still a
// member of the tenant (no_tenant) and still on the pilot allowlist
// (not_in_pilot). A failing read is unavailable.
func (h *Handlers) glovoRederiveOwner(ctx context.Context, o glovo.Owner) error {
	el := h.glovoRoutes().Resolver.Elig
	if el == nil || el.Membership == nil || el.Allowlist == nil {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	if el.NonSelectable[o.TenantID] {
		return glovo.Refuse(glovo.CodeScopeUnsupported)
	}
	roles, err := el.Membership.MemberRolesForPrincipal(o.TenantID, o.PrincipalID)
	if err != nil {
		return err
	}
	if _, known := operations.EffectiveTenantRole(roles); !known {
		return glovo.Refuse(glovo.CodeNoTenant)
	}
	listed, err := el.Allowlist.IsAllowlisted(ctx, o.TenantID, o.PrincipalID)
	if err != nil {
		return err
	}
	if !listed {
		return glovo.Refuse(glovo.CodeNotInPilot)
	}
	return nil
}

// GlovoWorkerCheck handles POST /api/v1/glovo/worker/check. The tenant comes
// from the connection row, never from the request. At call time it re-reads
// the install state and revision, the owner's live role, the allowlist row and
// the connection's state and expiry (database clock).
func (h *Handlers) GlovoWorkerCheck(w http.ResponseWriter, r *http.Request) {
	const route = "worker_check"
	if !h.requireGlovoWorker(w, r, route) {
		return
	}
	var req wire.WorkerCheckRequest
	if e := wire.Decode(w, r, &req, wire.SchemaWorkerCheckReq, false); e != nil {
		glovoRefuse(w, route, e)
		return
	}
	store := h.glovoRoutes().Store
	v, err := store.WorkerConnectionView(r.Context(), req.ConnectionID)
	if err != nil {
		glovoRefuse(w, route, err)
		return
	}
	inst, err := store.GetInstall(r.Context(), v.Owner.TenantID)
	if err != nil {
		glovoRefuse(w, route, err, "connection_id", v.ConnectionID)
		return
	}
	if req.InstallRevision != inst.InstallRevision || v.InstallRevision != inst.InstallRevision {
		glovoRefuse(w, route, glovo.Refuse(glovo.CodeStaleInstall), "connection_id", v.ConnectionID)
		return
	}
	if err := h.glovoRederiveOwner(r.Context(), v.Owner); err != nil {
		glovoRefuse(w, route, err, "connection_id", v.ConnectionID)
		return
	}
	state := v.EffectiveState()
	switch state {
	case glovo.Revoked:
		glovoRefuse(w, route, glovo.Refuse(glovo.CodeConnectionRevoked), "connection_id", v.ConnectionID)
		return
	case glovo.Expired:
		glovoRefuse(w, route, glovo.Refuse(glovo.CodeConnectionExpired), "connection_id", v.ConnectionID)
		return
	case glovo.Failed:
		glovoRefuse(w, route, glovo.Refuse(glovo.CodeNoConnection), "connection_id", v.ConnectionID)
		return
	}
	resp := wire.WorkerCheckResponse{
		Schema: wire.SchemaWorkerCheckResp, Allowed: state == glovo.Active, Tenant: v.Owner.TenantID,
		OwnerPrincipalID: v.Owner.PrincipalID, State: wire.PublicState(state),
	}
	if v.ExpiresAt != nil {
		t := v.ExpiresAt.UTC()
		resp.ExpiresAt = &t
	}
	writeJSON(w, http.StatusOK, resp)
}

// GlovoWorkerActivate handles POST /api/v1/glovo/worker/connections/{id}/activate.
// One call, glovo.Store.ActivateWithHandoff: the handoff reference is consumed
// and the connection activated in one transaction, or neither happens.
func (h *Handlers) GlovoWorkerActivate(w http.ResponseWriter, r *http.Request) {
	const route = "worker_activate"
	if !h.requireGlovoWorker(w, r, route) {
		return
	}
	var req wire.WorkerActivateRequest
	if e := wire.Decode(w, r, &req, wire.SchemaWorkerActivate, false); e != nil {
		glovoRefuse(w, route, e)
		return
	}
	id := chi.URLParam(r, "id")
	store := h.glovoRoutes().Store
	v, err := store.WorkerConnectionView(r.Context(), id)
	if err != nil {
		glovoRefuse(w, route, err)
		return
	}
	fail := func(err error) {
		ge := glovoRefuse(w, route, err, "connection_id", id)
		h.glovoAuditRefusal(r.Context(), ge, v.Owner.TenantID, "connection", id, glovoWorkerActor)
	}
	if err := h.glovoRederiveOwner(r.Context(), v.Owner); err != nil {
		fail(err)
		return
	}
	c, err := store.ActivateWithHandoff(glovo.WithActor(r.Context(), glovoWorkerActor), glovo.ActivateInput{
		Owner: v.Owner, ConnectionID: id, ExpectedVersion: v.Version,
		ExpectedInstallRevision: req.InstallRevision, ExpiresIn: glovoConnectionTTL, Actor: glovoWorkerActor,
	}, req.HandoffRef)
	if err != nil {
		fail(err)
		return
	}
	writeJSON(w, http.StatusOK, wire.FromConnection(glovo.ConnectionView{Connection: c}, false))
}

// GlovoWorkerExpire handles POST /api/v1/glovo/worker/connections/{id}/expire.
// It is synthetic and drives the expiry path deterministically.
func (h *Handlers) GlovoWorkerExpire(w http.ResponseWriter, r *http.Request) {
	const route = "worker_expire"
	if !h.requireGlovoWorker(w, r, route) {
		return
	}
	var body wire.Empty
	if e := wire.Decode(w, r, &body, wire.SchemaActionRequest, true); e != nil {
		glovoRefuse(w, route, e)
		return
	}
	id := chi.URLParam(r, "id")
	store := h.glovoRoutes().Store
	v, err := store.WorkerConnectionView(r.Context(), id)
	if err != nil {
		glovoRefuse(w, route, err)
		return
	}
	c, err := store.Transition(glovo.WithActor(r.Context(), glovoWorkerActor), v.Owner, id, glovo.Expired, v.Version, "synthetic_expire", nil)
	if err != nil {
		ge := glovoRefuse(w, route, err, "connection_id", id)
		h.glovoAuditRefusal(r.Context(), ge, v.Owner.TenantID, "connection", id, glovoWorkerActor)
		return
	}
	writeJSON(w, http.StatusOK, wire.FromConnection(glovo.ConnectionView{Connection: c}, false))
}
