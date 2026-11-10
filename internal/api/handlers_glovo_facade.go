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
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/wire"
)

// The facade routes are the only ones a Glovo-audience token may reach
// (glovoAudienceRoutes). Every handler first resolves the caller's scope from
// the selected-team grant (scope.Resolver); tenant, principal and install
// revision come only from that scope and the store, never from the request.

var idempotencyKeyRE = regexp.MustCompile(`^[\x21-\x7e]{1,200}$`)

type glovoFacadeCall struct {
	route string
	owner glovo.Owner
	actor glovo.Actor
}

// glovoFacadeScope resolves the caller's scope; ok false means the response
// was written.
func (h *Handlers) glovoFacadeScope(w http.ResponseWriter, r *http.Request, route string) (glovoFacadeCall, bool) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		glovo.WriteUnauthenticated(w, "")
		return glovoFacadeCall{}, false
	}
	sc, refusal := h.glovoRoutes().Resolver.Resolve(r.Context(), user)
	if refusal != nil {
		glovoRefuse(w, route, refusal)
		return glovoFacadeCall{}, false
	}
	return glovoFacadeCall{
		route: route,
		owner: glovo.Owner{TenantID: sc.Tenant, PrincipalID: sc.PrincipalID},
		actor: glovo.Actor{PrincipalID: sc.PrincipalID, Kind: glovo.ActorUser},
	}, true
}

func (c glovoFacadeCall) joinScope(rev int64) connect.JoinScope {
	return connect.JoinScope{Tenant: c.owner.TenantID, PrincipalID: c.owner.PrincipalID, InstallRevision: rev}
}

// glovoIdempotencyKey reads the required Idempotency-Key header.
func glovoIdempotencyKey(r *http.Request) (string, bool) {
	k := r.Header.Get("Idempotency-Key")
	return k, idempotencyKeyRE.MatchString(k)
}

// GlovoFacadeContext handles GET /api/v1/glovo/facade/context.
func (h *Handlers) GlovoFacadeContext(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_context")
	if !ok {
		return
	}
	store := h.glovoRoutes().Store
	inst, err := store.GetInstall(r.Context(), call.owner.TenantID)
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	views, err := store.ListOwnerConnections(r.Context(), call.owner, 10)
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	out := wire.Context{
		Schema: wire.SchemaContext, Tenant: call.owner.TenantID, PrincipalID: call.owner.PrincipalID,
		InstallationID: inst.InstallID, InstallRevision: inst.InstallRevision, Connections: []wire.Connection{},
	}
	for _, v := range views {
		out.Connections = append(out.Connections, wire.FromConnection(v, false))
	}
	writeJSON(w, http.StatusOK, out)
}

// GlovoFacadeConnect handles POST /api/v1/glovo/facade/connections.
func (h *Handlers) GlovoFacadeConnect(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_connect")
	if !ok {
		return
	}
	key, ok := glovoIdempotencyKey(r)
	if !ok {
		glovoRefuse(w, call.route, glovo.Refuse(glovo.CodeInvalidRequest))
		return
	}
	var body wire.Empty
	if e := wire.Decode(w, r, &body, wire.SchemaConnectRequest, true); e != nil {
		glovoRefuse(w, call.route, e)
		return
	}
	rt := h.glovoRoutes()
	inst, err := rt.Store.GetInstall(r.Context(), call.owner.TenantID)
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	out, err := rt.Connect.ConnectWithoutHandoff(r.Context(), call.joinScope(inst.InstallRevision), key)
	if err != nil {
		ge := glovoRefuse(w, call.route, err)
		switch ge.Code {
		case glovo.CodeConnectionExists, glovo.CodeIdempotencyReused, glovo.CodeStaleInstall:
			h.glovoAuditRefusal(r.Context(), ge, call.owner.TenantID, "install", inst.InstallID, call.actor)
		}
		return
	}
	h.glovoWriteConnection(w, r, call, out.Connection.ConnectionID, http.StatusCreated, out.Replayed)
}

// glovoWriteConnection reads the owner's connection back and writes it; a
// replay is 200 with replayed true.
func (h *Handlers) glovoWriteConnection(w http.ResponseWriter, r *http.Request, call glovoFacadeCall, id string, created int, replayed bool) {
	v, err := h.glovoRoutes().Store.GetConnectionView(r.Context(), call.owner, id)
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	status := created
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, wire.FromConnection(*v, replayed))
}

// GlovoFacadeGetConnection handles GET /api/v1/glovo/facade/connections/{id}.
// A foreign id and a missing id are the same 404.
func (h *Handlers) GlovoFacadeGetConnection(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_get")
	if !ok {
		return
	}
	v, err := h.glovoRoutes().Store.GetConnectionView(r.Context(), call.owner, chi.URLParam(r, "id"))
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.FromConnection(*v, false))
}

// GlovoFacadeHandoff handles POST /api/v1/glovo/facade/connections/{id}/handoff.
// It only issues the single-use reference; the connection stays pending until
// the worker activates it. The response is the one that carries a reference.
func (h *Handlers) GlovoFacadeHandoff(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_handoff")
	if !ok {
		return
	}
	var body wire.Empty
	if e := wire.Decode(w, r, &body, wire.SchemaActionRequest, true); e != nil {
		glovoRefuse(w, call.route, e)
		return
	}
	id := chi.URLParam(r, "id")
	issue, err := h.glovoRoutes().Store.IssueHandoff(r.Context(), call.owner, id, call.actor)
	if err != nil {
		ge := glovoRefuse(w, call.route, err, "connection_id", id)
		h.glovoAuditRefusal(r.Context(), ge, call.owner.TenantID, "connection", id, call.actor)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, wire.Handoff{
		Schema: wire.SchemaHandoff, ConnectionID: id, HandoffRef: issue.Ref, ExpiresAt: issue.ExpiresAt,
	})
}

// GlovoFacadeRevoke handles POST /api/v1/glovo/facade/connections/{id}/revoke.
// Revoking a revoked connection returns it.
func (h *Handlers) GlovoFacadeRevoke(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_revoke")
	if !ok {
		return
	}
	var body wire.Empty
	if e := wire.Decode(w, r, &body, wire.SchemaActionRequest, true); e != nil {
		glovoRefuse(w, call.route, e)
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := h.glovoRoutes().Store.Revoke(r.Context(), call.owner, call.actor, id, "user_revoked"); err != nil {
		ge := glovoRefuse(w, call.route, err, "connection_id", id)
		h.glovoAuditRefusal(r.Context(), ge, call.owner.TenantID, "connection", id, call.actor)
		return
	}
	h.glovoWriteConnection(w, r, call, id, http.StatusOK, false)
}

// GlovoFacadeReconnect handles POST /api/v1/glovo/facade/connections/{id}/reconnect:
// a new gcn_ id with supersedes_id set. A live prior is refused
// connection_exists; the route never supersedes.
func (h *Handlers) GlovoFacadeReconnect(w http.ResponseWriter, r *http.Request) {
	call, ok := h.glovoFacadeScope(w, r, "facade_reconnect")
	if !ok {
		return
	}
	key, ok := glovoIdempotencyKey(r)
	if !ok {
		glovoRefuse(w, call.route, glovo.Refuse(glovo.CodeInvalidRequest))
		return
	}
	var body wire.Empty
	if e := wire.Decode(w, r, &body, wire.SchemaConnectRequest, true); e != nil {
		glovoRefuse(w, call.route, e)
		return
	}
	rt := h.glovoRoutes()
	prior := chi.URLParam(r, "id")
	inst, err := rt.Store.GetInstall(r.Context(), call.owner.TenantID)
	if err != nil {
		glovoRefuse(w, call.route, err)
		return
	}
	res, err := rt.Connect.Reconnect(r.Context(), call.joinScope(inst.InstallRevision), key, prior)
	if err != nil {
		ge := glovoRefuse(w, call.route, err, "connection_id", prior)
		if ge.Code == glovo.CodeConnectionExists {
			h.glovoAuditRefusal(r.Context(), ge, call.owner.TenantID, "connection", prior, call.actor)
		}
		return
	}
	h.glovoWriteConnection(w, r, call, res.Connection.ConnectionID, http.StatusCreated, res.Replayed)
}
