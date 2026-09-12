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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
)

// Lifecycle ownership endpoints.
//
// Two authorization layers, deliberately distinct, because conflating them is
// how an ownership label turns into an authorization:
//
//  1. TRANSPORT — may this principal touch the lifecycle surface at all?
//     Enforced here, admin-only, matching every other agent-control surface in
//     this file's neighbours.
//  2. RECORD — may this ACTOR drive this particular row? Enforced by the store
//     (owner identity + fencing epoch + absorbing states). The API principal is
//     not the owner: the DevLoop authenticates as the mctl-agents service
//     principal while owning as devloop-workflow/dev-loop-<...>, so a check of
//     "principal == owner_id" would be both wrong and useless.
//
// Neither layer grants GitHub merge or approval authority. Ownership says who
// is responsible, never what they are permitted to do.

// requireLifecycleAdmin mirrors requireAgentRegistryAdmin and
// requireTemporalAdmin: configured, authenticated, admin.
//
// A nil store is 503 and not 404: "the ownership service is not available" and
// "nothing owns this" must never be the same answer to a caller that is about
// to decide whether it may act.
func (h *Handlers) requireLifecycleAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Lifecycle == nil {
		writeError(w, http.StatusServiceUnavailable, "lifecycle ownership store not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "lifecycle ownership is admin-only")
		return nil, false
	}
	return user, true
}

// ownershipResponse is the read model. It carries the derived answers
// (stale/healthy) so every caller computes them the same way, rather than each
// re-implementing the bound and drifting.
type ownershipResponse struct {
	*lifecycle.Ownership
	Stale   bool `json:"stale"`
	Healthy bool `json:"healthy"`
}

func newOwnershipResponse(o *lifecycle.Ownership) ownershipResponse {
	now := time.Now().UTC()
	return ownershipResponse{Ownership: o, Stale: o.IsStale(now), Healthy: o.IsHealthy(now)}
}

// writeLifecycleError maps store sentinels onto status codes.
//
// The distinctions are the point. A caller that cannot tell "someone else owns
// this" from "ownership moved while you were working" from "the store is
// down" will eventually treat all three as permission to act.
func writeLifecycleError(w http.ResponseWriter, err error, current *lifecycle.Ownership) {
	switch {
	case errors.Is(err, lifecycle.ErrOwnedByOther):
		// 409 with the winner in the body: the loser must learn WHO won, not
		// merely that it lost, or it cannot distinguish a healthy owner from
		// a stale one it should escalate.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":         "entity phase is owned by another actor",
			"current_owner": ownerOrNil(current),
			"ownership":     ownershipOrNil(current),
		})
	case errors.Is(err, lifecycle.ErrEpochMismatch):
		// 412, not 409: the caller's precondition failed. Ownership moved
		// underneath it, which is a different instruction — re-read, do not
		// retry blindly.
		writeError(w, http.StatusPreconditionFailed, err.Error())
	case errors.Is(err, lifecycle.ErrNotOwner), errors.Is(err, lifecycle.ErrNoHandoff):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, lifecycle.ErrUnknownPhase):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, lifecycle.ErrNotFound):
		writeError(w, http.StatusNotFound, "no ownership record for this entity phase")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func ownerOrNil(o *lifecycle.Ownership) any {
	if o == nil {
		return nil
	}
	return o.Owner
}

func ownershipOrNil(o *lifecycle.Ownership) any {
	if o == nil {
		return nil
	}
	return newOwnershipResponse(o)
}

// --- reads -------------------------------------------------------------

// GetLifecycleOwnership handles GET /api/v1/lifecycle/ownership — one record
// when kind+id+phase are given, otherwise a filtered list.
func (h *Handlers) GetLifecycleOwnership(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	kind, id, phase := q.Get("kind"), q.Get("id"), q.Get("phase")

	if id != "" {
		if kind == "" || phase == "" {
			writeError(w, http.StatusBadRequest, "id requires kind and phase")
			return
		}
		o, err := h.opts.Lifecycle.Get(r.Context(), lifecycle.EntityRef{Kind: kind, ID: id}, phase)
		if err != nil {
			writeLifecycleError(w, err, nil)
			return
		}
		writeJSON(w, http.StatusOK, newOwnershipResponse(o))
		return
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	records, err := h.opts.Lifecycle.List(r.Context(), lifecycle.ListFilter{
		Kind: kind, Phase: phase, State: q.Get("state"), Owner: q.Get("owner"), Limit: limit,
	})
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	out := make([]ownershipResponse, 0, len(records))
	for _, o := range records {
		out = append(out, newOwnershipResponse(o))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ownership": out, "count": len(out)})
}

// BatchGetLifecycleOwnership handles GET /api/v1/lifecycle/ownership/batch —
// many entity ids of one kind and phase in a single round trip.
//
// This is the shape the shepherd sweep needs. The per-proposal fan-out it
// replaces needed a worker pool and a wall-clock budget, and anything the
// budget did not answer in time was swept anyway — i.e. an unanswered probe
// was read as "unowned". One batched read removes both the pool and that
// failure mode.
//
// Entities with no record are ABSENT from the response rather than present
// with a null: "we have no record" is a real answer, and it must not be
// confusable with "the store did not respond", which is the 503 above.
func (h *Handlers) BatchGetLifecycleOwnership(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	kind, phase := q.Get("kind"), q.Get("phase")
	ids := q["id"]
	if kind == "" || phase == "" {
		writeError(w, http.StatusBadRequest, "kind and phase are required")
		return
	}
	if len(ids) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ownership": map[string]ownershipResponse{}, "count": 0})
		return
	}
	if len(ids) > 500 {
		writeError(w, http.StatusBadRequest, "at most 500 ids per batch")
		return
	}
	found, err := h.opts.Lifecycle.GetMany(r.Context(), kind, phase, ids)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	out := make(map[string]ownershipResponse, len(found))
	for id, o := range found {
		out[id] = newOwnershipResponse(o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ownership": out, "count": len(out)})
}

// ListLifecycleEvents handles GET /api/v1/lifecycle/events — the transition
// history for one entity phase, which is what makes a handoff or a lost
// acquire explicable after the fact rather than only observable live.
func (h *Handlers) ListLifecycleEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	kind, id, phase := q.Get("kind"), q.Get("id"), q.Get("phase")
	if kind == "" || id == "" || phase == "" {
		writeError(w, http.StatusBadRequest, "kind, id and phase are required")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	events, err := h.opts.Lifecycle.Events(r.Context(), lifecycle.EntityRef{Kind: kind, ID: id}, phase, limit)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

// --- writes ------------------------------------------------------------

type lifecycleWriteRequest struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Phase   string `json:"phase"`
	Version string `json:"version,omitempty"`

	OwnerType string `json:"owner_type"`
	OwnerID   string `json:"owner_id"`
	Epoch     int    `json:"epoch,omitempty"`

	ProposalRef        string `json:"proposal_ref,omitempty"`
	PolicyRef          string `json:"policy_ref,omitempty"`
	TemporalWorkflowID string `json:"temporal_workflow_id,omitempty"`

	Evidence string `json:"evidence,omitempty"`
	Reason   string `json:"reason,omitempty"`

	ToOwnerType string `json:"to_owner_type,omitempty"`
	ToOwnerID   string `json:"to_owner_id,omitempty"`
}

func (b lifecycleWriteRequest) entity() lifecycle.EntityRef {
	return lifecycle.EntityRef{Kind: b.Kind, ID: b.ID, Version: b.Version}
}

func (b lifecycleWriteRequest) owner() lifecycle.Owner {
	return lifecycle.Owner{Type: b.OwnerType, ID: b.OwnerID}
}

func decodeLifecycleWrite(w http.ResponseWriter, r *http.Request) (lifecycleWriteRequest, bool) {
	var body lifecycleWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return body, false
	}
	if body.Kind == "" || body.ID == "" || body.Phase == "" {
		writeError(w, http.StatusBadRequest, "kind, id and phase are required")
		return body, false
	}
	if body.OwnerType == "" || body.OwnerID == "" {
		writeError(w, http.StatusBadRequest, "owner_type and owner_id are required")
		return body, false
	}
	return body, true
}

// AcquireLifecycleOwnership handles POST /api/v1/lifecycle/ownership/acquire.
func (h *Handlers) AcquireLifecycleOwnership(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	body, ok := decodeLifecycleWrite(w, r)
	if !ok {
		return
	}
	got, err := h.opts.Lifecycle.Acquire(r.Context(), lifecycle.AcquireRequest{
		Entity: body.entity(), Phase: body.Phase, Owner: body.owner(),
		ProposalRef: body.ProposalRef, PolicyRef: body.PolicyRef,
		TemporalWorkflowID: body.TemporalWorkflowID,
	})
	if err != nil {
		writeLifecycleError(w, err, got)
		return
	}
	writeJSON(w, http.StatusOK, newOwnershipResponse(got))
}

// RecordLifecycleProgress handles POST /api/v1/lifecycle/ownership/progress.
//
// Callers must send this only when they effected a change. A tick that polled
// and found nothing must not call it: a heartbeat that refreshed the timer
// would let an owner prove liveness forever while achieving nothing, which is
// the failure mode the staleness bound exists to catch.
func (h *Handlers) RecordLifecycleProgress(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	body, ok := decodeLifecycleWrite(w, r)
	if !ok {
		return
	}
	if body.Evidence == "" {
		// Refusing an unexplained progress write is the cheapest way to keep
		// "progress" meaning something a human can audit later.
		writeError(w, http.StatusBadRequest, "evidence is required: say what changed")
		return
	}
	got, err := h.opts.Lifecycle.RecordProgress(r.Context(), body.entity(), body.Phase, body.owner(), body.Epoch, body.Evidence)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, newOwnershipResponse(got))
}

// StartLifecycleHandoff handles POST /api/v1/lifecycle/ownership/handoff/start.
func (h *Handlers) StartLifecycleHandoff(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	body, ok := decodeLifecycleWrite(w, r)
	if !ok {
		return
	}
	if body.ToOwnerType == "" || body.ToOwnerID == "" {
		writeError(w, http.StatusBadRequest, "to_owner_type and to_owner_id are required")
		return
	}
	got, err := h.opts.Lifecycle.HandoffStart(r.Context(), body.entity(), body.Phase, body.owner(), body.Epoch,
		lifecycle.Owner{Type: body.ToOwnerType, ID: body.ToOwnerID}, body.Reason)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, newOwnershipResponse(got))
}

// CompleteLifecycleHandoff handles
// POST /api/v1/lifecycle/ownership/handoff/complete. Called by the INCOMING
// owner, which is why owner_type/owner_id here name the arriving actor.
func (h *Handlers) CompleteLifecycleHandoff(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	body, ok := decodeLifecycleWrite(w, r)
	if !ok {
		return
	}
	got, err := h.opts.Lifecycle.HandoffComplete(r.Context(), body.entity(), body.Phase, body.owner())
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, newOwnershipResponse(got))
}

// ReleaseLifecycleOwnership handles POST /api/v1/lifecycle/ownership/release —
// the work remains, this actor is simply no longer driving it.
func (h *Handlers) ReleaseLifecycleOwnership(w http.ResponseWriter, r *http.Request) {
	h.finishLifecycle(w, r, false)
}

// TerminateLifecycleOwnership handles
// POST /api/v1/lifecycle/ownership/terminal — the phase is finished and
// nothing should pick it up.
func (h *Handlers) TerminateLifecycleOwnership(w http.ResponseWriter, r *http.Request) {
	h.finishLifecycle(w, r, true)
}

func (h *Handlers) finishLifecycle(w http.ResponseWriter, r *http.Request, terminal bool) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	body, ok := decodeLifecycleWrite(w, r)
	if !ok {
		return
	}
	var (
		got *lifecycle.Ownership
		err error
	)
	if terminal {
		got, err = h.opts.Lifecycle.Terminal(r.Context(), body.entity(), body.Phase, body.owner(), body.Epoch, body.Reason)
	} else {
		got, err = h.opts.Lifecycle.Release(r.Context(), body.entity(), body.Phase, body.owner(), body.Epoch, body.Reason)
	}
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, newOwnershipResponse(got))
}
