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

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Human-operator lifecycle RECOVERY: four named transitions (fence a dead
// claim, request a handoff off a stuck owner, retry a stalled handoff,
// request reconciliation), guarded by fail-closed preconditions and fully
// audited.
//
// This file imports NO client other than the lifecycle store and the audit
// log. No GitHub, Temporal or Argo client is reachable from anything below,
// so there is structurally no path from a recovery call to a merge, an
// approval or a push -- ownership recovery says who is responsible for a row,
// never what that actor may do with a repository.
//
// Deliberately absent: any force_owner-shaped parameter, any way to disable a
// precondition check, and any automatic sweep. A human names the transition
// and the reason every time (mctl-agents#353 is the separate, out-of-scope
// automatic sweep).

// lifecycleRecoveryMaxBodyBytes mirrors lifecycleMaxBodyBytes
// (handlers_lifecycle.go): the same cap, for the same reason -- reason and
// evidence-shaped text fields go straight into Postgres text columns with no
// length of their own.
const lifecycleRecoveryMaxBodyBytes = 64 * 1024

// lifecycleRecoveryRequest is the ONE body shape all four mutating recovery
// routes decode. Unlike lifecycleWriteRequest (handlers_lifecycle.go), no
// field's meaning depends on which route reads it: expected_* is always what
// the operator read and is pinning the decision to, and to_owner_* is always
// the handoff target (empty and ignored on the three routes that take no
// target).
type lifecycleRecoveryRequest struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Phase string `json:"phase"`

	ExpectedOwnerType  string     `json:"expected_owner_type"`
	ExpectedOwnerID    string     `json:"expected_owner_id"`
	ExpectedEpoch      int        `json:"expected_epoch"`
	ExpectedVersion    *string    `json:"expected_version"`
	ExpectedLastSeenAt *time.Time `json:"expected_last_seen_at,omitempty"`

	Reason string `json:"reason"`

	ToOwnerType string `json:"to_owner_type,omitempty"`
	ToOwnerID   string `json:"to_owner_id,omitempty"`
}

func (b lifecycleRecoveryRequest) entity() lifecycle.EntityRef {
	return lifecycle.EntityRef{Kind: b.Kind, ID: b.ID}
}

func (b lifecycleRecoveryRequest) preconditions() lifecycle.RecoveryPreconditions {
	return lifecycle.RecoveryPreconditions{
		ExpectedOwner:      lifecycle.Owner{Type: b.ExpectedOwnerType, ID: b.ExpectedOwnerID},
		ExpectedEpoch:      b.ExpectedEpoch,
		ExpectedVersion:    b.ExpectedVersion,
		ExpectedLastSeenAt: b.ExpectedLastSeenAt,
	}
}

func (b lifecycleRecoveryRequest) request(principal string) lifecycle.RecoveryRequest {
	return lifecycle.RecoveryRequest{
		Entity: b.entity(), Phase: b.Phase, Pre: b.preconditions(),
		Principal: principal, Reason: b.Reason,
	}
}

// decodeLifecycleRecovery decodes and field-validates a recovery request,
// answering 400 and naming the specific missing field -- never a generic
// "invalid request" -- and never touching the store: a request missing a
// precondition gets no read and no mutation, per the EARS criterion this
// endpoint family exists to satisfy.
//
// DisallowUnknownFields rejects a stray field (e.g. a would-be force_owner)
// outright rather than silently ignoring it.
func decodeLifecycleRecovery(w http.ResponseWriter, r *http.Request) (lifecycleRecoveryRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, lifecycleRecoveryMaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body lifecycleRecoveryRequest
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return body, false
	}
	if body.Kind == "" || body.ID == "" || body.Phase == "" {
		writeError(w, http.StatusBadRequest, "kind, id and phase are required")
		return body, false
	}
	if body.ExpectedOwnerType == "" || body.ExpectedOwnerID == "" {
		writeError(w, http.StatusBadRequest, "expected_owner_type and expected_owner_id are required")
		return body, false
	}
	if body.ExpectedEpoch <= 0 {
		writeError(w, http.StatusBadRequest, "expected_epoch is required")
		return body, false
	}
	if body.ExpectedVersion == nil {
		writeError(w, http.StatusBadRequest,
			"expected_version is required (send \"\" to match an unset version)")
		return body, false
	}
	if body.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return body, false
	}
	return body, true
}

// requireLifecycleRecovery layers a THIRD requirement on top of
// requireLifecycleAdmin's configured/authenticated/admin checks: the audit
// log must be configured too. A recovery transition that could not be
// audited must not proceed at all -- unlike the ordinary actor writes in
// handlers_lifecycle.go, whose logAudit call already tolerates a nil
// AuditLog silently, these are human-operator interventions and the one
// place ADR-010's story depends on the audit trail existing.
func (h *Handlers) requireLifecycleRecovery(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	user, ok := h.requireLifecycleAdmin(w, r)
	if !ok {
		return nil, false
	}
	if h.opts.AuditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured; recovery must not proceed unaudited")
		return nil, false
	}
	return user, true
}

// recoveryAuditParams builds the common parameter set every recovery audit
// entry carries, then callers add the transition-specific fields (e.g.
// to_owner, licensed_by) on top.
func recoveryAuditParams(body lifecycleRecoveryRequest, before lifecycle.Snapshot, outcome string) map[string]string {
	p := map[string]string{
		"entity":                body.Kind + "/" + body.ID,
		"phase":                 body.Phase,
		"expected_owner_type":   body.ExpectedOwnerType,
		"expected_owner_id":     body.ExpectedOwnerID,
		"expected_epoch":        strconv.Itoa(body.ExpectedEpoch),
		"reason":                body.Reason,
		"owner_before":          before.Owner.Type + "/" + before.Owner.ID,
		"epoch_before":          strconv.Itoa(before.Epoch),
		"state_before":          before.State,
		"entity_version_before": before.Version,
		"outcome":               outcome,
	}
	if body.ExpectedVersion != nil {
		p["expected_version"] = *body.ExpectedVersion
	}
	return p
}

// writeLifecycleRecoveryError writes the HTTP response for a failed recovery
// call AND records the one audit entry the EARS criteria require for a
// precondition refusal, before delegating status-code mapping to the shared
// writeLifecycleError.
func (h *Handlers) writeLifecycleRecoveryError(
	w http.ResponseWriter, r *http.Request, user *auth.User, operation string,
	body lifecycleRecoveryRequest, before lifecycle.Snapshot, err error,
) {
	params := recoveryAuditParams(body, before, "refused: "+err.Error())
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: operation, Parameters: params,
		Status: "failed", RiskLevel: string(operations.RiskHigh), Message: err.Error(),
	})
	// The mismatch arms of writeLifecycleError accept a CURRENT record so the
	// caller does not have to re-read; recovery methods do not return one on
	// failure (unlike Acquire's ErrOwnedByOther), so nil here means the
	// response carries the error text alone. The audit entry does not need
	// one either -- `outcome` and the `expected_*` parameters already say
	// what was asked for and why it was refused.
	writeLifecycleError(w, err, nil)
}

// writeLifecycleRecoverySuccess writes the 200 response AND the one audit
// entry a successful recovery transition requires.
func (h *Handlers) writeLifecycleRecoverySuccess(
	w http.ResponseWriter, r *http.Request, user *auth.User, operation string,
	body lifecycleRecoveryRequest, result *lifecycle.RecoveryResult, extra map[string]string,
) {
	params := recoveryAuditParams(body, result.Before, "succeeded")
	params["epoch_after"] = strconv.Itoa(result.Ownership.Epoch)
	params["state_after"] = result.Ownership.State
	params["licensed_by"] = result.Licensed
	for k, v := range extra {
		params[k] = v
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: operation, Parameters: params,
		Status: "succeeded", RiskLevel: string(operations.RiskHigh),
	})
	writeJSON(w, http.StatusOK, newOwnershipResponse(result.Ownership))
}

// RequestLifecycleReconcile handles
// POST /api/v1/lifecycle/ownership/recovery/reconcile -- appends a
// reconcile-requested event without touching any ownership column. The
// lightest recovery transition: a request for attention, not a claim.
func (h *Handlers) RequestLifecycleReconcile(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireLifecycleRecovery(w, r)
	if !ok {
		return
	}
	body, ok := decodeLifecycleRecovery(w, r)
	if !ok {
		return
	}
	// Read once up front so a precondition refusal still has a `before`
	// snapshot for the audit entry -- the store re-reads under its own
	// advisory lock regardless, so this is not the authority, only the audit
	// trail's own view of what was asked for.
	before, err := h.snapshotFor(r, body)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	result, err := h.opts.Lifecycle.RequestReconcile(lifecycleCaller(r, user), body.request(user.ID))
	if err != nil {
		h.writeLifecycleRecoveryError(w, r, user, "lifecycle-recovery-reconcile", body, before, err)
		return
	}
	h.writeLifecycleRecoverySuccess(w, r, user, "lifecycle-recovery-reconcile", body, result, nil)
}

// FenceLifecycleClaim handles POST /api/v1/lifecycle/ownership/recovery/fence
// -- releases a row whose owner is server-derived DEAD, installing no
// successor. The only recovery transition that changes the fencing epoch.
func (h *Handlers) FenceLifecycleClaim(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireLifecycleRecovery(w, r)
	if !ok {
		return
	}
	body, ok := decodeLifecycleRecovery(w, r)
	if !ok {
		return
	}
	before, err := h.snapshotFor(r, body)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	result, err := h.opts.Lifecycle.FenceDeadClaim(lifecycleCaller(r, user), body.request(user.ID))
	if err != nil {
		h.writeLifecycleRecoveryError(w, r, user, "lifecycle-recovery-fence", body, before, err)
		return
	}
	h.writeLifecycleRecoverySuccess(w, r, user, "lifecycle-recovery-fence", body, result, nil)
}

// RequestLifecycleHandoffRecovery handles
// POST /api/v1/lifecycle/ownership/recovery/handoff/request -- escalates a
// server-derived STUCK owner by starting a handoff toward to_owner_type/id.
// Deliberately a distinct static prefix from the actor-driven
// /lifecycle/ownership/handoff/start and /complete routes (handlers_lifecycle.go)
// so chi's radix tree cannot confuse an operator's escalation with an actor's
// own declared handoff.
func (h *Handlers) RequestLifecycleHandoffRecovery(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireLifecycleRecovery(w, r)
	if !ok {
		return
	}
	body, ok := decodeLifecycleRecovery(w, r)
	if !ok {
		return
	}
	if body.ToOwnerType == "" || body.ToOwnerID == "" {
		writeError(w, http.StatusBadRequest, "to_owner_type and to_owner_id are required")
		return
	}
	before, err := h.snapshotFor(r, body)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	toOwner := lifecycle.Owner{Type: body.ToOwnerType, ID: body.ToOwnerID}
	result, err := h.opts.Lifecycle.RequestHandoff(lifecycleCaller(r, user), body.request(user.ID), toOwner)
	if err != nil {
		h.writeLifecycleRecoveryError(w, r, user, "lifecycle-recovery-handoff-request", body, before, err)
		return
	}
	h.writeLifecycleRecoverySuccess(w, r, user, "lifecycle-recovery-handoff-request", body, result,
		map[string]string{"to_owner": toOwner.Type + "/" + toOwner.ID})
}

// RetryLifecycleHandoff handles
// POST /api/v1/lifecycle/ownership/recovery/handoff/retry -- re-arms a
// STALLED handoff's clocks for the same target. Owner, target, state and
// epoch are unchanged; handoff_started_at and last_seen_at both move, which
// is what makes the extension real (see handoffRetryUpdateSQL).
//
// Consequence worth knowing before calling it: the row comes back ALIVE, so
// for one liveness bound it is neither dead nor stalled -- Fence and Recover
// stop applying to it, and a second retry is refused with
// ErrHandoffNotStalled. That is the protection the operation grants the named
// target, and it is also a window in which the usual recovery levers are
// deliberately unavailable.
func (h *Handlers) RetryLifecycleHandoff(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireLifecycleRecovery(w, r)
	if !ok {
		return
	}
	body, ok := decodeLifecycleRecovery(w, r)
	if !ok {
		return
	}
	before, err := h.snapshotFor(r, body)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}
	result, err := h.opts.Lifecycle.RetryHandoff(lifecycleCaller(r, user), body.request(user.ID))
	if err != nil {
		h.writeLifecycleRecoveryError(w, r, user, "lifecycle-recovery-handoff-retry", body, before, err)
		return
	}
	h.writeLifecycleRecoverySuccess(w, r, user, "lifecycle-recovery-handoff-retry", body, result, nil)
}

// snapshotFor reads the CURRENT row once, up front, purely so a precondition
// refusal still has a `before` snapshot to put in its audit entry. It is not
// where the transition's own correctness lives -- every Store method below
// re-reads under its own advisory lock and pins what IT read into the CAS, so
// a row that changes between this call and the store call still refuses the
// write.
func (h *Handlers) snapshotFor(r *http.Request, body lifecycleRecoveryRequest) (lifecycle.Snapshot, error) {
	o, err := h.opts.Lifecycle.Get(r.Context(), body.entity(), body.Phase)
	if err != nil {
		if errors.Is(err, lifecycle.ErrNotFound) {
			// A snapshot of nothing is still a well-formed "before": the
			// recovery call itself will get the same ErrNotFound and answer
			// 404, so this is never surfaced to a caller as anything but
			// that same 404 by the handler that called it.
			return lifecycle.Snapshot{}, err
		}
		return lifecycle.Snapshot{}, err
	}
	return lifecycle.Snapshot{
		Owner: o.Owner, Epoch: o.Epoch, State: o.State,
		Version: o.Entity.Version, LastSeenAt: o.LastSeenAt,
	}, nil
}
