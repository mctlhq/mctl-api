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

package glovojoin

import (
	"context"
	"errors"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Wire order states and outcomes (design 3a).
const (
	OutcomeUnknown        = "OUTCOME_UNKNOWN"
	OutcomeObservedPlaced = "observed_placed"
)

// MapOrderStatus is the total mapping of design 3a. aar is the effective
// aar_ state, only consulted for a finalized order; status and effect are the
// command pair, only consulted for a dispatched or closed order. ok is false
// for every input outside the table: the caller answers 503 unavailable and
// never invents a state.
func MapOrderStatus(orderState, aar, status, effect string) (state, outcome string, ok bool) {
	switch orderState {
	case orders.StateOpen:
		return "open", OutcomeUnknown, true
	case orders.StateFinalized:
		switch aar {
		case workitems.ApprovalPending:
			return "awaiting_approval", OutcomeUnknown, true
		case workitems.ApprovalApproved:
			return "approved", OutcomeUnknown, true
		case workitems.GlovoStateRefused:
			return "refused", OutcomeUnknown, true
		case workitems.GlovoStateExpired:
			return "expired", OutcomeUnknown, true
		}
		return "", "", false
	case orders.StateCancelled:
		return "cancelled", OutcomeUnknown, true
	case orders.StateUnknown:
		return "unknown", OutcomeUnknown, true
	case orders.StateDispatched, orders.StateClosed:
		return mapCommandPair(status, effect)
	}
	return "", "", false
}

func mapCommandPair(status, effect string) (state, outcome string, ok bool) {
	switch status {
	case bridge.StatusPending, bridge.StatusLeased:
		switch effect {
		case bridge.EffectNone, bridge.EffectPermitted:
			return "dispatched", OutcomeUnknown, true
		case bridge.EffectUnknown:
			return "unknown", OutcomeUnknown, true
		}
	case bridge.StatusCompleted:
		switch effect {
		case bridge.EffectSucceeded:
			return "placed", OutcomeObservedPlaced, true
		case bridge.EffectFailed, bridge.EffectNotPerformed, bridge.EffectNone:
			return "failed", OutcomeUnknown, true
		case bridge.EffectUnknown:
			return "unknown", OutcomeUnknown, true
		}
	case bridge.StatusCancelled, bridge.StatusExpired:
		switch effect {
		case bridge.EffectNone, bridge.EffectNotPerformed:
			return "cancelled", OutcomeUnknown, true
		case bridge.EffectSucceeded, bridge.EffectFailed, bridge.EffectPermitted, bridge.EffectUnknown:
			return "unknown", OutcomeUnknown, true
		}
	}
	return "", "", false
}

// StatusOrders is the #988 read surface of the status route.
type StatusOrders interface {
	Get(ctx context.Context, q dbq.Querier, sc orders.Scope, orderRef string) (*orders.Order, error)
}

// StatusApprovals is the #989 read surface of the status route.
type StatusApprovals interface {
	GlovoApprovalStatus(ctx context.Context, q dbq.Querier, tenants []string, id string) (*workitems.GlovoApprovalStatus, error)
}

// StatusCommands is the #985 bridge read surface of the status route.
type StatusCommands interface {
	CommandEffect(ctx context.Context, q dbq.Querier, tenants []string, commandID string) (status, effectState string, err error)
}

var _ StatusCommands = (*bridge.Store)(nil)

// StatusReader derives the wire state of one order on every read.
type StatusReader struct {
	DB        dbq.Querier // the glovo_runtime pool, never the work-items pool
	Orders    StatusOrders
	Approvals StatusApprovals
	Commands  StatusCommands
	// OnUnobserved is called with the reason class when a read is answered
	// 503 (an audit hook); it never carries the order's content.
	OnUnobserved func(orderRef, reason string)
}

// Status returns the wire state and outcome of the owner's order. An order of
// another owner or tenant is not_found.
func (r *StatusReader) Status(ctx context.Context, tenant, principal, orderRef string) (state, outcome string, rf *Refusal) {
	unobserved := func(reason string) (string, string, *Refusal) {
		if r.OnUnobserved != nil {
			r.OnUnobserved(orderRef, reason)
		}
		return "", "", &Refusal{Err: glovo.Refuse(glovo.CodeUnavailable), Reason: "status_unobserved:" + reason}
	}
	o, err := r.Orders.Get(ctx, r.DB, orders.Scope{Tenant: tenant, PrincipalID: principal}, orderRef)
	if err != nil {
		if errors.Is(err, glovo.ErrNotFound) {
			return "", "", refusal(glovo.CodeNotFound, "order_not_found")
		}
		return "", "", toRefusal(err, "order_read")
	}
	var aar, status, effect string
	switch o.State {
	case orders.StateFinalized:
		if o.ApprovalRef == "" {
			return unobserved("finalized_without_approval")
		}
		st, err := r.Approvals.GlovoApprovalStatus(ctx, r.DB, []string{tenant}, o.ApprovalRef)
		if err != nil {
			return unobserved("approval_read")
		}
		aar = st.State
	case orders.StateDispatched, orders.StateClosed:
		if o.CommandID == "" {
			return unobserved("no_command_id")
		}
		status, effect, err = r.Commands.CommandEffect(ctx, r.DB, []string{tenant}, o.CommandID)
		if err != nil {
			if errors.Is(err, bridge.ErrCommandNotFound) {
				return unobserved("command_absent")
			}
			return unobserved("command_read")
		}
	}
	state, outcome, ok := MapOrderStatus(o.State, aar, status, effect)
	if !ok {
		return unobserved("outside_table")
	}
	return state, outcome, nil
}
