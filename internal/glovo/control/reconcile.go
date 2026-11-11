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

package control

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

// pair is a command (status, effect_state) as CommandEffect reads it.
type pair struct{ status, effect string }

// verdict is what reconcileOrder does for one pair on a dispatched order: the
// order call, and whether the receipt moves to unknown in the same transaction.
type verdict struct {
	order   string // "" none, "closed", "cancelled" or "unknown"
	receipt bool   // MarkGlovoApprovalUnknownTx
}

// reconcileTable is the total result-to-order table of mctl-api#985 design
// 2a, one entry per row. It is total over the five command statuses and six
// effect states: a pair absent from the map is the catch-all row (an invariant
// violation or an unobserved state), never "nothing happened". reconcileOrder
// is its only reader.
var reconcileTable = func() map[pair]verdict {
	t := map[pair]verdict{}
	set := func(statuses, effects []string, v verdict) {
		for _, s := range statuses {
			for _, e := range effects {
				t[pair{s, e}] = v
			}
		}
	}
	open := []string{bridge.StatusPending, bridge.StatusLeased}
	ended := []string{bridge.StatusCancelled, bridge.StatusExpired}
	completed := []string{bridge.StatusCompleted}
	// Not terminal: nothing to apply, whether the effect is none, permitted or
	// (after a reclaim) unknown.
	set(open, []string{bridge.EffectNone, bridge.EffectPermitted, bridge.EffectUnknown}, verdict{})
	// Completed with a verdict the permit or the provider made.
	set(completed, []string{bridge.EffectSucceeded, bridge.EffectFailed}, verdict{order: "closed"})
	// Completed with no permit row: the receipt can never be spent.
	set(completed, []string{bridge.EffectNotPerformed, bridge.EffectNone}, verdict{order: "closed", receipt: true})
	set(completed, []string{bridge.EffectUnknown}, verdict{order: "unknown"})
	// Ended without completing: cancelled only while nothing can have happened.
	set(ended, []string{bridge.EffectNone, bridge.EffectNotPerformed}, verdict{order: "cancelled", receipt: true})
	set(ended, []string{bridge.EffectSucceeded, bridge.EffectFailed, bridge.EffectPermitted, bridge.EffectUnknown}, verdict{order: "unknown"})
	return t
}()

// reconcileOrder applies the table to a locked order. It has two callers
// (Cancel after Store.Cancel, and the command read), each passing the pair it
// read once with CommandEffect on its own transaction. It first checks that
// the order is dispatched and does nothing otherwise: the order calls are CASes
// on version and state, so a repeat would fail, and an order that already
// moved has nothing left to learn. A pair outside the table on a dispatched
// order is unavailable and the caller's transaction rolls back; it is never read
// as "nothing happened". L4 is taken here only for the rows that call the
// receipt, after L3 and before any L5 write.
func (d *Dispatcher) reconcileOrder(ctx context.Context, tx pgx.Tx, o *orders.Order, commandID, status, effect string) error {
	if o.State != orders.StateDispatched {
		return nil
	}
	v, ok := reconcileTable[pair{status, effect}]
	if !ok {
		return refuse(glovo.CodeUnavailable, "reconcile: command status "+status+" with effect "+effect+" is outside the table")
	}
	if v.receipt {
		if o.ApprovalRef == "" || commandID == "" {
			return refuse(glovo.CodeUnavailable, "reconcile: a dispatched order has no approval or command")
		}
		if _, _, err := d.Receipts.LockGlovoApprovalTx(ctx, tx, o.ApprovalRef); err != nil {
			return err
		}
	}
	var err error
	switch v.order {
	case "":
		return nil
	case "closed":
		err = d.Orders.MarkClosed(ctx, tx, o, actor)
	case "cancelled":
		err = d.Orders.MarkCancelled(ctx, tx, o, actor)
	case "unknown":
		err = d.Orders.MarkUnknown(ctx, tx, o, actor)
	}
	if err != nil {
		return err
	}
	if v.receipt {
		return d.Receipts.MarkGlovoApprovalUnknownTx(ctx, tx, o.ApprovalRef, commandID)
	}
	return nil
}
