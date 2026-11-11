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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// callLog records the order and receipt calls of reconcileOrder.
type callLog struct{ calls []string }

func (c *callLog) add(s string) { c.calls = append(c.calls, s) }
func (c *callLog) String() string {
	if len(c.calls) == 0 {
		return "none"
	}
	return strings.Join(c.calls, "+")
}

type fakeOrderIndex struct{ log *callLog }

func (fakeOrderIndex) PeekOrderScope(context.Context, dbq.Querier, string, []string) (orders.Scope, error) {
	return orders.Scope{}, nil
}
func (fakeOrderIndex) LockOrderForControl(context.Context, pgx.Tx, string, []string) (*orders.Order, error) {
	return nil, nil
}
func (fakeOrderIndex) Snapshot(context.Context, dbq.Querier, orders.Scope, string, int) (*orders.Snapshot, error) {
	return nil, nil
}
func (f fakeOrderIndex) MarkDispatched(context.Context, pgx.Tx, *orders.Order, string, orders.Actor) error {
	f.log.add("MarkDispatched")
	return nil
}
func (f fakeOrderIndex) MarkCancelled(context.Context, pgx.Tx, *orders.Order, orders.Actor) error {
	f.log.add("MarkCancelled")
	return nil
}
func (f fakeOrderIndex) MarkUnknown(context.Context, pgx.Tx, *orders.Order, orders.Actor) error {
	f.log.add("MarkUnknown")
	return nil
}
func (f fakeOrderIndex) MarkClosed(context.Context, pgx.Tx, *orders.Order, orders.Actor) error {
	f.log.add("MarkClosed")
	return nil
}

type fakeReceipts struct{ log *callLog }

func (f fakeReceipts) LockGlovoApprovalTx(context.Context, pgx.Tx, string) (*workitems.ActionApprovalRequest, *workitems.GlovoBinding, error) {
	f.log.add("L4")
	return &workitems.ActionApprovalRequest{}, &workitems.GlovoBinding{}, nil
}
func (fakeReceipts) ReserveGlovoApprovalTx(context.Context, pgx.Tx, string, workitems.ReserveCommand) (bool, error) {
	return false, nil
}
func (fakeReceipts) RevokeGlovoApprovalTx(context.Context, pgx.Tx, string, string) error { return nil }
func (f fakeReceipts) MarkGlovoApprovalUnknownTx(context.Context, pgx.Tx, string, string) error {
	f.log.add("ReceiptUnknown")
	return nil
}
func (fakeReceipts) GlovoApprovalStatus(context.Context, dbq.Querier, []string, string) (*workitems.GlovoApprovalStatus, error) {
	return nil, nil
}

func reconcileDispatcher() (*Dispatcher, *callLog) {
	log := &callLog{}
	return &Dispatcher{Orders: fakeOrderIndex{log}, Receipts: fakeReceipts{log}}, log
}

// want is the table of mctl-api#985 design 2a, written out one pair per line
// and independent of reconcileTable's construction. "ERR" is the catch-all row.
var wantReconcile = map[pair]string{
	{bridge.StatusPending, "none"}:            "none",
	{bridge.StatusPending, "permitted"}:       "none",
	{bridge.StatusPending, "unknown"}:         "none",
	{bridge.StatusPending, "succeeded"}:       "ERR",
	{bridge.StatusPending, "failed"}:          "ERR",
	{bridge.StatusPending, "not_performed"}:   "ERR",
	{bridge.StatusLeased, "none"}:             "none",
	{bridge.StatusLeased, "permitted"}:        "none",
	{bridge.StatusLeased, "unknown"}:          "none",
	{bridge.StatusLeased, "succeeded"}:        "ERR",
	{bridge.StatusLeased, "failed"}:           "ERR",
	{bridge.StatusLeased, "not_performed"}:    "ERR",
	{bridge.StatusCompleted, "succeeded"}:     "MarkClosed",
	{bridge.StatusCompleted, "failed"}:        "MarkClosed",
	{bridge.StatusCompleted, "not_performed"}: "L4+MarkClosed+ReceiptUnknown",
	{bridge.StatusCompleted, "none"}:          "L4+MarkClosed+ReceiptUnknown",
	{bridge.StatusCompleted, "unknown"}:       "MarkUnknown",
	{bridge.StatusCompleted, "permitted"}:     "ERR",
	{bridge.StatusCancelled, "none"}:          "L4+MarkCancelled+ReceiptUnknown",
	{bridge.StatusCancelled, "not_performed"}: "L4+MarkCancelled+ReceiptUnknown",
	{bridge.StatusCancelled, "succeeded"}:     "MarkUnknown",
	{bridge.StatusCancelled, "failed"}:        "MarkUnknown",
	{bridge.StatusCancelled, "permitted"}:     "MarkUnknown",
	{bridge.StatusCancelled, "unknown"}:       "MarkUnknown",
	{bridge.StatusExpired, "none"}:            "L4+MarkCancelled+ReceiptUnknown",
	{bridge.StatusExpired, "not_performed"}:   "L4+MarkCancelled+ReceiptUnknown",
	{bridge.StatusExpired, "succeeded"}:       "MarkUnknown",
	{bridge.StatusExpired, "failed"}:          "MarkUnknown",
	{bridge.StatusExpired, "permitted"}:       "MarkUnknown",
	{bridge.StatusExpired, "unknown"}:         "MarkUnknown",
}

func TestReconcileOrderTable(t *testing.T) {
	statuses := []string{bridge.StatusPending, bridge.StatusLeased, bridge.StatusCompleted, bridge.StatusCancelled, bridge.StatusExpired}
	effects := []string{bridge.EffectNone, bridge.EffectPermitted, bridge.EffectSucceeded, bridge.EffectFailed, bridge.EffectNotPerformed, bridge.EffectUnknown}
	if len(wantReconcile) != len(statuses)*len(effects) {
		t.Fatalf("the expected table has %d rows, want %d: it must be total", len(wantReconcile), len(statuses)*len(effects))
	}
	ctx := context.Background()
	for _, s := range statuses {
		for _, e := range effects {
			want, ok := wantReconcile[pair{s, e}]
			if !ok {
				t.Fatalf("%s/%s is missing from the expected table", s, e)
			}
			d, log := reconcileDispatcher()
			o := &orders.Order{State: orders.StateDispatched, ApprovalRef: "aar_X", CommandID: "cmd_X"}
			err := d.reconcileOrder(ctx, nil, o, "cmd_X", s, e)
			if want == "ERR" {
				if err == nil || Refusal(err).Code != glovo.CodeUnavailable {
					t.Errorf("%s/%s: want unavailable, got %v", s, e, err)
				}
				if len(log.calls) != 0 {
					t.Errorf("%s/%s: the catch-all must make no call, got %s", s, e, log)
				}
			} else {
				if err != nil {
					t.Errorf("%s/%s: unexpected error %v", s, e, err)
				}
				if got := log.String(); got != want {
					t.Errorf("%s/%s: calls %s, want %s", s, e, got, want)
				}
			}
			// An order that is not dispatched makes no call and no error for any pair.
			for _, st := range []string{orders.StateOpen, orders.StateFinalized, orders.StateCancelled, orders.StateUnknown, orders.StateClosed} {
				d2, log2 := reconcileDispatcher()
				if err := d2.reconcileOrder(ctx, nil, &orders.Order{State: st, ApprovalRef: "aar_X"}, "cmd_X", s, e); err != nil || len(log2.calls) != 0 {
					t.Errorf("%s order with %s/%s: want no call and no error, got %v %s", st, s, e, err, log2)
				}
			}
		}
	}
	// A status outside the five is the catch-all too.
	d, log := reconcileDispatcher()
	if err := d.reconcileOrder(ctx, nil, &orders.Order{State: orders.StateDispatched, ApprovalRef: "aar_X"}, "cmd_X", "weird", "none"); err == nil || len(log.calls) != 0 {
		t.Errorf("an unknown status must be refused without a call, got %v %s", err, log)
	}
	// A receipt row with no approval or command is an invariant violation.
	d, log = reconcileDispatcher()
	if err := d.reconcileOrder(ctx, nil, &orders.Order{State: orders.StateDispatched}, "cmd_X", bridge.StatusCompleted, bridge.EffectNone); err == nil || len(log.calls) != 0 {
		t.Errorf("a dispatched order with no approval must be refused without a call, got %v %s", err, log)
	}
}

func TestRefusalIsClosedSet(t *testing.T) {
	in := map[glovo.Code]bool{}
	for _, c := range RefusalCodes {
		if !glovo.Registered(c) {
			t.Errorf("%s is not a registered glovo code", c)
		}
		in[c] = true
	}
	for _, c := range glovo.Codes() {
		got := Refusal(glovo.Refuse(c)).Code
		if !in[got] {
			t.Errorf("%s maps outside the closed set: %s", c, got)
		}
		if in[c] && got != c {
			t.Errorf("%s is in the set and must keep its code, got %s", c, got)
		}
		if !in[c] && got != glovo.CodeUnavailable {
			t.Errorf("%s is outside the set and must be unavailable, got %s", c, got)
		}
	}
	if Refusal(nil) != nil {
		t.Error("nil must stay nil")
	}
	if got := Refusal(fmt.Errorf("x: %w", &pgconn.PgError{Code: "55P03"})).Code; got != glovo.CodeTenantBusy {
		t.Errorf("a lock timeout must be tenant_busy, got %s", got)
	}
	if got := Refusal(fmt.Errorf("x: %w", bridge.ErrReadUnavailable)).Code; got != glovo.CodeNotReady {
		t.Errorf("a bridge read-level refusal must be not_ready, got %s", got)
	}
	if got := Refusal(errors.New("boom")).Code; got != glovo.CodeUnavailable {
		t.Errorf("a plain error must be unavailable, got %s", got)
	}
	if got := Refusal(unavailable("read", &pgconn.PgError{Code: "55P03"})).Code; got != glovo.CodeTenantBusy {
		t.Errorf("unavailable() must keep a lock timeout, got %s", got)
	}
	if got := Refusal(refuse(glovo.CodeApprovalExpired, "why")).Code; got != glovo.CodeApprovalExpired || !strings.Contains(Reason(refuse(glovo.CodeApprovalExpired, "why")), "why") {
		t.Errorf("refuse must keep code and reason, got %s", got)
	}
}
