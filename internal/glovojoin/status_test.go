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
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// T6: the literal expected table over every (status, effect) pair of #985
// 2a. "-" is the complement row: 503, no state body.
func TestMapOrderStatusEveryCommandPair(t *testing.T) {
	statuses := []string{"pending", "leased", "completed", "cancelled", "expired"}
	effects := []string{"none", "permitted", "succeeded", "failed", "not_performed", "unknown"}
	want := map[string][6]string{
		//             none        permitted   succeeded   failed      not_performed unknown
		"pending":   {"dispatched", "dispatched", "-", "-", "-", "unknown"},
		"leased":    {"dispatched", "dispatched", "-", "-", "-", "unknown"},
		"completed": {"failed", "-", "placed", "failed", "failed", "unknown"},
		"cancelled": {"cancelled", "unknown", "unknown", "unknown", "cancelled", "unknown"},
		"expired":   {"cancelled", "unknown", "unknown", "unknown", "cancelled", "unknown"},
	}
	for _, order := range []string{"dispatched", "closed"} {
		for _, st := range statuses {
			for i, ef := range effects {
				state, outcome, ok := MapOrderStatus(order, "", st, ef)
				w := want[st][i]
				if w == "-" {
					if ok || state != "" || outcome != "" {
						t.Errorf("%s (%s,%s) = %q %q %v, want 503", order, st, ef, state, outcome, ok)
					}
					continue
				}
				wantOutcome := OutcomeUnknown
				if w == "placed" {
					wantOutcome = OutcomeObservedPlaced
				}
				if !ok || state != w || outcome != wantOutcome {
					t.Errorf("%s (%s,%s) = %q %q %v, want %q %q", order, st, ef, state, outcome, ok, w, wantOutcome)
				}
			}
		}
	}
}

func TestMapOrderStatusEveryOrderState(t *testing.T) {
	rows := []struct{ order, aar, state string }{
		{"open", "", "open"}, {"cancelled", "", "cancelled"}, {"unknown", "", "unknown"},
		{"finalized", "pending", "awaiting_approval"}, {"finalized", "approved", "approved"},
		{"finalized", "refused", "refused"}, {"finalized", "expired", "expired"},
	}
	for _, r := range rows {
		state, outcome, ok := MapOrderStatus(r.order, r.aar, "", "")
		if !ok || state != r.state || outcome != OutcomeUnknown {
			t.Errorf("%s/%s = %q %q %v, want %q", r.order, r.aar, state, outcome, ok, r.state)
		}
	}
	// A finalized order whose aar_ is in a state outside the table, and a state
	// the order machine does not have, are never mapped to something benign.
	for _, r := range []struct{ order, aar string }{{"finalized", "reserved"}, {"finalized", "consumed"}, {"finalized", ""}, {"closed-ish", ""}, {"", ""}} {
		if _, _, ok := MapOrderStatus(r.order, r.aar, "", ""); ok {
			t.Errorf("%s/%s mapped; want no state", r.order, r.aar)
		}
	}
	// observed_placed only ever comes from (completed, succeeded).
	for _, st := range []string{"pending", "leased", "completed", "cancelled", "expired", ""} {
		for _, ef := range []string{"none", "permitted", "succeeded", "failed", "not_performed", "unknown", ""} {
			for _, o := range []string{"dispatched", "closed", "open", "finalized"} {
				placedPair := st == "completed" && ef == "succeeded" && (o == "dispatched" || o == "closed")
				if _, out, ok := MapOrderStatus(o, "approved", st, ef); ok && out == OutcomeObservedPlaced && !placedPair {
					t.Errorf("observed_placed for %s %s %s", o, st, ef)
				}
			}
		}
	}
}

type fakeStatusOrders struct {
	o   *orders.Order
	err error
}

func (f *fakeStatusOrders) Get(context.Context, dbq.Querier, orders.Scope, string) (*orders.Order, error) {
	return f.o, f.err
}

type fakeStatusApprovals struct {
	st  *workitems.GlovoApprovalStatus
	err error
}

func (f *fakeStatusApprovals) GlovoApprovalStatus(context.Context, dbq.Querier, []string, string) (*workitems.GlovoApprovalStatus, error) {
	return f.st, f.err
}

type fakeStatusCommands struct {
	status, effect string
	err            error
	calls          int
}

func (f *fakeStatusCommands) CommandEffect(context.Context, dbq.Querier, []string, string) (string, string, error) {
	f.calls++
	return f.status, f.effect, f.err
}

func TestStatusReaderNeverInventsAState(t *testing.T) {
	ctx := context.Background()
	disp := func() *orders.Order {
		return &orders.Order{OrderRef: "ordr_x", State: orders.StateDispatched, CommandID: "cmd_x"}
	}
	cases := []struct {
		name  string
		order *fakeStatusOrders
		appr  *fakeStatusApprovals
		cmd   *fakeStatusCommands
		code  glovo.Code
		state string
	}{
		{"placed", &fakeStatusOrders{o: disp()}, nil, &fakeStatusCommands{status: "completed", effect: "succeeded"}, "", "placed"},
		{"command absent", &fakeStatusOrders{o: disp()}, nil, &fakeStatusCommands{err: bridge.ErrCommandNotFound}, glovo.CodeUnavailable, ""},
		{"command read failed", &fakeStatusOrders{o: disp()}, nil, &fakeStatusCommands{err: &pgconn.PgError{Code: "08006"}}, glovo.CodeUnavailable, ""},
		{"pair outside the table", &fakeStatusOrders{o: disp()}, nil, &fakeStatusCommands{status: "pending", effect: "succeeded"}, glovo.CodeUnavailable, ""},
		{"dispatched without a command id", &fakeStatusOrders{o: &orders.Order{State: orders.StateDispatched}}, nil, &fakeStatusCommands{}, glovo.CodeUnavailable, ""},
		{"approval read failed", &fakeStatusOrders{o: &orders.Order{State: orders.StateFinalized, ApprovalRef: "aar_x"}}, &fakeStatusApprovals{err: errors.New("down")}, nil, glovo.CodeUnavailable, ""},
		{"awaiting", &fakeStatusOrders{o: &orders.Order{State: orders.StateFinalized, ApprovalRef: "aar_x"}}, &fakeStatusApprovals{st: &workitems.GlovoApprovalStatus{State: "pending"}}, nil, "", "awaiting_approval"},
		{"foreign order", &fakeStatusOrders{err: glovo.ErrNotFound}, nil, nil, glovo.CodeNotFound, ""},
		{"order read failed", &fakeStatusOrders{err: errors.New("down")}, nil, nil, glovo.CodeUnavailable, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var unobserved []string
			r := &StatusReader{Orders: c.order, OnUnobserved: func(_, reason string) { unobserved = append(unobserved, reason) }}
			if c.appr != nil {
				r.Approvals = c.appr
			}
			if c.cmd != nil {
				r.Commands = c.cmd
			}
			state, outcome, rf := r.Status(ctx, "acme", "prn_O", "ordr_x")
			if c.code == "" {
				if rf != nil || state != c.state || outcome == "" {
					t.Fatalf("got %q %q %v", state, outcome, rf)
				}
				return
			}
			if rf == nil || !errors.Is(rf, glovo.Refuse(c.code)) || state != "" || outcome != "" {
				t.Fatalf("got %q %q %v, want %s with no body", state, outcome, rf, c.code)
			}
			if c.code == glovo.CodeUnavailable && c.name != "order read failed" && len(unobserved) != 1 {
				t.Fatalf("unobserved hook calls = %v", unobserved)
			}
		})
	}
}
