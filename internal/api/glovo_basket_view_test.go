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
	"reflect"
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

type fakeBasketReader struct {
	payload  *glovobasket.DecisionPayload
	payErr   error
	head     *glovobasket.Basket
	headErr  error
	gotOwner glovobasket.Owner
	gotID    string
}

func (f *fakeBasketReader) DecisionPayload(context.Context, string) (*glovobasket.DecisionPayload, error) {
	return f.payload, f.payErr
}

func (f *fakeBasketReader) Get(_ context.Context, o glovobasket.Owner, id string) (*glovobasket.Basket, error) {
	f.gotOwner, f.gotID = o, id
	return f.head, f.headErr
}

func TestGlovoBasketStoreViewMapsTheFrozenRevision(t *testing.T) {
	ctx := context.Background()
	payload := func() *glovobasket.DecisionPayload {
		return &glovobasket.DecisionPayload{ApprovalRef: "aar_1", BasketID: "gbk_1", Revision: 2, Fingerprint: "sha256:ab",
			Tenant: "alpha", Owner: "prn_owner",
			Lines: []glovobasket.Line{{ItemCode: "FAKE-PASTA", Name: "Pasta", Quantity: 3, UnitPriceMinor: 159, LineTotalMinor: 477}},
			Totals: glovobasket.Totals{Currency: "EUR", SubtotalMinor: 477, DeliveryFeeMinor: 199, ServiceFeeMinor: 50,
				TotalMinor: 726}}
	}
	r := &fakeBasketReader{payload: payload(), head: &glovobasket.Basket{Current: glovobasket.Revision{Revision: 3}}}
	s, err := NewGlovoBasketApprovalView(r).BasketApproval(ctx, "aar_1")
	if err != nil {
		t.Fatal(err)
	}
	want := GlovoBasketApprovalSnapshot{ApprovalRef: "aar_1", Tenant: "alpha", OwnerPrincipalID: "prn_owner", BasketID: "gbk_1",
		Revision: 2, CurrentRevision: 3, Fingerprint: "sha256:ab", Currency: "EUR", FeesMinor: 249, TotalMinor: 726}
	got := *s
	got.Lines, want.Lines = nil, nil
	if !reflect.DeepEqual(got, want) || len(s.Lines) != 1 || s.Lines[0] != (GlovoBasketLine{ProductID: "FAKE-PASTA", Name: "Pasta", Quantity: 3,
		UnitPriceMinor: 159, LineTotalMinor: 477}) {
		t.Fatalf("snapshot: %+v", s)
	}
	// The head is read under the binding's own tenant and owner.
	if r.gotOwner != (glovobasket.Owner{Tenant: "alpha", PrincipalID: "prn_owner"}) || r.gotID != "gbk_1" {
		t.Fatalf("head read as %+v %q", r.gotOwner, r.gotID)
	}
	// The page's own arithmetic accepts what the adapter produces.
	if _, err := basketTableOf(s); err != nil {
		t.Fatalf("page refuses the adapted snapshot: %v", err)
	}

	// Only the ledger's absence is "not found"; every failed read is an error.
	down := glovo.Refuse(glovo.CodeUnavailable)
	for name, f := range map[string]*fakeBasketReader{
		"no approval":   {payErr: workitems.ErrApprovalNotFound},
		"payload down":  {payErr: down},
		"head down":     {payload: payload(), headErr: down},
		"head missing":  {payload: payload(), headErr: glovo.ErrNotFound},
		"empty payload": {},
		"discount": {payload: func() *glovobasket.DecisionPayload {
			p := payload()
			p.Totals.DiscountMinor, p.Totals.TotalMinor = 10, 716
			return p
		}(), head: &glovobasket.Basket{}},
	} {
		_, err := NewGlovoBasketApprovalView(f).BasketApproval(ctx, "aar_1")
		notFound := errors.Is(err, ErrGlovoBasketApprovalNotFound)
		if name == "no approval" {
			if !notFound {
				t.Errorf("%s: %v, want not found", name, err)
			}
			continue
		}
		if err == nil || notFound {
			t.Errorf("%s: %v, want a failed read", name, err)
		}
	}
}
