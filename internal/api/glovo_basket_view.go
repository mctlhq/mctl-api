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
	"fmt"

	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// GlovoBasketReader is what the approval page needs from the basket store
// (glovobasket.PGStore): the frozen revision an approval is bound to, and the
// basket's head.
type GlovoBasketReader interface {
	DecisionPayload(ctx context.Context, approvalRef string) (*glovobasket.DecisionPayload, error)
	Get(ctx context.Context, o glovobasket.Owner, basketID string) (*glovobasket.Basket, error)
}

// NewGlovoBasketApprovalView adapts the basket store to the approval page
// (mctl-api#1006). It lives here, not in glovobasket, because glovobasket
// cannot import this package.
func NewGlovoBasketApprovalView(r GlovoBasketReader) GlovoBasketApprovalView {
	return glovoBasketStoreView{r: r}
}

type glovoBasketStoreView struct{ r GlovoBasketReader }

// BasketApproval reads the frozen revision, then the head as of now. Only the
// ledger's "no such approval" is ErrGlovoBasketApprovalNotFound; a binding
// whose basket cannot be read under its own owner is a broken ledger, and
// every failed read stays an error, never an absence.
func (v glovoBasketStoreView) BasketApproval(ctx context.Context, approvalRef string) (*GlovoBasketApprovalSnapshot, error) {
	p, err := v.r.DecisionPayload(ctx, approvalRef)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return nil, ErrGlovoBasketApprovalNotFound
	case err != nil:
		return nil, err
	case p == nil:
		return nil, errors.New("glovo basket view: empty decision payload")
	}
	// v1 has no discounts; a snapshot the page cannot show exactly (lines +
	// fees = total) is refused rather than approximated.
	if p.Totals.DiscountMinor != 0 {
		return nil, fmt.Errorf("glovo basket view: %s carries a discount the page cannot show", approvalRef)
	}
	b, err := v.r.Get(ctx, glovobasket.Owner{Tenant: p.Tenant, PrincipalID: p.Owner}, p.BasketID)
	if err != nil {
		return nil, fmt.Errorf("glovo basket view: read head of %s: %w", p.BasketID, err)
	}
	s := &GlovoBasketApprovalSnapshot{
		ApprovalRef: p.ApprovalRef, Tenant: p.Tenant, OwnerPrincipalID: p.Owner, BasketID: p.BasketID,
		Revision: p.Revision, CurrentRevision: b.Current.Revision, Fingerprint: p.Fingerprint,
		Currency: p.Totals.Currency, FeesMinor: p.Totals.DeliveryFeeMinor + p.Totals.ServiceFeeMinor,
		TotalMinor: p.Totals.TotalMinor, Lines: make([]GlovoBasketLine, 0, len(p.Lines)),
	}
	for _, l := range p.Lines {
		s.Lines = append(s.Lines, GlovoBasketLine{ProductID: l.ItemCode, Name: l.Name, Quantity: l.Quantity,
			UnitPriceMinor: l.UnitPriceMinor, LineTotalMinor: l.LineTotalMinor})
	}
	return s, nil
}
