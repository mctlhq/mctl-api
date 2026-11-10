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

// Package glovobasket is the Glovo basket MCP (mctl-api#1006): a synthetic
// catalog, owner-scoped baskets whose every change is a new immutable
// revision priced by the server, and an owner approval of one exact revision
// through the action-approval ledger (kind glovo.basket_approval). Nothing
// here places an order or talks to a provider.
package glovobasket

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
)

// The synthetic store every basket is priced in.
const (
	StoreRef         = "pst_SYNTHETICSTORE0001"
	Currency         = "EUR"
	DeliveryFeeMinor = 199
	ServiceFeeMinor  = 50
)

// Limits of one basket and one update.
const (
	MaxLines        = 30
	MaxQuantity     = 100
	MaxOpsPerUpdate = 30
	MaxClientKeyLen = 128
	// MaxRevisions bounds how often one basket can change.
	MaxRevisions = 200
)

// Product is one synthetic catalog entry.
type Product struct {
	ItemCode       string `json:"item_code"`
	Name           string `json:"name"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
}

// catalog is sorted by item code and never changes at run time.
var catalog = []Product{
	{"FAKE-APPLE", "Apple (1 pc)", 45},
	{"FAKE-BREAD", "Sourdough bread", 320},
	{"FAKE-COFFEE", "Ground coffee 250 g", 649},
	{"FAKE-EGGS-12", "Eggs (12)", 389},
	{"FAKE-MILK-1L", "Whole milk 1 l", 129},
	{"FAKE-PASTA", "Spaghetti 500 g", 159},
	{"FAKE-RICE-1KG", "Rice 1 kg", 249},
	{"FAKE-WATER-6", "Still water 6 x 1.5 l", 399},
}

// Catalog returns a copy of the synthetic catalog.
func Catalog() []Product { return append([]Product(nil), catalog...) }

func product(code string) (Product, bool) {
	i := sort.Search(len(catalog), func(i int) bool { return catalog[i].ItemCode >= code })
	if i < len(catalog) && catalog[i].ItemCode == code {
		return catalog[i], true
	}
	return Product{}, false
}

// Line is one priced line of a revision. The price is the catalog's, never
// the client's.
type Line struct {
	ItemCode       string `json:"item_code"`
	Name           string `json:"name"`
	Quantity       int64  `json:"quantity"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
	LineTotalMinor int64  `json:"line_total_minor"`
}

// Totals are the server-computed totals of a revision.
type Totals struct {
	Currency         string `json:"currency"`
	SubtotalMinor    int64  `json:"subtotal_minor"`
	DeliveryFeeMinor int64  `json:"delivery_fee_minor"`
	ServiceFeeMinor  int64  `json:"service_fee_minor"`
	DiscountMinor    int64  `json:"discount_minor"`
	TotalMinor       int64  `json:"total_minor"`
}

// Revision is one frozen state of a basket. An empty revision has no
// canonical form and no fingerprint: there is nothing to approve.
type Revision struct {
	Revision    int64     `json:"revision"`
	StoreRef    string    `json:"store_ref"`
	Lines       []Line    `json:"lines"`
	Totals      Totals    `json:"totals"`
	Canonical   []byte    `json:"-"`
	Fingerprint string    `json:"basket_fingerprint,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Basket is a basket head with its current revision.
type Basket struct {
	ID        string    `json:"basket_id"`
	Tenant    string    `json:"-"`
	Owner     string    `json:"-"`
	ClientKey string    `json:"client_key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Current   Revision  `json:"current"`
}

// Owner is who a basket belongs to: the resolved principal in the selected
// team.
type Owner struct {
	Tenant      string
	PrincipalID string
}

// Op is one change of an update: add (increase), remove (drop the item) or
// set (exact quantity, 0 drops it). There is no price field: the client never
// sends one.
type Op struct {
	Op       string `json:"op"`
	ItemCode string `json:"item_code"`
	Quantity int64  `json:"quantity,omitempty"`
}

var errInvalid = errors.New("invalid")

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errInvalid, fmt.Sprintf(format, a...))
}

// IsInvalid reports a refusal of the caller's input.
func IsInvalid(err error) bool { return errors.Is(err, errInvalid) }

// applyOps returns the quantities after ops, or a refusal.
func applyOps(cur []Line, ops []Op) (map[string]int64, error) {
	if len(ops) == 0 || len(ops) > MaxOpsPerUpdate {
		return nil, invalidf("an update has 1 to %d operations", MaxOpsPerUpdate)
	}
	qty := make(map[string]int64, len(cur))
	for _, l := range cur {
		qty[l.ItemCode] = l.Quantity
	}
	for _, op := range ops {
		if _, ok := product(op.ItemCode); !ok {
			return nil, invalidf("unknown item_code")
		}
		switch op.Op {
		case "add":
			if op.Quantity < 1 || op.Quantity > MaxQuantity {
				return nil, invalidf("add quantity is 1 to %d", MaxQuantity)
			}
			qty[op.ItemCode] += op.Quantity
		case "set":
			if op.Quantity < 0 || op.Quantity > MaxQuantity {
				return nil, invalidf("set quantity is 0 to %d", MaxQuantity)
			}
			qty[op.ItemCode] = op.Quantity
		case "remove":
			if op.Quantity != 0 {
				return nil, invalidf("remove takes no quantity")
			}
			delete(qty, op.ItemCode)
		default:
			return nil, invalidf("op is add, set or remove")
		}
		if qty[op.ItemCode] == 0 {
			delete(qty, op.ItemCode)
		}
		if qty[op.ItemCode] > MaxQuantity {
			return nil, invalidf("a line holds at most %d", MaxQuantity)
		}
	}
	if len(qty) > MaxLines {
		return nil, invalidf("a basket holds at most %d lines", MaxLines)
	}
	return qty, nil
}

// price builds a revision from quantities with catalog prices, and freezes
// its canonical form and fingerprint through the approval-basket contract.
func price(rev int64, qty map[string]int64, now time.Time) (Revision, error) {
	r := Revision{Revision: rev, StoreRef: StoreRef, Lines: []Line{}, Totals: Totals{Currency: Currency}, CreatedAt: now}
	codes := make([]string, 0, len(qty))
	for c := range qty {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	a := basket.Approval{V: "mctl-approval-basket/v1", StoreRef: StoreRef, Currency: Currency}
	for _, c := range codes {
		p, ok := product(c)
		if !ok {
			return Revision{}, invalidf("unknown item_code")
		}
		q := qty[c]
		r.Lines = append(r.Lines, Line{ItemCode: c, Name: p.Name, Quantity: q, UnitPriceMinor: p.UnitPriceMinor, LineTotalMinor: q * p.UnitPriceMinor})
		a.Lines = append(a.Lines, basket.Line{ItemCode: c, Quantity: q, UnitPriceMinor: p.UnitPriceMinor})
		a.SubtotalMinor += q * p.UnitPriceMinor
	}
	if len(r.Lines) == 0 {
		return r, nil
	}
	a.DeliveryFeeMinor, a.ServiceFeeMinor = DeliveryFeeMinor, ServiceFeeMinor
	a.TotalMinor = a.SubtotalMinor + a.DeliveryFeeMinor + a.ServiceFeeMinor - a.DiscountMinor
	canonical, err := basket.Canonical(a)
	if err != nil {
		return Revision{}, fmt.Errorf("glovo basket: canonical form: %w", err)
	}
	r.Totals = Totals{Currency: Currency, SubtotalMinor: a.SubtotalMinor, DeliveryFeeMinor: a.DeliveryFeeMinor,
		ServiceFeeMinor: a.ServiceFeeMinor, DiscountMinor: a.DiscountMinor, TotalMinor: a.TotalMinor}
	r.Canonical, r.Fingerprint = canonical, basket.Fingerprint(canonical)
	return r, nil
}

// verifyFrozen re-parses a stored revision's canonical form and checks it
// against its fingerprint and its lines before anything is approved: a stored
// row that does not reproduce is refused, never trusted.
func verifyFrozen(r Revision) error {
	if len(r.Lines) == 0 || len(r.Canonical) == 0 {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	a, canonical, err := basket.Parse(r.Canonical)
	if err != nil || string(canonical) != string(r.Canonical) || basket.Fingerprint(canonical) != r.Fingerprint {
		return glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	if len(a.Lines) != len(r.Lines) || a.TotalMinor != r.Totals.TotalMinor || a.StoreRef != r.StoreRef {
		return glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	for i, l := range a.Lines {
		if l.ItemCode != r.Lines[i].ItemCode || l.Quantity != r.Lines[i].Quantity || l.UnitPriceMinor != r.Lines[i].UnitPriceMinor {
			return glovo.Refuse(glovo.CodeFingerprintChanged)
		}
	}
	return nil
}

// newBasketID mints gbk_ + 26 characters of a Crockford alphabet.
func newBasketID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var raw [26]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("glovo basket: crypto/rand: %w", err)
	}
	out := make([]byte, 26)
	for i, b := range raw {
		out[i] = alphabet[b&31]
	}
	return "gbk_" + string(out), nil
}
