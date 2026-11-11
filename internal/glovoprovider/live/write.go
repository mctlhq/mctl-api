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

package live

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// MutationKind names one cart write.
type MutationKind string

// Cart write kinds (upstream add_to_basket, set_quantity, remove_from_basket).
const (
	MutationAdd         MutationKind = "add"
	MutationSetQuantity MutationKind = "set_quantity"
	MutationRemove      MutationKind = "remove"
)

const maxLineQuantity = 99

// WriteRejected is the state of a write the provider definitively refused
// (4xx): nothing was applied.
const WriteRejected gp.WriteState = "rejected"

// CartMutation is one cart write on the owner's REAL Glovo cart.
//
// ExpectedVersion is the caller-supplied precondition: the Version of the
// CartSnapshot the caller read (NoBasketVersion when the store had no
// basket). ApplyCart reads the live cart first and refuses, writing nothing,
// when the live version differs.
type CartMutation struct {
	Kind            MutationKind
	StoreRef        string // "<storeId>:<storeAddressId>"
	StoreCategoryID string // required only when the add creates the basket
	ProductID       string
	// Options are the selected modifiers: the selection of an add, and with
	// ProductID the identity of the line for set_quantity and remove.
	Options         []gp.CartOption
	Quantity        int64 // add: units to add (>= 1); set_quantity: new quantity (>= 1)
	ExpectedVersion string
}

// ApplyResult is the terminal state of one write attempt. Cart is the
// reread cart when the reread succeeded (reconciled or mismatch), or the
// live cart that failed the precondition.
type ApplyResult struct {
	State gp.WriteState
	Cart  gp.CartSnapshot
}

// CartMutator is the effectful, separate write interface. Nothing in this
// change wires it to an MCP tool, a route or startup.
//
// ApplyCart performs: live read, version precondition, one write, reread,
// reconcile. It never retries a write. A write whose outcome is not known
// returns State reconcile_unknown with ErrWriteUnknown; the caller must read
// the cart back (Reader.CartForStore) before deciding anything.
type CartMutator interface {
	ApplyCart(ctx context.Context, m CartMutation) (ApplyResult, error)
}

// Writer adds the cart write to a Reader. It exists as a separate type so
// that holding a Reader gives no way to change the cart.
//
// Writer is NOT a glovoprovider.CartWriter: that interface binds a write to
// a cart fingerprint, an intent digest and a live human approval grant. Any
// caller of ApplyCart must sit behind an approval-bound wrapper that verifies
// the grant first; the adapter checks only the basket version. WriteRejected
// is outside glovoprovider's transition table and is terminal, like the
// other refusals.
type Writer struct{ *Reader }

var _ CartMutator = (*Writer)(nil)

// NewWriter builds a Writer.
func NewWriter(cfg Config, ts TokenSource) (*Writer, error) {
	r, err := NewReader(cfg, ts)
	if err != nil {
		return nil, err
	}
	return &Writer{Reader: r}, nil
}

func (m CartMutation) validate() error {
	op := gp.OpApplyCart
	switch m.Kind {
	case MutationAdd, MutationSetQuantity:
		if m.Quantity < 1 || m.Quantity > maxLineQuantity {
			return gp.Invalid(op, "quantity")
		}
	case MutationRemove:
	default:
		return gp.Invalid(op, "kind")
	}
	if _, _, err := parseRef(op, m.StoreRef); err != nil {
		return err
	}
	if !validID(m.ProductID) {
		return gp.Invalid(op, "product_id")
	}
	if m.ExpectedVersion != NoBasketVersion && !validID(m.ExpectedVersion) {
		return gp.Invalid(op, "expected_version")
	}
	seen := map[string]bool{}
	for _, o := range m.Options {
		k := o.GroupID + "=" + o.OptionID
		if !validID(o.GroupID) || !validID(o.OptionID) || seen[k] {
			return gp.Invalid(op, "options")
		}
		seen[k] = true
	}
	if m.StoreCategoryID != "" && !validID(m.StoreCategoryID) {
		return gp.Invalid(op, "store_category_id")
	}
	return nil
}

// ApplyCart applies one cart write. See CartMutator.
func (w *Writer) ApplyCart(ctx context.Context, m CartMutation) (ApplyResult, error) {
	op := gp.OpApplyCart
	if err := m.validate(); err != nil {
		return ApplyResult{State: gp.WritePlanned}, err
	}
	c := w.c
	live, err := c.basketByStore(ctx, op, m.StoreRef)
	if err != nil {
		return ApplyResult{State: gp.WritePlanned}, err
	}
	liveSnap, err := c.snapshotOf(live)
	if err != nil {
		return ApplyResult{State: gp.WritePlanned}, err
	}
	if liveSnap.Version != m.ExpectedVersion {
		return ApplyResult{State: gp.WritePreconditionFailed, Cart: liveSnap}, kindErr(op, ErrPrecondition)
	}

	req, expected, err := c.planWrite(ctx, m, live)
	if err != nil {
		return ApplyResult{State: gp.WritePlanned}, err
	}

	// The one and only write attempt.
	if _, werr := c.doWrite(ctx, op, req); werr != nil {
		switch {
		case errors.Is(werr, ErrWriteRejected):
			return ApplyResult{State: WriteRejected}, werr
		default:
			return ApplyResult{State: gp.WriteReconcileUnknown}, werr
		}
	}

	after, err := c.basketByStore(ctx, op, m.StoreRef)
	if err != nil {
		return ApplyResult{State: gp.WriteReconcileUnknown}, unobserved(op, errors.Join(ErrWriteUnknown, err))
	}
	snap, err := c.snapshotOf(after)
	if err != nil {
		return ApplyResult{State: gp.WriteReconcileUnknown}, unobserved(op, errors.Join(ErrWriteUnknown, err))
	}
	if !sameContent(snap, expected) {
		return ApplyResult{State: gp.WriteMismatch, Cart: snap}, kindErr(op, ErrReconcileMismatch)
	}
	return ApplyResult{State: gp.WriteReconciled, Cart: snap}, nil
}

func (c *core) snapshotOf(b *basket) (gp.CartSnapshot, error) {
	if b == nil {
		return c.emptyCart()
	}
	return b.snapshot, nil
}

// expectedCart is what the cart must contain after the write.
type expectedCart struct {
	storeRef string
	lines    map[string]int64
}

func sameContent(snap gp.CartSnapshot, e expectedCart) bool {
	got := sortedLineKeys(snap.Lines)
	if len(got) != len(e.lines) {
		return false
	}
	for k, v := range e.lines {
		if got[k] != v {
			return false
		}
	}
	return len(e.lines) == 0 || snap.StoreID == e.storeRef
}

func lineKey(productID string, opts []gp.CartOption) string {
	return productID + "|" + gp.OptionKey(opts)
}

func (c *core) basketPath(op, cid string, parts ...string) string {
	base := []string{"v1", "authenticated", "customers", pathEsc(cid), "baskets"}
	return joinPath(append(base, parts...)...)
}

// planWrite builds the single write request and the content the cart must
// have afterwards. It performs only reads.
func (c *core) planWrite(ctx context.Context, m CartMutation, live *basket) (reqSpec, expectedCart, error) {
	op := gp.OpApplyCart
	cid, err := c.customer(ctx)
	if err != nil {
		return reqSpec{}, expectedCart{}, err
	}
	exp := expectedCart{storeRef: m.StoreRef, lines: map[string]int64{}}
	var existing *basketLine
	if live != nil {
		matches := 0
		for i := range live.lines {
			l := live.lines[i]
			exp.lines[lineKey(l.line.ProductID, l.line.Options)] += l.line.Quantity
			if l.line.ProductID == m.ProductID && gp.OptionKey(l.line.Options) == gp.OptionKey(m.Options) {
				existing = &live.lines[i]
				matches++
			}
		}
		// Two lines with the same product and options cannot be told apart
		// by the neutral model; changing one would never reconcile.
		if matches > 1 {
			return reqSpec{}, exp, gp.Invalid(op, "ambiguous line")
		}
	}
	key := lineKey(m.ProductID, m.Options)

	if m.Kind != MutationAdd {
		if existing == nil {
			return reqSpec{}, exp, gp.Invalid(op, "line not in cart")
		}
		q := m.Quantity
		if m.Kind == MutationRemove {
			q = 0
		}
		if q == 0 {
			delete(exp.lines, key)
		} else {
			exp.lines[key] = q
		}
		return c.quantityRequest(cid, live, existing.basketProductID, q), exp, nil
	}

	d, err := c.productDetail(ctx, op, m.StoreRef, m.ProductID)
	if err != nil {
		return reqSpec{}, exp, err
	}
	if !d.product.Available {
		return reqSpec{}, exp, gp.Invalid(op, "product unavailable")
	}
	product, err := buildBasketProduct(d, m)
	if err != nil {
		return reqSpec{}, exp, err
	}
	exp.lines[key] += m.Quantity

	switch {
	case live == nil:
		if m.StoreCategoryID == "" {
			return reqSpec{}, exp, gp.Invalid(op, "store_category_id")
		}
		store, addr, _ := parseRef(op, m.StoreRef)
		return reqSpec{method: http.MethodPost, path: c.basketPath(op, cid), body: map[string]any{
			"products":         []any{product},
			"storeId":          numOrString(store),
			"storeAddressId":   numOrString(addr),
			"storeCategoryId":  numOrString(m.StoreCategoryID),
			"handlingStrategy": "DELIVERY",
		}}, exp, nil
	case existing != nil:
		if existing.line.Quantity+m.Quantity > maxLineQuantity {
			return reqSpec{}, exp, gp.Invalid(op, "quantity")
		}
		return c.quantityRequest(cid, live, existing.basketProductID, existing.line.Quantity+m.Quantity), exp, nil
	default:
		// Echo the basket as read, with its basketVersion, and append the line.
		var products []json.RawMessage
		if err := json.Unmarshal(live.raw["products"], &products); err != nil {
			return reqSpec{}, exp, unobserved(op, ErrSchemaDrift)
		}
		pj, err := json.Marshal(product)
		if err != nil {
			return reqSpec{}, exp, unobserved(op, ErrSchemaDrift)
		}
		body := make(map[string]json.RawMessage, len(live.raw))
		for k, v := range live.raw {
			body[k] = v
		}
		prods, err := json.Marshal(append(products, pj))
		if err != nil {
			return reqSpec{}, exp, unobserved(op, ErrSchemaDrift)
		}
		body["products"] = prods
		return reqSpec{method: http.MethodPut, path: c.basketPath(op, cid, pathEsc(live.id), "products"), body: body}, exp, nil
	}
}

func (c *core) quantityRequest(cid string, live *basket, basketProductID string, qty int64) reqSpec {
	return reqSpec{method: http.MethodPatch, path: c.basketPath("", cid, pathEsc(live.id), "products", "quantity"), body: map[string]any{
		"handlingStrategy": live.handling,
		"basketVersion":    live.version,
		"products":         []any{map[string]any{"basketProductId": basketProductID, "quantity": qty}},
	}}
}

func numOrString(s string) any {
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return json.Number(s)
	}
	return s
}

// buildBasketProduct validates the selected options against the live
// product view (known group and option, available, per-group min and max)
// and builds the upstream basket product payload from the view's own ids.
func buildBasketProduct(d productDetail, m CartMutation) (map[string]any, error) {
	op := gp.OpApplyCart
	if d.meta.ExternalID.s() == "" || d.meta.StoreProductID.s() == "" {
		return nil, unobserved(op, ErrSchemaDrift)
	}
	groups := map[string]groupMeta{}
	for i := range d.meta.Groups {
		groups[d.meta.Groups[i].ID.s()] = d.meta.Groups[i]
	}
	counts := map[string]int{}
	var customizations []any
	for _, sel := range m.Options {
		g, ok := groups[sel.GroupID]
		if !ok {
			return nil, gp.Invalid(op, "unknown option group")
		}
		var om *optMeta
		for i := range g.Attributes {
			if g.Attributes[i].ID.s() == sel.OptionID {
				om = &g.Attributes[i]
			}
		}
		if om == nil {
			return nil, gp.Invalid(op, "unknown option")
		}
		var ng gp.OptionGroup
		for _, pg := range d.product.OptionGroups {
			if pg.ID == sel.GroupID {
				ng = pg
			}
		}
		for _, po := range ng.Options {
			if po.ID == sel.OptionID && !po.Available {
				return nil, gp.Invalid(op, "option unavailable")
			}
		}
		if g.GroupID.s() == "" || g.ExternalID.s() == "" || g.Position == nil || om.ExternalID.s() == "" {
			return nil, unobserved(op, ErrSchemaDrift)
		}
		counts[sel.GroupID]++
		ids := map[string]any{
			"groupLegacyId":   g.ID,
			"groupId":         g.GroupID,
			"groupExternalId": g.ExternalID,
			"groupPosition":   *g.Position,
			"legacyId":        om.ID,
			"externalId":      om.ExternalID,
		}
		if om.OptionID.s() != "" {
			ids["id"] = om.OptionID
		}
		customizations = append(customizations, map[string]any{
			"ids":               ids,
			"name":              om.Name,
			"quantity":          map[string]any{"increments": 1},
			"customizationName": om.Name,
			"groupName":         g.Name,
		})
	}
	for _, pg := range d.product.OptionGroups {
		n := counts[pg.ID]
		if (pg.Required && n < pg.Min) || n > pg.Max {
			return nil, gp.Invalid(op, "option group selection count")
		}
	}
	product := map[string]any{
		"ids": map[string]any{
			"id":             d.meta.ID,
			"externalId":     d.meta.ExternalID,
			"storeProductId": d.meta.StoreProductID,
		},
		"quantity": map[string]any{"increments": m.Quantity},
	}
	if len(customizations) > 0 {
		product["customizations"] = customizations
	}
	return product, nil
}
