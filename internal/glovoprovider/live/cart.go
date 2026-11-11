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
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// NoBasketVersion is the Version of a snapshot of a store with no basket.
// It is the value a caller passes as ExpectedVersion to create one.
const NoBasketVersion = "none"

type basketWire struct {
	BasketID       flexString           `json:"basketId"`
	BasketVersion  flexString           `json:"basketVersion"`
	StoreID        flexString           `json:"storeId"`
	StoreAddressID flexString           `json:"storeAddressId"`
	Handling       string               `json:"handlingStrategy"`
	Products       *[]basketProductWire `json:"products"`
}

type basketProductWire struct {
	IDs struct {
		BasketProductID flexString `json:"basketProductId"`
		ID              flexString `json:"id"`
	} `json:"ids"`
	Quantity struct {
		Increments json.RawMessage `json:"increments"`
	} `json:"quantity"`
	Price struct {
		Final struct {
			Major     json.RawMessage `json:"major"`
			Formatted json.RawMessage `json:"formatted"`
		} `json:"final"`
	} `json:"price"`
	Customizations []struct {
		IDs *struct {
			GroupLegacyID flexString `json:"groupLegacyId"`
			LegacyID      flexString `json:"legacyId"`
		} `json:"ids"`
		Quantity *struct {
			Increments json.RawMessage `json:"increments"`
		} `json:"quantity"`
	} `json:"customizations"`
}

// basket is a parsed live basket plus the identifiers the write needs. The
// raw body is kept so a PUT can echo it unchanged, as upstream does.
type basket struct {
	snapshot gp.CartSnapshot
	id       string
	version  json.RawMessage
	handling string
	raw      map[string]json.RawMessage
	lines    []basketLine
}

type basketLine struct {
	basketProductID string
	line            gp.CartLine
}

func (c *core) parseBasket(op string, raw []byte) (*basket, error) {
	var w basketWire
	if err := decode(op, raw, &w); err != nil {
		return nil, err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil, unobserved(op, ErrSchemaDrift)
	}
	if !validID(string(w.BasketID)) || !validID(string(w.BasketVersion)) ||
		!validID(string(w.StoreID)) || !validID(string(w.StoreAddressID)) || w.Products == nil {
		return nil, unobserved(op, ErrSchemaDrift)
	}
	b := &basket{id: string(w.BasketID), version: rawMap["basketVersion"], handling: w.Handling, raw: rawMap}
	if b.handling == "" {
		b.handling = "DELIVERY"
	}
	lines := make([]gp.CartLine, 0, len(*w.Products))
	for i := range *w.Products {
		p := &(*w.Products)[i]
		if !validID(string(p.IDs.ID)) || !validID(string(p.IDs.BasketProductID)) {
			return nil, unobserved(op, ErrSchemaDrift)
		}
		qty, err := parseQuantity(p.Quantity.Increments)
		if err != nil {
			return nil, unobserved(op, err)
		}
		pr := firstRaw(p.Price.Final.Major, p.Price.Final.Formatted)
		total, err := parseMoney(pr, c.cfg.Currency)
		if err != nil || total < 0 || total%qty != 0 {
			return nil, unobserved(op, ErrSchemaDrift)
		}
		l := gp.CartLine{ProductID: string(p.IDs.ID), Quantity: qty, UnitPriceMinor: total / qty}
		for _, cz := range p.Customizations {
			if cz.IDs == nil || !validID(string(cz.IDs.GroupLegacyID)) || !validID(string(cz.IDs.LegacyID)) {
				return nil, unobserved(op, ErrSchemaDrift)
			}
			if cz.Quantity != nil && len(cz.Quantity.Increments) > 0 {
				if n, err := parseQuantity(cz.Quantity.Increments); err != nil || n != 1 {
					return nil, unobserved(op, ErrSchemaDrift) // CartOption has no quantity
				}
			}
			l.Options = append(l.Options, gp.CartOption{GroupID: string(cz.IDs.GroupLegacyID), OptionID: string(cz.IDs.LegacyID)})
		}
		lines = append(lines, l)
		b.lines = append(b.lines, basketLine{basketProductID: string(p.IDs.BasketProductID), line: l})
	}
	snap := gp.CartSnapshot{StoreID: makeRef(string(w.StoreID), string(w.StoreAddressID)), Currency: c.cfg.Currency, Lines: lines, Version: string(w.BasketVersion)}
	fp, err := gp.CartFingerprint(snap)
	if err != nil {
		return nil, unobserved(op, ErrSchemaDrift)
	}
	snap.Fingerprint = fp
	b.snapshot = snap
	return b, nil
}

func (c *core) emptyCart() (gp.CartSnapshot, error) {
	snap := gp.CartSnapshot{Currency: c.cfg.Currency, Lines: []gp.CartLine{}, Version: NoBasketVersion}
	fp, err := gp.CartFingerprint(snap)
	if err != nil {
		return gp.CartSnapshot{}, unobserved(gp.OpCart, ErrSchemaDrift)
	}
	snap.Fingerprint = fp
	return snap, nil
}

// basketByStore reads the basket of one store. 404 is upstream's documented
// "no basket for this store" signal and yields (nil, nil).
func (c *core) basketByStore(ctx context.Context, op, storeRef string) (*basket, error) {
	store, _, err := parseRef(op, storeRef)
	if err != nil {
		return nil, err
	}
	cid, err := c.customer(ctx)
	if err != nil {
		return nil, err
	}
	body, status, err := c.do(ctx, op, reqSpec{method: http.MethodGet, path: joinPath("v1", "authenticated", "customers", pathEsc(cid), "baskets", "stores", pathEsc(store)), allow404: true})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	b, err := c.parseBasket(op, body)
	if err != nil {
		return nil, err
	}
	if b.snapshot.StoreID != storeRef {
		return nil, unobserved(op, ErrSchemaDrift) // the basket is for another store address
	}
	return b, nil
}

// Cart returns the owner's real cart. Zero baskets is an observed empty
// cart; more than one basket cannot be expressed as one snapshot and is
// unobserved (use CartForStore).
func (r *Reader) Cart(ctx context.Context) (gp.CartSnapshot, error) {
	cid, err := r.c.customer(ctx)
	if err != nil {
		return gp.CartSnapshot{}, retag(err, gp.OpCart)
	}
	body, _, err := r.c.do(ctx, gp.OpCart, reqSpec{method: http.MethodGet, path: joinPath("v1", "authenticated", "customers", pathEsc(cid), "baskets")})
	if err != nil {
		return gp.CartSnapshot{}, err
	}
	var items []json.RawMessage
	trim := bytes.TrimSpace(body)
	switch {
	case len(trim) > 0 && trim[0] == '[':
		if err := decode(gp.OpCart, body, &items); err != nil {
			return gp.CartSnapshot{}, err
		}
	default:
		var w struct {
			Baskets *[]json.RawMessage `json:"baskets"`
		}
		if err := decode(gp.OpCart, body, &w); err != nil {
			return gp.CartSnapshot{}, err
		}
		if w.Baskets == nil {
			return gp.CartSnapshot{}, unobserved(gp.OpCart, ErrSchemaDrift)
		}
		items = *w.Baskets
	}
	switch len(items) {
	case 0:
		return r.c.emptyCart()
	case 1:
		b, err := r.c.parseBasket(gp.OpCart, items[0])
		if err != nil {
			return gp.CartSnapshot{}, err
		}
		return b.snapshot, nil
	default:
		return gp.CartSnapshot{}, unobserved(gp.OpCart, ErrSchemaDrift)
	}
}

func retag(err error, op string) error {
	if re, ok := err.(*gp.ReadError); ok {
		cp := *re
		cp.Op = op
		return &cp
	}
	return err
}

// CartForStore reads the basket of one store ("<storeId>:<addressId>"). No
// basket is an observed empty cart with Version NoBasketVersion.
func (r *Reader) CartForStore(ctx context.Context, storeRef string) (gp.CartSnapshot, error) {
	return r.c.cartForStore(ctx, storeRef)
}

func (c *core) cartForStore(ctx context.Context, storeRef string) (gp.CartSnapshot, error) {
	b, err := c.basketByStore(ctx, gp.OpCart, storeRef)
	if err != nil {
		return gp.CartSnapshot{}, err
	}
	if b == nil {
		return c.emptyCart()
	}
	return b.snapshot, nil
}

func sortedLineKeys(lines []gp.CartLine) map[string]int64 {
	m := map[string]int64{}
	for _, l := range lines {
		m[l.ProductID+"|"+gp.OptionKey(l.Options)] += l.Quantity
	}
	return m
}
