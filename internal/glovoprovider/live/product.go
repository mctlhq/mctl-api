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
	"net/http"
	"net/url"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

type productViewWire struct {
	Data *struct {
		Metadata *struct {
			Product *productMeta `json:"product"`
		} `json:"metadata"`
		Footer *struct {
			Data struct {
				Elements []struct {
					Data struct {
						IsEnabled *bool `json:"isEnabled"`
					} `json:"data"`
				} `json:"elements"`
			} `json:"data"`
		} `json:"footer"`
	} `json:"data"`
}

type productMeta struct {
	ID             flexID      `json:"id"`
	ExternalID     flexID      `json:"externalId"`
	StoreProductID flexID      `json:"storeProductId"`
	CategoryID     flexString  `json:"categoryId"`
	Name           string      `json:"name"`
	PriceInfo      *priceInfo  `json:"priceInfo"`
	Groups         []groupMeta `json:"attributeGroups"`
}

type groupMeta struct {
	ID         flexID    `json:"id"`
	GroupID    flexID    `json:"attributeGroupId"`
	ExternalID flexID    `json:"externalId"`
	Position   *int      `json:"position"`
	Name       string    `json:"name"`
	Required   bool      `json:"required"`
	MinSel     *int      `json:"minSelection"`
	Min        *int      `json:"min"`
	MaxSel     *int      `json:"maxSelection"`
	Max        *int      `json:"max"`
	Attributes []optMeta `json:"attributes"`
}

type optMeta struct {
	ID         flexID     `json:"id"`
	OptionID   flexID     `json:"attributeId"`
	ExternalID flexID     `json:"externalId"`
	Name       string     `json:"name"`
	PriceInfo  *priceInfo `json:"priceInfo"`
	Available  *bool      `json:"available"`
	IsAvail    *bool      `json:"isAvailable"`
	Enabled    *bool      `json:"enabled"`
}

// productDetail is the product view parsed twice over: the provider-neutral
// Product and the provider identifiers the cart write needs.
type productDetail struct {
	product gp.Product
	meta    productMeta
}

func (c *core) productDetail(ctx context.Context, op, storeRef, productID string) (productDetail, error) {
	store, addr, err := parseRef(op, storeRef)
	if err != nil {
		return productDetail{}, err
	}
	if !validID(productID) {
		return productDetail{}, gp.Invalid(op, "product_id")
	}
	var w productViewWire
	err = c.getJSON(ctx, op, reqSpec{
		method: http.MethodPost,
		path:   joinPath("v4", "stores", pathEsc(store), "addresses", pathEsc(addr), "products", pathEsc(productID), "view"),
		query:  url.Values{},
		body:   map[string]any{"editingMode": false, "origin": "STORE", "translation": nil, "trackingOrigin": nil, "quantity": 1},
	}, &w)
	if err != nil {
		return productDetail{}, err
	}
	if w.Data == nil || w.Data.Metadata == nil || w.Data.Metadata.Product == nil {
		return productDetail{}, unobserved(op, ErrSchemaDrift)
	}
	m := *w.Data.Metadata.Product
	if m.ID.s() != productID || m.Name == "" || m.PriceInfo == nil {
		return productDetail{}, unobserved(op, ErrSchemaDrift)
	}
	price, err := parseMoney(m.PriceInfo.Amount, c.cfg.Currency)
	if err != nil || price < 0 {
		return productDetail{}, unobserved(op, ErrSchemaDrift)
	}
	// Availability comes from the add-to-basket button state. No button
	// state means unknown, which is reported unavailable.
	avail := false
	if w.Data.Footer != nil {
		for _, el := range w.Data.Footer.Data.Elements {
			if el.Data.IsEnabled != nil {
				avail = *el.Data.IsEnabled
				break
			}
		}
	}
	p := gp.Product{ID: productID, StoreID: storeRef, CategoryID: string(m.CategoryID), Name: m.Name, PriceMinor: price, Available: avail}
	seenG := map[string]bool{}
	for i := range m.Groups {
		g := &m.Groups[i]
		og, err := c.optionGroup(op, g)
		if err != nil {
			return productDetail{}, err
		}
		if seenG[og.ID] {
			return productDetail{}, unobserved(op, ErrSchemaDrift)
		}
		seenG[og.ID] = true
		p.OptionGroups = append(p.OptionGroups, og)
	}
	return productDetail{product: p, meta: m}, nil
}

func (c *core) optionGroup(op string, g *groupMeta) (gp.OptionGroup, error) {
	if !validID(g.ID.s()) || g.Name == "" || g.Attributes == nil {
		return gp.OptionGroup{}, unobserved(op, ErrSchemaDrift)
	}
	min := 0
	switch {
	case g.MinSel != nil:
		min = *g.MinSel
	case g.Min != nil:
		min = *g.Min
	}
	// A group with no declared maximum accepts as many selections as it has
	// options; the provider enforces the real limit on write.
	max := len(g.Attributes)
	switch {
	case g.MaxSel != nil:
		max = *g.MaxSel
	case g.Max != nil:
		max = *g.Max
	}
	required := g.Required || min >= 1
	if required && min < 1 {
		min = 1
	}
	if min < 0 || max < 0 || min > max {
		return gp.OptionGroup{}, unobserved(op, ErrSchemaDrift)
	}
	og := gp.OptionGroup{ID: g.ID.s(), Name: g.Name, Required: required, Min: min, Max: max, Options: []gp.Option{}}
	seen := map[string]bool{}
	for _, o := range g.Attributes {
		if !validID(o.ID.s()) || o.Name == "" || seen[o.ID.s()] {
			return gp.OptionGroup{}, unobserved(op, ErrSchemaDrift)
		}
		seen[o.ID.s()] = true
		var delta int64
		if o.PriceInfo != nil {
			d, err := parseMoney(o.PriceInfo.Amount, c.cfg.Currency)
			if err != nil {
				return gp.OptionGroup{}, unobserved(op, ErrSchemaDrift)
			}
			delta = d
		}
		// No availability signal on an option means unavailable.
		avail := false
		for _, v := range []*bool{o.Available, o.IsAvail, o.Enabled} {
			if v != nil {
				avail = *v
				break
			}
		}
		og.Options = append(og.Options, gp.Option{ID: o.ID.s(), Name: o.Name, PriceDeltaMinor: delta, Available: avail})
	}
	return og, nil
}
