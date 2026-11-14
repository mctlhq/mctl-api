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

package glovoprovider

import "time"

// The types below are the minimized read model. They deliberately have no
// field for a delivery address, a phone number, an email, a customer or
// courier identity or precise coordinates: an adapter that sees such data
// drops it at the boundary, so it cannot reach the planner, the model, an
// audit record or a trace. TestTypesCarryNoPersonalFields enforces this.

// StoreKind separates restaurant menus from Express/grocery-style stores.
type StoreKind string

// Store kinds.
const (
	StoreRestaurant StoreKind = "restaurant"
	StoreExpress    StoreKind = "express"
)

// LocationContext is the coarse delivery context a provider resolves stores
// and prices against. It is a city and country code, never coordinates or a
// street address; the live adapter keeps the precise location in the user's
// own session.
type LocationContext struct {
	CountryCode string `json:"country_code"`
	CityCode    string `json:"city_code"`
	Currency    string `json:"currency"`
}

// StoreQuery bounds a store listing.
type StoreQuery struct {
	Kind  StoreKind `json:"kind,omitempty"`
	Limit int       `json:"limit"`
}

// StoreSummary is one entry of a store listing.
type StoreSummary struct {
	ID       string    `json:"store_id"`
	Name     string    `json:"name"`
	Kind     StoreKind `json:"kind"`
	Currency string    `json:"currency"`
	Open     bool      `json:"open"`
}

// Category groups products of one store. Tags are provider-neutral labels
// such as "drinks" that user constraints filter on.
type Category struct {
	ID   string   `json:"category_id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// Option is one choice inside an option group (a modifier). PriceDeltaMinor
// is added to the product price when the option is selected.
type Option struct {
	ID              string `json:"option_id"`
	Name            string `json:"name"`
	PriceDeltaMinor int64  `json:"price_delta_minor"`
	Available       bool   `json:"available"`
}

// OptionGroup is a modifier group. Required groups need at least Min (>= 1)
// selections; no group accepts more than Max.
type OptionGroup struct {
	ID       string   `json:"group_id"`
	Name     string   `json:"name"`
	Required bool     `json:"required"`
	Min      int      `json:"min"`
	Max      int      `json:"max"`
	Options  []Option `json:"options"`
}

// Product is one sellable item with its current price and availability.
// Prices are integer minor units of the catalog currency.
type Product struct {
	ID           string        `json:"product_id"`
	StoreID      string        `json:"store_id"`
	CategoryID   string        `json:"category_id"`
	Name         string        `json:"name"`
	PriceMinor   int64         `json:"price_minor"`
	Available    bool          `json:"available"`
	OptionGroups []OptionGroup `json:"option_groups,omitempty"`
}

// Catalog is the current menu or assortment of one store.
type Catalog struct {
	StoreID    string     `json:"store_id"`
	StoreName  string     `json:"store_name"`
	Kind       StoreKind  `json:"kind"`
	Currency   string     `json:"currency"`
	Open       bool       `json:"open"`
	Categories []Category `json:"categories"`
	Products   []Product  `json:"products"`
}

// Product returns the product with id, if the catalog lists it.
func (c Catalog) Product(id string) (Product, bool) {
	for _, p := range c.Products {
		if p.ID == id {
			return p, true
		}
	}
	return Product{}, false
}

// Category returns the category with id, if the catalog lists it.
func (c Catalog) Category(id string) (Category, bool) {
	for _, cat := range c.Categories {
		if cat.ID == id {
			return cat, true
		}
	}
	return Category{}, false
}

// HistoryQuery bounds an order-history read. Limit must be 1..MaxHistoryOrders.
type HistoryQuery struct {
	Limit int       `json:"limit"`
	Since time.Time `json:"since,omitempty"`
}

// MaxHistoryOrders is the largest history page a provider returns.
const MaxHistoryOrders = 20

// OrderSummary is one past order, minimized. NativeReorderAllowed mirrors the
// provider's own "reorder" button; false never blocks a manual reconstruction
// through the planner.
type OrderSummary struct {
	ID                   string    `json:"order_id"`
	StoreID              string    `json:"store_id"`
	StoreName            string    `json:"store_name"`
	PlacedAt             time.Time `json:"placed_at"`
	ItemCount            int       `json:"item_count"`
	TotalMinor           int64     `json:"total_minor"`
	Currency             string    `json:"currency"`
	NativeReorderAllowed bool      `json:"native_reorder_allowed"`
}

// SelectedOption is a modifier chosen on a past order line.
type SelectedOption struct {
	GroupID  string `json:"group_id"`
	OptionID string `json:"option_id"`
	Name     string `json:"name"`
}

// OrderItem is one line of a past order, as it was priced then.
type OrderItem struct {
	ProductID      string           `json:"product_id"`
	Name           string           `json:"name"`
	CategoryTags   []string         `json:"category_tags,omitempty"`
	Quantity       int64            `json:"quantity"`
	UnitPriceMinor int64            `json:"unit_price_minor"`
	Options        []SelectedOption `json:"options,omitempty"`
}

// HistoricalOrder is one past order with its lines.
type HistoricalOrder struct {
	Summary OrderSummary `json:"summary"`
	Items   []OrderItem  `json:"items"`
}

// CartOption is a modifier on a provider cart line.
type CartOption struct {
	GroupID  string `json:"group_id"`
	OptionID string `json:"option_id"`
}

// CartLine is one line of the provider cart.
type CartLine struct {
	ProductID      string       `json:"product_id"`
	Quantity       int64        `json:"quantity"`
	UnitPriceMinor int64        `json:"unit_price_minor"`
	Options        []CartOption `json:"options,omitempty"`
}

// CartSnapshot is one observation of the provider cart. An empty cart is an
// observed snapshot with no lines; a cart that could not be read is an
// ErrUnobserved error, never an empty snapshot. Fingerprint is
// CartFingerprint over the observed content; Version is the provider's own
// opaque revision, when it exposes one.
type CartSnapshot struct {
	StoreID     string     `json:"store_id,omitempty"`
	Currency    string     `json:"currency,omitempty"`
	Lines       []CartLine `json:"lines"`
	Version     string     `json:"version,omitempty"`
	Fingerprint string     `json:"fingerprint"`
}
