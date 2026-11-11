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

// Package live is the LIVE Glovo provider adapter of mctl-api#1006: it reads
// the owner's own Glovo account through the consumer API and maps it onto the
// provider-neutral read model of internal/glovoprovider.
//
// It is a port of a deliberately small subset of denya/glovo-skill (commit
// 42f25483, api.mjs): authenticated address book, store wall, store search,
// product view with modifiers, order history and detail, and the basket
// read. The cart write operations live behind the separate CartMutator
// interface, on a type (Writer) that nothing in this change constructs
// outside tests. Checkout, payment, order placement, location change and
// marketing consent are not implemented.
//
// Safety properties, each pinned by a test: a host allowlist with no
// redirects, a context deadline and a body size cap on every request, one
// token refresh on 401 and no other retry, no retry of a write, typed
// failures instead of empty results, and personal data dropped while parsing.
package live

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// Reader is the read-only adapter. It implements glovoprovider.Provider and
// has no write method at all.
type Reader struct{ c *core }

var _ gp.Provider = (*Reader)(nil)

// NewReader builds a Reader. The TokenSource supplies the bearer.
func NewReader(cfg Config, ts TokenSource) (*Reader, error) {
	c, err := newCore(cfg, ts)
	if err != nil {
		return nil, err
	}
	return &Reader{c: c}, nil
}

// Store ids returned by this adapter are "<storeId>:<storeAddressId>", the
// pair every Glovo store endpoint needs.
const refSep = ":"

func makeRef(store, addr string) string { return store + refSep + addr }

func parseRef(op, ref string) (store, addr string, err error) {
	store, addr, ok := strings.Cut(ref, refSep)
	if !ok || !validID(store) || !validID(addr) {
		return "", "", gp.Invalid(op, "store_id")
	}
	return store, addr, nil
}

func checkLimit(op string, limit int) error {
	if limit < 1 || limit > gp.MaxListLimit {
		return gp.Invalid(op, "limit")
	}
	return nil
}

// Glovo store-wall category ids (upstream storeClassFromCategoryId).
const (
	categoryRestaurant = 1
	categoryGrocery    = 4
)

// Location returns the coarse delivery context. The address book is read
// only to prove that the account has a saved address in the configured city;
// street, details, coordinates and every other field are dropped.
func (r *Reader) Location(ctx context.Context) (gp.LocationContext, error) {
	var body struct {
		Data      *addressList `json:"data"`
		Addresses []addrEntry  `json:"addresses"`
	}
	err := r.c.getJSON(ctx, gp.OpLocation, reqSpec{method: http.MethodGet, path: "/customer_profile/api/v1/address_book/me/addresses"}, &body)
	if err != nil {
		return gp.LocationContext{}, err
	}
	entries := body.Addresses
	if body.Data != nil && body.Data.Addresses != nil {
		entries = body.Data.Addresses
	}
	if entries == nil {
		return gp.LocationContext{}, unobserved(gp.OpLocation, ErrSchemaDrift)
	}
	d := r.c.cfg.Delivery
	for _, e := range entries {
		a := e.Address
		if a == nil {
			continue
		}
		if strings.EqualFold(a.CountryCode, d.CountryCode) && strings.EqualFold(a.CityCode, d.CityCode) {
			return gp.LocationContext{CountryCode: d.CountryCode, CityCode: d.CityCode, Currency: r.c.cfg.Currency}, nil
		}
	}
	return gp.LocationContext{}, unobserved(gp.OpLocation, ErrLocationMismatch)
}

type addressList struct {
	Addresses []addrEntry `json:"addresses"`
}

// addrEntry deliberately declares only the two codes: the address line,
// details, coordinates and labels in the payload are never decoded.
type addrEntry struct {
	Address *struct {
		CountryCode string `json:"countryCode"`
		CityCode    string `json:"cityCode"`
	} `json:"address"`
}

// Stores lists stores from the store wall. Without a Kind it reads the
// restaurant and the grocery wall and concatenates them.
func (r *Reader) Stores(ctx context.Context, q gp.StoreQuery) ([]gp.StoreSummary, error) {
	if err := checkLimit(gp.OpStores, q.Limit); err != nil {
		return nil, err
	}
	var cats []int
	switch q.Kind {
	case "":
		cats = []int{categoryRestaurant, categoryGrocery}
	case gp.StoreRestaurant:
		cats = []int{categoryRestaurant}
	case gp.StoreExpress:
		cats = []int{categoryGrocery}
	default:
		return nil, gp.Invalid(gp.OpStores, "kind")
	}
	out := []gp.StoreSummary{}
	for _, cat := range cats {
		if len(out) >= q.Limit {
			break
		}
		page, err := r.storeWall(ctx, cat, q.Limit-len(out))
		if err != nil {
			return nil, err // a failed wall is a failed read, not a shorter list
		}
		out = append(out, page...)
	}
	return out, nil
}

type storeWallWire struct {
	Data *struct {
		Stores *struct {
			Entries *[]storeEntryWire `json:"entries"`
		} `json:"stores"`
	} `json:"data"`
}

type storeEntryWire struct {
	ID        flexString `json:"id"`
	StoreID   flexString `json:"storeId"`
	AddressID flexString `json:"addressId"`
	Metadata  *struct {
		StoreAddressID flexString `json:"storeAddressId"`
	} `json:"metadata"`
	StoreAddressID flexString `json:"storeAddressId"`
	Title          string     `json:"title"`
	Name           string     `json:"name"`
	Open           *bool      `json:"open"`
	Availability   *struct {
		Status string `json:"status"`
	} `json:"availability"`
}

func (r *Reader) storeWall(ctx context.Context, category, limit int) ([]gp.StoreSummary, error) {
	qs := url.Values{"moduleId": {"StoreFeeds"}, "offset": {"0"}, "limit": {strconv.Itoa(limit)}, "handlingType": {"DELIVERY"}}
	var w storeWallWire
	err := r.c.getJSON(ctx, gp.OpStores, reqSpec{
		method: http.MethodPost,
		path:   "/v1/web/store_wall/category/" + strconv.Itoa(category),
		query:  qs,
		body:   map[string]any{"filters": []any{}, "previousStoreIds": []any{}},
	}, &w)
	if err != nil {
		return nil, err
	}
	if w.Data == nil || w.Data.Stores == nil || w.Data.Stores.Entries == nil {
		return nil, unobserved(gp.OpStores, ErrSchemaDrift)
	}
	kind := gp.StoreRestaurant
	if category == categoryGrocery {
		kind = gp.StoreExpress
	}
	out := make([]gp.StoreSummary, 0, len(*w.Data.Stores.Entries))
	for _, e := range *w.Data.Stores.Entries {
		store := firstNonEmpty(string(e.ID), string(e.StoreID))
		addr := firstNonEmpty(string(e.StoreAddressID), string(e.AddressID))
		if e.Metadata != nil && addr == "" {
			addr = string(e.Metadata.StoreAddressID)
		}
		name := firstNonEmpty(e.Title, e.Name)
		var open bool
		switch {
		case e.Open != nil:
			open = *e.Open
		case e.Availability != nil && e.Availability.Status != "":
			open = e.Availability.Status == "OPEN"
		default:
			return nil, unobserved(gp.OpStores, ErrSchemaDrift)
		}
		if !validID(store) || !validID(addr) || name == "" {
			return nil, unobserved(gp.OpStores, ErrSchemaDrift)
		}
		out = append(out, gp.StoreSummary{ID: makeRef(store, addr), Name: name, Kind: kind, Currency: r.c.cfg.Currency, Open: open})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Catalog is not supported: the upstream menu is a tree of lazily fetched
// content nodes, and a partial menu would violate the "whole menu or
// unobserved" contract. Callers revalidate single products with Product.
func (r *Reader) Catalog(_ context.Context, _ string) (gp.Catalog, error) {
	return gp.Catalog{}, gp.NotSupported(gp.OpCatalog)
}

type searchWire struct {
	Results *[]struct {
		Products []itemWire `json:"products"`
	} `json:"results"`
}

type itemWire struct {
	ID         flexString `json:"id"`
	ProductID  flexString `json:"productId"`
	CategoryID flexString `json:"categoryId"`
	Name       string     `json:"name"`
	PriceInfo  *priceInfo `json:"priceInfo"`
	Available  *bool      `json:"available"`
	IsAvail    *bool      `json:"isAvailable"`
	Enabled    *bool      `json:"enabled"`
	OutOfStock *bool      `json:"outOfStock"`
	SoldOut    *bool      `json:"soldOut"`
	Disabled   *bool      `json:"disabled"`
}

// available reports availability. A payload that carries no availability
// signal is reported unavailable: unknown is never "available".
func (i itemWire) available() bool {
	for _, v := range []*bool{i.Available, i.IsAvail, i.Enabled} {
		if v != nil {
			return *v
		}
	}
	for _, v := range []*bool{i.OutOfStock, i.SoldOut, i.Disabled} {
		if v != nil {
			return !*v
		}
	}
	return false
}

// Search searches one store by product name.
func (r *Reader) Search(ctx context.Context, storeID, query string, limit int) ([]gp.Product, error) {
	if err := checkLimit(gp.OpSearch, limit); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 100 {
		return nil, gp.Invalid(gp.OpSearch, "query")
	}
	store, addr, err := parseRef(gp.OpSearch, storeID)
	if err != nil {
		return nil, err
	}
	var w searchWire
	err = r.c.getJSON(ctx, gp.OpSearch, reqSpec{
		method: http.MethodGet,
		path:   joinPath("v3", "stores", pathEsc(store), "addresses", pathEsc(addr), "search"),
		query:  url.Values{"query": {query}, "searchId": {requestID()}},
	}, &w)
	if err != nil {
		return nil, err
	}
	if w.Results == nil {
		return nil, unobserved(gp.OpSearch, ErrSchemaDrift)
	}
	out := []gp.Product{}
	for _, res := range *w.Results {
		for _, it := range res.Products {
			p, err := r.itemProduct(gp.OpSearch, storeID, it)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func (r *Reader) itemProduct(op, storeRef string, it itemWire) (gp.Product, error) {
	id := firstNonEmpty(string(it.ID), string(it.ProductID))
	if !validID(id) || it.Name == "" || it.PriceInfo == nil {
		return gp.Product{}, unobserved(op, ErrSchemaDrift)
	}
	price, err := parseMoney(it.PriceInfo.Amount, r.c.cfg.Currency)
	if err != nil || price < 0 {
		return gp.Product{}, unobserved(op, ErrSchemaDrift)
	}
	return gp.Product{ID: id, StoreID: storeRef, CategoryID: string(it.CategoryID), Name: it.Name, PriceMinor: price, Available: it.available()}, nil
}

// Product returns one product with its modifier groups.
func (r *Reader) Product(ctx context.Context, storeID, productID string) (gp.Product, error) {
	d, err := r.c.productDetail(ctx, gp.OpProduct, storeID, productID)
	if err != nil {
		return gp.Product{}, err
	}
	return d.product, nil
}
