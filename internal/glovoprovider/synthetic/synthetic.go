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

// Package synthetic is the deterministic fixture implementation of
// glovoprovider.Provider. Every store, product, order and price in it is
// invented; it holds no real account, address or contact data and performs no
// I/O beyond reading its embedded fixture. Scenario knobs mutate a copy of the
// fixture so tests can make an item unavailable, change a price, remove an
// option or fail a read.
package synthetic

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

//go:embed testdata/fixture.json
var defaultFixture []byte

// Fixture is the whole synthetic world.
type Fixture struct {
	Location gp.LocationContext   `json:"location"`
	Stores   []gp.StoreSummary    `json:"stores"`
	Catalogs []gp.Catalog         `json:"catalogs"`
	Orders   []gp.HistoricalOrder `json:"orders"`
	Cart     gp.CartSnapshot      `json:"cart"`
}

// Scenario mutates the fixture as seen by one Provider value.
type Scenario struct {
	Name string `json:"name"`
	// UnavailableProducts are listed but marked unavailable.
	UnavailableProducts []string `json:"unavailable_products,omitempty"`
	// RemovedProducts disappear from catalogs (Product reads ErrAbsent).
	RemovedProducts []string `json:"removed_products,omitempty"`
	// PriceOverrides sets the current price of a product.
	PriceOverrides map[string]int64 `json:"price_overrides,omitempty"`
	// RemovedOptions disappear from every option group.
	RemovedOptions []string `json:"removed_options,omitempty"`
	// RemovedStores disappear from listings (Catalog reads ErrAbsent).
	RemovedStores []string `json:"removed_stores,omitempty"`
	// Cart replaces the fixture cart.
	Cart *gp.CartSnapshot `json:"cart,omitempty"`
	// FailOps makes the named reads (glovoprovider.Op*) fail as
	// ErrUnobserved.
	FailOps []string `json:"fail_ops,omitempty"`
}

// errSyntheticFault is the cause of every injected read failure.
var errSyntheticFault = errors.New("synthetic: injected read failure")

// Provider is the synthetic provider. Its zero value is not usable; build it
// with New or FromJSON. A Provider is immutable; WithScenario returns a copy.
type Provider struct {
	fx       Fixture
	scenario Scenario
}

var (
	_ gp.Provider   = (*Provider)(nil)
	_ gp.CartWriter = (*Provider)(nil)
)

// New returns the provider over the embedded default fixture.
func New() (*Provider, error) { return FromJSON(defaultFixture) }

// FromJSON parses and validates a fixture. Unknown fields are refused, so a
// fixture cannot smuggle in a field the minimized types do not have.
func FromJSON(raw []byte) (*Provider, error) {
	var fx Fixture
	if err := decodeStrict(raw, &fx); err != nil {
		return nil, fmt.Errorf("synthetic: fixture: %w", err)
	}
	if err := validate(fx); err != nil {
		return nil, fmt.Errorf("synthetic: fixture: %w", err)
	}
	return &Provider{fx: fx}, nil
}

// ParseScenario parses a scenario file, refusing unknown fields.
func ParseScenario(raw []byte) (Scenario, error) {
	var s Scenario
	if err := decodeStrict(raw, &s); err != nil {
		return Scenario{}, fmt.Errorf("synthetic: scenario: %w", err)
	}
	return s, nil
}

// WithScenario returns a provider that applies s on every read.
func (p *Provider) WithScenario(s Scenario) *Provider {
	return &Provider{fx: p.fx, scenario: s}
}

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

var (
	idPattern       = regexp.MustCompile(`^[a-z]{2,4}_[a-z0-9_]{3,48}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
)

func validate(fx Fixture) error {
	seen := map[string]bool{}
	id := func(kind, v string) error {
		if !idPattern.MatchString(v) {
			return fmt.Errorf("%s id %q is not a synthetic id", kind, v)
		}
		return nil
	}
	stores := map[string]bool{}
	for _, s := range fx.Stores {
		if err := id("store", s.ID); err != nil {
			return err
		}
		if stores[s.ID] {
			return fmt.Errorf("duplicate store %s", s.ID)
		}
		stores[s.ID] = true
		if !currencyPattern.MatchString(s.Currency) {
			return fmt.Errorf("store %s currency", s.ID)
		}
	}
	for _, c := range fx.Catalogs {
		if !stores[c.StoreID] {
			return fmt.Errorf("catalog for unknown store %s", c.StoreID)
		}
		cats := map[string]bool{}
		for _, cat := range c.Categories {
			if err := id("category", cat.ID); err != nil {
				return err
			}
			cats[cat.ID] = true
		}
		for _, pr := range c.Products {
			if err := id("product", pr.ID); err != nil {
				return err
			}
			if seen[pr.ID] {
				return fmt.Errorf("duplicate product %s", pr.ID)
			}
			seen[pr.ID] = true
			if pr.StoreID != c.StoreID || !cats[pr.CategoryID] || pr.PriceMinor < 0 {
				return fmt.Errorf("product %s store, category or price", pr.ID)
			}
			for _, g := range pr.OptionGroups {
				if err := id("option group", g.ID); err != nil {
					return err
				}
				if g.Max < 1 || g.Min < 0 || g.Min > g.Max || (g.Required && g.Min < 1) {
					return fmt.Errorf("option group %s bounds", g.ID)
				}
				for _, o := range g.Options {
					if err := id("option", o.ID); err != nil {
						return err
					}
				}
			}
		}
	}
	for i := range fx.Orders {
		o := &fx.Orders[i]
		if err := id("order", o.Summary.ID); err != nil {
			return err
		}
		if !stores[o.Summary.StoreID] || len(o.Items) == 0 {
			return fmt.Errorf("order %s store or items", o.Summary.ID)
		}
		for _, it := range o.Items {
			if err := id("product", it.ProductID); err != nil {
				return err
			}
			if it.Quantity < 1 || it.UnitPriceMinor < 0 {
				return fmt.Errorf("order %s line bounds", o.Summary.ID)
			}
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func (p *Provider) check(ctx context.Context, op string) error {
	if err := ctx.Err(); err != nil {
		return gp.Unobserved(op, err)
	}
	if contains(p.scenario.FailOps, op) {
		return gp.Unobserved(op, errSyntheticFault)
	}
	return nil
}

// clone deep-copies v through JSON so a caller can never mutate the fixture.
func clone[T any](v T) T {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err) // the fixture types always marshal
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

// Location implements glovoprovider.Provider.
func (p *Provider) Location(ctx context.Context) (gp.LocationContext, error) {
	if err := p.check(ctx, gp.OpLocation); err != nil {
		return gp.LocationContext{}, err
	}
	return p.fx.Location, nil
}

// Stores implements glovoprovider.Provider.
func (p *Provider) Stores(ctx context.Context, q gp.StoreQuery) ([]gp.StoreSummary, error) {
	if err := p.check(ctx, gp.OpStores); err != nil {
		return nil, err
	}
	if q.Limit < 1 || q.Limit > gp.MaxListLimit {
		return nil, gp.Invalid(gp.OpStores, "limit")
	}
	out := []gp.StoreSummary{}
	for _, s := range p.fx.Stores {
		if contains(p.scenario.RemovedStores, s.ID) || (q.Kind != "" && s.Kind != q.Kind) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Catalog implements glovoprovider.Provider.
func (p *Provider) Catalog(ctx context.Context, storeID string) (gp.Catalog, error) {
	if err := p.check(ctx, gp.OpCatalog); err != nil {
		return gp.Catalog{}, err
	}
	return p.catalog(storeID)
}

func (p *Provider) catalog(storeID string) (gp.Catalog, error) {
	if contains(p.scenario.RemovedStores, storeID) {
		return gp.Catalog{}, gp.Absent(gp.OpCatalog)
	}
	for _, c := range p.fx.Catalogs {
		if c.StoreID != storeID {
			continue
		}
		c = clone(c)
		products := make([]gp.Product, 0, len(c.Products))
		for _, pr := range c.Products {
			if contains(p.scenario.RemovedProducts, pr.ID) {
				continue
			}
			if contains(p.scenario.UnavailableProducts, pr.ID) {
				pr.Available = false
			}
			if price, ok := p.scenario.PriceOverrides[pr.ID]; ok {
				pr.PriceMinor = price
			}
			for gi := range pr.OptionGroups {
				kept := []gp.Option{}
				for _, o := range pr.OptionGroups[gi].Options {
					if !contains(p.scenario.RemovedOptions, o.ID) {
						kept = append(kept, o)
					}
				}
				pr.OptionGroups[gi].Options = kept
			}
			products = append(products, pr)
		}
		c.Products = products
		return c, nil
	}
	return gp.Catalog{}, gp.Absent(gp.OpCatalog)
}

// Search implements glovoprovider.Provider.
func (p *Provider) Search(ctx context.Context, storeID, query string, limit int) ([]gp.Product, error) {
	if err := p.check(ctx, gp.OpSearch); err != nil {
		return nil, err
	}
	if limit < 1 || limit > gp.MaxListLimit || strings.TrimSpace(query) == "" {
		return nil, gp.Invalid(gp.OpSearch, "query or limit")
	}
	c, err := p.catalog(storeID)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := []gp.Product{}
	for _, pr := range c.Products {
		if strings.Contains(strings.ToLower(pr.Name), q) {
			out = append(out, pr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Product implements glovoprovider.Provider.
func (p *Provider) Product(ctx context.Context, storeID, productID string) (gp.Product, error) {
	if err := p.check(ctx, gp.OpProduct); err != nil {
		return gp.Product{}, err
	}
	c, err := p.catalog(storeID)
	if err != nil {
		return gp.Product{}, err
	}
	if pr, ok := c.Product(productID); ok {
		return pr, nil
	}
	return gp.Product{}, gp.Absent(gp.OpProduct)
}

// OrderHistory implements glovoprovider.Provider.
func (p *Provider) OrderHistory(ctx context.Context, q gp.HistoryQuery) ([]gp.OrderSummary, error) {
	if err := p.check(ctx, gp.OpOrderHistory); err != nil {
		return nil, err
	}
	if q.Limit < 1 || q.Limit > gp.MaxHistoryOrders {
		return nil, gp.Invalid(gp.OpOrderHistory, "limit")
	}
	out := []gp.OrderSummary{}
	for i := range p.fx.Orders {
		o := &p.fx.Orders[i]
		if !q.Since.IsZero() && o.Summary.PlacedAt.Before(q.Since) {
			continue
		}
		out = append(out, o.Summary)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].PlacedAt.Equal(out[j].PlacedAt) {
			return out[i].PlacedAt.After(out[j].PlacedAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Order implements glovoprovider.Provider.
func (p *Provider) Order(ctx context.Context, orderID string) (gp.HistoricalOrder, error) {
	if err := p.check(ctx, gp.OpOrder); err != nil {
		return gp.HistoricalOrder{}, err
	}
	for i := range p.fx.Orders {
		if o := p.fx.Orders[i]; o.Summary.ID == orderID {
			return clone(o), nil
		}
	}
	return gp.HistoricalOrder{}, gp.Absent(gp.OpOrder)
}

// Cart implements glovoprovider.Provider.
func (p *Provider) Cart(ctx context.Context) (gp.CartSnapshot, error) {
	if err := p.check(ctx, gp.OpCart); err != nil {
		return gp.CartSnapshot{}, err
	}
	c := clone(p.fx.Cart)
	if p.scenario.Cart != nil {
		c = clone(*p.scenario.Cart)
	}
	if c.Lines == nil {
		c.Lines = []gp.CartLine{}
	}
	fp, err := gp.CartFingerprint(c)
	if err != nil {
		return gp.CartSnapshot{}, gp.Unobserved(gp.OpCart, err)
	}
	c.Fingerprint = fp
	return c, nil
}

// ApplyCart implements glovoprovider.CartWriter as not supported: the
// synthetic provider never writes, and nothing wires a writer yet.
func (p *Provider) ApplyCart(context.Context, gp.ApplyCartRequest) (gp.ApplyCartResult, error) {
	return gp.ApplyCartResult{}, gp.NotSupported(gp.OpApplyCart)
}

// FixedNow is the reference clock of the fixture: every fixture order is
// before it, and tests plan against it.
var FixedNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
