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

package synthetic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

func mustNew(t *testing.T) *Provider {
	t.Helper()
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func scenario(t *testing.T, name string) Scenario {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "scenarios", name+".json")) //nolint:gosec // fixed test path
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseScenario(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReads(t *testing.T) {
	ctx := context.Background()
	p := mustNew(t)
	loc, err := p.Location(ctx)
	if err != nil || loc.CityCode == "" || loc.Currency != "EUR" {
		t.Fatalf("location %+v %v", loc, err)
	}
	stores, err := p.Stores(ctx, gp.StoreQuery{Limit: 10})
	if err != nil || len(stores) != 3 {
		t.Fatalf("stores %d %v", len(stores), err)
	}
	express, _ := p.Stores(ctx, gp.StoreQuery{Kind: gp.StoreExpress, Limit: 10})
	if len(express) != 1 || express[0].ID != "st_synth_express_01" {
		t.Fatalf("express filter %+v", express)
	}
	hist, err := p.OrderHistory(ctx, gp.HistoryQuery{Limit: 2})
	if err != nil || len(hist) != 2 || hist[0].ID != "ord_synth_0002" {
		t.Fatalf("history newest first, bounded: %+v %v", hist, err)
	}
	found, err := p.Search(ctx, "st_synth_burger_01", "wrap", 5)
	if err != nil || len(found) != 2 {
		t.Fatalf("search %+v %v", found, err)
	}
	pr, err := p.Product(ctx, "st_synth_burger_01", "prd_burger_classic")
	if err != nil || len(pr.OptionGroups) != 2 || !pr.OptionGroups[0].Required {
		t.Fatalf("product %+v %v", pr, err)
	}
	cart, err := p.Cart(ctx)
	if err != nil || len(cart.Lines) != 1 || cart.Fingerprint == "" {
		t.Fatalf("cart %+v %v", cart, err)
	}
	again, _ := p.Cart(ctx)
	if again.Fingerprint != cart.Fingerprint {
		t.Fatal("cart fingerprint is not deterministic")
	}
}

func TestBoundsAreRefused(t *testing.T) {
	ctx := context.Background()
	p := mustNew(t)
	if _, err := p.OrderHistory(ctx, gp.HistoryQuery{Limit: gp.MaxHistoryOrders + 1}); !errors.Is(err, gp.ErrInvalidRequest) {
		t.Fatalf("history above max: %v", err)
	}
	if _, err := p.OrderHistory(ctx, gp.HistoryQuery{}); !errors.Is(err, gp.ErrInvalidRequest) {
		t.Fatalf("history limit 0: %v", err)
	}
	if _, err := p.Stores(ctx, gp.StoreQuery{Limit: 0}); !errors.Is(err, gp.ErrInvalidRequest) {
		t.Fatalf("stores limit 0: %v", err)
	}
	if _, err := p.Search(ctx, "st_synth_burger_01", " ", 5); !errors.Is(err, gp.ErrInvalidRequest) {
		t.Fatalf("blank search: %v", err)
	}
}

// TestCouldNotObserveIsNotAbsent: an injected read failure is ErrUnobserved
// with no data, a positively absent thing is ErrAbsent, and an observed
// empty result is an empty non-nil slice with no error.
func TestCouldNotObserveIsNotAbsent(t *testing.T) {
	ctx := context.Background()
	base := mustNew(t)
	failing := base.WithScenario(Scenario{FailOps: []string{gp.OpCatalog, gp.OpCart, gp.OpOrderHistory, gp.OpStores, gp.OpOrder}})

	if _, err := failing.Catalog(ctx, "st_synth_burger_01"); !errors.Is(err, gp.ErrUnobserved) || errors.Is(err, gp.ErrAbsent) {
		t.Fatalf("catalog failure: %v", err)
	}
	if c, err := failing.Cart(ctx); !errors.Is(err, gp.ErrUnobserved) || c.Lines != nil || c.Fingerprint != "" {
		t.Fatalf("cart failure must not look like an empty cart: %+v %v", c, err)
	}
	if h, err := failing.OrderHistory(ctx, gp.HistoryQuery{Limit: 5}); !errors.Is(err, gp.ErrUnobserved) || h != nil {
		t.Fatalf("history failure must not look like no orders: %v %v", h, err)
	}
	if s, err := failing.Stores(ctx, gp.StoreQuery{Limit: 5}); !errors.Is(err, gp.ErrUnobserved) || s != nil {
		t.Fatalf("stores failure: %v %v", s, err)
	}

	if _, err := base.Order(ctx, "ord_synth_9999"); !errors.Is(err, gp.ErrAbsent) || errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("missing order: %v", err)
	}
	if _, err := base.Catalog(ctx, "st_synth_nowhere"); !errors.Is(err, gp.ErrAbsent) {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := base.Product(ctx, "st_synth_burger_01", "prd_nothing"); !errors.Is(err, gp.ErrAbsent) {
		t.Fatalf("missing product: %v", err)
	}
	empty, err := base.Stores(ctx, gp.StoreQuery{Kind: "nothing", Limit: 5})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("observed-empty listing must be [] with nil error: %v %v", empty, err)
	}
	ctxDone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := base.Cart(ctxDone); !errors.Is(err, gp.ErrUnobserved) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: %v", err)
	}
}

func TestScenarioKnobs(t *testing.T) {
	ctx := context.Background()
	base := mustNew(t)

	un := base.WithScenario(scenario(t, "item-unavailable"))
	if pr, _ := un.Product(ctx, "st_synth_burger_01", "prd_fries"); pr.Available {
		t.Fatal("item-unavailable did not apply")
	}
	pc := base.WithScenario(scenario(t, "price-change"))
	if pr, _ := pc.Product(ctx, "st_synth_burger_01", "prd_burger_classic"); pr.PriceMinor != 990 {
		t.Fatalf("price-change did not apply: %d", pr.PriceMinor)
	}
	or := base.WithScenario(scenario(t, "option-removed"))
	pr, _ := or.Product(ctx, "st_synth_burger_01", "prd_burger_classic")
	for _, g := range pr.OptionGroups {
		for _, o := range g.Options {
			if o.ID == "opt_cheese" || o.ID == "opt_medium" {
				t.Fatalf("option-removed left %s", o.ID)
			}
		}
	}
	if _, err := base.WithScenario(scenario(t, "store-removed")).Catalog(ctx, "st_synth_burger_01"); !errors.Is(err, gp.ErrAbsent) {
		t.Fatalf("store-removed: %v", err)
	}
	if _, err := base.WithScenario(scenario(t, "catalog-unobserved")).Catalog(ctx, "st_synth_burger_01"); !errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("catalog-unobserved: %v", err)
	}
	// The base provider is untouched by any scenario.
	if pr, _ := base.Product(ctx, "st_synth_burger_01", "prd_burger_classic"); pr.PriceMinor != 950 || len(pr.OptionGroups[1].Options) != 2 {
		t.Fatal("a scenario leaked into the base provider")
	}
}

func TestReadsReturnCopies(t *testing.T) {
	ctx := context.Background()
	p := mustNew(t)
	c, _ := p.Catalog(ctx, "st_synth_burger_01")
	c.Products[0].PriceMinor = 1
	c.Products[0].OptionGroups[0].Options[0].Available = false
	again, _ := p.Catalog(ctx, "st_synth_burger_01")
	if again.Products[0].PriceMinor == 1 || !again.Products[0].OptionGroups[0].Options[0].Available {
		t.Fatal("a caller mutated the fixture through a returned catalog")
	}
}

func TestApplyCartNotSupported(t *testing.T) {
	p := mustNew(t)
	_, err := p.ApplyCart(context.Background(), gp.ApplyCartRequest{})
	if !errors.Is(err, gp.ErrNotSupported) {
		t.Fatalf("synthetic ApplyCart must be not supported: %v", err)
	}
}

func TestFixtureRefusesUnknownFields(t *testing.T) {
	raw := []byte(`{"location":{"country_code":"ZZ","city_code":"X","currency":"EUR","street":"x"},"stores":[],"catalogs":[],"orders":[],"cart":{"lines":[],"fingerprint":""}}`)
	if _, err := FromJSON(raw); err == nil {
		t.Fatal("a fixture with an extra field was accepted")
	}
	if _, err := ParseScenario([]byte(`{"name":"x","phone":"1"}`)); err == nil {
		t.Fatal("a scenario with an extra field was accepted")
	}
}
