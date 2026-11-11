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

package live_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/live"
)

func readFake(t *testing.T) (*fakeGlovo, *live.Reader, *tokenSrc) {
	f := newFake(t)
	f.onFixture("GET", "/v3/me", "me.json")
	f.onFixture("GET", "/customer_profile/api/v1/address_book/me/addresses", "addresses.json")
	f.onFixture("POST", "/v1/web/store_wall/category/1", "store_wall_restaurant.json")
	f.onFixture("POST", "/v1/web/store_wall/category/4", "store_wall_grocery.json")
	f.onFixture("GET", "/v3/stores/700001/addresses/710001/search", "search.json")
	f.onFixture("POST", "/v4/stores/700001/addresses/710001/products/800001/view", "product_view.json")
	f.on("GET", "/v3/customer/orders-list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "cursor-2" {
			serveFixture(w, "orders_list_p2.json")
			return
		}
		serveFixture(w, "orders_list_p1.json")
	})
	for _, id := range []string{"990003", "990002", "990001"} {
		f.onFixture("GET", "/v3/customer/orders/"+id, "order_"+id+".json")
	}
	ts := newTokens()
	return f, newReader(t, f, ts), ts
}

func TestReaderMapsEndpointsOntoProviderModel(t *testing.T) {
	f, r, _ := readFake(t)
	ctx := context.Background()

	loc, err := r.Location(ctx)
	if err != nil || loc != (gp.LocationContext{CountryCode: "ZZ", CityCode: "SYNCITY", Currency: "EUR"}) {
		t.Fatalf("location = %+v, %v", loc, err)
	}

	stores, err := r.Stores(ctx, gp.StoreQuery{Limit: 10})
	if err != nil || len(stores) != 3 {
		t.Fatalf("stores = %+v, %v", stores, err)
	}
	if stores[0].ID != "700001:710001" || stores[0].Kind != gp.StoreRestaurant || !stores[0].Open || stores[1].Open || stores[2].Kind != gp.StoreExpress {
		t.Fatalf("stores mapped wrong: %+v", stores)
	}
	if one, err := r.Stores(ctx, gp.StoreQuery{Kind: gp.StoreExpress, Limit: 1}); err != nil || len(one) != 1 || one[0].ID != "700003:710003" {
		t.Fatalf("express only = %+v, %v", one, err)
	}

	found, err := r.Search(ctx, storeRefBurger, "burger", 5)
	if err != nil || len(found) != 3 {
		t.Fatalf("search = %+v, %v", found, err)
	}
	if found[0].PriceMinor != 950 || !found[0].Available || found[0].CategoryID != "600001" {
		t.Fatalf("search[0] = %+v", found[0])
	}
	if found[1].PriceMinor != 1100 || found[1].Available {
		t.Fatalf("search[1] = %+v (outOfStock must be unavailable, comma money parsed)", found[1])
	}

	if found[2].Available || found[2].PriceMinor != 500 {
		t.Fatalf("search[2] = %+v (no availability signal must be unavailable)", found[2])
	}

	p, err := r.Product(ctx, storeRefBurger, "800001")
	if err != nil {
		t.Fatal(err)
	}
	if p.PriceMinor != 950 || !p.Available || len(p.OptionGroups) != 2 {
		t.Fatalf("product = %+v", p)
	}
	g0, g1 := p.OptionGroups[0], p.OptionGroups[1]
	if g0.ID != "701" || !g0.Required || g0.Min != 1 || g0.Max != 1 || g1.Required || g1.Max != 2 {
		t.Fatalf("groups = %+v", p.OptionGroups)
	}
	if g1.Options[0].PriceDeltaMinor != 80 || !g1.Options[0].Available || g1.Options[1].Available || g0.Options[1].PriceDeltaMinor != 0 {
		t.Fatalf("options = %+v", g1.Options)
	}

	hist, err := r.OrderHistory(ctx, gp.HistoryQuery{Limit: 3})
	if err != nil || len(hist) != 3 {
		t.Fatalf("history = %+v, %v", hist, err)
	}
	if hist[0].ID != "990003" || hist[0].TotalMinor != 2060 || hist[0].ItemCount != 2 || !hist[0].NativeReorderAllowed ||
		hist[0].StoreID != "700001:710001" || hist[2].PlacedAt.Year() != 2026 || hist[1].NativeReorderAllowed {
		t.Fatalf("history mapped wrong: %+v", hist)
	}
	if f.count("GET", "/v3/customer/orders-list") != 2 {
		t.Fatalf("expected two cursor pages, got %d", f.count("GET", "/v3/customer/orders-list"))
	}
	if two, err := r.OrderHistory(ctx, gp.HistoryQuery{Limit: 2}); err != nil || len(two) != 2 {
		t.Fatalf("limit not honored: %+v, %v", two, err)
	}
	since := hist[1].PlacedAt
	if recent, err := r.OrderHistory(ctx, gp.HistoryQuery{Limit: 5, Since: since}); err != nil || len(recent) != 2 {
		t.Fatalf("since filter: %+v, %v", recent, err)
	}

	o, err := r.Order(ctx, "990003")
	if err != nil || len(o.Items) != 1 {
		t.Fatalf("order = %+v, %v", o, err)
	}
	it := o.Items[0]
	if it.ProductID != "800001" || it.Quantity != 2 || it.UnitPriceMinor != 1030 || len(it.Options) != 2 ||
		it.Options[0] != (gp.SelectedOption{GroupID: "701", OptionID: "801", Name: "Medium"}) {
		t.Fatalf("item = %+v", it)
	}
	if o2, err := r.Order(ctx, "990001"); err != nil || o2.Items[0].ProductID != "800003" || o2.Items[0].Quantity != 1 {
		t.Fatalf("order via ids.id/quantity object: %+v, %v", o2, err)
	}
}

func TestCatalogIsNotSupported(t *testing.T) {
	_, r, _ := readFake(t)
	if _, err := r.Catalog(context.Background(), storeRefBurger); !errors.Is(err, gp.ErrNotSupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestOrderMissingIsAbsentOnlyOn404(t *testing.T) {
	f, r, _ := readFake(t)
	if _, err := r.Order(context.Background(), "424242"); !errors.Is(err, gp.ErrAbsent) {
		t.Fatalf("404 must be absent, got %v", err)
	}
	f.on("GET", "/v3/customer/orders/424243", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) })
	err := func() error { _, err := r.Order(context.Background(), "424243"); return err }()
	if errors.Is(err, gp.ErrAbsent) || !errors.Is(err, gp.ErrUnobserved) || !errors.Is(err, live.ErrUnavailable) {
		t.Fatalf("500 must be unobserved/unavailable, got %v", err)
	}
}

func TestCartReads(t *testing.T) {
	f, r, _ := readFake(t)
	ctx := context.Background()
	base := "/v1/authenticated/customers/900001/baskets"

	f.on("GET", base, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	empty, err := r.Cart(ctx)
	if err != nil || len(empty.Lines) != 0 || empty.Lines == nil || empty.Version != live.NoBasketVersion || empty.Fingerprint == "" {
		t.Fatalf("empty cart = %+v, %v", empty, err)
	}
	f.on("GET", base, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"baskets":[` + string(fixture(t, "basket_store.json")) + `]}`))
	})
	c, err := r.Cart(ctx)
	if err != nil || c.Version != "7" || c.StoreID != "700001:710001" || len(c.Lines) != 1 {
		t.Fatalf("cart = %+v, %v", c, err)
	}
	l := c.Lines[0]
	if l.ProductID != "800001" || l.Quantity != 1 || l.UnitPriceMinor != 1030 || len(l.Options) != 1 || l.Options[0] != (gp.CartOption{GroupID: "701", OptionID: "801"}) {
		t.Fatalf("line = %+v", l)
	}
	want, _ := gp.CartFingerprint(c)
	if c.Fingerprint != want {
		t.Fatal("fingerprint must be CartFingerprint of the observed content")
	}

	f.on("GET", base, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[` + string(fixture(t, "basket_store.json")) + `,` + string(fixture(t, "basket_store.json")) + `]`))
	})
	if _, err := r.Cart(ctx); !errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("two baskets cannot be one snapshot: %v", err)
	}

	f.on("GET", base+"/stores/700001", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	none, err := r.CartForStore(ctx, storeRefBurger)
	if err != nil || none.Version != live.NoBasketVersion || len(none.Lines) != 0 {
		t.Fatalf("no basket for store = %+v, %v", none, err)
	}
	f.onFixture("GET", base+"/stores/700001", "basket_store.json")
	if got, err := r.CartForStore(ctx, storeRefBurger); err != nil || got.Version != "7" {
		t.Fatalf("by store = %+v, %v", got, err)
	}
}

func TestValidation(t *testing.T) {
	_, r, _ := readFake(t)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"stores limit 0":     func() error { _, e := r.Stores(ctx, gp.StoreQuery{Limit: 0}); return e },
		"stores limit 51":    func() error { _, e := r.Stores(ctx, gp.StoreQuery{Limit: 51}); return e },
		"stores kind":        func() error { _, e := r.Stores(ctx, gp.StoreQuery{Kind: "x", Limit: 1}); return e },
		"search limit":       func() error { _, e := r.Search(ctx, storeRefBurger, "a", 51); return e },
		"search empty":       func() error { _, e := r.Search(ctx, storeRefBurger, "  ", 5); return e },
		"search store":       func() error { _, e := r.Search(ctx, "700001", "a", 5); return e },
		"search path inject": func() error { _, e := r.Search(ctx, "700001/../x:710001", "a", 5); return e },
		"product id":         func() error { _, e := r.Product(ctx, storeRefBurger, "../me"); return e },
		"history limit":      func() error { _, e := r.OrderHistory(ctx, gp.HistoryQuery{Limit: 21}); return e },
		"order id":           func() error { _, e := r.Order(ctx, "1/2"); return e },
	} {
		if err := call(); !errors.Is(err, gp.ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestLocationMismatchIsUnobserved(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/customer_profile/api/v1/address_book/me/addresses", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"addresses":[{"entryType":"SAVED_ADDRESS","address":{"countryCode":"ZZ","cityCode":"ELSEWHERE"}}]}`))
	})
	r := newReader(t, f, newTokens())
	if _, err := r.Location(context.Background()); !errors.Is(err, live.ErrLocationMismatch) || !errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestShape(t *testing.T) {
	f, r, ts := readFake(t)
	if _, err := r.Search(context.Background(), storeRefBurger, "burger", 5); err != nil {
		t.Fatal(err)
	}
	req := f.requests()[0]
	if req.Header.Get("Authorization") != testToken {
		t.Fatal("token must be sent as the Authorization header")
	}
	if ts.tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", ts.tokenCalls.Load())
	}
	for k := range req.Header {
		if strings.Contains(strings.ToLower(k), "consent") {
			t.Fatalf("marketing consent header %q must never be sent", k)
		}
	}
	if req.Header.Get("Glovo-Location-City-Code") != "SYNCITY" || req.Header.Get("Glovo-Device-Urn") != "glv:device:synthetic" {
		t.Fatalf("headers = %v", req.Header)
	}
	if !strings.Contains(req.Query, "query=burger") {
		t.Fatalf("query = %q", req.Query)
	}
}

func TestConfigValidation(t *testing.T) {
	ok := baseCfg("http://127.0.0.1:1")
	if _, err := live.NewReader(ok, newTokens()); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*live.Config){
		"http non-loopback": func(c *live.Config) { c.BaseURL = "http://api.example.invalid" },
		"userinfo":          func(c *live.Config) { c.BaseURL = "https://u:p@api.example.invalid" },
		"path":              func(c *live.Config) { c.BaseURL = "https://api.example.invalid/x" },
		"scheme":            func(c *live.Config) { c.BaseURL = "ftp://api.example.invalid" },
		"currency":          func(c *live.Config) { c.Currency = "EURO" },
		"country":           func(c *live.Config) { c.Delivery.CountryCode = "ZZZ" },
		"lat":               func(c *live.Config) { c.Delivery.Latitude = "north" },
		"authorization hdr": func(c *live.Config) { c.ExtraHeaders = map[string]string{"authorization": "x"} },
		"consent hdr": func(c *live.Config) {
			c.ExtraHeaders = map[string]string{"Glovo-Perseus-Consent": "essential_functional_marketing"}
		},
	} {
		c := baseCfg("http://127.0.0.1:1")
		mut(&c)
		if _, err := live.NewReader(c, newTokens()); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	if _, err := live.NewReader(ok, nil); err == nil {
		t.Error("nil token source accepted")
	}
	c := baseCfg("https://api.example.invalid")
	if _, err := live.NewWriter(c, newTokens()); err != nil {
		t.Fatalf("https accepted: %v", err)
	}
}

var _ = time.Second
