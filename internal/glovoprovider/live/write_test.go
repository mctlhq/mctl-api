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
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/live"
)

const (
	patchPath = "/v1/authenticated/customers/" + cid + "/baskets/bsk-synth-1/products/quantity"
	putPath   = "/v1/authenticated/customers/" + cid + "/baskets/bsk-synth-1/products"
	postPath  = "/v1/authenticated/customers/" + cid + "/baskets"
)

func lastBody(t *testing.T, f *fakeGlovo, method, path string) map[string]json.RawMessage {
	t.Helper()
	var body []byte
	for _, r := range f.requests() {
		if r.Method == method && r.Path == path {
			body = r.Body
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("no %s %s body: %v", method, path, err)
	}
	return m
}

// The version precondition: a live version other than the one the caller
// read means nothing is written.
func TestVersionPreconditionRefusesStaleWrite(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 4, ExpectedVersion: "6"})
	if !errors.Is(err, live.ErrPrecondition) || res.State != gp.WritePreconditionFailed {
		t.Fatalf("state = %q err = %v", res.State, err)
	}
	if res.Cart.Version != "7" {
		t.Fatalf("the live cart must be returned: %+v", res.Cart)
	}
	if n := f.writes(); n != 0 {
		t.Fatalf("%d write requests sent despite a stale version", n)
	}
	// "no basket expected" against an existing basket is the same refusal.
	if _, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationAdd, StoreRef: storeRefBurger, StoreCategoryID: "1", ProductID: "800001", Options: opts("701", "801"), Quantity: 1, ExpectedVersion: live.NoBasketVersion}); !errors.Is(err, live.ErrPrecondition) {
		t.Fatalf("err = %v", err)
	}
	if f.writes() != 0 {
		t.Fatal("write sent")
	}
}

func TestSetQuantitySendsTheReadVersionAndReconciles(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	read, err := w.CartForStore(context.Background(), storeRefBurger)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 3, ExpectedVersion: read.Version})
	if err != nil || res.State != gp.WriteReconciled {
		t.Fatalf("state = %q err = %v", res.State, err)
	}
	body := lastBody(t, f, "PATCH", patchPath)
	if string(body["basketVersion"]) != "7" || string(body["handlingStrategy"]) != `"DELIVERY"` {
		t.Fatalf("PATCH body = %v", body)
	}
	if !strings.Contains(string(body["products"]), `"basketProductId":"bp-synth-1"`) || !strings.Contains(string(body["products"]), `"quantity":3`) {
		t.Fatalf("products = %s", body["products"])
	}
	if res.Cart.Version != "8" || len(res.Cart.Lines) != 1 || res.Cart.Lines[0].Quantity != 3 {
		t.Fatalf("reconciled cart = %+v", res.Cart)
	}
	if f.count("PATCH", patchPath) != 1 {
		t.Fatal("exactly one write expected")
	}
	// The same expected version is now stale.
	if _, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 5, ExpectedVersion: read.Version}); !errors.Is(err, live.ErrPrecondition) {
		t.Fatalf("replay of a used version: %v", err)
	}
}

func TestRemoveWritesQuantityZero(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationRemove, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), ExpectedVersion: "7"})
	if err != nil || res.State != gp.WriteReconciled || len(res.Cart.Lines) != 0 {
		t.Fatalf("state = %q err = %v cart = %+v", res.State, err, res.Cart)
	}
	if !strings.Contains(string(lastBody(t, f, "PATCH", patchPath)["products"]), `"quantity":0`) {
		t.Fatal("remove must write quantity 0")
	}
	// The line is gone: removing it again is an invalid request, not a write.
	f2 := newFake(t)
	b2 := seededBasket()
	b2.wire(f2)
	w2 := newWriter(t, f2, newTokens())
	if _, err := w2.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationRemove, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "999"), ExpectedVersion: "7"}); !errors.Is(err, gp.ErrInvalidRequest) {
		t.Fatalf("unknown line: %v", err)
	}
	if f2.writes() != 0 {
		t.Fatal("write sent for a missing line")
	}
}

func TestAddNewLineWithOptionsEchoesBasketAndAppends(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationAdd, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "802", "702", "811"), Quantity: 2, ExpectedVersion: "7"})
	if err != nil || res.State != gp.WriteReconciled {
		t.Fatalf("state = %q err = %v", res.State, err)
	}
	body := lastBody(t, f, "PUT", putPath)
	if string(body["basketVersion"]) != "7" {
		t.Fatalf("PUT must carry the version it read: %s", body["basketVersion"])
	}
	var products []map[string]json.RawMessage
	if err := json.Unmarshal(body["products"], &products); err != nil || len(products) != 2 {
		t.Fatalf("products = %s", body["products"])
	}
	added := products[1]
	if !strings.Contains(string(added["ids"]), `"id":800001`) || !strings.Contains(string(added["ids"]), `"externalId":"ext-burger-1"`) || !strings.Contains(string(added["ids"]), `"storeProductId":"sp-burger-1"`) {
		t.Fatalf("ids = %s", added["ids"])
	}
	var cz []struct {
		IDs map[string]json.RawMessage `json:"ids"`
	}
	if err := json.Unmarshal(added["customizations"], &cz); err != nil || len(cz) != 2 {
		t.Fatalf("customizations = %s", added["customizations"])
	}
	if string(cz[0].IDs["groupLegacyId"]) != "701" || string(cz[0].IDs["groupId"]) != `"grp-stable-701"` || string(cz[0].IDs["legacyId"]) != "802" || string(cz[0].IDs["id"]) != `"opt-stable-802"` {
		t.Fatalf("id types must be preserved: %v", cz[0].IDs)
	}
	if len(res.Cart.Lines) != 2 {
		t.Fatalf("cart = %+v", res.Cart)
	}
}

func TestAddToExistingLineIncrementsQuantity(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationAdd, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 2, ExpectedVersion: "7"})
	if err != nil || res.State != gp.WriteReconciled || res.Cart.Lines[0].Quantity != 3 {
		t.Fatalf("state = %q err = %v cart = %+v", res.State, err, res.Cart)
	}
	if f.count("PUT", putPath) != 0 || f.count("PATCH", patchPath) != 1 {
		t.Fatal("an existing line is updated with PATCH, not re-added")
	}
}

func TestAddCreatesBasketWhenNone(t *testing.T) {
	f := newFake(t)
	b := &fakeBasket{}
	b.wire(f)
	w := newWriter(t, f, newTokens())
	m := live.CartMutation{Kind: live.MutationAdd, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 1, ExpectedVersion: live.NoBasketVersion}
	if _, err := w.ApplyCart(context.Background(), m); !errors.Is(err, gp.ErrInvalidRequest) || f.writes() != 0 {
		t.Fatalf("creating a basket needs a store category: %v", err)
	}
	m.StoreCategoryID = "1"
	res, err := w.ApplyCart(context.Background(), m)
	if err != nil || res.State != gp.WriteReconciled || len(res.Cart.Lines) != 1 {
		t.Fatalf("state = %q err = %v", res.State, err)
	}
	body := lastBody(t, f, "POST", postPath)
	if string(body["storeId"]) != "700001" || string(body["storeAddressId"]) != "710001" || string(body["storeCategoryId"]) != "1" || string(body["handlingStrategy"]) != `"DELIVERY"` {
		t.Fatalf("POST body = %v", body)
	}
}

func TestAddValidatesOptionsBeforeWriting(t *testing.T) {
	cases := map[string][]gp.CartOption{
		"required group missing": opts("702", "811"),
		"unknown group":          opts("999", "801"),
		"unknown option":         opts("701", "999"),
		"unavailable option":     opts("701", "801", "702", "812"),
		"too many in group":      opts("701", "801", "701", "802"),
		"too many extras":        opts("701", "801", "702", "811", "702", "812"),
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			b := seededBasket()
			b.wire(f)
			w := newWriter(t, f, newTokens())
			_, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationAdd, StoreRef: storeRefBurger, ProductID: "800001", Options: o, Quantity: 1, ExpectedVersion: "7"})
			if !errors.Is(err, gp.ErrInvalidRequest) {
				t.Fatalf("err = %v", err)
			}
			if f.writes() != 0 {
				t.Fatal("a write was sent for an invalid selection")
			}
		})
	}
}

func TestReconcileMismatch(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	b.ignore = true // provider answers 200 but changes nothing
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 3, ExpectedVersion: "7"})
	if !errors.Is(err, live.ErrReconcileMismatch) || res.State != gp.WriteMismatch || res.Cart.Lines[0].Quantity != 1 {
		t.Fatalf("state = %q err = %v cart = %+v", res.State, err, res.Cart)
	}
}

func TestRereadFailureAfterWriteIsUnknown(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	reads := 0
	f.on("GET", "/v1/authenticated/customers/"+cid+"/baskets/stores/700001", func(w2 http.ResponseWriter, _ *http.Request) {
		reads++
		if reads == 1 {
			_, _ = w2.Write(b.json())
			return
		}
		w2.WriteHeader(500)
	})
	w := newWriter(t, f, newTokens())
	res, err := w.ApplyCart(context.Background(), live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 3, ExpectedVersion: "7"})
	if !errors.Is(err, live.ErrWriteUnknown) || res.State != gp.WriteReconcileUnknown {
		t.Fatalf("state = %q err = %v", res.State, err)
	}
	if f.count("PATCH", patchPath) != 1 {
		t.Fatal("one write only")
	}
}

func TestMutationValidation(t *testing.T) {
	f := newFake(t)
	b := seededBasket()
	b.wire(f)
	w := newWriter(t, f, newTokens())
	ok := live.CartMutation{Kind: live.MutationSetQuantity, StoreRef: storeRefBurger, ProductID: "800001", Options: opts("701", "801"), Quantity: 2, ExpectedVersion: "7"}
	for name, mut := range map[string]func(*live.CartMutation){
		"kind":             func(m *live.CartMutation) { m.Kind = "checkout" },
		"quantity 0":       func(m *live.CartMutation) { m.Quantity = 0 },
		"quantity 100":     func(m *live.CartMutation) { m.Quantity = 100 },
		"no version":       func(m *live.CartMutation) { m.ExpectedVersion = "" },
		"version junk":     func(m *live.CartMutation) { m.ExpectedVersion = "7/../x" },
		"store":            func(m *live.CartMutation) { m.StoreRef = "700001" },
		"product":          func(m *live.CartMutation) { m.ProductID = "a/b" },
		"duplicate option": func(m *live.CartMutation) { m.Options = opts("701", "801", "701", "801") },
		"category":         func(m *live.CartMutation) { m.StoreCategoryID = "x/y" },
	} {
		m := ok
		mut(&m)
		if _, err := w.ApplyCart(context.Background(), m); !errors.Is(err, gp.ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(f.requests()) != 0 {
		t.Fatalf("invalid mutations must not even read: %d requests", len(f.requests()))
	}
}

// The Reader type has no write method; only Writer does, and only through
// CartMutator.
func TestReaderHasNoWriteSurface(t *testing.T) {
	var r any = &live.Reader{}
	if _, ok := r.(live.CartMutator); ok {
		t.Fatal("Reader must not implement CartMutator")
	}
	if _, ok := r.(gp.CartWriter); ok {
		t.Fatal("Reader must not implement CartWriter")
	}
	var w any = &live.Writer{}
	if _, ok := w.(gp.Provider); !ok {
		t.Fatal("Writer reads through Provider")
	}
}
