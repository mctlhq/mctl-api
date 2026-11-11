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

package reorder_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/reorder"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/synthetic"
)

var now = synthetic.FixedNow

func provider(t *testing.T, s ...synthetic.Scenario) *synthetic.Provider {
	t.Helper()
	p, err := synthetic.New()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) > 0 {
		return p.WithScenario(s[0])
	}
	return p
}

func order(t *testing.T, p gp.Provider, id string) gp.HistoricalOrder {
	t.Helper()
	o, err := p.Order(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func plan(t *testing.T, p gp.Provider, orderID string, c reorder.Constraints) reorder.Intent {
	t.Helper()
	in, err := reorder.Plan(context.Background(), p, reorder.Request{Order: order(t, p, orderID), Constraints: c, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.VerifyDigest(); err != nil {
		t.Fatal(err)
	}
	return in
}

// outcome is where one historical product ended up.
type outcome struct {
	disposition string // line, substitution, excluded
	class       reorder.Class
	reasons     []string
}

func outcomes(in reorder.Intent) map[string]outcome {
	out := map[string]outcome{}
	for _, l := range in.Lines {
		out[l.ProductID] = outcome{"line", reorder.ClassExact, nil}
	}
	for i := range in.Substitutions {
		s := &in.Substitutions[i]
		out[s.HistoricalProductID] = outcome{"substitution", reorder.ClassCandidate, s.Reasons}
	}
	for _, e := range in.Excluded {
		out[e.HistoricalProductID] = outcome{"excluded", e.Class, e.Reasons}
	}
	return out
}

func TestClassification(t *testing.T) {
	p := provider(t)
	cases := []struct {
		order, product string
		want           outcome
	}{
		{"ord_synth_0001", "prd_burger_classic", outcome{"line", reorder.ClassExact, nil}},
		{"ord_synth_0001", "prd_fries", outcome{"line", reorder.ClassExact, nil}},
		{"ord_synth_0001", "prd_cola_330", outcome{"line", reorder.ClassExact, nil}},
		{"ord_synth_0001", "prd_burger_veggie_old", outcome{"substitution", reorder.ClassCandidate, []string{reorder.ReasonProductIDChanged}}},
		{"ord_synth_0001", "prd_wrap_chicken_old", outcome{"excluded", reorder.ClassAmbiguous, []string{reorder.ReasonTie}}},
		{"ord_synth_0001", "prd_onion_rings", outcome{"excluded", reorder.ClassUnavailable, []string{reorder.ReasonItemUnavailable}}},
		{"ord_synth_0002", "prd_milk_whole_1l", outcome{"line", reorder.ClassExact, nil}},
		{"ord_synth_0002", "prd_juice_orange_1l", outcome{"excluded", reorder.ClassUnavailable, []string{reorder.ReasonItemUnavailable}}},
		{"ord_synth_0002", "prd_yogurt_greek_old", outcome{"excluded", reorder.ClassUnavailable, []string{reorder.ReasonNotFound}}},
		{"ord_synth_0003", "prd_pizza_margherita", outcome{"excluded", reorder.ClassMissingRequiredOptions, []string{reorder.ReasonRequiredOptionMissing}}},
		{"ord_synth_0003", "prd_pizza_diavola", outcome{"line", reorder.ClassExact, nil}},
	}
	intents := map[string]reorder.Intent{}
	for _, c := range cases {
		in, ok := intents[c.order]
		if !ok {
			in = plan(t, p, c.order, reorder.Constraints{})
			intents[c.order] = in
		}
		got, ok := outcomes(in)[c.product]
		if !ok {
			t.Errorf("%s/%s: line vanished from the intent", c.order, c.product)
			continue
		}
		if got.disposition != c.want.disposition || got.class != c.want.class || !reflect.DeepEqual(got.reasons, c.want.reasons) {
			t.Errorf("%s/%s = %+v, want %+v", c.order, c.product, got, c.want)
		}
	}
	// Every historical line is accounted for exactly once.
	for id, in := range intents {
		o := order(t, p, id)
		if n := len(in.Lines) + len(in.Substitutions) + len(in.Excluded); n != len(o.Items) {
			t.Errorf("%s: %d outcomes for %d lines", id, n, len(o.Items))
		}
	}
	amb := intents["ord_synth_0001"]
	for _, e := range amb.Excluded {
		if e.HistoricalProductID == "prd_wrap_chicken_old" && !reflect.DeepEqual(e.CandidateProductIDs, []string{"prd_wrap_classic", "prd_wrap_spicy"}) {
			t.Errorf("ambiguous candidates %v", e.CandidateProductIDs)
		}
	}
}

func TestPricesAndTotals(t *testing.T) {
	in := plan(t, provider(t), "ord_synth_0001", reorder.Constraints{})
	// Classic Burger: 950 + cheese 80 = 1030 now, 1000 then, x2.
	var burger reorder.Line
	for _, l := range in.Lines {
		if l.ProductID == "prd_burger_classic" {
			burger = l
		}
	}
	if burger.UnitPriceMinor != 1030 || burger.PriceDeltaMinor != 30 || burger.LineTotalMinor != 2060 {
		t.Fatalf("burger pricing %+v", burger)
	}
	if in.EstimatedSubtotalMinor != 2910 || in.HistoricalSubtotalMinor != 2850 || in.PriceDeltaMinor != 60 {
		t.Fatalf("totals est=%d hist=%d delta=%d", in.EstimatedSubtotalMinor, in.HistoricalSubtotalMinor, in.PriceDeltaMinor)
	}
	if in.Substitutions[0].UnitPriceMinor != 890 || in.Substitutions[0].PriceDeltaMinor != 20 || in.Substitutions[0].ScorePermille != 1000 {
		t.Fatalf("substitution pricing %+v", in.Substitutions[0])
	}
	// Substitutions never count towards the estimate.
	if !contains(in.Warnings, reorder.WarnSubstitutionsPending) || !contains(in.Warnings, reorder.WarnPriceIncreased) {
		t.Fatalf("warnings %v", in.Warnings)
	}
}

func TestPriceDrift(t *testing.T) {
	s := synthetic.Scenario{PriceOverrides: map[string]int64{"prd_burger_classic": 900, "prd_milk_whole_1l": 139}}
	in := plan(t, provider(t, s), "ord_synth_0001", reorder.Constraints{})
	for _, l := range in.Lines {
		if l.ProductID == "prd_burger_classic" && (l.UnitPriceMinor != 980 || l.PriceDeltaMinor != -20) {
			t.Fatalf("drift down: %+v", l)
		}
	}
	milk := plan(t, provider(t, s), "ord_synth_0002", reorder.Constraints{})
	if milk.Lines[0].ProductID != "prd_bread_sourdough" {
		t.Fatalf("lines not in canonical order: %+v", milk.Lines)
	}
	for _, l := range milk.Lines {
		if l.ProductID == "prd_milk_whole_1l" && l.PriceDeltaMinor != 20 {
			t.Fatalf("drift up: %+v", l)
		}
	}
}

func TestExcludeCategory(t *testing.T) {
	in := plan(t, provider(t), "ord_synth_0001", reorder.Constraints{ExcludeCategoryTags: []string{" Drinks "}})
	o := outcomes(in)["prd_cola_330"]
	if o.disposition != "excluded" || o.class != reorder.ClassExact || !reflect.DeepEqual(o.reasons, []string{reorder.ReasonExcludedCategory}) {
		t.Fatalf("cola not excluded: %+v", o)
	}
	if in.EstimatedSubtotalMinor != 2410 {
		t.Fatalf("subtotal %d", in.EstimatedSubtotalMinor)
	}
	if !reflect.DeepEqual(in.Constraints.ExcludeCategoryTags, []string{"drinks"}) {
		t.Fatalf("constraints not normalized: %v", in.Constraints.ExcludeCategoryTags)
	}
	// Express store: drinks are tagged by the current category even when
	// the historical line is matched by id, and the unavailable juice keeps
	// its class while also recording the exclusion.
	ex := outcomes(plan(t, provider(t), "ord_synth_0002", reorder.Constraints{ExcludeCategoryTags: []string{"drinks"}}))
	if ex["prd_water_still_6x15"].disposition != "excluded" {
		t.Fatal("water not excluded")
	}
	if j := ex["prd_juice_orange_1l"]; j.class != reorder.ClassUnavailable || !contains(j.reasons, reorder.ReasonExcludedCategory) {
		t.Fatalf("juice %+v", j)
	}
	// Exclusion follows the current catalog category, not only history tags.
	untagged := provider(t)
	o2 := order(t, untagged, "ord_synth_0001")
	for i := range o2.Items {
		o2.Items[i].CategoryTags = nil
	}
	in2, err := reorder.Plan(context.Background(), untagged, reorder.Request{Order: o2, Constraints: reorder.Constraints{ExcludeCategoryTags: []string{"drinks"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if outcomes(in2)["prd_cola_330"].disposition != "excluded" {
		t.Fatal("catalog category tag ignored")
	}
}

func TestBudget(t *testing.T) {
	in := plan(t, provider(t), "ord_synth_0001", reorder.Constraints{MaxBudgetMinor: 2500})
	// Canonical order: burger 2060 fits, cola 500 would exceed, fries 350 fits.
	o := outcomes(in)
	if o["prd_burger_classic"].disposition != "line" || o["prd_fries"].disposition != "line" {
		t.Fatalf("budget kept %+v", in.Lines)
	}
	if c := o["prd_cola_330"]; c.disposition != "excluded" || !reflect.DeepEqual(c.reasons, []string{reorder.ReasonOverBudget}) {
		t.Fatalf("cola %+v", c)
	}
	if in.EstimatedSubtotalMinor != 2410 || in.EstimatedSubtotalMinor > in.Constraints.MaxBudgetMinor {
		t.Fatalf("subtotal %d", in.EstimatedSubtotalMinor)
	}
	tiny := plan(t, provider(t), "ord_synth_0001", reorder.Constraints{MaxBudgetMinor: 100})
	if len(tiny.Lines) != 0 || !contains(tiny.Warnings, reorder.WarnNothingToAdd) {
		t.Fatalf("tiny budget %+v", tiny.Lines)
	}
	if _, err := reorder.Build(reorder.Request{Order: order(t, provider(t), "ord_synth_0001"), Now: now,
		Constraints: reorder.Constraints{MaxBudgetMinor: -1}}, reorder.Snapshot{}); !errors.Is(err, reorder.ErrInvalidRequest) {
		t.Fatalf("negative budget: %v", err)
	}
}

func TestOptionScenarios(t *testing.T) {
	// opt_medium was a required doneness choice; removing it makes the
	// burger impossible to rebuild as ordered.
	in := plan(t, provider(t, synthetic.Scenario{RemovedOptions: []string{"opt_medium"}}), "ord_synth_0001", reorder.Constraints{})
	if b := outcomes(in)["prd_burger_classic"]; b.class != reorder.ClassMissingRequiredOptions ||
		!reflect.DeepEqual(b.reasons, []string{reorder.ReasonOptionRemoved, reorder.ReasonRequiredOptionMissing}) {
		t.Fatalf("required option removed: %+v", b)
	}
	// opt_cheese was optional; the burger becomes a confirmation-required
	// candidate at the cheaper price, never a silent exact match.
	in = plan(t, provider(t, synthetic.Scenario{RemovedOptions: []string{"opt_cheese"}}), "ord_synth_0001", reorder.Constraints{})
	if b := outcomes(in)["prd_burger_classic"]; b.disposition != "substitution" || !reflect.DeepEqual(b.reasons, []string{reorder.ReasonOptionRemoved}) {
		t.Fatalf("optional option removed: %+v", b)
	}
	for _, s := range in.Substitutions {
		if s.CandidateProductID == "prd_burger_classic" && (s.UnitPriceMinor != 950 || len(s.Options) != 1) {
			t.Fatalf("dropped option still priced: %+v", s)
		}
	}
}

func TestMatchingThresholdAndTies(t *testing.T) {
	cat := gp.Catalog{StoreID: "st_t", Currency: "EUR", Open: true,
		Categories: []gp.Category{{ID: "cat_a", Name: "A"}},
		Products: []gp.Product{
			{ID: "prd_x1", StoreID: "st_t", CategoryID: "cat_a", Name: "Tomato Soup Large", PriceMinor: 500, Available: true},
			{ID: "prd_x2", StoreID: "st_t", CategoryID: "cat_a", Name: "Tomato Soup Small", PriceMinor: 300, Available: true},
			{ID: "prd_x3", StoreID: "st_t", CategoryID: "cat_a", Name: "Green Salad Bowl", PriceMinor: 400, Available: true},
		}}
	cart := gp.CartSnapshot{Lines: []gp.CartLine{}}
	cart.Fingerprint, _ = gp.CartFingerprint(cart)
	run := func(name string) reorder.Intent {
		in, err := reorder.Build(reorder.Request{Now: now, Order: gp.HistoricalOrder{
			Summary: gp.OrderSummary{ID: "ord_t", StoreID: "st_t", Currency: "EUR", NativeReorderAllowed: true},
			Items:   []gp.OrderItem{{ProductID: "prd_gone", Name: name, Quantity: 1, UnitPriceMinor: 100}},
		}}, reorder.Snapshot{Catalog: &cat, Cart: &cart})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	cases := []struct {
		name  string
		class reorder.Class
		disp  string
	}{
		{"Tomato Soup", reorder.ClassAmbiguous, "excluded"},                // 666 vs 666: tie
		{"Green Salad Bowl", reorder.ClassCandidate, "substitution"},       // 1000, unique, but id changed
		{"Green Salad", reorder.ClassCandidate, "substitution"},            // 666 >= 600, unique
		{"Salad", reorder.ClassUnavailable, "excluded"},                    // 333 < 600
		{"Tomato Soup Large Bowl", reorder.ClassCandidate, "substitution"}, // 750; Small is 400 < 600
	}
	for _, c := range cases {
		got := outcomes(run(c.name))["prd_gone"]
		if got.class != c.class || got.disposition != c.disp {
			t.Errorf("%q: %+v, want %s/%s", c.name, got, c.class, c.disp)
		}
	}
}

func TestNativeReorderFalseDoesNotBlock(t *testing.T) {
	in := plan(t, provider(t), "ord_synth_0003", reorder.Constraints{})
	if in.NativeReorderAllowed || len(in.Lines) != 1 || !contains(in.Warnings, reorder.WarnNativeReorderOff) || !contains(in.Warnings, reorder.WarnStoreClosed) {
		t.Fatalf("manual reconstruction blocked or warnings missing: %+v", in)
	}
}

func TestCouldNotObserveNeverBecomesUnavailable(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{gp.OpCatalog, gp.OpCart} {
		p := provider(t, synthetic.Scenario{FailOps: []string{op}})
		o := order(t, provider(t), "ord_synth_0001")
		in, err := reorder.Plan(ctx, p, reorder.Request{Order: o, Now: now})
		if !errors.Is(err, gp.ErrUnobserved) {
			t.Fatalf("%s: got %v, want ErrUnobserved", op, err)
		}
		if in.Digest != "" || len(in.Excluded) != 0 {
			t.Fatalf("%s: a failed read produced an intent", op)
		}
	}
	if _, err := reorder.Build(reorder.Request{Order: order(t, provider(t), "ord_synth_0001"), Now: now},
		reorder.Snapshot{Cart: &gp.CartSnapshot{Lines: []gp.CartLine{}}}); !errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("nil catalog: %v", err)
	}
	// A store the provider positively reports absent is an observation:
	// every line is unavailable with store_unavailable.
	in := plan(t, provider(t, synthetic.Scenario{RemovedStores: []string{"st_synth_burger_01"}}), "ord_synth_0001", reorder.Constraints{})
	if len(in.Lines) != 0 || len(in.Excluded) != 6 || !contains(in.Warnings, reorder.WarnStoreUnavailable) {
		t.Fatalf("store absent: %+v", in)
	}
	for _, e := range in.Excluded {
		if e.Class != reorder.ClassUnavailable || !contains(e.Reasons, reorder.ReasonStoreUnavailable) {
			t.Fatalf("store absent line %+v", e)
		}
	}
}

func TestDeterminism(t *testing.T) {
	p := provider(t)
	o := order(t, p, "ord_synth_0001")
	c := reorder.Constraints{ExcludeCategoryTags: []string{"drinks", "sides"}, MaxBudgetMinor: 5000}
	snap, err := reorder.Gather(context.Background(), p, o.Summary.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	build := func(o gp.HistoricalOrder, c reorder.Constraints) reorder.Intent {
		in, err := reorder.Build(reorder.Request{Order: o, Constraints: c, Now: now}, snap)
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	base := build(o, c)
	if again := build(o, c); again.Digest != base.Digest || !reflect.DeepEqual(again, base) {
		t.Fatal("same input, different intent")
	}
	rev := o
	rev.Items = make([]gp.OrderItem, len(o.Items))
	for i, it := range o.Items {
		rev.Items[len(o.Items)-1-i] = it
	}
	for i := range rev.Items {
		if rev.Items[i].ProductID == "prd_burger_classic" {
			opts := rev.Items[i].Options
			rev.Items[i].Options = []gp.SelectedOption{opts[1], opts[0]}
		}
	}
	revC := reorder.Constraints{ExcludeCategoryTags: []string{"Sides", "drinks", "drinks"}, MaxBudgetMinor: 5000}
	if got := build(rev, revC); got.Digest != base.Digest {
		t.Fatalf("reordering lines, options or tags changed the digest")
	}
	// Splitting one line into two with the same total merges back.
	split := o
	split.Items = append([]gp.OrderItem(nil), o.Items...)
	split.Items[0].Quantity = 1
	split.Items = append(split.Items, split.Items[0])
	if got := build(split, c); got.Digest != base.Digest {
		t.Fatal("a split line changed the digest")
	}

	mutations := map[string]func(*gp.HistoricalOrder){
		"quantity":   func(o *gp.HistoricalOrder) { o.Items[0].Quantity++ },
		"option":     func(o *gp.HistoricalOrder) { o.Items[0].Options = o.Items[0].Options[:1] },
		"product":    func(o *gp.HistoricalOrder) { o.Items[1].ProductID = "prd_lemonade" },
		"hist_price": func(o *gp.HistoricalOrder) { o.Items[0].UnitPriceMinor++ },
		"drop_line":  func(o *gp.HistoricalOrder) { o.Items = o.Items[1:] },
	}
	for name, mut := range mutations {
		m := order(t, p, "ord_synth_0001")
		mut(&m)
		if got := build(m, c); got.Digest == base.Digest {
			t.Errorf("%s: digest did not change", name)
		}
	}
	if got := build(o, reorder.Constraints{ExcludeCategoryTags: []string{"drinks"}, MaxBudgetMinor: 5000}); got.Digest == base.Digest {
		t.Error("constraint change did not change the digest")
	}
	later, _ := reorder.Build(reorder.Request{Order: o, Constraints: c, Now: now.Add(time.Minute)}, snap)
	if later.Digest == base.Digest {
		t.Error("expiry is not bound by the digest")
	}
	// Tampering after the fact is detected.
	tampered := base
	tampered.Lines = append([]reorder.Line(nil), base.Lines...)
	tampered.Lines[0].Quantity = 99
	if !errors.Is(tampered.VerifyDigest(), reorder.ErrDigestMismatch) {
		t.Fatal("tampered intent verified")
	}
}

func TestTTL(t *testing.T) {
	p := provider(t)
	o := order(t, p, "ord_synth_0002")
	in, err := reorder.Plan(context.Background(), p, reorder.Request{Order: o, Now: now, TTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if in.ExpiresAt != now.Add(5*time.Minute).Format(time.RFC3339) || in.Expired(now.Add(4*time.Minute)) || !in.Expired(now.Add(5*time.Minute)) {
		t.Fatalf("expiry %s", in.ExpiresAt)
	}
	if _, err := reorder.Plan(context.Background(), p, reorder.Request{Order: o, Now: now, TTL: 2 * time.Hour}); !errors.Is(err, reorder.ErrInvalidRequest) {
		t.Fatalf("ttl above max: %v", err)
	}
}

func TestRevalidateMatrix(t *testing.T) {
	ctx := context.Background()
	in := plan(t, provider(t), "ord_synth_0001", reorder.Constraints{})
	cases := []struct {
		name     string
		scenario synthetic.Scenario
		at       time.Time
		verdict  reorder.Verdict
		changes  []reorder.Change
	}{
		{"unchanged", synthetic.Scenario{}, now, reorder.VerdictUnchanged, nil},
		{"excluded line changed", synthetic.Scenario{PriceOverrides: map[string]int64{"prd_onion_rings": 1}}, now, reorder.VerdictUnchanged, nil},
		{"price", synthetic.Scenario{PriceOverrides: map[string]int64{"prd_fries": 360}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_fries", Kind: reorder.ChangePrice}}},
		{"availability", synthetic.Scenario{UnavailableProducts: []string{"prd_fries"}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_fries", Kind: reorder.ChangeAvailability}}},
		{"option", synthetic.Scenario{RemovedOptions: []string{"opt_cheese"}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_burger_classic", Kind: reorder.ChangeOption}}},
		{"option price", synthetic.Scenario{PriceOverrides: map[string]int64{"prd_burger_classic": 951}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_burger_classic", Kind: reorder.ChangePrice}}},
		{"item removed", synthetic.Scenario{RemovedProducts: []string{"prd_cola_330"}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_cola_330", Kind: reorder.ChangeItemRemoved}}},
		{"substitution price", synthetic.Scenario{PriceOverrides: map[string]int64{"prd_burger_veggie_v2": 900}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{ProductID: "prd_burger_veggie_v2", Kind: reorder.ChangePrice}}},
		{"cart state", synthetic.Scenario{Cart: &gp.CartSnapshot{Lines: []gp.CartLine{}}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{Kind: reorder.ChangeCartState}}},
		{"store removed", synthetic.Scenario{RemovedStores: []string{"st_synth_burger_01"}}, now, reorder.VerdictMaterialChange,
			[]reorder.Change{{Kind: reorder.ChangeStore}}},
		{"catalog unobserved", synthetic.Scenario{FailOps: []string{gp.OpCatalog}}, now, reorder.VerdictUnknown, nil},
		{"cart unobserved", synthetic.Scenario{FailOps: []string{gp.OpCart}}, now, reorder.VerdictUnknown, nil},
		{"unobserved and changed", synthetic.Scenario{FailOps: []string{gp.OpCart}, PriceOverrides: map[string]int64{"prd_fries": 1}}, now, reorder.VerdictUnknown, nil},
		{"expired", synthetic.Scenario{}, now.Add(reorder.DefaultTTL), reorder.VerdictExpired, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := reorder.RevalidateFrom(ctx, provider(t, c.scenario), in, c.at)
			if err != nil {
				t.Fatal(err)
			}
			want := c.changes
			if want == nil {
				want = []reorder.Change{}
			}
			if res.Verdict != c.verdict || !reflect.DeepEqual(res.Changes, want) {
				t.Fatalf("got %+v, want %s %+v", res, c.verdict, want)
			}
			if res.RequiresNewApproval != (c.verdict != reorder.VerdictUnchanged) {
				t.Fatalf("requires_new_approval %v for %s", res.RequiresNewApproval, res.Verdict)
			}
		})
	}
	// Pure form: a nil snapshot part is unknown, never unchanged.
	if r := reorder.Revalidate(in, reorder.Snapshot{}, now); r.Verdict != reorder.VerdictUnknown {
		t.Fatalf("empty snapshot: %s", r.Verdict)
	}
	tampered := in
	tampered.EstimatedSubtotalMinor--
	if r := reorder.Revalidate(tampered, reorder.Snapshot{}, now); r.Verdict != reorder.VerdictTampered {
		t.Fatalf("tampered: %s", r.Verdict)
	}
}

// TestRevalidateSnapshotEdits covers changes the synthetic knobs cannot
// express: a same-id rename, a retag into an excluded category, a store that
// closed after planning, and an adapter-supplied cart fingerprint that does
// not match the cart content.
func TestRevalidateSnapshotEdits(t *testing.T) {
	ctx := context.Background()
	p := provider(t)
	in := plan(t, p, "ord_synth_0001", reorder.Constraints{ExcludeCategoryTags: []string{"drinks"}})
	fresh := func() reorder.Snapshot {
		snap, err := reorder.Gather(ctx, p, "st_synth_burger_01")
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	if r := reorder.Revalidate(in, fresh(), now); r.Verdict != reorder.VerdictUnchanged {
		t.Fatalf("baseline %+v", r)
	}
	cases := []struct {
		name    string
		edit    func(*reorder.Snapshot)
		verdict reorder.Verdict
		changes []reorder.Change
	}{
		{"renamed", func(s *reorder.Snapshot) {
			for i := range s.Catalog.Products {
				if s.Catalog.Products[i].ID == "prd_fries" {
					s.Catalog.Products[i].Name = "Vegan Nuggets"
				}
			}
		}, reorder.VerdictMaterialChange, []reorder.Change{{ProductID: "prd_fries", Kind: reorder.ChangeRenamed}}},
		{"retagged into excluded", func(s *reorder.Snapshot) {
			for i := range s.Catalog.Categories {
				if s.Catalog.Categories[i].ID == "cat_sides" {
					s.Catalog.Categories[i].Tags = []string{"Drinks"}
				}
			}
		}, reorder.VerdictMaterialChange, []reorder.Change{{ProductID: "prd_fries", Kind: reorder.ChangeExcludedCategory}}},
		{"store closed", func(s *reorder.Snapshot) { s.Catalog.Open = false },
			reorder.VerdictMaterialChange, []reorder.Change{{Kind: reorder.ChangeStore}}},
		{"stale cart fingerprint", func(s *reorder.Snapshot) { s.Cart.Lines = []gp.CartLine{} },
			reorder.VerdictUnknown, []reorder.Change{}},
		{"empty cart fingerprint", func(s *reorder.Snapshot) { s.Cart.Fingerprint = "" },
			reorder.VerdictUnknown, []reorder.Change{}},
	}
	for _, c := range cases {
		snap := fresh()
		c.edit(&snap)
		if r := reorder.Revalidate(in, snap, now); r.Verdict != c.verdict || !reflect.DeepEqual(r.Changes, c.changes) {
			t.Errorf("%s: %+v, want %s %+v", c.name, r, c.verdict, c.changes)
		}
	}
	// Build refuses an untrustworthy cart fingerprint as unobserved.
	snap := fresh()
	snap.Cart.Fingerprint = ""
	if _, err := reorder.Build(reorder.Request{Order: order(t, p, "ord_synth_0001"), Now: now}, snap); !errors.Is(err, gp.ErrUnobserved) {
		t.Fatalf("empty fingerprint: %v", err)
	}
	// A closed store already flagged at planning time is not a new change.
	closed := plan(t, p, "ord_synth_0003", reorder.Constraints{})
	snap3, _ := reorder.Gather(ctx, p, "st_synth_pizza_01")
	if r := reorder.Revalidate(closed, snap3, now); r.Verdict != reorder.VerdictUnchanged {
		t.Fatalf("known-closed store: %+v", r)
	}
}

func TestCurrencyMismatchKeepsHistoricalCurrency(t *testing.T) {
	p := provider(t)
	o := order(t, p, "ord_synth_0002")
	o.Summary.Currency = "USD"
	in, err := reorder.Plan(context.Background(), p, reorder.Request{Order: o, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if in.Currency != "EUR" || in.HistoricalCurrency != "USD" || in.PriceDeltaMinor != 0 || !contains(in.Warnings, reorder.WarnCurrencyMismatch) {
		t.Fatalf("currency mismatch: cur=%s hist=%s delta=%d %v", in.Currency, in.HistoricalCurrency, in.PriceDeltaMinor, in.Warnings)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
