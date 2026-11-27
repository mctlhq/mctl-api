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

package reorder

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// Bounds of a reconstruction.
const (
	DefaultTTL      = 15 * time.Minute
	MaxTTL          = time.Hour
	MaxOrderLines   = 50
	MaxLineQuantity = 100
)

// ErrInvalidRequest wraps every refusal of a malformed Request.
var ErrInvalidRequest = errors.New("reorder: invalid request")

// Request is the input of one reconstruction.
type Request struct {
	Order       gp.HistoricalOrder
	Constraints Constraints
	// Now is the planning clock; the caller supplies it so Build stays pure.
	Now time.Time
	// TTL is the intent lifetime; 0 means DefaultTTL, at most MaxTTL.
	TTL time.Duration
}

// Snapshot is what the planner observed of the provider. A nil Catalog
// (unless StoreAbsent) or a nil Cart means "not observed", which is never
// treated as empty.
type Snapshot struct {
	Catalog     *gp.Catalog
	StoreAbsent bool
	Cart        *gp.CartSnapshot
}

// Gather reads the catalog of storeID and the cart. A store the provider
// reports absent is recorded as StoreAbsent; any other failed read is
// returned as an error, so a reconstruction never runs on a partial view.
func Gather(ctx context.Context, p gp.Provider, storeID string) (Snapshot, error) {
	var snap Snapshot
	cat, err := p.Catalog(ctx, storeID)
	switch {
	case errors.Is(err, gp.ErrAbsent):
		snap.StoreAbsent = true
	case err != nil:
		return Snapshot{}, err
	default:
		snap.Catalog = &cat
	}
	cart, err := p.Cart(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Cart = &cart
	return snap, nil
}

// Plan reads through p and builds the intent. It never writes.
func Plan(ctx context.Context, p gp.Provider, req Request) (Intent, error) {
	snap, err := Gather(ctx, p, req.Order.Summary.StoreID)
	if err != nil {
		return Intent{}, err
	}
	return Build(req, snap)
}

// histLine is one merged historical line.
type histLine struct {
	key            string
	ProductID      string
	Name           string
	Tags           []string
	Quantity       int64
	UnitPriceMinor int64
	Options        []OptionRef
}

func invalidReq(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidRequest, reason) }

func lowerSet(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return uniqSorted(out)
}

// mergeLines merges duplicate lines (same product and options) and returns
// them in canonical key order, so input order never affects the result.
func mergeLines(items []gp.OrderItem) ([]histLine, error) {
	if len(items) == 0 || len(items) > MaxOrderLines {
		return nil, invalidReq("order has 1 to 50 lines")
	}
	byKey := map[string]*histLine{}
	for _, it := range items {
		if it.ProductID == "" || it.Quantity < 1 || it.Quantity > MaxLineQuantity || it.UnitPriceMinor < 0 {
			return nil, invalidReq("order line bounds")
		}
		opts := make([]OptionRef, 0, len(it.Options))
		cartOpts := make([]gp.CartOption, 0, len(it.Options))
		for _, o := range it.Options {
			opts = append(opts, OptionRef{GroupID: o.GroupID, OptionID: o.OptionID})
			cartOpts = append(cartOpts, gp.CartOption{GroupID: o.GroupID, OptionID: o.OptionID})
		}
		sortOptions(opts)
		key := it.ProductID + "|" + gp.OptionKey(cartOpts)
		h, ok := byKey[key]
		if !ok {
			byKey[key] = &histLine{key: key, ProductID: it.ProductID, Name: it.Name, Tags: lowerSet(it.CategoryTags),
				Quantity: it.Quantity, UnitPriceMinor: it.UnitPriceMinor, Options: opts}
			continue
		}
		h.Quantity += it.Quantity
		if h.Quantity > MaxLineQuantity {
			return nil, invalidReq("order line bounds")
		}
		// Deterministic regardless of input order.
		if it.UnitPriceMinor > h.UnitPriceMinor {
			h.UnitPriceMinor = it.UnitPriceMinor
		}
		if it.Name < h.Name {
			h.Name = it.Name
		}
		h.Tags = lowerSet(append(h.Tags, it.CategoryTags...))
	}
	out := make([]histLine, 0, len(byKey))
	for _, h := range byKey {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out, nil
}

func sortOptions(o []OptionRef) {
	sort.Slice(o, func(i, j int) bool {
		if o[i].GroupID != o[j].GroupID {
			return o[i].GroupID < o[j].GroupID
		}
		return o[i].OptionID < o[j].OptionID
	})
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Build is the pure planner: same Request and Snapshot, same Intent and
// digest. It classifies every historical line, adds only exact matches,
// proposes candidates as substitutions, and records every other line in
// Excluded with its class and reasons.
func Build(req Request, snap Snapshot) (Intent, error) {
	if req.Now.IsZero() {
		return Intent{}, invalidReq("now")
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < 0 || ttl > MaxTTL {
		return Intent{}, invalidReq("ttl")
	}
	if req.Constraints.MaxBudgetMinor < 0 {
		return Intent{}, invalidReq("max_budget_minor")
	}
	if req.Order.Summary.ID == "" || req.Order.Summary.StoreID == "" {
		return Intent{}, invalidReq("order")
	}
	if snap.Cart == nil {
		return Intent{}, errUnobserved("cart")
	}
	if snap.Catalog == nil && !snap.StoreAbsent {
		return Intent{}, errUnobserved("catalog")
	}
	cartFP, ok := observedCartFingerprint(snap.Cart)
	if !ok {
		return Intent{}, errUnobserved("cart fingerprint")
	}
	if snap.Catalog != nil && snap.Catalog.StoreID != req.Order.Summary.StoreID {
		return Intent{}, invalidReq("catalog is for another store")
	}
	lines, err := mergeLines(req.Order.Items)
	if err != nil {
		return Intent{}, err
	}
	exclude := lowerSet(req.Constraints.ExcludeCategoryTags)
	now := req.Now.UTC().Truncate(time.Second)

	in := Intent{
		V:                    IntentVersion,
		SourceOrderID:        req.Order.Summary.ID,
		StoreID:              req.Order.Summary.StoreID,
		Currency:             req.Order.Summary.Currency,
		HistoricalCurrency:   req.Order.Summary.Currency,
		CreatedAt:            now.Format(time.RFC3339),
		ExpiresAt:            now.Add(ttl).Format(time.RFC3339),
		NativeReorderAllowed: req.Order.Summary.NativeReorderAllowed,
		Constraints:          Constraints{ExcludeCategoryTags: exclude, MaxBudgetMinor: req.Constraints.MaxBudgetMinor},
		CartFingerprint:      cartFP,
		Lines:                []Line{},
		Substitutions:        []Substitution{},
		Excluded:             []Excluded{},
	}
	if in.Constraints.ExcludeCategoryTags == nil {
		in.Constraints.ExcludeCategoryTags = []string{}
	}
	warn := map[string]bool{WarnFeesNotEstimated: true}
	if !in.NativeReorderAllowed {
		// Informational only: the manual reconstruction proceeds.
		warn[WarnNativeReorderOff] = true
	}
	if len(snap.Cart.Lines) > 0 {
		warn[WarnCartNotEmpty] = true
		if snap.Cart.StoreID != in.StoreID {
			warn[WarnCartOtherStore] = true
		}
	}
	samePriceBasis := true
	if snap.StoreAbsent {
		warn[WarnStoreUnavailable] = true
	} else {
		if !snap.Catalog.Open {
			warn[WarnStoreClosed] = true
		}
		if snap.Catalog.Currency != in.Currency {
			// Prices in another currency cannot be compared with history.
			warn[WarnCurrencyMismatch] = true
			samePriceBasis = false
			in.Currency = snap.Catalog.Currency
		}
	}

	for _, h := range lines {
		if snap.StoreAbsent {
			in.Excluded = append(in.Excluded, excluded(h, ClassUnavailable, []string{ReasonStoreUnavailable}, nil, exclude))
			continue
		}
		cat := *snap.Catalog
		m := matchProduct(h, cat)
		if m.product == nil {
			in.Excluded = append(in.Excluded, excluded(h, m.class, m.reasons, m.candidates, exclude))
			continue
		}
		p := *m.product
		tags := h.Tags
		if c, ok := cat.Category(p.CategoryID); ok {
			tags = lowerSet(append(append([]string(nil), tags...), c.Tags...))
		}
		class, reasons := m.class, append([]string(nil), m.reasons...)
		ev := evalOptions(p, h.Options)
		switch {
		case !p.Available:
			class, reasons = ClassUnavailable, append(reasons, ReasonItemUnavailable)
		case len(ev.required) > 0:
			class, reasons = ClassMissingRequiredOptions, append(append(reasons, ev.required...), ev.dropped...)
		case len(ev.dropped) > 0:
			class, reasons = ClassCandidate, append(reasons, ev.dropped...)
		}
		reasons = uniqSorted(reasons)
		if intersects(tags, exclude) {
			reasons = uniqSorted(append(reasons, ReasonExcludedCategory))
			in.Excluded = append(in.Excluded, Excluded{HistoricalProductID: h.ProductID, Name: h.Name, Quantity: h.Quantity,
				Class: class, Reasons: reasons, CandidateProductIDs: candidateIDs(m, p)})
			continue
		}
		delta := int64(0)
		if samePriceBasis {
			delta = ev.unitPrice - h.UnitPriceMinor
		}
		switch class {
		case ClassExact:
			in.Lines = append(in.Lines, Line{ProductID: p.ID, Name: p.Name, Quantity: h.Quantity, Options: ev.kept,
				UnitPriceMinor: ev.unitPrice, LineTotalMinor: ev.unitPrice * h.Quantity,
				HistoricalUnitPriceMinor: h.UnitPriceMinor, PriceDeltaMinor: delta})
		case ClassCandidate:
			if reasons == nil {
				reasons = []string{}
			}
			in.Substitutions = append(in.Substitutions, Substitution{HistoricalProductID: h.ProductID, HistoricalName: h.Name,
				CandidateProductID: p.ID, CandidateName: p.Name, Quantity: h.Quantity, Options: ev.kept,
				UnitPriceMinor: ev.unitPrice, HistoricalUnitPriceMinor: h.UnitPriceMinor, PriceDeltaMinor: delta,
				ScorePermille: m.score, Reasons: reasons})
		default:
			in.Excluded = append(in.Excluded, Excluded{HistoricalProductID: h.ProductID, Name: h.Name, Quantity: h.Quantity,
				Class: class, Reasons: reasons, CandidateProductIDs: candidateIDs(m, p)})
		}
	}

	// Budget: lines are already in canonical order; keep each line that
	// still fits, move the rest to Excluded. Greedy and order-independent.
	if budget := in.Constraints.MaxBudgetMinor; budget > 0 {
		kept := []Line{}
		var running int64
		for _, l := range in.Lines {
			if running+l.LineTotalMinor > budget {
				in.Excluded = append(in.Excluded, Excluded{HistoricalProductID: l.ProductID, Name: l.Name, Quantity: l.Quantity,
					Class: ClassExact, Reasons: []string{ReasonOverBudget}, CandidateProductIDs: []string{l.ProductID}})
				continue
			}
			running += l.LineTotalMinor
			kept = append(kept, l)
		}
		in.Lines = kept
	}
	for _, l := range in.Lines {
		in.EstimatedSubtotalMinor += l.LineTotalMinor
		in.HistoricalSubtotalMinor += l.HistoricalUnitPriceMinor * l.Quantity
	}
	if samePriceBasis {
		in.PriceDeltaMinor = in.EstimatedSubtotalMinor - in.HistoricalSubtotalMinor
	}
	if in.PriceDeltaMinor > 0 {
		warn[WarnPriceIncreased] = true
	}
	if len(in.Lines) == 0 {
		warn[WarnNothingToAdd] = true
	}
	if len(in.Substitutions) > 0 {
		warn[WarnSubstitutionsPending] = true
	}
	sort.SliceStable(in.Excluded, func(i, j int) bool {
		a, b := in.Excluded[i], in.Excluded[j]
		if a.HistoricalProductID != b.HistoricalProductID {
			return a.HistoricalProductID < b.HistoricalProductID
		}
		return strings.Join(a.Reasons, ",") < strings.Join(b.Reasons, ",")
	})
	for w := range warn {
		in.Warnings = append(in.Warnings, w)
	}
	sort.Strings(in.Warnings)

	d, _, err := in.Canonical()
	if err != nil {
		return Intent{}, err
	}
	in.Digest = d
	return in, nil
}

func candidateIDs(m match, p gp.Product) []string {
	if len(m.candidates) > 0 {
		return m.candidates
	}
	return []string{p.ID}
}

func excluded(h histLine, class Class, reasons, candidates, exclude []string) Excluded {
	if intersects(h.Tags, exclude) {
		reasons = append(append([]string(nil), reasons...), ReasonExcludedCategory)
	}
	reasons = uniqSorted(reasons)
	if reasons == nil {
		reasons = []string{}
	}
	if candidates == nil {
		candidates = []string{}
	}
	return Excluded{HistoricalProductID: h.ProductID, Name: h.Name, Quantity: h.Quantity, Class: class,
		Reasons: reasons, CandidateProductIDs: candidates}
}
