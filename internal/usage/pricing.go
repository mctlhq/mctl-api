// Copyright 2025 MCTL Authors
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

package usage

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Pricing is one versioned rate card for one model, valid from EffectiveFrom
// until superseded by a later entry for the same model.
//
// Rates are US dollars per million tokens, which is how providers publish
// them; storing them in the published unit keeps a rate card reviewable against
// the provider's page without arithmetic.
type Pricing struct {
	Version           string    `json:"version"`
	CanonicalModel    string    `json:"canonical_model"`
	Provider          string    `json:"provider,omitempty"`
	EffectiveFrom     time.Time `json:"effective_from"`
	InputPerMTok      float64   `json:"input_per_mtok"`
	OutputPerMTok     float64   `json:"output_per_mtok"`
	CacheReadPerMTok  float64   `json:"cache_read_per_mtok"`
	CacheWritePerMTok float64   `json:"cache_write_per_mtok"`
	WebSearchPerCall  float64   `json:"web_search_per_call"`
}

// Catalog resolves a model and an instant to the rate card that was in force.
//
// Resolution is by instant, not by "current", because ADR-012 invariant 7 says
// a price-table change must not alter any stored calculated_cost. This catalog
// is only ever consulted at ingest; the resulting number and the Version that
// produced it are then stored on the row. Adding a later rate card cannot reach
// back and change history, and re-deriving a historical cost picks the card
// that was effective then rather than the newest one.
type Catalog struct {
	// byModel holds entries sorted by EffectiveFrom ascending.
	byModel map[string][]Pricing
}

// NewCatalog builds a catalog from a flat list of rate cards.
func NewCatalog(entries []Pricing) (*Catalog, error) {
	c := &Catalog{byModel: make(map[string][]Pricing)}
	for _, e := range entries {
		if strings.TrimSpace(e.Version) == "" {
			return nil, fmt.Errorf("%w: pricing entry for %q has no version", ErrInvalidRecord, e.CanonicalModel)
		}
		if strings.TrimSpace(e.CanonicalModel) == "" {
			return nil, fmt.Errorf("%w: pricing version %q has no canonical_model", ErrInvalidRecord, e.Version)
		}
		if e.EffectiveFrom.IsZero() {
			return nil, fmt.Errorf("%w: pricing version %q has no effective_from", ErrInvalidRecord, e.Version)
		}
		k := pricingKey(e.CanonicalModel)
		c.byModel[k] = append(c.byModel[k], e)
	}
	for k := range c.byModel {
		list := c.byModel[k]
		sort.Slice(list, func(i, j int) bool { return list[i].EffectiveFrom.Before(list[j].EffectiveFrom) })
		c.byModel[k] = list
	}
	return c, nil
}

func pricingKey(model string) string { return strings.ToLower(strings.TrimSpace(model)) }

// At returns the rate card in force for model at instant t.
func (c *Catalog) At(model string, t time.Time) (Pricing, bool) {
	if c == nil {
		return Pricing{}, false
	}
	list := c.byModel[pricingKey(model)]
	var found Pricing
	var ok bool
	for _, e := range list {
		if e.EffectiveFrom.After(t) {
			break
		}
		found, ok = e, true
	}
	return found, ok
}

// Calculate fills CalculatedCost and PricingVersion on r from the catalog.
//
// Absent counters contribute nothing rather than zero. That is not the same
// statement: a model whose cache tokens are unreported yields a cost over the
// dimensions that ARE reported, and the record still says the cache figure was
// never measured. Callers that need "this number covers every dimension" must
// read the token fields, which is why they stay on the row.
//
// A record that already carries a ProviderReportedCost is left alone —
// ADR-012 forbids overwriting a reported cost with an estimate.
func (c *Catalog) Calculate(r *Record) error {
	if r.ProviderReportedCost != nil {
		return nil
	}
	model := r.CanonicalModel
	if model == "" {
		model = r.ModelKey
	}
	p, ok := c.At(model, r.RecordedAt)
	if !ok {
		return fmt.Errorf("%w: %s at %s", ErrNoPricing, model, r.RecordedAt.Format(time.RFC3339))
	}
	perMTok := func(n *int64, rate float64) float64 {
		if n == nil {
			return 0
		}
		return float64(*n) / 1_000_000 * rate
	}
	total := perMTok(r.InputTokens, p.InputPerMTok) +
		perMTok(r.OutputTokens, p.OutputPerMTok) +
		perMTok(r.CacheReadTokens, p.CacheReadPerMTok) +
		perMTok(r.CacheWriteTokens, p.CacheWritePerMTok)
	if r.WebSearchRequests != nil {
		total += float64(*r.WebSearchRequests) * p.WebSearchPerCall
	}
	r.CalculatedCost = &total
	r.PricingVersion = p.Version
	return nil
}
