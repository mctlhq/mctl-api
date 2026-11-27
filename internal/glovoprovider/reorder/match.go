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
	"sort"
	"strings"
	"unicode"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// Matching is conservative on purpose:
//
//   - Only the same product id with the same normalized name is an exact
//     match. Nothing found by name similarity is ever accepted automatically,
//     however high its score.
//   - A name candidate must score at least CandidateThresholdPermille (token
//     Jaccard similarity, in thousandths). Below it the line is not matched.
//   - If the second-best candidate is within AmbiguityMarginPermille of the
//     best, the line is ambiguous and lists every candidate in the margin.
const (
	CandidateThresholdPermille = 600
	AmbiguityMarginPermille    = 100
)

// normalize lowercases a name and keeps letters and digits as tokens.
func normalize(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func sameName(a, b string) bool {
	return strings.Join(normalize(a), " ") == strings.Join(normalize(b), " ")
}

// similarity is the token-set Jaccard index of two names, in thousandths.
func similarity(a, b string) int64 {
	sa, sb := map[string]bool{}, map[string]bool{}
	for _, t := range normalize(a) {
		sa[t] = true
	}
	for _, t := range normalize(b) {
		sb[t] = true
	}
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	inter := 0
	for t := range sa {
		if sb[t] {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	return int64(inter * 1000 / union)
}

type match struct {
	product    *gp.Product
	class      Class
	reasons    []string
	score      int64
	candidates []string
}

// matchProduct finds the current product for a historical line.
func matchProduct(h histLine, c gp.Catalog) match {
	if p, ok := c.Product(h.ProductID); ok {
		if sameName(p.Name, h.Name) {
			return match{product: &p, class: ClassExact, score: 1000}
		}
		return match{product: &p, class: ClassCandidate, reasons: []string{ReasonProductRenamed}, score: similarity(p.Name, h.Name)}
	}
	type scored struct {
		id    string
		score int64
	}
	var cands []scored
	for _, p := range c.Products {
		if s := similarity(p.Name, h.Name); s >= CandidateThresholdPermille {
			cands = append(cands, scored{p.ID, s})
		}
	}
	if len(cands) == 0 {
		return match{class: ClassUnavailable, reasons: []string{ReasonNotFound}}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].id < cands[j].id
	})
	best := cands[0]
	if len(cands) > 1 && best.score-cands[1].score < AmbiguityMarginPermille {
		ids := []string{}
		for _, cd := range cands {
			if best.score-cd.score < AmbiguityMarginPermille {
				ids = append(ids, cd.id)
			}
		}
		sort.Strings(ids)
		return match{class: ClassAmbiguous, reasons: []string{ReasonTie}, candidates: ids, score: best.score}
	}
	p, _ := c.Product(best.id)
	return match{product: &p, class: ClassCandidate, reasons: []string{ReasonProductIDChanged}, score: best.score, candidates: []string{best.id}}
}

// optionEval is the result of checking past options against a product now.
type optionEval struct {
	kept      []OptionRef
	dropped   []string // reasons for optional selections that no longer apply
	required  []string // reasons a required group cannot be satisfied
	unitPrice int64
}

// evalOptions checks selected options against p's current option groups.
func evalOptions(p gp.Product, selected []OptionRef) optionEval {
	ev := optionEval{unitPrice: p.PriceMinor, kept: []OptionRef{}}
	groups := map[string]gp.OptionGroup{}
	for _, g := range p.OptionGroups {
		groups[g.ID] = g
	}
	count := map[string]int{}
	for _, s := range selected {
		g, ok := groups[s.GroupID]
		if !ok {
			ev.dropped = append(ev.dropped, ReasonOptionRemoved)
			continue
		}
		var opt *gp.Option
		for i := range g.Options {
			if g.Options[i].ID == s.OptionID {
				opt = &g.Options[i]
				break
			}
		}
		switch {
		case opt == nil:
			ev.dropped = append(ev.dropped, ReasonOptionRemoved)
		case !opt.Available:
			ev.dropped = append(ev.dropped, ReasonOptionUnavailable)
		default:
			ev.kept = append(ev.kept, s)
			ev.unitPrice += opt.PriceDeltaMinor
			count[g.ID]++
		}
	}
	for _, g := range p.OptionGroups {
		n := count[g.ID]
		switch {
		case n > g.Max:
			ev.required = append(ev.required, ReasonOptionBounds)
		case n < g.Min:
			ev.required = append(ev.required, ReasonRequiredOptionMissing)
		}
	}
	ev.dropped = uniqSorted(ev.dropped)
	ev.required = uniqSorted(ev.required)
	return ev
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	s := append([]string(nil), in...)
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
