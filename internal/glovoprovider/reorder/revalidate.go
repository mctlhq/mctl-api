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
	"sort"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// Verdict is the outcome of revalidating an intent against a fresh read.
type Verdict string

// Verdicts. Only VerdictUnchanged lets an existing approval stand; every
// other verdict requires a new plan and a new human approval.
const (
	VerdictUnchanged Verdict = "unchanged"
	// VerdictMaterialChange: something the human approved is different now.
	VerdictMaterialChange Verdict = "material_change"
	// VerdictExpired: the intent outlived its ExpiresAt.
	VerdictExpired Verdict = "expired"
	// VerdictUnknown: the provider could not be observed, so "unchanged"
	// cannot be claimed. It is never reported as unchanged.
	VerdictUnknown Verdict = "unknown"
	// VerdictTampered: the intent no longer matches its own digest.
	VerdictTampered Verdict = "tampered"
)

// ChangeKind classifies one material change.
type ChangeKind string

// Change kinds.
const (
	ChangePrice        ChangeKind = "price"
	ChangeAvailability ChangeKind = "availability"
	ChangeOption       ChangeKind = "option"
	ChangeItemRemoved  ChangeKind = "item_removed"
	ChangeCartState    ChangeKind = "cart_state"
	ChangeStore        ChangeKind = "store"
	ChangeCurrency     ChangeKind = "currency"
	// ChangeRenamed: the approved product id now carries another name, so
	// it may be a different item.
	ChangeRenamed ChangeKind = "renamed"
	// ChangeExcludedCategory: the product moved into a category the user
	// excluded.
	ChangeExcludedCategory ChangeKind = "excluded_category"
)

// Change is one material difference.
type Change struct {
	ProductID string     `json:"product_id,omitempty"`
	Kind      ChangeKind `json:"kind"`
}

// Result of a revalidation.
type Result struct {
	Verdict             Verdict  `json:"verdict"`
	RequiresNewApproval bool     `json:"requires_new_approval"`
	Changes             []Change `json:"changes"`
}

func result(v Verdict, changes []Change) Result {
	if changes == nil {
		changes = []Change{}
	}
	return Result{Verdict: v, RequiresNewApproval: v != VerdictUnchanged, Changes: changes}
}

// Revalidate compares an approved intent with a fresh snapshot. It is pure.
// Precedence: tampered, expired, unknown (could not observe), then material
// change. Excluded lines are not compared: they are not part of what the
// human approved.
func Revalidate(in Intent, snap Snapshot, now time.Time) Result {
	if r, done := precheck(in, now); done {
		return r
	}
	if snap.Cart == nil || (snap.Catalog == nil && !snap.StoreAbsent) {
		return result(VerdictUnknown, nil)
	}
	cartFP, ok := observedCartFingerprint(snap.Cart)
	if !ok {
		return result(VerdictUnknown, nil)
	}
	var changes []Change
	if cartFP != in.CartFingerprint {
		changes = append(changes, Change{Kind: ChangeCartState})
	}
	switch {
	case snap.StoreAbsent || snap.Catalog.StoreID != in.StoreID:
		changes = append(changes, Change{Kind: ChangeStore})
	case snap.Catalog.Currency != in.Currency:
		changes = append(changes, Change{Kind: ChangeCurrency})
	default:
		if !snap.Catalog.Open && !hasWarning(in, WarnStoreClosed) {
			changes = append(changes, Change{Kind: ChangeStore})
		}
		exclude := in.Constraints.ExcludeCategoryTags
		for _, l := range in.Lines {
			changes = append(changes, lineChanges(*snap.Catalog, exclude, l.ProductID, l.Name, l.Options, l.UnitPriceMinor)...)
		}
		for i := range in.Substitutions {
			s := &in.Substitutions[i]
			changes = append(changes, lineChanges(*snap.Catalog, exclude, s.CandidateProductID, s.CandidateName, s.Options, s.UnitPriceMinor)...)
		}
	}
	if len(changes) == 0 {
		return result(VerdictUnchanged, nil)
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].ProductID != changes[j].ProductID {
			return changes[i].ProductID < changes[j].ProductID
		}
		return changes[i].Kind < changes[j].Kind
	})
	return result(VerdictMaterialChange, changes)
}

func hasWarning(in Intent, w string) bool {
	for _, x := range in.Warnings {
		if x == w {
			return true
		}
	}
	return false
}

func lineChanges(c gp.Catalog, exclude []string, productID, name string, opts []OptionRef, unitPrice int64) []Change {
	p, ok := c.Product(productID)
	if !ok {
		return []Change{{ProductID: productID, Kind: ChangeItemRemoved}}
	}
	var out []Change
	if !sameName(p.Name, name) {
		out = append(out, Change{ProductID: productID, Kind: ChangeRenamed})
	}
	if cat, ok := c.Category(p.CategoryID); ok && intersects(lowerSet(cat.Tags), exclude) {
		out = append(out, Change{ProductID: productID, Kind: ChangeExcludedCategory})
	}
	if !p.Available {
		out = append(out, Change{ProductID: productID, Kind: ChangeAvailability})
	}
	ev := evalOptions(p, opts)
	if len(ev.dropped) > 0 || len(ev.required) > 0 {
		out = append(out, Change{ProductID: productID, Kind: ChangeOption})
	} else if ev.unitPrice != unitPrice {
		out = append(out, Change{ProductID: productID, Kind: ChangePrice})
	}
	return out
}

// RevalidateFrom reads a fresh snapshot through p and revalidates. A read
// that could not observe the provider yields VerdictUnknown, never
// VerdictUnchanged; other errors are returned.
func RevalidateFrom(ctx context.Context, p gp.Provider, in Intent, now time.Time) (Result, error) {
	if r, done := precheck(in, now); done {
		return r, nil
	}
	snap, err := Gather(ctx, p, in.StoreID)
	switch {
	case errors.Is(err, gp.ErrUnobserved):
		// Could not observe: reported as a verdict, never as unchanged.
		return result(VerdictUnknown, nil), nil //nolint:nilerr // the verdict carries the failure
	case err != nil:
		return Result{}, err
	}
	return Revalidate(in, snap, now), nil
}

// precheck decides the verdicts that need no provider read: a tampered or
// expired intent needs a new approval whatever the provider says now.
func precheck(in Intent, now time.Time) (Result, bool) {
	if in.VerifyDigest() != nil {
		return result(VerdictTampered, nil), true
	}
	if in.Expired(now) {
		return result(VerdictExpired, nil), true
	}
	return Result{}, false
}
