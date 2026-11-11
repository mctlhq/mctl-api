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

// Package reorder is the Reorder Planning Engine: it turns one past order and
// the current catalog into a read-only BasketIntent. Build and Revalidate are
// pure and deterministic; only Gather, Plan and RevalidateFrom read through a
// glovoprovider.Provider. Nothing here writes a cart: an intent is what a
// human approves, and applying it is a separate, gated step
// (glovoprovider.CartWriter) that this package never calls.
package reorder

import (
	"errors"
	"fmt"
	"time"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// IntentVersion is the "v" of every intent this package produces.
const IntentVersion = "mctl-reorder-intent/v1"

// Class is the classification of one historical line.
type Class string

// Line classes.
const (
	// ClassExact: same product id and name, available, every past option
	// still offered. The only class that is added to the intent's lines.
	ClassExact Class = "exact_match"
	// ClassCandidate: a single plausible replacement (renamed product, new id
	// with a matching name, or a dropped optional modifier). Never added; it
	// is proposed as a substitution for the user to confirm.
	ClassCandidate Class = "candidate_match_requires_confirmation"
	// ClassUnavailable: no match, or the match is not orderable now.
	ClassUnavailable Class = "unavailable"
	// ClassAmbiguous: two or more candidates within the ambiguity margin.
	ClassAmbiguous Class = "ambiguous"
	// ClassMissingRequiredOptions: the product now needs a choice the past
	// order cannot supply.
	ClassMissingRequiredOptions Class = "missing_required_options"
)

// Reason codes attached to lines and changes. They are fixed strings, never
// provider text.
const (
	ReasonNotFound              = "not_found"
	ReasonItemUnavailable       = "item_unavailable"
	ReasonStoreUnavailable      = "store_unavailable"
	ReasonProductIDChanged      = "product_id_changed"
	ReasonProductRenamed        = "product_renamed"
	ReasonOptionRemoved         = "option_removed"
	ReasonOptionUnavailable     = "option_unavailable"
	ReasonRequiredOptionMissing = "required_option_missing"
	ReasonOptionBounds          = "option_bounds"
	ReasonTie                   = "tie"
	ReasonExcludedCategory      = "excluded_category"
	ReasonOverBudget            = "over_budget"
)

// Warning codes on an intent.
const (
	WarnStoreClosed          = "store_closed"
	WarnStoreUnavailable     = "store_unavailable"
	WarnNativeReorderOff     = "native_reorder_unavailable_manual_reconstruction"
	WarnCartNotEmpty         = "cart_not_empty"
	WarnCartOtherStore       = "cart_holds_other_store"
	WarnPriceIncreased       = "price_increased"
	WarnCurrencyMismatch     = "currency_mismatch_price_delta_unknown"
	WarnFeesNotEstimated     = "fees_not_estimated"
	WarnNothingToAdd         = "nothing_to_add"
	WarnSubstitutionsPending = "substitutions_need_confirmation"
)

// OptionRef is a selected modifier on an intent line.
type OptionRef struct {
	GroupID  string `json:"group_id"`
	OptionID string `json:"option_id"`
}

// Line is one line the intent proposes to put in the cart.
type Line struct {
	ProductID                string      `json:"product_id"`
	Name                     string      `json:"name"`
	Quantity                 int64       `json:"quantity"`
	Options                  []OptionRef `json:"options"`
	UnitPriceMinor           int64       `json:"unit_price_minor"`
	LineTotalMinor           int64       `json:"line_total_minor"`
	HistoricalUnitPriceMinor int64       `json:"historical_unit_price_minor"`
	PriceDeltaMinor          int64       `json:"unit_price_delta_minor"`
}

// Substitution is a candidate the user must confirm before it may be added.
type Substitution struct {
	HistoricalProductID      string      `json:"historical_product_id"`
	HistoricalName           string      `json:"historical_name"`
	CandidateProductID       string      `json:"candidate_product_id"`
	CandidateName            string      `json:"candidate_name"`
	Quantity                 int64       `json:"quantity"`
	Options                  []OptionRef `json:"options"`
	UnitPriceMinor           int64       `json:"unit_price_minor"`
	HistoricalUnitPriceMinor int64       `json:"historical_unit_price_minor"`
	PriceDeltaMinor          int64       `json:"unit_price_delta_minor"`
	ScorePermille            int64       `json:"score_permille"`
	Reasons                  []string    `json:"reasons"`
}

// Excluded is a historical line that the intent does not add, with why.
type Excluded struct {
	HistoricalProductID string   `json:"historical_product_id"`
	Name                string   `json:"name"`
	Quantity            int64    `json:"quantity"`
	Class               Class    `json:"class"`
	Reasons             []string `json:"reasons"`
	CandidateProductIDs []string `json:"candidate_product_ids"`
}

// Constraints are the user's limits on a reconstruction.
type Constraints struct {
	// ExcludeCategoryTags drops every line whose category carries one of
	// these tags (for example "drinks").
	ExcludeCategoryTags []string `json:"exclude_category_tags"`
	// MaxBudgetMinor caps the estimated subtotal of added lines; 0 is no cap.
	MaxBudgetMinor int64 `json:"max_budget_minor"`
}

// Intent is the read-only BasketIntent. Its Digest binds every other field
// in RFC 8785 form; an approval grant names the digest, and any change to the
// intent (or a reconstruction against a changed catalog) is a new digest
// that needs a new approval.
type Intent struct {
	V                       string         `json:"v"`
	SourceOrderID           string         `json:"source_order_id"`
	StoreID                 string         `json:"store_id"`
	Currency                string         `json:"currency"`
	CreatedAt               string         `json:"created_at"`
	ExpiresAt               string         `json:"expires_at"`
	NativeReorderAllowed    bool           `json:"native_reorder_allowed"`
	Constraints             Constraints    `json:"constraints"`
	CartFingerprint         string         `json:"cart_fingerprint"`
	Lines                   []Line         `json:"lines"`
	Substitutions           []Substitution `json:"substitutions"`
	Excluded                []Excluded     `json:"excluded"`
	EstimatedSubtotalMinor  int64          `json:"estimated_subtotal_minor"`
	HistoricalSubtotalMinor int64          `json:"historical_subtotal_minor"`
	PriceDeltaMinor         int64          `json:"price_delta_minor"`
	Warnings                []string       `json:"warnings"`
	Digest                  string         `json:"digest,omitempty"`
}

// ErrDigestMismatch: the intent was changed after it was built.
var ErrDigestMismatch = errors.New("reorder: intent digest mismatch")

// Canonical returns the RFC 8785 bytes the digest is computed over (the
// intent without its Digest field) and that digest.
func (in Intent) Canonical() (digest string, canonical []byte, err error) {
	in.Digest = ""
	return gp.Digest(in)
}

// VerifyDigest recomputes the digest and compares it with in.Digest.
func (in Intent) VerifyDigest() error {
	d, _, err := in.Canonical()
	if err != nil {
		return err
	}
	if d != in.Digest {
		return ErrDigestMismatch
	}
	return nil
}

// Expired reports whether now is at or past the intent's expiry. An
// unparsable expiry counts as expired.
func (in Intent) Expired(now time.Time) bool {
	exp, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		return true
	}
	return !now.Before(exp)
}

func errUnobserved(what string) error {
	return fmt.Errorf("reorder: %s: %w", what, gp.ErrUnobserved)
}
