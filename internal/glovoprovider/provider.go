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

// Package glovoprovider is the provider-neutral contract of the Glovo
// real-provider direction (mctl-api#1006): the read interface that both the
// synthetic fixture provider and a future live adapter implement, a separate
// and unwired write interface, the minimized read model and the typed errors
// that keep "could not observe" apart from "observed absent". Nothing in this
// package performs network I/O, and no route, tool or startup path uses it.
// See docs/glovo-provider-contract.md.
package glovoprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/jcs"
)

// Read operation names, used in errors and by the synthetic provider's
// failure knobs.
const (
	OpLocation     = "location"
	OpStores       = "stores"
	OpCatalog      = "catalog"
	OpSearch       = "search"
	OpProduct      = "product"
	OpOrderHistory = "order_history"
	OpOrder        = "order"
	OpCart         = "cart"
	OpApplyCart    = "apply_cart"
)

// Provider is the read side. Every method either returns a complete
// observation or an error whose kind is ErrUnobserved, ErrAbsent,
// ErrNotSupported or ErrInvalidRequest. An implementation never turns a
// failed or partial read into an empty slice: an empty slice with a nil error
// means the provider positively reported "none".
type Provider interface {
	// Location returns the coarse delivery context of the session.
	Location(ctx context.Context) (LocationContext, error)
	// Stores lists stores available at the location. Limit is 1..50.
	Stores(ctx context.Context, q StoreQuery) ([]StoreSummary, error)
	// Catalog returns the current menu of one store. ErrAbsent: the store
	// does not exist or no longer serves the location.
	Catalog(ctx context.Context, storeID string) (Catalog, error)
	// Search returns at most limit (1..50) products of one store whose name
	// matches query.
	Search(ctx context.Context, storeID, query string, limit int) ([]Product, error)
	// Product returns one product with its options, price and availability.
	Product(ctx context.Context, storeID, productID string) (Product, error)
	// OrderHistory returns at most q.Limit (1..MaxHistoryOrders) order
	// summaries, newest first.
	OrderHistory(ctx context.Context, q HistoryQuery) ([]OrderSummary, error)
	// Order returns one past order with its lines.
	Order(ctx context.Context, orderID string) (HistoricalOrder, error)
	// Cart returns the current provider cart. An empty cart is a snapshot
	// with no lines.
	Cart(ctx context.Context) (CartSnapshot, error)
}

// MaxListLimit bounds Stores and Search.
const MaxListLimit = 50

// CartWriter is the gated write side. Nothing in this change wires it, and
// the synthetic provider returns ErrNotSupported. A live implementation must
// follow this order and no other:
//
//  1. reread the provider cart and compare its fingerprint with
//     ExpectedCartFingerprint; a mismatch is WritePreconditionFailed;
//  2. verify that ApprovalGrantRef is a live human approval bound to
//     IntentDigest (outside this package, by the approval service);
//  3. write the cart once;
//  4. reread the cart;
//  5. reconcile: the reread content must equal the requested lines.
//
// A write whose outcome is not known (timeout, dropped connection, malformed
// response) ends in WriteReconcileUnknown. From there the only way forward is
// another read; the write is never retried blindly, because a retry of a
// write that did land doubles the effect.
type CartWriter interface {
	ApplyCart(ctx context.Context, req ApplyCartRequest) (ApplyCartResult, error)
}

// ApplyCartRequest is one gated cart write.
type ApplyCartRequest struct {
	ExpectedCartFingerprint string     `json:"expected_cart_fingerprint"`
	IntentDigest            string     `json:"intent_digest"`
	ApprovalGrantRef        string     `json:"approval_grant_ref"`
	StoreID                 string     `json:"store_id"`
	Lines                   []CartLine `json:"lines"`
}

// Validate refuses a request that lacks any of the three binding values.
// It does not prove the grant; that is the approval service's job.
func (r ApplyCartRequest) Validate() error {
	switch {
	case !strings.HasPrefix(r.ExpectedCartFingerprint, "sha256:"):
		return Invalid(OpApplyCart, "expected_cart_fingerprint")
	case !strings.HasPrefix(r.IntentDigest, "sha256:"):
		return Invalid(OpApplyCart, "intent_digest")
	case r.ApprovalGrantRef == "":
		return Invalid(OpApplyCart, "approval_grant_ref")
	case r.StoreID == "" || len(r.Lines) == 0:
		return Invalid(OpApplyCart, "lines")
	}
	return nil
}

// ApplyCartResult reports the terminal state of one write attempt.
type ApplyCartResult struct {
	State           WriteState `json:"state"`
	CartFingerprint string     `json:"cart_fingerprint,omitempty"`
}

// WriteState is the state of the gated write protocol.
type WriteState string

// Write protocol states.
const (
	WritePlanned            WriteState = "planned"
	WriteCartReread         WriteState = "cart_reread"
	WriteGrantVerified      WriteState = "grant_verified"
	WriteInFlight           WriteState = "writing"
	WriteVerifyReread       WriteState = "verify_reread"
	WriteReconciled         WriteState = "reconciled"
	WritePreconditionFailed WriteState = "precondition_failed"
	WriteMismatch           WriteState = "reconcile_mismatch"
	WriteReconcileUnknown   WriteState = "reconcile_unknown"
)

var writeTransitions = map[WriteState][]WriteState{
	WritePlanned:       {WriteCartReread},
	WriteCartReread:    {WriteGrantVerified, WritePreconditionFailed, WriteReconcileUnknown},
	WriteGrantVerified: {WriteInFlight, WritePreconditionFailed},
	WriteInFlight:      {WriteVerifyReread, WriteReconcileUnknown},
	WriteVerifyReread:  {WriteReconciled, WriteMismatch, WriteReconcileUnknown},
	// From an unknown outcome only a read may follow, never a write.
	WriteReconcileUnknown: {WriteVerifyReread},
}

// CanTransition reports whether the write protocol allows from -> to.
// Terminal states (reconciled, precondition_failed, reconcile_mismatch) allow
// nothing; a new attempt starts from a new plan and a new approval.
func CanTransition(from, to WriteState) bool {
	for _, s := range writeTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Digest is "sha256:" + hex(sha256(JCS(json(v)))), the same construction as
// the basket fingerprint (internal/glovo/basket), over the RFC 8785 form
// produced by internal/jcs. v must hold no floating-point values.
func Digest(v any) (string, []byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", nil, fmt.Errorf("glovoprovider: marshal: %w", err)
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", nil, fmt.Errorf("glovoprovider: canonicalize: %w", err)
	}
	return basket.Fingerprint(canonical), canonical, nil
}

// OptionKey is the order-independent key of a set of (group, option) pairs.
func OptionKey(opts []CartOption) string {
	keys := make([]string, 0, len(opts))
	for _, o := range opts {
		keys = append(keys, o.GroupID+"="+o.OptionID)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// CartFingerprint is the Digest of the observed cart content (store,
// currency, lines in a canonical order, options sorted). The provider's
// Version and the Fingerprint field itself are not part of it, so two reads
// of the same content agree regardless of line order.
func CartFingerprint(c CartSnapshot) (string, error) {
	lines := make([]CartLine, len(c.Lines))
	for i, l := range c.Lines {
		opts := append([]CartOption(nil), l.Options...)
		sort.Slice(opts, func(a, b int) bool {
			if opts[a].GroupID != opts[b].GroupID {
				return opts[a].GroupID < opts[b].GroupID
			}
			return opts[a].OptionID < opts[b].OptionID
		})
		l.Options = opts
		lines[i] = l
	}
	sort.Slice(lines, func(a, b int) bool {
		if lines[a].ProductID != lines[b].ProductID {
			return lines[a].ProductID < lines[b].ProductID
		}
		return OptionKey(lines[a].Options) < OptionKey(lines[b].Options)
	})
	body := struct {
		V        string     `json:"v"`
		StoreID  string     `json:"store_id"`
		Currency string     `json:"currency"`
		Lines    []CartLine `json:"lines"`
	}{"mctl-provider-cart/v1", c.StoreID, c.Currency, lines}
	d, _, err := Digest(body)
	return d, err
}
