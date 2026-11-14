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

package glovobasket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// MaxItemNameBytes bounds the display name of one snapshot line.
const MaxItemNameBytes = 200

// Snapshot is the frozen content of one basket revision as an approval
// stores it: the canonical form, the fingerprint computed here from it, and
// the priced lines the owner is shown. Build one with FreezeSnapshot; a
// Snapshot is never assembled from a fingerprint someone else computed.
type Snapshot struct {
	Canonical   []byte
	Fingerprint string
	Lines       []Line
	Totals      Totals
	StoreRef    string
}

// FreezeSnapshot parses raw as an approval basket (mctl-approval-basket/v1,
// the vendored schema, no extra field, sorted unique lines, exact
// arithmetic), canonicalizes it and computes the fingerprint from the
// canonical bytes. names gives the display name of every item code; a line
// without one, a name for an item that is not in the basket, or an empty,
// oversized or non-UTF-8 name is invalid. Every failure is a refusal of the
// input (IsInvalid).
func FreezeSnapshot(raw []byte, names map[string]string) (Snapshot, error) {
	a, canonical, err := basket.Parse(raw)
	if err != nil {
		if errors.Is(err, basket.ErrInvalid) {
			return Snapshot{}, invalidf("basket is not a valid approval basket")
		}
		return Snapshot{}, fmt.Errorf("glovo basket: parse snapshot: %w", err)
	}
	if len(a.Lines) > MaxLines {
		return Snapshot{}, invalidf("a basket holds at most %d lines", MaxLines)
	}
	if len(names) != len(a.Lines) {
		return Snapshot{}, invalidf("item_names must name every line and nothing else")
	}
	s := Snapshot{Canonical: canonical, Fingerprint: basket.Fingerprint(canonical), StoreRef: a.StoreRef,
		Lines: make([]Line, 0, len(a.Lines)),
		Totals: Totals{Currency: a.Currency, SubtotalMinor: a.SubtotalMinor, DeliveryFeeMinor: a.DeliveryFeeMinor,
			ServiceFeeMinor: a.ServiceFeeMinor, DiscountMinor: a.DiscountMinor, TotalMinor: a.TotalMinor}}
	for _, l := range a.Lines {
		name, ok := names[l.ItemCode]
		if !ok || name == "" || len(name) > MaxItemNameBytes || !utf8.ValidString(name) {
			return Snapshot{}, invalidf("item_names must name every line with 1 to %d bytes of UTF-8", MaxItemNameBytes)
		}
		s.Lines = append(s.Lines, Line{ItemCode: l.ItemCode, Name: name, Quantity: l.Quantity,
			UnitPriceMinor: l.UnitPriceMinor, LineTotalMinor: l.Quantity * l.UnitPriceMinor})
	}
	return s, nil
}

// ledgerSnapshot is the snapshot in the shape the ledger stores.
func ledgerSnapshot(canonical []byte, lines []Line) (*workitems.GlovoBasketSnapshot, error) {
	raw, err := json.Marshal(lines)
	if err != nil {
		return nil, fmt.Errorf("glovo basket: marshal snapshot lines: %w", err)
	}
	return &workitems.GlovoBasketSnapshot{Canonical: canonical, Lines: raw}, nil
}

// writesSnapshots reports whether this store writes the binding snapshot
// itself: only against basket schema version 2 or later, which has the
// columns.
func (s *PGStore) writesSnapshots() bool { return s.SchemaVersion >= 2 }

// SnapshotApprovalInput is an approval request that arrives with the
// revision's content instead of reading it from basket_revisions: the basket
// service's join call. BasketFingerprint, when set, is only compared with
// the fingerprint computed from Snapshot; it is never stored.
type SnapshotApprovalInput struct {
	BasketID          string
	Revision          int64
	Snapshot          Snapshot
	BasketFingerprint string
}

// RequestApprovalFromSnapshot creates (or returns) the pending approval of
// one revision of the owner's basket from a snapshot frozen by
// FreezeSnapshot. The owner is the resolved caller, never an input. The
// stored fingerprint is the one computed from the snapshot; a caller-sent
// fingerprint that differs is fingerprint_changed and nothing is written.
// While the binding's foreign key into basket_revisions exists, a revision
// that is not the owner's, or whose stored fingerprint differs, is
// fingerprint_changed too. It needs basket schema version 2 (not_ready
// otherwise): an approval created here must carry its snapshot.
func (s *PGStore) RequestApprovalFromSnapshot(ctx context.Context, o Owner, in SnapshotApprovalInput, ttl time.Duration) (*ApprovalRequest, error) {
	if !s.writesSnapshots() {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	snap := in.Snapshot
	if len(snap.Canonical) == 0 || len(snap.Lines) == 0 || snap.Fingerprint != basket.Fingerprint(snap.Canonical) {
		return nil, glovo.Refuse(glovo.CodeInvalidRequest)
	}
	if in.BasketFingerprint != "" && in.BasketFingerprint != snap.Fingerprint {
		return nil, glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	if !workitems.GlovoBasketIDRE.MatchString(in.BasketID) || in.Revision < 1 {
		return nil, glovo.Refuse(glovo.CodeInvalidRequest)
	}
	ls, err := ledgerSnapshot(snap.Canonical, snap.Lines)
	if err != nil {
		return nil, unavailable("snapshot", err)
	}
	var out *ApprovalRequest
	err = s.inTx(ctx, "request approval from snapshot", func(tx pgx.Tx) error {
		a, created, err := workitems.CreateGlovoBasketApprovalTx(ctx, tx, workitems.GlovoBasketApprovalInput{
			Tenant: o.Tenant, OwnerPrincipalID: o.PrincipalID, BasketID: in.BasketID, Revision: in.Revision,
			BasketFingerprint: snap.Fingerprint, ExpiresIn: ttl, Snapshot: ls})
		if errors.Is(err, workitems.ErrGlovoBasketRevisionUnknown) {
			return glovo.Refuse(glovo.CodeFingerprintChanged)
		}
		if err != nil {
			return mapApprovalErr(err)
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return unavailable("read clock", err)
		}
		out = &ApprovalRequest{ApprovalRef: a.ID, BasketID: in.BasketID, Revision: in.Revision, Fingerprint: snap.Fingerprint,
			State: workitems.GlovoBasketReceiptState(a.State, a.ExpiresAt, a.FreshUntil, now), ExpiresAt: a.ExpiresAt.UTC(), Created: created}
		return nil
	})
	return out, err
}
