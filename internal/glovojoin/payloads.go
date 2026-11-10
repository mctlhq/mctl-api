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

package glovojoin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
)

// HistoryStoreName is the store name of a history row. The #1059 history
// payload carries no store, the pinned tool output requires one, and a wire
// field with no source must not be invented from provider data: this constant
// is the decided value (recorded as a deviation in the PR).
const HistoryStoreName = "Glovo"

// ErrPayload is a provider payload that does not match the #1059 schema. It is
// a dependency failure (unavailable), never an empty answer.
var ErrPayload = errors.New("glovojoin: read payload does not match the #1059 schema")

var (
	phoRE      = regexp.MustCompile(`^pho_[A-Za-z0-9]{16,40}$`)
	itemCodeRE = regexp.MustCompile(`^FAKE-[A-Z0-9-]{1,32}$`)
	itemNameRE = regexp.MustCompile(`^[A-Za-z0-9 .,'()-]{1,60}$`)
	cursorRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	dateRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)
)

func payloadErr(why string) error { return fmt.Errorf("%w: %s", ErrPayload, why) }

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return payloadErr("decode")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return payloadErr("trailing data")
	}
	return nil
}

// HistoryOrder is one wire history row (the pinned tool output).
type HistoryOrder struct {
	OrderRef   string `json:"order_ref"`
	StoreName  string `json:"store_name"`
	PlacedAt   string `json:"placed_at"`
	TotalLabel string `json:"total_label"`
	ItemCount  int    `json:"item_count"`
}

// HistoryView is a parsed history payload: the wire body and the refs the
// provider issued, which the caller records before answering.
type HistoryView struct {
	Orders     []HistoryOrder
	NextCursor string
}

// IssuedPho is the list of pho_ refs the view returned.
func (h HistoryView) IssuedPho() []string {
	out := make([]string, len(h.Orders))
	for i, o := range h.Orders {
		out[i] = o.OrderRef
	}
	return out
}

type historyPayload struct {
	Orders []struct {
		Ref        string `json:"history_order_ref"`
		PlacedOn   string `json:"placed_on"`
		Status     string `json:"status"`
		TotalMinor *int64 `json:"total_minor"`
		Currency   string `json:"currency"`
		LineCount  int    `json:"line_count"`
		Lines      []struct {
			ItemCode string `json:"item_code"`
			Quantity int    `json:"quantity"`
		} `json:"lines"`
	} `json:"orders"`
	NextCursor *string `json:"next_cursor"`
}

// ParseHistory validates a canonical read_history payload and maps it to the
// wire body: order_ref is the pho_ ref, placed_at is the placed_on date at
// 00:00:00Z, total_label is "<major>.<minor> <currency>" and item_count is
// line_count.
func ParseHistory(data []byte) (HistoryView, error) {
	var p historyPayload
	if err := strictDecode(data, &p); err != nil {
		return HistoryView{}, err
	}
	if p.Orders == nil || len(p.Orders) > 20 {
		return HistoryView{}, payloadErr("orders")
	}
	v := HistoryView{Orders: make([]HistoryOrder, 0, len(p.Orders))}
	seen := map[string]bool{}
	for _, o := range p.Orders {
		if !phoRE.MatchString(o.Ref) || seen[o.Ref] || !dateRE.MatchString(o.PlacedOn) || o.Status == "" ||
			o.TotalMinor == nil || *o.TotalMinor < 0 || *o.TotalMinor > 10000000 || !currencyRE.MatchString(o.Currency) ||
			o.LineCount < 1 || o.LineCount > 100 || len(o.Lines) < 1 || len(o.Lines) > 5 {
			return HistoryView{}, payloadErr("order")
		}
		seen[o.Ref] = true
		for _, l := range o.Lines {
			if !itemCodeRE.MatchString(l.ItemCode) || l.Quantity < 1 || l.Quantity > 100 {
				return HistoryView{}, payloadErr("line")
			}
		}
		day, err := time.Parse("2006-01-02", o.PlacedOn)
		if err != nil {
			return HistoryView{}, payloadErr("placed_on")
		}
		v.Orders = append(v.Orders, HistoryOrder{
			OrderRef: o.Ref, StoreName: HistoryStoreName, PlacedAt: day.UTC().Format(time.RFC3339),
			TotalLabel: moneyLabel(*o.TotalMinor, o.Currency), ItemCount: o.LineCount,
		})
	}
	if p.NextCursor != nil {
		if !cursorRE.MatchString(*p.NextCursor) {
			return HistoryView{}, payloadErr("next_cursor")
		}
		v.NextCursor = *p.NextCursor
	}
	return v, nil
}

func moneyLabel(minor int64, currency string) string {
	return fmt.Sprintf("%d.%02d %s", minor/100, minor%100, currency)
}

// Item is one wire item line.
type Item struct {
	Name     string `json:"name"`
	Quantity int64  `json:"quantity"`
}

type displayLine struct {
	ItemCode string `json:"item_code"`
	ItemName string `json:"item_name"`
}

// BasketView is a parsed preview or basket payload. Empty views carry no
// approval basket and an empty fingerprint: an empty read is shown, never
// fingerprinted, prepared or approved.
type BasketView struct {
	Empty bool
	// StoreName is present on a basket read only.
	StoreName string
	Items     []Item
	// Unavailable lists the codes the provider could not add (preview only),
	// as items of quantity 1 named by their code: the payload carries no name
	// or quantity for them.
	Unavailable []Item
	TotalsLabel string
	// Approval is the canonical approval basket bytes (nil when Empty), the
	// exact bytes the fingerprint covers and a preview row stores.
	Approval    []byte
	Fingerprint string
}

type basketPayload struct {
	Empty       *bool           `json:"empty"`
	StoreName   *string         `json:"store_name"`
	Display     []displayLine   `json:"display"`
	Unavailable *[]string       `json:"unavailable_items"`
	Approval    json.RawMessage `json:"approval_basket"`
}

// ParsePreview validates a canonical read_preview payload.
func ParsePreview(data []byte) (BasketView, error) { return parseBasketPayload(data, true) }

// ParseBasket validates a canonical read_basket payload.
func ParseBasket(data []byte) (BasketView, error) { return parseBasketPayload(data, false) }

func parseBasketPayload(data []byte, preview bool) (BasketView, error) {
	var p basketPayload
	if err := strictDecode(data, &p); err != nil {
		return BasketView{}, err
	}
	if p.Empty == nil || p.Display == nil || len(p.Display) > 30 {
		return BasketView{}, payloadErr("display")
	}
	if preview != (p.Unavailable != nil) {
		return BasketView{}, payloadErr("unavailable_items")
	}
	if !preview && p.StoreName != nil && !itemNameRE.MatchString(*p.StoreName) {
		return BasketView{}, payloadErr("store_name")
	}
	if preview && p.StoreName != nil {
		return BasketView{}, payloadErr("store_name")
	}
	v := BasketView{Empty: *p.Empty, Items: []Item{}, Unavailable: []Item{}}
	if p.StoreName != nil {
		v.StoreName = *p.StoreName
	}
	display := map[string]string{}
	for _, d := range p.Display {
		if !itemCodeRE.MatchString(d.ItemCode) || !itemNameRE.MatchString(d.ItemName) {
			return BasketView{}, payloadErr("display line")
		}
		if _, dup := display[d.ItemCode]; dup {
			return BasketView{}, payloadErr("display duplicate")
		}
		display[d.ItemCode] = d.ItemName
	}
	if p.Unavailable != nil {
		if len(*p.Unavailable) > 30 {
			return BasketView{}, payloadErr("unavailable_items")
		}
		for _, c := range *p.Unavailable {
			if !itemCodeRE.MatchString(c) {
				return BasketView{}, payloadErr("unavailable code")
			}
			if _, inBasket := display[c]; inBasket {
				return BasketView{}, payloadErr("unavailable overlaps the basket")
			}
			v.Unavailable = append(v.Unavailable, Item{Name: c, Quantity: 1})
		}
	}
	hasApproval := len(p.Approval) > 0 && !bytes.Equal(bytes.TrimSpace(p.Approval), []byte("null"))
	if *p.Empty {
		if hasApproval || len(p.Display) != 0 {
			return BasketView{}, payloadErr("empty with content")
		}
		if !preview {
			v.TotalsLabel = ""
		}
		return v, nil
	}
	if !hasApproval {
		return BasketView{}, payloadErr("non-empty without approval basket")
	}
	a, canonical, err := basket.Parse(p.Approval)
	if err != nil {
		return BasketView{}, payloadErr("approval basket")
	}
	if len(display) != len(a.Lines) {
		return BasketView{}, payloadErr("display and lines differ")
	}
	for _, l := range a.Lines {
		name, ok := display[l.ItemCode]
		if !ok {
			return BasketView{}, payloadErr("display misses a line")
		}
		v.Items = append(v.Items, Item{Name: name, Quantity: l.Quantity})
	}
	v.Approval = canonical
	v.Fingerprint = basket.Fingerprint(canonical)
	v.TotalsLabel = moneyLabel(a.TotalMinor, a.Currency)
	return v, nil
}
