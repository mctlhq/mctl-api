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

package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

const maxOrderPages = 4

type ordersListWire struct {
	Orders     *[]orderCardWire `json:"orders"`
	Pagination *struct {
		Next *struct {
			Offset json.RawMessage `json:"offset"`
		} `json:"next"`
	} `json:"pagination"`
}

// orderCardWire reads only the order id off a card: the card text (store
// name, items, footer) is free-form and the detail endpoint is the source.
type orderCardWire struct {
	ID        flexString `json:"id"`
	OrderID   flexString `json:"orderId"`
	OrderCode flexString `json:"orderCode"`
}

// OrderHistory returns up to q.Limit orders, newest first. It reads cursor
// pages of the orders list and then each order's detail, one at a time. A
// page or a detail that fails fails the whole call: the result is never a
// shorter list.
func (r *Reader) OrderHistory(ctx context.Context, q gp.HistoryQuery) ([]gp.OrderSummary, error) {
	if q.Limit < 1 || q.Limit > gp.MaxHistoryOrders {
		return nil, gp.Invalid(gp.OpOrderHistory, "limit")
	}
	out := []gp.OrderSummary{}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < maxOrderPages && len(out) < q.Limit; page++ {
		if seen[cursor] {
			break
		}
		seen[cursor] = true
		qs := url.Values{"offset": {firstNonEmpty(cursor, "0")}, "limit": {strconv.Itoa(ordersPageSize)}}
		var w ordersListWire
		if err := r.c.getJSON(ctx, gp.OpOrderHistory, reqSpec{method: http.MethodGet, path: "/v3/customer/orders-list", query: qs}, &w); err != nil {
			return nil, err
		}
		if w.Orders == nil {
			return nil, unobserved(gp.OpOrderHistory, ErrSchemaDrift)
		}
		for _, card := range *w.Orders {
			id := firstNonEmpty(string(card.ID), string(card.OrderID), string(card.OrderCode))
			if !validID(id) {
				return nil, unobserved(gp.OpOrderHistory, ErrSchemaDrift)
			}
			o, err := r.c.orderDetail(ctx, gp.OpOrderHistory, id)
			if err != nil {
				return nil, err
			}
			if !q.Since.IsZero() && o.Summary.PlacedAt.Before(q.Since) {
				return out, nil // newest first: everything after is older
			}
			out = append(out, o.Summary)
			if len(out) >= q.Limit {
				return out, nil
			}
		}
		cursor = ""
		if w.Pagination != nil && w.Pagination.Next != nil {
			var c flexString
			if err := json.Unmarshal(w.Pagination.Next.Offset, &c); err == nil {
				cursor = string(c)
			}
		}
		if cursor == "" {
			break
		}
	}
	return out, nil
}

// Order returns one past order. A 404 is the provider's absence signal.
func (r *Reader) Order(ctx context.Context, orderID string) (gp.HistoricalOrder, error) {
	if !validID(orderID) {
		return gp.HistoricalOrder{}, gp.Invalid(gp.OpOrder, "order_id")
	}
	return r.c.orderDetail(ctx, gp.OpOrder, orderID)
}

type orderDetailWire struct {
	ID             flexString `json:"id"`
	OrderID        flexString `json:"orderId"`
	StoreID        flexString `json:"storeId"`
	StoreAddressID flexString `json:"storeAddressId"`
	Store          *struct {
		ID        flexString `json:"id"`
		AddressID flexString `json:"addressId"`
		Name      string     `json:"name"`
	} `json:"store"`
	StoreName    string `json:"storeName"`
	ProviderName string `json:"providerName"`
	Total        *struct {
		Formatted json.RawMessage `json:"formatted"`
	} `json:"total"`
	TotalAmount   json.RawMessage `json:"totalAmount"`
	Price         json.RawMessage `json:"price"`
	CreationTime  json.RawMessage `json:"creationTime"`
	CreatedAt     json.RawMessage `json:"createdAt"`
	OrderTime     json.RawMessage `json:"orderTime"`
	DeliveredAt   json.RawMessage `json:"deliveredAt"`
	CurrentStatus *struct {
		CreationTime json.RawMessage `json:"creationTime"`
	} `json:"currentStatus"`
	ReorderData *struct {
		Allowed   bool `json:"allowed"`
		IsAllowed bool `json:"isAllowed"`
	} `json:"reorderData"`
	IsRemake bool             `json:"isRemake"`
	Bought   *[]orderLineWire `json:"boughtProducts"`
}

type orderLineWire struct {
	ID        flexString `json:"id"`
	ProductID flexString `json:"productId"`
	IDs       *struct {
		ID flexString `json:"id"`
	} `json:"ids"`
	Name               string          `json:"name"`
	Quantity           json.RawMessage `json:"quantity"`
	Price              json.RawMessage `json:"price"`
	CustomizationsText string          `json:"customizationsDescription"`
	Customizations     []struct {
		IDs *struct {
			GroupLegacyID flexString `json:"groupLegacyId"`
			LegacyID      flexString `json:"legacyId"`
		} `json:"ids"`
		Name string `json:"name"`
	} `json:"customizations"`
}

func (c *core) orderDetail(ctx context.Context, op, orderID string) (gp.HistoricalOrder, error) {
	body, status, err := c.do(ctx, op, reqSpec{method: http.MethodGet, path: joinPath("v3", "customer", "orders", pathEsc(orderID)), allow404: true})
	if err != nil {
		return gp.HistoricalOrder{}, err
	}
	if status == http.StatusNotFound {
		return gp.HistoricalOrder{}, gp.Absent(op)
	}
	var w orderDetailWire
	if err := decode(op, body, &w); err != nil {
		return gp.HistoricalOrder{}, err
	}
	return c.mapOrder(op, orderID, w)
}

func (c *core) mapOrder(op, orderID string, w orderDetailWire) (gp.HistoricalOrder, error) {
	drift := func() (gp.HistoricalOrder, error) { return gp.HistoricalOrder{}, unobserved(op, ErrSchemaDrift) }
	if id := firstNonEmpty(string(w.ID), string(w.OrderID)); id != orderID {
		return drift()
	}
	store, addr, name := string(w.StoreID), string(w.StoreAddressID), firstNonEmpty(w.StoreName, w.ProviderName)
	if w.Store != nil {
		store, addr, name = firstNonEmpty(store, string(w.Store.ID)), firstNonEmpty(addr, string(w.Store.AddressID)), firstNonEmpty(name, w.Store.Name)
	}
	if !validID(store) || !validID(addr) || name == "" || w.Bought == nil {
		return drift()
	}
	var placed json.RawMessage
	for _, t := range []json.RawMessage{w.CreationTime, w.CreatedAt, w.OrderTime, w.DeliveredAt} {
		if len(t) > 0 {
			placed = t
			break
		}
	}
	if placed == nil && w.CurrentStatus != nil {
		placed = w.CurrentStatus.CreationTime
	}
	placedAt, ok := parseTime(placed)
	if !ok {
		return drift()
	}
	totalRaw := firstRaw(rawOf(w.Total), w.TotalAmount, w.Price)
	total, err := parseMoney(totalRaw, c.cfg.Currency)
	if err != nil || total < 0 {
		return drift()
	}
	items := make([]gp.OrderItem, 0, len(*w.Bought))
	var count int64
	for i := range *w.Bought {
		l := &(*w.Bought)[i]
		it, err := c.mapOrderLine(l)
		if err != nil {
			return gp.HistoricalOrder{}, unobserved(op, err)
		}
		count += it.Quantity
		items = append(items, it)
	}
	ref := makeRef(store, addr)
	reorder := w.IsRemake || (w.ReorderData != nil && (w.ReorderData.Allowed || w.ReorderData.IsAllowed))
	return gp.HistoricalOrder{
		Summary: gp.OrderSummary{ID: orderID, StoreID: ref, StoreName: name, PlacedAt: placedAt, ItemCount: int(count), TotalMinor: total, Currency: c.cfg.Currency, NativeReorderAllowed: reorder},
		Items:   items,
	}, nil
}

func rawOf(t *struct {
	Formatted json.RawMessage `json:"formatted"`
}) json.RawMessage {
	if t == nil {
		return nil
	}
	return t.Formatted
}

func firstRaw(v ...json.RawMessage) json.RawMessage {
	for _, r := range v {
		if len(r) > 0 && string(r) != "null" {
			return r
		}
	}
	return nil
}

// mapOrderLine maps one bought line. The line price is the line total
// (upstream fixtures: quantity "2", price "3.00 EUR" against a 3.00 total);
// it must divide evenly into a unit price. A line that names customizations
// without structured ids cannot be represented and is drift: guessing its
// modifiers would let a reorder silently drop them.
func (c *core) mapOrderLine(l *orderLineWire) (gp.OrderItem, error) {
	id := firstNonEmpty(string(l.ID), string(l.ProductID))
	if id == "" && l.IDs != nil {
		id = string(l.IDs.ID)
	}
	if !validID(id) || l.Name == "" {
		return gp.OrderItem{}, ErrSchemaDrift
	}
	qraw := l.Quantity
	if len(qraw) > 0 && qraw[0] == '{' {
		var q struct {
			Increments json.RawMessage `json:"increments"`
		}
		if json.Unmarshal(qraw, &q) != nil {
			return gp.OrderItem{}, ErrSchemaDrift
		}
		qraw = q.Increments
	}
	qty, err := parseQuantity(qraw)
	if err != nil {
		return gp.OrderItem{}, err
	}
	line, err := parseMoney(l.Price, c.cfg.Currency)
	if err != nil || line < 0 || line%qty != 0 {
		return gp.OrderItem{}, ErrSchemaDrift
	}
	it := gp.OrderItem{ProductID: id, Name: l.Name, Quantity: qty, UnitPriceMinor: line / qty}
	for _, cz := range l.Customizations {
		if cz.IDs == nil || !validID(string(cz.IDs.GroupLegacyID)) || !validID(string(cz.IDs.LegacyID)) || cz.Name == "" {
			return gp.OrderItem{}, ErrSchemaDrift
		}
		it.Options = append(it.Options, gp.SelectedOption{GroupID: string(cz.IDs.GroupLegacyID), OptionID: string(cz.IDs.LegacyID), Name: cz.Name})
	}
	if l.CustomizationsText != "" && len(it.Options) == 0 {
		return gp.OrderItem{}, ErrSchemaDrift
	}
	return it, nil
}
