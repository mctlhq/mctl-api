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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// fixturePayload returns the payload of a vendored #1059 read-result fixture.
func fixturePayload(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "bridge", "schema", "v1alpha2", "fixtures", name)) //nolint:gosec // fixed fixture directory in this repository
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(b, &d); err != nil || len(d.Payload) == 0 {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return d.Payload
}

func TestParseHistoryMapsTheVendoredFixture(t *testing.T) {
	v, err := ParseHistory(fixturePayload(t, "read-result.history.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Orders) != 2 || v.NextCursor != "c2VlZC1jdXJzb3I" {
		t.Fatalf("view = %+v", v)
	}
	o := v.Orders[0]
	if o.OrderRef != "pho_00000000000000000000" || o.StoreName != HistoryStoreName || o.PlacedAt != "2026-11-01T00:00:00Z" ||
		o.TotalLabel != "15.00 EUR" || o.ItemCount != 2 {
		t.Fatalf("row = %+v", o)
	}
	if got := v.IssuedPho(); len(got) != 2 || got[1] != "pho_00000000000000000001" {
		t.Fatalf("issued = %v", got)
	}
	if _, err := ParseHistory(fixturePayload(t, "read-result.history.max.valid.json")); err != nil {
		t.Fatalf("the max fixture: %v", err)
	}
}

func TestParsePreviewAndBasketMapTheVendoredFixtures(t *testing.T) {
	p, err := ParsePreview(fixturePayload(t, "read-result.preview.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Empty || len(p.Items) != 2 || p.Items[0] != (Item{Name: "Fake Bread", Quantity: 2}) || p.Items[1] != (Item{Name: "Fake Milk", Quantity: 1}) ||
		len(p.Unavailable) != 1 || p.Unavailable[0] != (Item{Name: "FAKE-GONE", Quantity: 1}) ||
		!strings.HasPrefix(p.Fingerprint, "sha256:") || len(p.Approval) == 0 {
		t.Fatalf("preview = %+v", p)
	}
	b, err := ParseBasket(fixturePayload(t, "read-result.basket.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.StoreName != "Fake Store (Test)" || b.TotalsLabel != "6.69 EUR" || b.Fingerprint != p.Fingerprint || len(b.Items) != 2 {
		t.Fatalf("basket = %+v (preview fingerprint %s)", b, p.Fingerprint)
	}
	e, err := ParsePreview(fixturePayload(t, "read-result.preview.empty.valid.json"))
	if err != nil || !e.Empty || e.Fingerprint != "" || e.Approval != nil || len(e.Items) != 0 {
		t.Fatalf("empty preview = %+v, %v", e, err)
	}
	au, err := ParsePreview(fixturePayload(t, "read-result.preview.all-unavailable.valid.json"))
	if err != nil || !au.Empty || len(au.Unavailable) != 2 || au.Approval != nil {
		t.Fatalf("all-unavailable preview = %+v, %v", au, err)
	}
	eb, err := ParseBasket(fixturePayload(t, "read-result.basket.empty.valid.json"))
	if err != nil || !eb.Empty || eb.Fingerprint != "" {
		t.Fatalf("empty basket = %+v, %v", eb, err)
	}
}

// Every vendored invalid fixture is refused as a payload failure: a bad
// provider payload is never an empty answer.
func TestParseRefusesTheVendoredInvalidPayloads(t *testing.T) {
	for _, c := range []struct {
		name  string
		parse func([]byte) error
	}{
		{"read-result.history.missing-field.json", func(b []byte) error { _, e := ParseHistory(b); return e }},
		{"read-result.preview.missing-field.json", func(b []byte) error { _, e := ParsePreview(b); return e }},
		{"read-result.basket.missing-field.json", func(b []byte) error { _, e := ParseBasket(b); return e }},
		{"read-result.empty-with-basket.json", func(b []byte) error { _, e := ParsePreview(b); return e }},
		{"read-result.nonempty-without-basket.json", func(b []byte) error { _, e := ParsePreview(b); return e }},
		{"read-result.quantity-float.json", func(b []byte) error { _, e := ParsePreview(b); return e }},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "bridge", "schema", "v1alpha2", "fixtures", c.name))
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(raw, &d) != nil || len(d.Payload) == 0 {
			t.Fatalf("%s has no payload", c.name)
		}
		if err := c.parse(d.Payload); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: %v, want ErrPayload", c.name, err)
		}
	}
	for name, raw := range map[string]string{
		"extra field":   `{"orders":[],"extra":1}`,
		"trailing data": `{"orders":[]} {}`,
		"null orders":   `{"orders":null}`,
		"empty":         ``,
	} {
		if _, err := ParseHistory([]byte(raw)); !errors.Is(err, ErrPayload) {
			t.Errorf("history %s: %v", name, err)
		}
	}
}

func TestNotReadyBridgeRefusesEveryRead(t *testing.T) {
	res, err := NotReadyBridge{}.Read(context.Background(), bridge.ReadRequest{Kind: bridge.ReadHistory})
	if res != nil || !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		t.Fatalf("read = %v, %v", res, err)
	}
}

func TestMapReadError(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		code glovo.Code
	}{
		"nil":               {nil, ""},
		"scope":             {bridge.ErrReadNotAuthorized, glovo.CodeScopeUnsupported},
		"unavailable":       {fmt.Errorf("%w: deadline", bridge.ErrReadUnavailable), glovo.CodeUnavailable},
		"command not found": {bridge.ErrCommandNotFound, glovo.CodeUnavailable},
		"command expired":   {bridge.ErrCommandExpired, glovo.CodeUnavailable},
		"binding no state":  {bridge.ErrBindingMismatch, glovo.CodeUnavailable},
		"binding revoked":   {fmt.Errorf("%w: connection %s", bridge.ErrBindingMismatch, "connection_revoked"), glovo.CodeConnectionRevoked},
		"binding expired":   {fmt.Errorf("%w: connection %s", bridge.ErrBindingMismatch, "connection_expired"), glovo.CodeConnectionExpired},
		"binding stale":     {fmt.Errorf("%w: connection %s", bridge.ErrBindingMismatch, "stale_install"), glovo.CodeStaleInstall},
		"binding none":      {fmt.Errorf("%w: connection %s", bridge.ErrBindingMismatch, "no_connection"), glovo.CodeNoConnection},
		"binding odd state": {fmt.Errorf("%w: connection %s", bridge.ErrBindingMismatch, "weird"), glovo.CodeUnavailable},
		"glovo refusal":     {glovo.Refuse(glovo.CodeNotReady), glovo.CodeNotReady},
		"context":           {context.DeadlineExceeded, glovo.CodeUnavailable},
		"anything else":     {errors.New("boom"), glovo.CodeUnavailable},
	} {
		r := MapReadError(c.err)
		if c.err == nil {
			if r != nil {
				t.Errorf("%s: %+v", name, r)
			}
			continue
		}
		if r == nil || r.Err.Code != c.code || r.Unauthenticated {
			t.Errorf("%s: %+v, want %s", name, r, c.code)
		}
	}
}
