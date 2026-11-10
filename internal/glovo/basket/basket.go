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

// Package basket is the one M1 basket fingerprint of the Glovo facade:
// "sha256:" + hex(sha256(JCS(approval basket))), over the approval basket
// projection of the mctl-agents#1059 contract (prices included). The schema and
// the golden vectors are vendored, never redefined, under contract/.
package basket

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/mctlhq/mctl-api/internal/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed contract/approval-basket.schema.json contract/basket-fingerprint.json contract/pattern-parity.json contract/PROVENANCE
var contractFS embed.FS

const schemaURL = "https://mctl.ai/schemas/bridge/v1alpha2/approval-basket.schema.json"

// ErrInvalid is wrapped by every refusal of Parse and Validate. The text
// names the reason code only, never a value.
var ErrInvalid = errors.New("basket: invalid")

// Line is one basket line. Prices are integer minor units.
type Line struct {
	ItemCode       string `json:"item_code"`
	Quantity       int64  `json:"quantity"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
}

// Approval is the Go mirror of approval-basket.schema.json.
type Approval struct {
	V                string `json:"v"`
	StoreRef         string `json:"store_ref"`
	Currency         string `json:"currency"`
	Lines            []Line `json:"lines"`
	SubtotalMinor    int64  `json:"subtotal_minor"`
	DeliveryFeeMinor int64  `json:"delivery_fee_minor"`
	ServiceFeeMinor  int64  `json:"service_fee_minor"`
	DiscountMinor    int64  `json:"discount_minor"`
	TotalMinor       int64  `json:"total_minor"`
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

// Validate enforces what the schema cannot: lines sorted ascending by a
// unique item_code (unsorted input is refused, never re-sorted), and the
// subtotal and total arithmetic.
func (a Approval) Validate() error {
	if len(a.Lines) == 0 {
		return invalid("schema_invalid")
	}
	for i := 1; i < len(a.Lines); i++ {
		switch {
		case a.Lines[i-1].ItemCode == a.Lines[i].ItemCode:
			return invalid("duplicate_item")
		case a.Lines[i-1].ItemCode > a.Lines[i].ItemCode:
			return invalid("unsorted_lines")
		}
	}
	if !sort.SliceIsSorted(a.Lines, func(i, j int) bool { return a.Lines[i].ItemCode < a.Lines[j].ItemCode }) {
		return invalid("unsorted_lines")
	}
	var sub int64
	for _, l := range a.Lines {
		sub += l.Quantity * l.UnitPriceMinor
	}
	if sub != a.SubtotalMinor {
		return invalid("subtotal_mismatch")
	}
	if a.SubtotalMinor+a.DeliveryFeeMinor+a.ServiceFeeMinor-a.DiscountMinor != a.TotalMinor {
		return invalid("total_mismatch")
	}
	return nil
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiled() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		raw, err := contractFS.ReadFile("contract/approval-basket.schema.json")
		if err != nil {
			schemaErr = err
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource(schemaURL, doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile(schemaURL)
	})
	return schema, schemaErr
}

// Parse is the one raw-bytes entry point. It runs the shared raw-bytes
// pre-check (internal/jcs.PrecheckIntegers: duplicate keys, BOM, number
// forms, depth, size), validates against the vendored schema (no extra
// field), runs Validate and returns the RFC 8785 bytes of the input.
func Parse(raw []byte) (Approval, []byte, error) {
	if err := jcs.PrecheckIntegers(raw); err != nil {
		return Approval{}, nil, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	s, err := compiled()
	if err != nil {
		return Approval{}, nil, fmt.Errorf("basket: compile schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return Approval{}, nil, invalid("schema_invalid")
	}
	if err := s.Validate(inst); err != nil {
		return Approval{}, nil, invalid("schema_invalid")
	}
	var a Approval
	if err := json.Unmarshal(raw, &a); err != nil {
		return Approval{}, nil, invalid("schema_invalid")
	}
	if err := a.Validate(); err != nil {
		return Approval{}, nil, err
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return Approval{}, nil, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	return a, canonical, nil
}

// Canonical returns the RFC 8785 bytes of a validated basket.
func Canonical(a Approval) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("basket: marshal: %w", err)
	}
	_, canonical, err := Parse(raw)
	return canonical, err
}

// Fingerprint is "sha256:" + hex(sha256(canonical)).
func Fingerprint(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
