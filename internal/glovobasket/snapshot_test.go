package glovobasket

import (
	"strings"
	"testing"
)

// minimalBasket is the "minimal" vector of the vendored fingerprint contract.
const (
	minimalBasket = `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`
	minimalFP     = "sha256:662ad98455b98d60da709cb520e7b519b94ee5125e8743b47952b02553666d96"
)

func TestFreezeSnapshotComputesTheFingerprint(t *testing.T) {
	s, err := FreezeSnapshot([]byte(minimalBasket), map[string]string{"FAKE-1": "Fake coffee"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Fingerprint != minimalFP || sha(s.Canonical) != minimalFP || s.StoreRef != "pst_0123456789abcdef0123" {
		t.Fatalf("snapshot: %+v", s)
	}
	if len(s.Lines) != 1 || s.Lines[0].Name != "Fake coffee" || s.Lines[0].LineTotalMinor != 500 || s.Totals.TotalMinor != 749 {
		t.Fatalf("lines: %+v totals %+v", s.Lines, s.Totals)
	}
	// Key order and whitespace do not change the canonical form.
	reordered := `{ "total_minor":749, "discount_minor":0,"service_fee_minor":50,"delivery_fee_minor":199,"subtotal_minor":500,"lines":[{"unit_price_minor":500,"quantity":1,"item_code":"FAKE-1"}],"currency":"EUR","store_ref":"pst_0123456789abcdef0123","v":"mctl-approval-basket/v1"}`
	if r, err := FreezeSnapshot([]byte(reordered), map[string]string{"FAKE-1": "x"}); err != nil || r.Fingerprint != minimalFP {
		t.Fatalf("reordered: %v %s", err, r.Fingerprint)
	}
}

func TestFreezeSnapshotRefusals(t *testing.T) {
	ok := map[string]string{"FAKE-1": "Fake coffee"}
	for name, c := range map[string]struct {
		raw   string
		names map[string]string
	}{
		"not json":         {"{", ok},
		"extra field":      {strings.Replace(minimalBasket, `"total_minor":749`, `"total_minor":749,"x":1`, 1), ok},
		"bad arithmetic":   {strings.Replace(minimalBasket, `"total_minor":749`, `"total_minor":748`, 1), ok},
		"missing name":     {minimalBasket, map[string]string{}},
		"extra name":       {minimalBasket, map[string]string{"FAKE-1": "a", "FAKE-2": "b"}},
		"wrong item named": {minimalBasket, map[string]string{"FAKE-2": "b"}},
		"empty name":       {minimalBasket, map[string]string{"FAKE-1": ""}},
		"oversized name":   {minimalBasket, map[string]string{"FAKE-1": strings.Repeat("a", MaxItemNameBytes+1)}},
		"invalid utf-8":    {minimalBasket, map[string]string{"FAKE-1": "\xff"}},
	} {
		if _, err := FreezeSnapshot([]byte(c.raw), c.names); !IsInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
