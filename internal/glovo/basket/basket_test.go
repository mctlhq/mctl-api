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

package basket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVendoredContractMatchesProvenance(t *testing.T) {
	prov, err := os.ReadFile("contract/PROVENANCE")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"approval-basket.schema.json", "basket-fingerprint.json", "pattern-parity.json"} {
		raw, err := os.ReadFile("contract/" + f) //nolint:gosec // fixed vendored contract file names
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if want := hex.EncodeToString(sum[:]) + "  " + f; !strings.Contains(string(prov), want) {
			t.Errorf("%s: sha256 %x is not the pinned value in PROVENANCE", f, sum)
		}
	}
}

type vectors struct {
	Vectors []struct {
		Name, Canonical, Fingerprint string
		InputText                    string `json:"input_text"`
		SameFingerprintAs            string `json:"same_fingerprint_as"`
		DifferentFrom                string `json:"different_from"`
	} `json:"vectors"`
	MustReject []struct {
		Name, Reason string
		InputText    string `json:"input_text"`
	} `json:"must_reject"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("contract/basket-fingerprint.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFingerprintVectors(t *testing.T) {
	v := loadVectors(t)
	byName := map[string]string{}
	for _, x := range v.Vectors {
		_, canonical, err := Parse([]byte(x.InputText))
		if err != nil {
			t.Fatalf("%s: %v", x.Name, err)
		}
		if string(canonical) != x.Canonical {
			t.Errorf("%s: canonical %q, want %q", x.Name, canonical, x.Canonical)
		}
		fp := Fingerprint(canonical)
		if fp != x.Fingerprint {
			t.Errorf("%s: fingerprint %s, want %s", x.Name, fp, x.Fingerprint)
		}
		byName[x.Name] = fp
	}
	for _, x := range v.Vectors {
		if x.SameFingerprintAs != "" && byName[x.Name] != byName[x.SameFingerprintAs] {
			t.Errorf("%s must equal %s", x.Name, x.SameFingerprintAs)
		}
		if x.DifferentFrom != "" && byName[x.Name] == byName[x.DifferentFrom] {
			t.Errorf("%s must differ from %s", x.Name, x.DifferentFrom)
		}
	}
}

func TestMustRejectVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.MustReject) == 0 {
		t.Fatal("no must_reject vectors")
	}
	for _, x := range v.MustReject {
		_, _, err := Parse([]byte(x.InputText))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse = %v, want ErrInvalid", x.Name, err)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	good := `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`
	if _, _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"item_name":    strings.Replace(good, `"item_code":"FAKE-1"`, `"item_code":"FAKE-1","item_name":"x"`, 1),
		"quantity 1.0": strings.Replace(good, `"quantity":1,`, `"quantity":1.0,`, 1),
		"duplicate":    strings.Replace(good, `"currency":"EUR",`, `"currency":"EUR","currency":"EUR",`, 1),
		"empty":        "",
	} {
		if _, _, err := Parse([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse = %v", name, err)
		}
	}
}

// TestPatternParity is the Go leg of the #1059 pattern-parity test for the
// patterns of the approval basket schema this package vendors.
func TestPatternParity(t *testing.T) {
	raw, err := os.ReadFile("contract/pattern-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			ID, Schema, Pointer string
			Accept, Reject      []string
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	schemaRaw, err := os.ReadFile("contract/approval-basket.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(schemaRaw, &doc); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range f.Cases {
		if c.Schema != "approval-basket.schema.json" {
			continue // the other schemas are vendored by their own consumer
		}
		cur := doc
		for _, part := range strings.Split(strings.TrimPrefix(c.Pointer, "/"), "/") {
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("%s: bad pointer %s", c.ID, c.Pointer)
			}
			cur = m[part]
		}
		pat, ok := cur.(string)
		if !ok {
			t.Fatalf("%s: no pattern at %s", c.ID, c.Pointer)
		}
		re := regexp.MustCompile(pat)
		for _, s := range c.Accept {
			if !re.MatchString(s) {
				t.Errorf("%s: %q must match", c.ID, s)
			}
		}
		for _, s := range c.Reject {
			if re.MatchString(s) {
				t.Errorf("%s: %q must not match", c.ID, s)
			}
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("no approval-basket pattern cases ran")
	}
}

func TestMustRejectFromJCSOwner(t *testing.T) {
	// The raw-bytes must-reject cases live once, in internal/jcs/testdata.
	if _, err := os.Stat("../../jcs/testdata/must-reject.json"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse([]byte("\ufeff{}")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("BOM: %v", err)
	}
}
