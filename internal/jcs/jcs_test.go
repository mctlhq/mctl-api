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

package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVendoredVectorsMatchProvenance(t *testing.T) {
	prov, err := os.ReadFile("testdata/PROVENANCE")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"jcs-digest.json", "must-reject.json"} {
		raw, err := os.ReadFile("testdata/" + f) //nolint:gosec // fixed vendored vector names
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if want := hex.EncodeToString(sum[:]) + "  " + f; !strings.Contains(string(prov), want) {
			t.Errorf("%s: sha256 %x is not the pinned value in PROVENANCE", f, sum)
		}
	}
}

func TestJCSDigestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/jcs-digest.json")
	if err != nil {
		t.Fatal(err)
	}
	var generic struct {
		Vectors []map[string]string `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if len(generic.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range generic.Vectors {
		got, err := Canonicalize([]byte(v["input_text"]))
		if err != nil {
			t.Errorf("%s: %v", v["name"], err)
			continue
		}
		if string(got) != v["canonical"] {
			t.Errorf("%s: canonical %q, want %q", v["name"], got, v["canonical"])
		}
		sum := sha256.Sum256(got)
		if d := "sha256:" + hex.EncodeToString(sum[:]); d != v["digest"] {
			t.Errorf("%s: digest %s, want %s", v["name"], d, v["digest"])
		}
	}
}

func TestMustReject(t *testing.T) {
	raw, err := os.ReadFile("testdata/must-reject.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Entries []struct {
			Name, Reason string
			Applies      []string
			Raw          string
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.Entries {
		switch e.Reason {
		case "schema_invalid":
			continue // a schema decision, not a raw-bytes one
		case "non_integer_token":
			if err := PrecheckIntegers([]byte(e.Raw)); !errors.Is(err, ErrNonInteger) {
				t.Errorf("%s: PrecheckIntegers = %v", e.Name, err)
			}
		default:
			if err := Precheck([]byte(e.Raw)); err == nil {
				t.Errorf("%s: Precheck accepted it (%s)", e.Name, e.Reason)
			}
		}
	}
}

func TestPrecheckAcceptsPlainObject(t *testing.T) {
	if err := Precheck([]byte(`{"a":[1,2.5,{"b":"x"}],"c":null}`)); err != nil {
		t.Fatal(err)
	}
	if err := PrecheckIntegers([]byte(`{"a":[1,2,{"b":-3}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizeRefusals(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `"\ud800"`, `[1e400]`, "\ufeff{}", `{} {}`, `[01]`, `[1.]`, `{"a":}`} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%q) accepted", in)
		}
	}
}

// TestNoOtherCanonicalizer asserts that internal/glovo and internal/bridge do
// not implement their own RFC 8785 key ordering or number formatting: they
// import this package.
func TestNoOtherCanonicalizer(t *testing.T) {
	banned := []string{"utf16.Encode", "unicode/utf16", "FormatFloat(", "RFC 8785 implementation"}
	for _, root := range []string{"../glovo", "../bridge"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			raw, err := os.ReadFile(p) //nolint:gosec // path comes from WalkDir over the repo source tree
			if err != nil {
				return err
			}
			for _, b := range banned {
				if strings.Contains(string(raw), b) {
					t.Errorf("%s contains %q: canonicalization belongs to internal/jcs", p, b)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
