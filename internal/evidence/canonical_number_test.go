// Copyright 2025 MCTL Authors
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

package evidence

import (
	"bytes"
	"testing"
)

// pythonNumberVectors were produced by CPython 3 as
// json.dumps(json.loads(lit), allow_nan=False), which is what Tier A hashes.
var pythonNumberVectors = []struct{ lit, want string }{
	{"0", "0"},
	{"-0", "0"},
	{"10", "10"},
	{"-10", "-10"},
	{"123456789012345678901234567890", "123456789012345678901234567890"},
	{"-0.0", "-0.0"},
	{"0.0", "0.0"},
	{"1.0", "1.0"},
	{"1.50", "1.5"},
	{"1E2", "100.0"},
	{"1e2", "100.0"},
	{"1e+2", "100.0"},
	{"1E-2", "0.01"},
	{"0.1", "0.1"},
	{"0.0001", "0.0001"},
	{"0.00001", "1e-05"},
	{"1e-05", "1e-05"},
	{"1e16", "1e+16"},
	{"1e15", "1000000000000000.0"},
	{"9999999999999998", "9999999999999998"},
	{"9999999999999998.0", "9999999999999998.0"},
	{"12345678901234567.0", "1.2345678901234568e+16"},
	{"1.5e16", "1.5e+16"},
	{"-2.5e-7", "-2.5e-07"},
	{"1e-400", "0.0"},
	{"3.141592653589793", "3.141592653589793"},
	{"0.30000000000000004", "0.30000000000000004"},
	{"1e22", "1e+22"},
	{"123.456e3", "123456.0"},
	{"5e-324", "5e-324"},
	{"1.7976931348623157e308", "1.7976931348623157e+308"},
}

func TestCanonicalNumberMatchesPython(t *testing.T) {
	for _, v := range pythonNumberVectors {
		got, err := canonicalNumber(v.lit)
		if err != nil {
			t.Errorf("%s: unexpected error %v", v.lit, err)
			continue
		}
		if got != v.want {
			t.Errorf("%s: got %s, want %s (CPython json.dumps)", v.lit, got, v.want)
		}
	}
}

// Python refuses an overflowing float under allow_nan=False, so Tier A can
// never have sealed one; refusing it here keeps the two layers in step.
func TestCanonicalNumberRefusesOverflow(t *testing.T) {
	for _, lit := range []string{"1e400", "-1e400"} {
		if got, err := canonicalNumber(lit); err == nil {
			t.Errorf("%s: want an error, got %s", lit, got)
		}
	}
}

// The canonical bytes, and so the content hash, depend on a number's value,
// not on how the sender spelled it.
func TestCanonicalJSONNumberSpellingIsIrrelevant(t *testing.T) {
	spellings := [][]string{
		{`{"n":100.0}`, `{"n":1E2}`, `{"n":1e+2}`, `{"n":100.00}`},
		{`{"n":0}`, `{"n":-0}`},
		{`{"n":0.00001}`, `{"n":1e-5}`, `{"n":1.0E-05}`},
	}
	for _, group := range spellings {
		var first []byte
		for _, raw := range group {
			obj, err := decodeStrictObject([]byte(raw))
			if err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			got, err := canonicalJSON(obj)
			if err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if first == nil {
				first = got
				continue
			}
			if !bytes.Equal(first, got) {
				t.Errorf("%s canonicalised to %s, but %s to %s", group[0], first, raw, got)
			}
		}
	}
}
