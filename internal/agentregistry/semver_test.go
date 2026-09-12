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

package agentregistry

import (
	"errors"
	"testing"
)

func mustParseVersion(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatalf("ParseVersion(%q): %v", s, err)
	}
	return v
}

func TestParseVersion_ValidAndInvalid(t *testing.T) {
	valid := []string{"0.0.0", "1.2.3", "10.20.30", "1.0.0"}
	for _, s := range valid {
		if _, err := ParseVersion(s); err != nil {
			t.Errorf("ParseVersion(%q): expected success, got %v", s, err)
		}
	}

	invalid := []string{"", "1", "1.2", "1.2.3.4", "v1.2.3", "1.2.x", "latest", "1..3", "1.2.-3", "1.2.3-alpha"}
	for _, s := range invalid {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q): expected an error, got none", s)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
	}
	for _, c := range cases {
		a := mustParseVersion(t, c.a)
		b := mustParseVersion(t, c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseRange_RejectsUnknownSyntax(t *testing.T) {
	cases := []string{"", "   ", ">=1.0", "1.x", "latest", ">=1.0.0 && <2.0.0", "!=1.0.0", "*", "abc"}
	for _, s := range cases {
		if _, err := ParseRange(s); err == nil {
			t.Errorf("ParseRange(%q): expected ErrInvalidRange, got none", s)
		} else if !errors.Is(err, ErrInvalidRange) {
			t.Errorf("ParseRange(%q): expected ErrInvalidRange, got %v", s, err)
		}
	}
}

func TestParseRange_AcceptsSupportedGrammar(t *testing.T) {
	cases := []string{
		">=1.0.0",
		">1.0.0",
		"<=2.0.0",
		"<2.0.0",
		"=1.2.3",
		"^1.2.3",
		"~1.2.3",
		">=2.0.0 <3.0.0",
		">=2.0.0,<3.0.0",
		">=2.0.0, <3.0.0",
	}
	for _, s := range cases {
		if _, err := ParseRange(s); err != nil {
			t.Errorf("ParseRange(%q): expected success, got %v", s, err)
		}
	}
}

func TestRange_BoundaryInclusiveExclusive(t *testing.T) {
	rng, err := ParseRange(">=2.0.0 <3.0.0")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}

	cases := []struct {
		version string
		want    bool
	}{
		{"2.0.0", true},  // lower bound inclusive
		{"2.9.9", true},  // within range
		{"3.0.0", false}, // upper bound exclusive
		{"1.9.9", false}, // below lower bound
		{"3.0.1", false}, // above upper bound
	}
	for _, c := range cases {
		v := mustParseVersion(t, c.version)
		if got := rng.Satisfies(v); got != c.want {
			t.Errorf("Range(%q).Satisfies(%q) = %v, want %v", rng.String(), c.version, got, c.want)
		}
	}
}

func TestRange_CaretSemantics(t *testing.T) {
	rng, err := ParseRange("^1.2.3")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.2.3", true},  // exact match
		{"1.2.4", true},  // patch bump within same major
		{"1.9.9", true},  // minor bump within same major
		{"1.2.2", false}, // below the pinned version
		{"2.0.0", false}, // next major excluded
	}
	for _, c := range cases {
		v := mustParseVersion(t, c.version)
		if got := rng.Satisfies(v); got != c.want {
			t.Errorf("^1.2.3.Satisfies(%q) = %v, want %v", c.version, got, c.want)
		}
	}

	// ^0.2.3 pins the leftmost nonzero component: minor here, so only patch
	// bumps within 0.2.x are allowed.
	zeroMajor, err := ParseRange("^0.2.3")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	zeroCases := []struct {
		version string
		want    bool
	}{
		{"0.2.3", true},
		{"0.2.9", true},
		{"0.3.0", false},
		{"1.0.0", false},
	}
	for _, c := range zeroCases {
		v := mustParseVersion(t, c.version)
		if got := zeroMajor.Satisfies(v); got != c.want {
			t.Errorf("^0.2.3.Satisfies(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestRange_TildeSemantics(t *testing.T) {
	rng, err := ParseRange("~1.2.3")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.2.3", true},  // exact match
		{"1.2.9", true},  // patch bump within same minor
		{"1.2.2", false}, // below the pinned version
		{"1.3.0", false}, // next minor excluded
		{"2.0.0", false}, // next major excluded
	}
	for _, c := range cases {
		v := mustParseVersion(t, c.version)
		if got := rng.Satisfies(v); got != c.want {
			t.Errorf("~1.2.3.Satisfies(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestRange_MultipleClausesAllMustBeSatisfied(t *testing.T) {
	rng, err := ParseRange(">=1.0.0 <2.0.0 !=1.5.0")
	if err == nil {
		t.Fatalf("expected ParseRange to reject the unsupported != comparator, got range %q", rng.String())
	}
}
