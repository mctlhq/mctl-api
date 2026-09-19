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
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed MAJOR.MINOR.PATCH version. This grammar is
// deliberately narrow — see design.md's "Compatibility ranges" section and
// the "Adopt a semver library" alternative it rejects for now. Anything
// outside MAJOR.MINOR.PATCH (pre-release/build metadata, partial versions
// like "1.x", the literal "latest", etc.) fails to parse.
type Version struct {
	Major, Minor, Patch int
}

// ParseVersion parses a strict MAJOR.MINOR.PATCH string. No leading "v", no
// pre-release or build metadata, no partial versions.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: %q: want MAJOR.MINOR.PATCH", ErrInvalidRange, s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" {
			return Version{}, fmt.Errorf("%w: %q: empty version component", ErrInvalidRange, s)
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return Version{}, fmt.Errorf("%w: %q: non-numeric version component %q", ErrInvalidRange, s, p)
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("%w: %q: %v", ErrInvalidRange, s, err)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}, nil
}

// Compare returns -1, 0 or 1 as v is less than, equal to, or greater than o.
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		return sign(v.Major - o.Major)
	case v.Minor != o.Minor:
		return sign(v.Minor - o.Minor)
	default:
		return sign(v.Patch - o.Patch)
	}
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// comparator is one >=/>/<=/</=/^/~ clause of a Range.
type comparator struct {
	op      string
	version Version
}

func (c comparator) satisfies(v Version) bool {
	switch c.op {
	case ">=":
		return v.Compare(c.version) >= 0
	case ">":
		return v.Compare(c.version) > 0
	case "<=":
		return v.Compare(c.version) <= 0
	case "<":
		return v.Compare(c.version) < 0
	case "=":
		return v.Compare(c.version) == 0
	case "^":
		// ^MAJOR.MINOR.PATCH: >=that version, <next major (or, for a 0.x.y
		// base, <next minor — the common "^ pins the leftmost nonzero
		// component" caret semantics).
		if v.Compare(c.version) < 0 {
			return false
		}
		if c.version.Major > 0 {
			return v.Major == c.version.Major
		}
		if c.version.Minor > 0 {
			return v.Major == 0 && v.Minor == c.version.Minor
		}
		return v.Major == 0 && v.Minor == 0 && v.Patch == c.version.Patch
	case "~":
		// ~MAJOR.MINOR.PATCH: >=that version, <next minor.
		if v.Compare(c.version) < 0 {
			return false
		}
		return v.Major == c.version.Major && v.Minor == c.version.Minor
	default:
		return false
	}
}

// Range is a parsed compatibility range: a set of comparator clauses that
// must ALL be satisfied (space or comma separated), e.g. ">=2.0.0 <3.0.0".
type Range struct {
	raw         string
	comparators []comparator
}

// String returns the range exactly as it was parsed.
func (r Range) String() string { return r.raw }

// Satisfies reports whether v satisfies every clause of the range.
func (r Range) Satisfies(v Version) bool {
	for _, c := range r.comparators {
		if !c.satisfies(v) {
			return false
		}
	}
	return true
}

// validOps, longest first so a naive prefix scan finds ">=" before ">".
var validOps = []string{">=", "<=", ">", "<", "=", "^", "~"}

// ParseRange parses a compatibility range string: comparator clauses
// (">=", ">", "<=", "<", "=", "^", "~") over MAJOR.MINOR.PATCH, joined by
// whitespace or commas. Anything else — including an empty string — is
// rejected with ErrInvalidRange: a range that cannot be evaluated must never
// reach bind time, where failing open would be the dangerous outcome.
func ParseRange(s string) (Range, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return Range{}, fmt.Errorf("%w: empty range", ErrInvalidRange)
	}
	// Normalize comma separators to whitespace, then split.
	normalized := strings.ReplaceAll(trimmed, ",", " ")
	fields := strings.Fields(normalized)
	if len(fields) == 0 {
		return Range{}, fmt.Errorf("%w: empty range", ErrInvalidRange)
	}

	var comparators []comparator
	for _, field := range fields {
		op, rest := splitOp(field)
		if op == "" {
			return Range{}, fmt.Errorf("%w: %q: missing or unknown comparator", ErrInvalidRange, field)
		}
		version, err := ParseVersion(rest)
		if err != nil {
			return Range{}, fmt.Errorf("%w: %q: %v", ErrInvalidRange, field, err)
		}
		comparators = append(comparators, comparator{op: op, version: version})
	}
	return Range{raw: trimmed, comparators: comparators}, nil
}

// splitOp finds the longest matching comparator prefix and returns it plus
// the remaining version string. Returns ("", field) if no known comparator
// prefixes the field.
func splitOp(field string) (op, rest string) {
	for _, candidate := range validOps {
		if strings.HasPrefix(field, candidate) {
			return candidate, strings.TrimPrefix(field, candidate)
		}
	}
	return "", field
}
