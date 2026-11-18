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

package glovoconsent

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The masked identity is what mctl-glovo shows a person at the link preview
// (token-store design 4.1 step 3) so they can recognise their own MCTL
// account before a Glovo session is attached to it. It is derived here, from
// live identity facts, and never carries more than the first character of
// anything: "github:a***". A person recognises it; a screen, a log or a
// bystander learns almost nothing.

// ErrNoIdentityLabel means no recognisable label could be built from the
// facts that were read. It is a "cannot label", never a label: the caller
// refuses rather than print a blank or a raw value.
var ErrNoIdentityLabel = errors.New("glovoconsent: no identity label")

// IdentityFact is one live external identity of a principal.
type IdentityFact struct {
	Provider string
	// Display is informational only (a GitHub login). It is never emitted
	// beyond its first character.
	Display string
}

// IdentityFacts are the raw facts a label is built from.
type IdentityFacts struct {
	// DisplayName is the principal's own display name: the label source for
	// a Google customer, whose identity row carries no readable display.
	DisplayName string
	// Identities are the principal's non-revoked external identities.
	Identities []IdentityFact
}

// IdentitySource reads the facts of one principal. An error is a failed
// read, never "no identity"; the documented absence of a principal is
// ErrNoIdentityLabel-free and returned as an error by the implementation.
type IdentitySource interface {
	IdentityFacts(ctx context.Context, principalID string) (IdentityFacts, error)
}

// Provider prefixes that may appear in a label: a closed set, so an
// arbitrary provider string (a federation name) never reaches a screen.
const (
	labelGitHub = "github"
	labelGoogle = "google"
	labelMCTL   = "mctl"
)

// MaskIdentity builds the label: provider prefix, the first character of the
// readable name, and "***". A GitHub login is preferred; a Google identity,
// or no usable identity display, falls back to the principal's display name.
// A value that is empty, or that is a machine-made username
// (google.<sub>@...), is skipped: the first character of a generated name
// would mislead. No usable source is ErrNoIdentityLabel.
func MaskIdentity(f IdentityFacts) (string, error) {
	for _, x := range f.Identities {
		if x.Provider == labelGitHub {
			if c, ok := firstChar(x.Display); ok {
				return labelGitHub + ":" + c + "***", nil
			}
		}
	}
	if c, ok := firstChar(f.DisplayName); ok {
		prefix := labelMCTL
		for _, x := range f.Identities {
			if x.Provider == labelGoogle {
				prefix = labelGoogle
				break
			}
			if x.Provider == labelGitHub {
				prefix = labelGitHub
			}
		}
		return prefix + ":" + c + "***", nil
	}
	return "", ErrNoIdentityLabel
}

// firstChar is the first character of s when s is a readable name: valid
// UTF-8, not machine-made, its first rune a letter or digit.
func firstChar(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || strings.HasPrefix(strings.ToLower(s), "google.") {
		return "", false
	}
	r, _ := utf8.DecodeRuneInString(s)
	if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
		return "", false
	}
	return string(r), true
}
