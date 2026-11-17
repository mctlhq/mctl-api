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
	"errors"
	"strings"
	"testing"
)

func TestMaskIdentity(t *testing.T) {
	gh := func(d string) IdentityFact { return IdentityFact{Provider: "github", Display: d} }
	cases := []struct {
		name string
		in   IdentityFacts
		want string
	}{
		{"github login", IdentityFacts{DisplayName: "Zed Zed", Identities: []IdentityFact{gh("alice-dev")}}, "github:a***"},
		{"first rune only, multibyte", IdentityFacts{Identities: []IdentityFact{gh("Ärger")}}, "github:Ä***"},
		{"google customer uses display name", IdentityFacts{DisplayName: "Jane Roe", Identities: []IdentityFact{{Provider: "google", Display: "google.109876543210987654321@mctl.ai"}}}, "google:J***"},
		{"google with empty display", IdentityFacts{DisplayName: "bob", Identities: []IdentityFact{{Provider: "google"}}}, "google:b***"},
		{"github without display falls back to name", IdentityFacts{DisplayName: "carol", Identities: []IdentityFact{gh("")}}, "github:c***"},
		{"unknown provider never printed", IdentityFacts{DisplayName: "dave", Identities: []IdentityFact{{Provider: "zitadel-internal-x", Display: "dave"}}}, "mctl:d***"},
	}
	for _, c := range cases {
		got, err := MaskIdentity(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestMaskIdentityNeverLeaksMoreThanTheFirstCharacter(t *testing.T) {
	secrets := []string{"supersecretlogin", "raw.person@example.com", "prn_01HZZZZZZZZZZZZZZZZZZZZZZZ", "Ünïcode Name"}
	for _, s := range secrets {
		for _, f := range []IdentityFacts{
			{Identities: []IdentityFact{{Provider: "github", Display: s}}},
			{DisplayName: s, Identities: []IdentityFact{{Provider: "google"}}},
			{DisplayName: s},
		} {
			got, err := MaskIdentity(f)
			if err != nil {
				t.Fatalf("%q: %v", s, err)
			}
			if !strings.HasSuffix(got, "***") || strings.Contains(got, s) {
				t.Errorf("label %q leaks %q", got, s)
			}
			body := strings.TrimSuffix(got, "***")
			body = body[strings.Index(body, ":")+1:]
			if n := len([]rune(body)); n != 1 {
				t.Errorf("label %q shows %d characters, want exactly 1", got, n)
			}
		}
	}
}

func TestMaskIdentityRefusesWhenNothingIsReadable(t *testing.T) {
	for name, f := range map[string]IdentityFacts{
		"empty":             {},
		"blank name":        {DisplayName: "   "},
		"machine username":  {DisplayName: "google.109876543210987654321@mctl.ai"},
		"symbol first rune": {DisplayName: "***"},
		"invalid utf8":      {DisplayName: "\xff\xfeabc"},
		"github blank":      {Identities: []IdentityFact{{Provider: "github", Display: " "}}},
	} {
		if got, err := MaskIdentity(f); !errors.Is(err, ErrNoIdentityLabel) || got != "" {
			t.Errorf("%s: got %q, %v; want ErrNoIdentityLabel and no label", name, got, err)
		}
	}
}
