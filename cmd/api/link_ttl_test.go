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

package main

import (
	"testing"
	"time"
)

// A malformed SURFACE_LINK_TTL turns the feature off (every surface identity
// route answers 503) rather than defaulting to links that never expire.
func TestParseLinkTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":       0,
		"  ":     0,
		"2160h":  2160 * time.Hour,
		" 720h ": 720 * time.Hour,
		"90m":    90 * time.Minute,
	} {
		if got, err := parseLinkTTL(in); err != nil || got != want {
			t.Errorf("parseLinkTTL(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"0s", "0", "-1h", "2160", "forever", "1y"} {
		if got, err := parseLinkTTL(in); err == nil {
			t.Errorf("parseLinkTTL(%q) = %v, want an error", in, got)
		}
	}
}
