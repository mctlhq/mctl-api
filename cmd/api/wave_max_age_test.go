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

// An invalid ROADMAP_WAVE_MAX_AGE turns wave execution off; it never falls
// back to an unbounded or a zero age.
func TestParseWaveMaxAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":     30 * time.Minute,
		" ":    30 * time.Minute,
		"10m":  10 * time.Minute,
		" 1h ": time.Hour,
		"90s":  90 * time.Second,
	} {
		if got, err := parseWaveMaxAge(in); err != nil || got != want {
			t.Errorf("parseWaveMaxAge(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "0s", "-5m", "30", "forever"} {
		if got, err := parseWaveMaxAge(in); err == nil {
			t.Errorf("parseWaveMaxAge(%q) = %v, want an error", in, got)
		}
	}
}
