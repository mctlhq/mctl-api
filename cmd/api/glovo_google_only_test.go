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
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
)

// GLOVO_GOOGLE_ONLY_MODE: off and shadow boot; enforce and anything unknown
// refuse the boot, so a refusal with no implementation cannot be switched on
// and a typo is never read as off.
func TestGlovoGoogleOnlyModeAtBoot(t *testing.T) {
	base := func(raw string) config {
		return config{OAuthGitHubClientID: "gh", OAuthJWTSecret: "k", GlovoGoogleOnlyRaw: raw}
	}
	for _, tc := range []struct {
		raw  string
		want mctlapi.GlovoGoogleOnlyMode
	}{{"", mctlapi.GlovoGoogleOnlyOff}, {"off", mctlapi.GlovoGoogleOnlyOff}, {"shadow", mctlapi.GlovoGoogleOnlyShadow}} {
		c := base(tc.raw)
		if err := c.validate(); err != nil {
			t.Errorf("GLOVO_GOOGLE_ONLY_MODE=%q: validate = %v, want it to boot", tc.raw, err)
		}
		if got := c.glovoGoogleOnlyMode(); got != tc.want {
			t.Errorf("GLOVO_GOOGLE_ONLY_MODE=%q: mode = %q, want %q", tc.raw, got, tc.want)
		}
	}
	for _, raw := range []string{"enforce", "ENFORCE", "Shadow", "on", "true", "garbage"} {
		c := base(raw)
		err := c.validate()
		if err == nil || !strings.Contains(err.Error(), "GLOVO_GOOGLE_ONLY_MODE") {
			t.Errorf("GLOVO_GOOGLE_ONLY_MODE=%q: validate = %v, want a refusal naming the variable", raw, err)
		}
		// Even if validate were skipped, a refused value never becomes a
		// working mode.
		if got := c.glovoGoogleOnlyMode(); got != mctlapi.GlovoGoogleOnlyOff {
			t.Errorf("GLOVO_GOOGLE_ONLY_MODE=%q: mode = %q, want off", raw, got)
		}
	}
}
