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
	"os"
	"regexp"
	"testing"
)

func TestKillSwitchErrsTowardOff(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false}, {"false", false}, {"f", false}, {"F", false}, {"0", false}, {"no", false}, {"off", false},
		{"  FALSE\t", false},
		{"true", true}, {"1", true}, {"TRUE", true}, {"yes", true}, {"on", true}, {"disabled", true},
	}
	for _, c := range cases {
		if got := killSwitchOn(c.value); got != c.want {
			t.Errorf("killSwitchOn(%q) = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestLoadConfigReadsCommerceAcceptDisabled(t *testing.T) {
	for value, want := range map[string]bool{"": false, "off": false, "false": false, "true": true, "1": true} {
		t.Setenv("COMMERCE_ACCEPT_DISABLED", value)
		if got := loadConfig().CommerceAcceptDisabled; got != want {
			t.Errorf("COMMERCE_ACCEPT_DISABLED=%q: CommerceAcceptDisabled = %v, want %v", value, got, want)
		}
	}
}

// main() is not unit-testable, so pin in the source that the switch reaches
// the router: read but never passed, it would silently mean nothing.
func TestMainPassesCommerceAcceptDisabledToTheRouter(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`CommerceAcceptDisabled:\s+cfg\.CommerceAcceptDisabled,`).Match(src) {
		t.Error("main.go does not pass cfg.CommerceAcceptDisabled into mctlapi.Options")
	}
}
