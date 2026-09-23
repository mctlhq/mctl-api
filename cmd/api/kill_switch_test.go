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

import "testing"

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
