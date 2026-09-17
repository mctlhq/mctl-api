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
	"reflect"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"":                 nil,
		"mctlhq":           {"mctlhq"},
		" mctlhq , other ": {"mctlhq", "other"},
		",,a,,":            {"a"},
	}
	for in, want := range cases {
		if got := splitCSV(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitCSV(%q) = %#v, want %#v", in, got, want)
		}
	}
}
