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

package main

import "testing"

func TestConfigureGlovoJoinIsDarkUnlessEnabledAndConfigured(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	for name, c := range map[string]struct {
		env        map[string]string
		configured bool
		mounted    bool
		err        bool
	}{
		"unset":     {nil, true, false, false},
		"false":     {map[string]string{"GLOVO_JOIN_ENABLED": "false"}, true, false, false},
		"no facade": {map[string]string{"GLOVO_JOIN_ENABLED": "true"}, false, false, false},
		"on":        {map[string]string{"GLOVO_JOIN_ENABLED": "true"}, true, true, false},
		"garbage":   {map[string]string{"GLOVO_JOIN_ENABLED": "yes"}, true, false, true},
	} {
		got, err := configureGlovoJoin(env(c.env), c.configured)
		if (err != nil) != c.err || (got != nil) != c.mounted {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
		if got != nil && got.Routes != nil {
			t.Errorf("%s: a dependency was wired", name)
		}
	}
}
