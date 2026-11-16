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

func killLookupOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestGlovoC2KillSwitchConfigDarkAndFailClosed(t *testing.T) {
	for _, m := range []map[string]string{{}, {"GLOVO_C2_KILLSWITCH_ENABLED": ""}, {"GLOVO_C2_KILLSWITCH_ENABLED": "false"}} {
		if k, err := configureGlovoC2KillSwitch(killLookupOf(m)); k != nil || err != nil {
			t.Fatalf("%v: k=%v err=%v", m, k, err)
		}
	}
	for _, m := range []map[string]string{
		{"GLOVO_C2_KILLSWITCH_ENABLED": "yes"},
		{"GLOVO_C2_KILLSWITCH_ENABLED": "true"},
		{"GLOVO_C2_KILLSWITCH_ENABLED": "true", "GLOVO_C2_CONTROL_URL": "http://x"},
		{"GLOVO_C2_KILLSWITCH_ENABLED": "true", "GLOVO_C2_CONTROL_TOKEN_FILE": "/var/run/glovo/token"},
	} {
		if k, err := configureGlovoC2KillSwitch(killLookupOf(m)); k != nil || err == nil {
			t.Fatalf("%v: k=%v err=%v", m, k, err)
		}
	}
	for _, rel := range []string{"token", "./token", "relative/token"} {
		m := map[string]string{"GLOVO_C2_KILLSWITCH_ENABLED": "true", "GLOVO_C2_CONTROL_URL": "http://x", "GLOVO_C2_CONTROL_TOKEN_FILE": rel}
		if k, err := configureGlovoC2KillSwitch(killLookupOf(m)); k != nil || err == nil {
			t.Fatalf("relative token path %q accepted", rel)
		}
	}
	// The retired static token alone must not enable the route.
	if k, err := configureGlovoC2KillSwitch(killLookupOf(map[string]string{"GLOVO_C2_KILLSWITCH_ENABLED": "true", "GLOVO_C2_CONTROL_URL": "http://x", "GLOVO_C2_CONTROL_TOKEN": "t"})); k != nil || err == nil {
		t.Fatalf("static token accepted: k=%v err=%v", k, err)
	}
	k, err := configureGlovoC2KillSwitch(killLookupOf(map[string]string{"GLOVO_C2_KILLSWITCH_ENABLED": "true", "GLOVO_C2_CONTROL_URL": "http://x", "GLOVO_C2_CONTROL_TOKEN_FILE": "/var/run/glovo/token"}))
	if k == nil || err != nil {
		t.Fatalf("k=%v err=%v", k, err)
	}
}
