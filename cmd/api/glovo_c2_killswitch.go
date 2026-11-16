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

import (
	"fmt"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/glovoc2control"
)

// configureGlovoC2KillSwitch is dark unless GLOVO_C2_KILLSWITCH_ENABLED is
// "true". Enabled without GLOVO_C2_CONTROL_URL and GLOVO_C2_CONTROL_TOKEN (or
// with an invalid flag value) is a configuration error that refuses the boot,
// never a silently absent route.
func configureGlovoC2KillSwitch(lookup func(string) (string, bool)) (*mctlapi.GlovoC2KillSwitch, error) {
	v, ok := lookup("GLOVO_C2_KILLSWITCH_ENABLED")
	if !ok || v == "" || v == "false" {
		return nil, nil
	}
	if v != "true" {
		return nil, fmt.Errorf("GLOVO_C2_KILLSWITCH_ENABLED must be true or false")
	}
	base, _ := lookup("GLOVO_C2_CONTROL_URL")
	token, _ := lookup("GLOVO_C2_CONTROL_TOKEN")
	c, err := glovoc2control.New(base, token, nil)
	if err != nil {
		return nil, fmt.Errorf("GLOVO_C2_KILLSWITCH_ENABLED needs a valid GLOVO_C2_CONTROL_URL and GLOVO_C2_CONTROL_TOKEN: %w", err)
	}
	return &mctlapi.GlovoC2KillSwitch{Setter: c}, nil
}
