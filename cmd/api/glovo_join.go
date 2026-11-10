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
	"strings"

	"github.com/mctlhq/mctl-api/internal/api"
)

// configureGlovoJoin builds the join facade routes (mctl-api#957).
//
// It is dark by construction: the routes are mounted only when
// GLOVO_JOIN_ENABLED is true and the facade token is configured, and even then
// no dependency is attached here (no subject verifier, connection registry,
// read bridge or worker heartbeat is constructed in this binary yet), so every
// route but /compatibility answers 503 not_ready and /compatibility reports
// deploy_ready false. A nil result leaves the routes unmounted (404).
func configureGlovoJoin(lookup func(string) (string, bool), facadeConfigured bool) (*api.GlovoJoinRoutes, error) {
	v, _ := lookup("GLOVO_JOIN_ENABLED")
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fmt.Errorf("GLOVO_JOIN_ENABLED %q must be true or false", v)
	}
	if !facadeConfigured {
		return nil, nil
	}
	return &api.GlovoJoinRoutes{Enabled: true}, nil
}
