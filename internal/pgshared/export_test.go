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

package pgshared

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WithSharing turns sharing on for one test (internal or external package)
// and, at cleanup, turns it off and checks that the test released every pool
// it opened: a leftover entry would otherwise be handed to a later test.
func WithSharing(t *testing.T) { withSharing(t) }

func withSharing(t *testing.T) {
	t.Helper()
	EnableSharing()
	t.Cleanup(func() { resetRegistry(t) })
}

func resetRegistry(t *testing.T) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	sharing = false
	if len(byConn) != 0 || len(byPool) != 0 {
		t.Errorf("registry not empty after the test: %d conn strings, %d pools", len(byConn), len(byPool))
	}
	byConn = map[string]*entry{}
	byPool = map[*pgxpool.Pool]string{}
}
