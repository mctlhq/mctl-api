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

package control

import (
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The collaborator interfaces are narrow views of the real stores. These pins
// make the compiler, not a test double, say when a real store drifts from what
// the dispatcher calls.
var (
	_ OrderIndex  = (*orders.Store)(nil)
	_ Receipts    = (*workitems.Store)(nil)
	_ Executions  = (*workitems.Store)(nil)
	_ Connections = (*glovo.Store)(nil)
	_ Bridge      = (*bridge.Store)(nil)
	_ JoinRefs    = (*orders.Store)(nil)

	_ ControlStartFunc = glovojoin.ControlStartTx
)
