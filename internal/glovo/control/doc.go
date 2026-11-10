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

// Package control is the Glovo control-worker slice of mctl-api#985 (M1b-3):
// the dispatcher that turns an approved, finalized order into one
// place_order_fake bridge command in a single transaction, cancels it, and
// answers the two reads the DevLoop control activities poll. It also holds the
// one-database proof and the result-to-order table (reconcileOrder).
//
// Everything is dark: nothing mounts a route or installs a write fence unless
// the build constant glovo.ControlDefault is open and the wiring says so, and a
// missing collaborator or a failed proof answers not_ready. The lock order is
// the canonical L1..L6 of mctl-api#957 design 6b; see docs/glovo-control.md.
package control
