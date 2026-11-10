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

//go:build glovojoin_fixture

package control

import "time"

// DispatchCommandTTL is a variable only in the fixture build
// (glovojoin_fixture), so mctl-api#990 can drive a timeout row with a short
// real duration. No release-build code path reads a variable.
var DispatchCommandTTL = 900 * time.Second

// SetFixtureDispatchCommandTTL sets DispatchCommandTTL. A test calls it before
// it starts the router.
func SetFixtureDispatchCommandTTL(d time.Duration) { DispatchCommandTTL = d }
