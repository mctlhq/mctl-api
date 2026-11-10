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

package glovojoin

import "time"

// GlovoApprovalTTL is a variable only in the fixture build
// (glovojoin_fixture) so a test can drive an approval expiry with a short real
// duration (T13). No release-build code path reads a variable.
var GlovoApprovalTTL = 15 * time.Minute

// SetFixtureGlovoApprovalTTL sets GlovoApprovalTTL. A test calls it before it
// starts the router.
func SetFixtureGlovoApprovalTTL(d time.Duration) { GlovoApprovalTTL = d }
