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

import (
	"testing"
	"time"
)

// T13 (fixture half): the seam moves the TTL and nothing else.
func TestFixtureApprovalTTLSeam(t *testing.T) {
	prev := GlovoApprovalTTL
	t.Cleanup(func() { GlovoApprovalTTL = prev })
	SetFixtureGlovoApprovalTTL(2 * time.Second)
	if GlovoApprovalTTL != 2*time.Second {
		t.Fatalf("TTL %s", GlovoApprovalTTL)
	}
}
