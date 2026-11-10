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

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func TestFixtureSeam(t *testing.T) {
	if !glovo.ControlDefault.Open {
		t.Fatal("the fixture build must open the control gate")
	}
	if glovo.Default.Open {
		t.Fatal("the fixture tag must not open the Glovo gate")
	}
	prev := DispatchCommandTTL
	t.Cleanup(func() { DispatchCommandTTL = prev })
	SetFixtureDispatchCommandTTL(3 * time.Second)
	if DispatchCommandTTL != 3*time.Second {
		t.Fatalf("TTL %s", DispatchCommandTTL)
	}
}
