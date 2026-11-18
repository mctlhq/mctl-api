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

package glovoconsent

import (
	"context"
	"testing"
	"time"
)

// Version must equal mctl-glovo's linkflow.ConsentVersion, as a literal:
// comparing the constant with itself would never notice a drift.
func TestVersionMatchesMctlGlovo(t *testing.T) {
	if Version != "c2-link-v2" {
		t.Fatalf("Version = %q, want the text version mctl-glovo shows (c2-link-v2)", Version)
	}
}

// A consent recorded to the earlier text (c2-link-v1, which allowed more
// than the current read-only wording) is not a consent to the current one:
// it grants nothing and starts no personal grant. Re-consent is required.
func TestPreviousTextConsentIsNotCurrent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	v1 := Record{ID: "gcn_1", PrincipalID: pidA, Version: "c2-link-v1", RecordedAt: now}
	g := ConsentGrants{Store: rowStore{rec: v1}}
	if ok, err := g.HasGrant(ctx, pidA, GrantC2); ok || err != nil {
		t.Fatalf("v1 consent HasGrant = %v %v, want no grant", ok, err)
	}
	if ok, err := g.HeldSince(ctx, pidA, now.Add(time.Hour)); ok || err != nil {
		t.Fatalf("v1 consent HeldSince = %v %v, want false", ok, err)
	}
	cur := v1
	cur.Version = Version
	if ok, err := (ConsentGrants{Store: rowStore{rec: cur}}).HasGrant(ctx, pidA, GrantC2); !ok || err != nil {
		t.Fatalf("current consent HasGrant = %v %v, want the grant", ok, err)
	}
}
