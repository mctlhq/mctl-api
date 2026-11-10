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

import "testing"

// Bridge enabled with only AUDIT_DB_URL: no DSN, so main opens no store and
// the bridge routes answer 503 (mctl-api#987).
func TestBridgeStoreDSNIgnoresAuditDBURL(t *testing.T) {
	t.Setenv("MCTL_BRIDGE_ENABLED", "true")
	t.Setenv("COMMERCE_DB_URL", "")
	t.Setenv("AUDIT_DB_URL", "postgresql://audit.example:5432/audit?sslmode=require")
	if got := bridgeStoreDSN(); got != "" {
		t.Fatalf("bridgeStoreDSN() = %q with only AUDIT_DB_URL set; want empty (no store opened)", got)
	}
}

func TestBridgeStoreDSNUsesCommerceDBURL(t *testing.T) {
	const commerce = "postgresql://commerce.example:5432/commerce?sslmode=require"
	t.Setenv("COMMERCE_DB_URL", commerce)
	t.Setenv("AUDIT_DB_URL", "postgresql://audit.example:5432/audit?sslmode=require")
	if got := bridgeStoreDSN(); got != commerce {
		t.Fatalf("bridgeStoreDSN() = %q; want the COMMERCE_DB_URL value", got)
	}
}
