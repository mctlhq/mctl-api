// Copyright 2025 MCTL Authors
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

// Dex is retired by removing DEX_ISSUER_URL from the deployment. That only
// works if an unset variable means "no Dex" rather than a built-in issuer:
// with a default, the verifier and its /readyz check would keep pointing at
// a Dex that no longer exists, and every pod would go unready.
//
// Mutation check (verified by hand): restoring the old
// envOr("DEX_ISSUER_URL", "https://ops.mctl.ai/api/dex") fails the first case.
func TestDexIssuerURLHasNoDefault(t *testing.T) {
	t.Setenv("DEX_ISSUER_URL", "")
	if got := loadConfig().DexIssuerURL; got != "" {
		t.Errorf("DexIssuerURL with DEX_ISSUER_URL unset: got %q, want empty (Dex off)", got)
	}

	t.Setenv("DEX_ISSUER_URL", "https://dex.example/api/dex")
	if got := loadConfig().DexIssuerURL; got != "https://dex.example/api/dex" {
		t.Errorf("DexIssuerURL: got %q, want the configured issuer", got)
	}
}
