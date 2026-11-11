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

package auth

import (
	"path/filepath"
	"testing"
)

//nolint:gosec // G101: synthetic test-only token, not a credential
const glovoFacadeToken40 = "glovo-facade-token-0123456789abcdef-xyz"

func TestGlovoFacadeIsOffByDefault(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_GLOVO_FACADE_TOKEN", "")
	if GlovoFacadeConfigured() || GlovoFacadeTokenProblem() != "" {
		t.Fatal("configured or problem with no token")
	}
	if u := authAs(t, glovoFacadeToken40); u != nil && u.IsGlovoFacade() {
		t.Fatal("a facade was minted with no credential configured")
	}
	if (&User{ID: GlovoFacadeUserID}).IsGlovoFacade() {
		t.Fatal("the reserved id alone must not be the facade")
	}
}

func TestGlovoFacadeCredentialMintsANarrowPrincipal(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_GLOVO_FACADE_TOKEN", glovoFacadeToken40)
	if !GlovoFacadeConfigured() {
		t.Fatal("not configured")
	}
	u := authAs(t, glovoFacadeToken40)
	if u == nil || !u.IsGlovoFacade() || u.ID != GlovoFacadeUserID {
		t.Fatalf("user = %+v", u)
	}
	if u.IsAdmin() || u.IsService() || u.IsAgent() || u.IsGlovoAudience() || u.IsGlovoWorker() || u.IsGlovoControlWorker() ||
		len(u.Groups) != 0 || u.BridgeProviderRef() != "" || u.PrincipalID() != "" {
		t.Fatalf("the facade carries authority or a user identity: %+v", u)
	}
	id, ok := u.Identity()
	if !ok || id.Provider != ProviderService || id.Subject != GlovoFacadeUserID || id.Kind != KindService {
		t.Fatalf("identity = %+v", id)
	}
	if svc := authAs(t, "svc-token-123"); svc == nil || svc.IsGlovoFacade() {
		t.Fatalf("service principal = %+v", svc)
	}
	if other := authAs(t, glovoFacadeToken40+"x"); other != nil && other.IsGlovoFacade() {
		t.Fatal("a different token is the facade")
	}
	if glovoFacadeUserFor(glovoFacadeToken40, glovoFacadeToken40[:len(glovoFacadeToken40)-1]) != nil {
		t.Fatal("a prefix matched")
	}
}

// Startup refusal: a facade token equal to any other machine token is a
// problem the process must refuse to boot with.
func TestGlovoFacadeTokenEqualToAnotherPrincipalIsRefused(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	for name, c := range map[string]struct{ token, service, evidence, bridge, worker, want string }{
		"too short":                   {"short", "svc-token-123", "", "", "", "too_short"},
		"equal to the service token":  {glovoFacadeToken40, glovoFacadeToken40, "", "", "", "equals_MCTL_AGENT_SERVICE_TOKEN"},
		"equal to the evidence token": {glovoFacadeToken40, "svc-token-123", glovoFacadeToken40, "", "", "equals_MCTL_EVIDENCE_WRITER_TOKEN"},
		"equal to a bridge token":     {glovoFacadeToken40, "svc-token-123", "", "ref=" + glovoFacadeToken40, "", "equals_MCTL_BRIDGE_PROVIDER_TOKENS"},
		"equal to the worker token":   {glovoFacadeToken40, "svc-token-123", "", "", glovoFacadeToken40, "equals_MCTL_GLOVO_WORKER_TOKEN_FILE"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", c.service)
			t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.evidence)
			t.Setenv("MCTL_BRIDGE_PROVIDER_TOKENS", c.bridge)
			t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", "")
			if c.worker != "" {
				writeWorkerToken(t, c.worker)
			}
			t.Setenv("MCTL_GLOVO_FACADE_TOKEN", c.token)
			if got := GlovoFacadeTokenProblem(); got != c.want {
				t.Fatalf("problem = %q, want %q", got, c.want)
			}
			if GlovoFacadeConfigured() {
				t.Fatal("configured")
			}
			if u := authAs(t, glovoFacadeToken40); u != nil && u.IsGlovoFacade() {
				t.Fatalf("minted the facade from a credential that proves something else: %+v", u)
			}
		})
	}
	t.Run("missing worker file is no conflict", func(t *testing.T) {
		t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
		t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
		t.Setenv("MCTL_GLOVO_FACADE_TOKEN", glovoFacadeToken40)
		if !GlovoFacadeConfigured() {
			t.Fatal("not configured")
		}
	})
}
