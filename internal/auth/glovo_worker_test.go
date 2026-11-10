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
	"os"
	"path/filepath"
	"testing"
)

const glovoWorkerToken32 = "glovo-worker-token-0123456789abcdef"

func writeWorkerToken(t *testing.T, content string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", f)
}

// Default OFF: with no credential file there is no worker, and no token maps
// to one.
func TestGlovoWorkerIsOffByDefault(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", "")
	if GlovoWorkerConfigured() {
		t.Fatal("configured with no file")
	}
	if u := authAs(t, glovoWorkerToken32); u != nil && u.IsGlovoWorker() {
		t.Fatal("a worker was minted with no credential configured")
	}
	if (&User{ID: GlovoWorkerUserID}).IsGlovoWorker() {
		t.Fatal("the reserved id alone must not be the worker")
	}
}

func TestGlovoWorkerCredentialMintsANarrowPrincipal(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	writeWorkerToken(t, glovoWorkerToken32+"\n")
	if !GlovoWorkerConfigured() {
		t.Fatal("not configured")
	}
	u := authAs(t, glovoWorkerToken32)
	if u == nil || !u.IsGlovoWorker() || u.ID != GlovoWorkerUserID {
		t.Fatalf("user = %+v", u)
	}
	if u.IsAdmin() || u.IsService() || u.IsAgent() || u.IsGlovoAudience() || len(u.Groups) != 0 || u.BridgeProviderRef() != "" {
		t.Fatalf("the worker carries authority: %+v", u)
	}
	id, ok := u.Identity()
	if !ok || id.Provider != ProviderService || id.Subject != GlovoWorkerUserID || id.Kind != KindService {
		t.Fatalf("identity = %+v", id)
	}
	if svc := authAs(t, "svc-token-123"); svc == nil || svc.IsGlovoWorker() {
		t.Fatalf("service principal = %+v", svc)
	}
	if other := authAs(t, glovoWorkerToken32+"x"); other != nil && other.IsGlovoWorker() {
		t.Fatal("a different token is the worker")
	}
}

func TestGlovoWorkerCredentialThatCouldBeConfusedIsRefused(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	for name, c := range map[string]struct{ file, service, evidence, bridge string }{
		"too short":                   {"short", "svc-token-123", "", ""},
		"equal to the service token":  {glovoWorkerToken32, glovoWorkerToken32, "", ""},
		"equal to the evidence token": {glovoWorkerToken32, "svc-token-123", glovoWorkerToken32, ""},
		"equal to a bridge token":     {glovoWorkerToken32, "svc-token-123", "", "ref=" + glovoWorkerToken32},
		"empty":                       {"\n", "svc-token-123", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", c.service)
			t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.evidence)
			t.Setenv("MCTL_BRIDGE_PROVIDER_TOKENS", c.bridge)
			writeWorkerToken(t, c.file)
			if GlovoWorkerConfigured() {
				t.Fatal("configured")
			}
			if u := authAs(t, glovoWorkerToken32); u != nil && u.IsGlovoWorker() {
				t.Fatalf("minted the worker from a credential that proves something else: %+v", u)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
		if GlovoWorkerConfigured() {
			t.Fatal("configured with a missing file")
		}
	})
}
