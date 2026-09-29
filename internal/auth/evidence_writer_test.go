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

package auth

import "testing"

const evidenceWriterToken32 = "evidence-writer-token-0123456789abcd"

// mctl-api#409: the evidence producer gets its own principal with a single
// permission, never the admin mctl-agent -- modelled one-for-one on the
// usage writer (TestUsageWriterTokenMintsASinglePermissionPrincipal).
func TestEvidenceWriterTokenMintsASinglePermissionPrincipal(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", evidenceWriterToken32)
	u := authAs(t, evidenceWriterToken32)
	if u == nil {
		t.Fatal("evidence-writer token refused")
	}
	if !u.IsEvidenceWriter() || u.ID != EvidenceWriterUserID {
		t.Fatalf("user = %+v", u)
	}
	if u.IsAdmin() || u.IsService() || len(u.Groups) != 0 {
		t.Fatalf("the evidence writer carries authority: admin=%v service=%v groups=%v", u.IsAdmin(), u.IsService(), u.Groups)
	}
	if _, ok := u.Surface(); ok {
		t.Fatal("the evidence writer is a surface principal")
	}
	if !u.HasPermission(PermissionEvidenceWrite) || u.HasPermission("evidence:read") || u.HasPermission("") {
		t.Fatal("the evidence writer's permissions are not exactly evidence:write")
	}
	id, ok := u.Identity()
	if !ok || id.Provider != ProviderService || id.Subject != EvidenceWriterUserID || id.Kind != KindService {
		t.Fatalf("identity = %+v", id)
	}
	if svc := authAs(t, "svc-token-123"); svc == nil || !svc.IsService() || svc.IsEvidenceWriter() {
		t.Fatalf("service principal = %+v", svc)
	}
	if u := authAs(t, evidenceWriterToken32+"x"); u != nil {
		t.Fatalf("a wrong token authenticated as %+v", u)
	}
}

func TestEvidenceWriterTokenThatCouldBeConfusedIsRefused(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	cases := []struct{ name, service, telegram, usage, writer string }{
		{"too short", "svc-token-123", "", "", "short"},
		{"equal to the service token", evidenceWriterToken32, "", "", evidenceWriterToken32},
		{"equal to a surface token", "svc-token-123", evidenceWriterToken32, "", evidenceWriterToken32},
		{"equal to the usage-writer token", "svc-token-123", "", evidenceWriterToken32, evidenceWriterToken32},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", c.service)
			t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", c.telegram)
			t.Setenv("MCTL_USAGE_WRITER_TOKEN", c.usage)
			t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.writer)
			if u := authAs(t, c.writer); u.IsEvidenceWriter() {
				t.Fatalf("minted the evidence writer from a token that proves something else: %+v", u)
			}
		})
	}
}

func TestOnlyAdminsAndTheEvidenceWriterMayWriteEvidence(t *testing.T) {
	var nobody *User
	for name, c := range map[string]struct {
		u    *User
		want bool
	}{
		"evidence writer": {NewEvidenceWriterUser(), true},
		"admin":           {&User{ID: "a", Groups: []string{"admins"}}, true},
		"service":         {NewServiceUser(), true},
		"usage writer":    {NewUsageWriterUser(), false},
		"tenant member":   {&User{ID: "t", Groups: []string{"some-tenant"}}, false},
		"surface":         {NewSurfaceUser("telegram"), false},
		"nil":             {nobody, false},
	} {
		if got := c.u.HasPermission(PermissionEvidenceWrite); got != c.want {
			t.Errorf("%s: HasPermission(evidence:write) = %v, want %v", name, got, c.want)
		}
	}
}
