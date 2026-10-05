// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const registryPublisherToken32 = "registry-publisher-token-0123456789ab"

// mctlhq/mctl-agents#470: publishing to the agent registry gets its own
// principal, never the admin mctl-agent -- modelled on the two writers
// (TestEvidenceWriterTokenMintsASinglePermissionPrincipal). Run under both
// the federation registry and the pre-registry chain: the principal must be
// the same one whichever path authenticated it.
func TestRegistryPublisherTokenMintsANarrowPrincipal(t *testing.T) {
	for _, killSwitch := range []string{"", "true"} {
		t.Run("MCTL_FEDERATION_DISABLED="+killSwitch, func(t *testing.T) {
			t.Setenv("AUTH_REQUIRED", "true")
			t.Setenv("MCTL_FEDERATION_DISABLED", killSwitch)
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
			t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", registryPublisherToken32)
			u := authAs(t, registryPublisherToken32)
			if u == nil {
				t.Fatal("registry-publisher token refused")
			}
			if !u.IsRegistryPublisher() || u.ID != RegistryPublisherUserID {
				t.Fatalf("user = %+v", u)
			}
			if u.IsAdmin() || u.IsService() || u.IsUsageWriter() || u.IsEvidenceWriter() || u.IsAgent() || len(u.Groups) != 0 {
				t.Fatalf("the registry publisher carries authority: admin=%v service=%v groups=%v", u.IsAdmin(), u.IsService(), u.Groups)
			}
			if _, ok := u.Surface(); ok {
				t.Fatal("the registry publisher is a surface principal")
			}
			if u.HasTenantAccess("mctl") {
				t.Fatal("the registry publisher belongs to a tenant")
			}
			for _, p := range []string{PermissionUsageWrite, PermissionEvidenceWrite, "evidence:read", ""} {
				if u.HasPermission(p) {
					t.Fatalf("the registry publisher holds permission %q", p)
				}
			}
			id, ok := u.Identity()
			if !ok || id.Provider != ProviderService || id.Subject != RegistryPublisherUserID || id.Kind != KindService {
				t.Fatalf("identity = %+v", id)
			}
			// The agent service token is unchanged by the new principal.
			svc := authAs(t, "svc-token-123")
			if svc == nil || !svc.IsService() || !svc.IsAdmin() || svc.IsRegistryPublisher() || svc.ID != ServiceUserID {
				t.Fatalf("service principal = %+v", svc)
			}
			if u := authAs(t, registryPublisherToken32+"x"); u != nil {
				t.Fatalf("a wrong token authenticated as %+v", u)
			}
		})
	}
}

// statusFor runs the middleware for token and reports the status it wrote
// and whether the wrapped handler ran.
func statusFor(t *testing.T, token string) (code int, reached bool) {
	t.Helper()
	h := Middleware(NewGitHubValidator(nil), nil, nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, reached
}

// Unset is the state every deployment is in until the token is seeded: the
// principal does not exist, so a caller presenting what would be its token
// is unauthenticated (401), not forbidden, and the process still serves
// everyone else.
func TestRegistryPublisherUnsetMeansUnauthenticated(t *testing.T) {
	for _, killSwitch := range []string{"", "true"} {
		t.Run("MCTL_FEDERATION_DISABLED="+killSwitch, func(t *testing.T) {
			t.Setenv("AUTH_REQUIRED", "true")
			t.Setenv("MCTL_FEDERATION_DISABLED", killSwitch)
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
			t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", "")
			if code, reached := statusFor(t, registryPublisherToken32); code != http.StatusUnauthorized || reached {
				t.Fatalf("unset publisher token: got %d reached=%v, want 401 and no handler", code, reached)
			}
			if code, reached := statusFor(t, "svc-token-123"); code != http.StatusOK || !reached {
				t.Fatalf("service token with the publisher unset: got %d reached=%v, want it served", code, reached)
			}
			// Set, the same request is authenticated: the 401 above is the
			// unset variable, not a token this middleware could never accept.
			t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", registryPublisherToken32)
			if code, reached := statusFor(t, registryPublisherToken32); code != http.StatusOK || !reached {
				t.Fatalf("set publisher token: got %d reached=%v, want it authenticated", code, reached)
			}
		})
	}
}

// A token that is too short, or that another principal already uses, never
// mints the registry publisher -- and a shared value disables the other side
// too, so which provider is tried first cannot decide who the caller is. The
// one exception is the service token, which has no "disabled" state: it keeps
// authenticating as the service principal, and only the publisher is refused.
func TestRegistryPublisherTokenThatCouldBeConfusedIsRefused(t *testing.T) {
	const shared = registryPublisherToken32
	cases := []struct {
		name                                       string
		service, telegram, portal, usage, evidence string
		publisher                                  string
		wantOther                                  func(*User) bool
		wantOtherDescription                       string
	}{
		{name: "too short", service: "svc-token-123", publisher: "short-publisher-token",
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
		{name: "one character short", service: "svc-token-123", publisher: shared[:minSurfaceTokenLen-1],
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
		{name: "equal to the service token", service: shared, publisher: shared,
			wantOther: func(u *User) bool { return u.IsService() }, wantOtherDescription: "the service principal"},
		{name: "equal to the telegram surface token", service: "svc-token-123", telegram: shared, publisher: shared,
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
		{name: "equal to the portal surface token", service: "svc-token-123", portal: shared, publisher: shared,
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
		{name: "equal to the usage-writer token", service: "svc-token-123", usage: shared, publisher: shared,
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
		{name: "equal to the evidence-writer token", service: "svc-token-123", evidence: shared, publisher: shared,
			wantOther: func(u *User) bool { return u == nil }, wantOtherDescription: "refused"},
	}
	for _, c := range cases {
		for _, killSwitch := range []string{"", "true"} {
			t.Run(c.name+"/MCTL_FEDERATION_DISABLED="+killSwitch, func(t *testing.T) {
				t.Setenv("AUTH_REQUIRED", "true")
				t.Setenv("MCTL_FEDERATION_DISABLED", killSwitch)
				t.Setenv("MCTL_AGENT_SERVICE_TOKEN", c.service)
				t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", c.telegram)
				t.Setenv("MCTL_SURFACE_PORTAL_TOKEN", c.portal)
				t.Setenv("MCTL_USAGE_WRITER_TOKEN", c.usage)
				t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.evidence)
				t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", c.publisher)
				u := authAs(t, c.publisher)
				if u.IsRegistryPublisher() {
					t.Fatalf("minted the registry publisher from a token that proves something else: %+v", u)
				}
				if !c.wantOther(u) {
					t.Fatalf("the confusable token authenticated as %+v, want %s", u, c.wantOtherDescription)
				}
				// A refused publisher token is never a startup failure: the
				// service principal still authenticates.
				if c.service != c.publisher {
					if svc := authAs(t, c.service); svc == nil || !svc.IsService() {
						t.Fatalf("service principal = %+v after a refused publisher token", svc)
					}
				}
			})
		}
	}
}

// The minimum length is exactly minSurfaceTokenLen: a token of that length
// is accepted, one shorter is not (the case above).
func TestRegistryPublisherTokenAtTheMinimumLengthIsAccepted(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	token := registryPublisherToken32[:minSurfaceTokenLen]
	t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", token)
	if u := authAs(t, token); !u.IsRegistryPublisher() {
		t.Fatalf("a %d-character token was refused: %+v", len(token), u)
	}
}

// The other tokens are untouched by a publisher token that differs from
// them: adding the principal must not disable anything.
func TestRegistryPublisherTokenLeavesDistinctTokensAlone(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", tgToken)
	t.Setenv("MCTL_SURFACE_PORTAL_TOKEN", portalToken)
	t.Setenv("MCTL_USAGE_WRITER_TOKEN", usageWriterToken32)
	t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", evidenceWriterToken32)
	for _, publisher := range []string{"", registryPublisherToken32} {
		t.Setenv("MCTL_REGISTRY_PUBLISHER_TOKEN", publisher)
		if u := authAs(t, usageWriterToken32); !u.IsUsageWriter() {
			t.Fatalf("publisher=%q: usage writer = %+v", publisher, u)
		}
		if u := authAs(t, evidenceWriterToken32); !u.IsEvidenceWriter() {
			t.Fatalf("publisher=%q: evidence writer = %+v", publisher, u)
		}
		for token, surface := range map[string]string{tgToken: "telegram", portalToken: "portal"} {
			if got, ok := authAs(t, token).Surface(); !ok || got != surface {
				t.Fatalf("publisher=%q: surface %s = %q %v", publisher, surface, got, ok)
			}
		}
	}
}

// The registry publisher holds neither writer permission, and no other
// principal becomes the registry publisher by holding one.
func TestRegistryPublisherHoldsNoWriterPermission(t *testing.T) {
	u := NewRegistryPublisherUser()
	if u.HasPermission(PermissionUsageWrite) || u.HasPermission(PermissionEvidenceWrite) {
		t.Fatal("the registry publisher holds a writer permission")
	}
	var nobody *User
	for name, other := range map[string]*User{
		"admin":           {ID: "a", Groups: []string{"admins"}},
		"service":         NewServiceUser(),
		"usage writer":    NewUsageWriterUser(),
		"evidence writer": NewEvidenceWriterUser(),
		"surface":         NewSurfaceUser("telegram"),
		"tenant member":   {ID: "t", Groups: []string{"some-tenant"}},
		"nil":             nobody,
	} {
		if other.IsRegistryPublisher() {
			t.Errorf("%s is the registry publisher", name)
		}
	}
}
