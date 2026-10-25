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

import (
	"reflect"
	"testing"
)

//nolint:gosec // test fixtures, not credentials
const (
	secTrivyToken      = "trivy-provider-token-0123456789abcdef"
	secDependabotToken = "dependabot-provider-token-0123456789ab"
	secProvidersJSON   = `[{"ref":"trivy","max_strength":"scanner_rerun_exact_revision","tenants":["admins"]},` +
		`{"ref":"dependabot","max_strength":"provider_claim","tenants":["labs","karabu"]}]`
)

// T21: a configured provider token authenticates as
// service:security-provider:<ref>; short, duplicated, cross-reused or
// unconfigured tokens disable that provider.
func TestSecurityProviderTokenMintsANarrowPrincipal(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("SECURITY_PROVIDERS", secProvidersJSON)
	t.Setenv("MCTL_SECURITY_PROVIDER_TOKENS", "trivy="+secTrivyToken+"\n# a comment\ndependabot="+secDependabotToken+"\n")

	u := authAs(t, secTrivyToken)
	if u == nil || u.SecurityProviderRef() != "trivy" || u.ID != "service:security-provider:trivy" {
		t.Fatalf("trivy token: %+v", u)
	}
	d := authAs(t, secDependabotToken)
	if d == nil || d.SecurityProviderRef() != "dependabot" {
		t.Fatalf("dependabot token: %+v", d)
	}
	id, ok := u.Identity()
	if !ok || id.Provider != ProviderService || id.Subject != "service:security-provider:trivy" || id.Kind != KindService {
		t.Fatalf("identity = %+v", id)
	}
	if got := authAs(t, secTrivyToken+"x"); got != nil {
		t.Fatalf("a wrong token authenticated as %+v", got)
	}
	if svc := authAs(t, "svc-token-123"); svc == nil || !svc.IsService() || svc.SecurityProviderRef() != "" {
		t.Fatalf("service principal = %+v", svc)
	}
}

func TestSecurityProviderTokenThatCouldBeConfusedIsRefused(t *testing.T) {
	cases := []struct {
		name, tokens, evidence, providers string
	}{
		{"too short", "trivy=short", "", secProvidersJSON},
		{"equal to another principal's token", "trivy=" + secTrivyToken, secTrivyToken, secProvidersJSON},
		{"shared by two providers", "trivy=" + secTrivyToken + "\ndependabot=" + secTrivyToken, "", secProvidersJSON},
		{"no SECURITY_PROVIDERS entry", "ghost=" + secTrivyToken, "", secProvidersJSON},
		{"provider configuration is malformed", "trivy=" + secTrivyToken, "", `[{"ref":"trivy"`},
		{"provider has no tenants", "trivy=" + secTrivyToken, "", `[{"ref":"trivy","max_strength":"provider_claim","tenants":[]}]`},
		{"two tokens for one provider", "trivy=" + secTrivyToken + "\ntrivy=" + secDependabotToken, "", secProvidersJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AUTH_REQUIRED", "true")
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
			t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.evidence)
			t.Setenv("SECURITY_PROVIDERS", c.providers)
			t.Setenv("MCTL_SECURITY_PROVIDER_TOKENS", c.tokens)
			for _, token := range []string{secTrivyToken, secDependabotToken, "short"} {
				if u := authAs(t, token); u != nil && u.SecurityProviderRef() != "" {
					t.Fatalf("minted a provider principal from a token that proves something else: %+v", u)
				}
			}
		})
	}
}

// T22: the provider principal is not an admin, has no tenant access and holds
// only security:ingest.
func TestSecurityProviderHoldsOnlyIngest(t *testing.T) {
	u := NewSecurityProviderUser("trivy")
	if u.IsAdmin() || u.IsService() || u.HasTenantAccess("admins") || len(u.Groups) != 0 {
		t.Fatalf("the provider carries authority: %+v", u)
	}
	if !u.HasPermission(PermissionSecurityIngest) {
		t.Fatal("a provider must hold security:ingest")
	}
	for _, p := range []string{PermissionSecurityRemediate, PermissionEvidenceWrite, PermissionUsageWrite, "", "security:read"} {
		if u.HasPermission(p) {
			t.Fatalf("a provider must not hold %q", p)
		}
	}
	// Only admins, besides providers, may ingest; only the service
	// principal (and agents minted with it) may remediate.
	admin := &User{ID: "root", Groups: []string{"admins"}}
	if !admin.HasPermission(PermissionSecurityIngest) || admin.HasPermission(PermissionSecurityRemediate) {
		t.Fatal("admins may ingest but hold remediate only through the roles rules")
	}
	if !NewServiceUser().HasPermission(PermissionSecurityRemediate) {
		t.Fatal("the service principal holds security:remediate")
	}
	agent := NewAgentUser("remediator", AgentRun{Permissions: []string{PermissionSecurityRemediate}})
	if !agent.HasPermission(PermissionSecurityRemediate) || agent.HasPermission(PermissionSecurityIngest) {
		t.Fatal("an agent holds exactly the permissions it was minted with")
	}
	var nobody *User
	if nobody.HasPermission(PermissionSecurityIngest) || nobody.SecurityProviderRef() != "" {
		t.Fatal("a nil user holds nothing")
	}
}

func TestParseSecurityProviders(t *testing.T) {
	got, err := ParseSecurityProviders(secProvidersJSON)
	if err != nil {
		t.Fatal(err)
	}
	want := []SecurityProviderConfig{
		{Ref: "trivy", MaxStrength: "scanner_rerun_exact_revision", Tenants: []string{"admins"}},
		{Ref: "dependabot", MaxStrength: "provider_claim", Tenants: []string{"labs", "karabu"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if none, err := ParseSecurityProviders("  "); err != nil || none != nil {
		t.Fatalf("empty configuration: %v %v", none, err)
	}
	for name, raw := range map[string]string{
		"bad ref":   `[{"ref":"Bad Ref","tenants":["a"]}]`,
		"duplicate": `[{"ref":"a","tenants":["x"]},{"ref":"a","tenants":["y"]}]`,
		"no tenant": `[{"ref":"a","tenants":[]}]`,
		"blank":     `[{"ref":"a","tenants":[" "]}]`,
		"not json":  `trivy`,
	} {
		if _, err := ParseSecurityProviders(raw); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
