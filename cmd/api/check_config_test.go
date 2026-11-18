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

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// checkConfigEnv is the environment the platform runs with: the zitadel entry
// as zitadel-iac renders it, and the keys that cross-check it.
func checkConfigEnv(t *testing.T, providers string) {
	t.Helper()
	for _, k := range []string{
		"MCTL_OIDC_PROVIDERS", "MCTL_FEDERATION_DISABLED", "OAUTH_UPSTREAM",
		"OAUTH_ZITADEL_PROVIDER", "ZITADEL_LINK_PROVIDER", "OAUTH_JWT_SECRET",
		"OAUTH_ZITADEL_CLIENT_ID", "OAUTH_ZITADEL_CLIENT_SECRET",
		"ZITADEL_HOOK_CUSTOMERS_ORG_ID", "ZITADEL_HOOK_GITHUB_IDP_ID",
		"GLOVO_CONSENT_ENABLED", "GLOVO_CONSENT_SERVICE_PROVIDER", "GLOVO_CONSENT_SERVICE_SUBJECT",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("MCTL_OIDC_PROVIDERS", providers)
	t.Setenv("OAUTH_UPSTREAM", "zitadel")
	t.Setenv("OAUTH_ZITADEL_PROVIDER", "zitadel")
	t.Setenv("ZITADEL_LINK_PROVIDER", "zitadel")
	t.Setenv("OAUTH_JWT_SECRET", "placeholder")
	t.Setenv("OAUTH_ZITADEL_CLIENT_ID", "placeholder")
	t.Setenv("OAUTH_ZITADEL_CLIENT_SECRET", "placeholder")
	t.Setenv("ZITADEL_HOOK_CUSTOMERS_ORG_ID", "100000000000000001")
	t.Setenv("ZITADEL_HOOK_GITHUB_IDP_ID", "100000000000000002")
}

const zitadelEntryWithServiceSubjects = `[{"name":"zitadel","issuer":"https://auth.example.test","audiences":["100000000000000003"],"customers_org_id":"100000000000000001","service_subjects":{"100000000000000077":"100000000000000010"}}]`

const goodZitadelEntry = `[{"name":"zitadel","issuer":"https://auth.example.test","audiences":["100000000000000003"],"customers_org_id":"100000000000000001"}]`

func TestRunCheckConfig(t *testing.T) {
	cases := []struct {
		name      string
		providers string
		mutate    func(t *testing.T)
		wantCode  int
		wantErr   string
	}{
		{name: "the entry zitadel-iac renders", providers: goodZitadelEntry, wantCode: 0},
		{
			// gitops#2737, the 2026-11-17 crash loop: allowed since the owner
			// decision of the same day (service subjects skip the customers
			// checks; docs/federation.md "Threat model").
			name:      "service_subjects with customers_org_id",
			providers: zitadelEntryWithServiceSubjects,
			wantCode:  0,
		},
		{
			name:      "service_subjects with customers_org_id and a padded subject",
			providers: strings.Replace(zitadelEntryWithServiceSubjects, `"100000000000000077"`, `" 100000000000000077"`, 1),
			wantCode:  1,
			wantErr:   "empty or padded",
		},
		{
			name:      "same service subject on two entries",
			providers: `[` + zitadelEntryWithServiceSubjects[1:len(zitadelEntryWithServiceSubjects)-1] + `,{"name":"other","issuer":"https://other.example.test","audiences":["a"],"service_subjects":{"100000000000000077":"p"}}]`,
			wantCode:  1,
			wantErr:   "is listed on both entry",
		},
		{
			name:      "consent reader on a human entry without the subject in service_subjects",
			providers: goodZitadelEntry,
			mutate:    consentReader("zitadel", "100000000000000077"),
			wantCode:  1,
			wantErr:   "list it in that entry's service_subjects",
		},
		{
			name:      "consent reader listed in service_subjects",
			providers: zitadelEntryWithServiceSubjects,
			mutate:    consentReader("zitadel", "100000000000000077"),
			wantCode:  0,
		},
		{
			name:      "consent reader that is another subject than the listed one",
			providers: zitadelEntryWithServiceSubjects,
			mutate:    consentReader("zitadel", "100000000000000078"),
			wantCode:  1,
			wantErr:   "is not a service identity",
		},
		{
			name:      "consent reader naming a provider that is not configured",
			providers: zitadelEntryWithServiceSubjects,
			mutate:    consentReader("nowhere", "100000000000000077"),
			wantCode:  1,
			wantErr:   "is not an MCTL_OIDC_PROVIDERS entry",
		},
		{
			name:      "consent reader on a kind service entry",
			providers: `[{"name":"k8s-glovo","issuer":"https://k8s.example.test","audiences":["a"],"kind":"service"},` + goodZitadelEntry[1:],
			mutate:    consentReader("k8s-glovo", "system:serviceaccount:glovo:mctl-glovo"),
			wantCode:  0,
		},
		{
			name:      "consent enabled with no provider and no subject is refused, not silently off",
			providers: goodZitadelEntry,
			mutate:    consentReader("", ""),
			wantCode:  1,
			wantErr:   "requires GLOVO_CONSENT_SERVICE_PROVIDER and GLOVO_CONSENT_SERVICE_SUBJECT",
		},
		{
			name:      "consent enabled with a provider but an empty subject",
			providers: goodZitadelEntry,
			mutate:    consentReader("zitadel", "  "),
			wantCode:  1,
			wantErr:   "requires GLOVO_CONSENT_SERVICE_PROVIDER and GLOVO_CONSENT_SERVICE_SUBJECT",
		},
		{
			name:      "consent enabled with a subject but an empty provider",
			providers: goodZitadelEntry,
			mutate:    consentReader("", "100000000000000077"),
			wantCode:  1,
			wantErr:   "requires GLOVO_CONSENT_SERVICE_PROVIDER and GLOVO_CONSENT_SERVICE_SUBJECT",
		},
		{
			name:      "consent flag that is neither true nor false (the boot refuses it too)",
			providers: goodZitadelEntry,
			mutate: func(t *testing.T) {
				consentReader("zitadel", "100000000000000077")(t)
				t.Setenv("GLOVO_CONSENT_ENABLED", "yes")
			},
			wantCode: 1,
			wantErr:  "must be true or false",
		},
		{
			name:      "consent unset leaves the empty reader alone",
			providers: goodZitadelEntry,
			mutate:    func(t *testing.T) { t.Setenv("GLOVO_CONSENT_ENABLED", "") },
			wantCode:  0,
		},
		{
			name:      "consent disabled leaves the reader unchecked",
			providers: goodZitadelEntry,
			mutate: func(t *testing.T) {
				consentReader("nowhere", "x")(t)
				t.Setenv("GLOVO_CONSENT_ENABLED", "false")
			},
			wantCode: 0,
		},
		{
			name:      "customers_org_id differs from the identity hook",
			providers: strings.Replace(goodZitadelEntry, "100000000000000001", "100000000000000009", 1),
			wantCode:  1,
			wantErr:   "ZITADEL_HOOK_CUSTOMERS_ORG_ID",
		},
		{
			name:      "zitadel upstream without its provider entry",
			providers: ``,
			wantCode:  1,
			wantErr:   "OAUTH_UPSTREAM=zitadel needs",
		},
		{
			name:      "a malformed value is not an empty one",
			providers: `[{"name":"zitadel"`,
			wantCode:  1,
			wantErr:   "MCTL_OIDC_PROVIDERS",
		},
		{
			// The kill switch lets boot pass; the guard must not.
			name:      "kill switch does not hide a bad value",
			providers: strings.Replace(zitadelEntryWithServiceSubjects, `"100000000000000077"`, `" 100000000000000077"`, 1),
			mutate:    func(t *testing.T) { t.Setenv("MCTL_FEDERATION_DISABLED", "true") },
			wantCode:  1,
			wantErr:   "empty or padded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkConfigEnv(t, tc.providers)
			if tc.mutate != nil {
				tc.mutate(t)
			}
			var out, errb bytes.Buffer
			code := runCheckConfig(&out, &errb)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, tc.wantCode, errb.String())
			}
			if tc.wantCode == 0 {
				if strings.TrimSpace(out.String()) != checkConfigOK {
					t.Errorf("stdout = %q, want %q", out.String(), checkConfigOK)
				}
				return
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q on a refusal, want empty (the OK line must not appear)", out.String())
			}
			if !strings.Contains(errb.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", errb.String(), tc.wantErr)
			}
		})
	}
}

// Boot and the check share one function: with the kill switch off, validate()
// must refuse exactly what the check refuses.
func TestValidateRunsTheSameZitadelChecks(t *testing.T) {
	checkConfigEnv(t, strings.Replace(zitadelEntryWithServiceSubjects, `"100000000000000077"`, `" 100000000000000077"`, 1))
	err := loadConfig().validate()
	if err == nil || !strings.Contains(err.Error(), "empty or padded") {
		t.Fatalf("validate() = %v, want the service_subjects refusal", err)
	}
	// The consent reader cross-check is part of boot too.
	checkConfigEnv(t, goodZitadelEntry)
	consentReader("zitadel", "100000000000000077")(t)
	if err := loadConfig().validate(); err == nil || !strings.Contains(err.Error(), "service_subjects") {
		t.Fatalf("validate() = %v, want the consent reader refusal", err)
	}
}

// The gitops fixture (mctl-gitops zitadel-iac, platform-gitops/helm-charts/
// zitadel-iac/iac/mctl-api.tf): the MCTL_OIDC_PROVIDERS JSON the Job renders
// for the zitadel entry once it carries service_subjects again. The gitops
// guard (mctl-gitops#2766) runs `mctl-api --check-config` on exactly this
// shape; the file here is that shape with placeholder ids.
func TestCheckConfigAcceptsTheRenderedZitadelIACEntry(t *testing.T) {
	raw, err := os.ReadFile("testdata/zitadel_iac_mctl_oidc_providers.json")
	if err != nil {
		t.Fatal(err)
	}
	checkConfigEnv(t, strings.TrimSpace(string(raw)))
	consentReader("zitadel", "100000000000000077")(t)
	var out, errb bytes.Buffer
	if code := runCheckConfig(&out, &errb); code != 0 {
		t.Fatalf("rendered entry refused: %s", errb.String())
	}
	// Mutation guard: the same JSON with the subject dropped from the
	// reader's point of view is refused, so the fixture cannot pass blindly.
	consentReader("zitadel", "100000000000000099")(t)
	if code := runCheckConfig(&out, &errb); code != 1 {
		t.Fatal("check passed for a consent reader that is not a service subject")
	}
}

func consentReader(provider, subject string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Setenv("GLOVO_CONSENT_ENABLED", "true")
		t.Setenv("GLOVO_CONSENT_SERVICE_PROVIDER", provider)
		t.Setenv("GLOVO_CONSENT_SERVICE_SUBJECT", subject)
	}
}
