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
			// gitops#2737, the 2026-11-17 crash loop.
			name:      "service_subjects with customers_org_id",
			providers: `[{"name":"zitadel","issuer":"https://auth.example.test","audiences":["100000000000000003"],"customers_org_id":"100000000000000001","service_subjects":{"svc-sub":"aud"}}]`,
			wantCode:  1,
			wantErr:   "may not combine service_subjects with customers_org_id",
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
			providers: `[{"name":"zitadel","issuer":"https://auth.example.test","audiences":["100000000000000003"],"customers_org_id":"100000000000000001","service_subjects":{"svc-sub":"aud"}}]`,
			mutate:    func(t *testing.T) { t.Setenv("MCTL_FEDERATION_DISABLED", "true") },
			wantCode:  1,
			wantErr:   "may not combine service_subjects with customers_org_id",
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
	checkConfigEnv(t, `[{"name":"zitadel","issuer":"https://auth.example.test","audiences":["100000000000000003"],"customers_org_id":"100000000000000001","service_subjects":{"svc-sub":"aud"}}]`)
	err := loadConfig().validate()
	if err == nil || !strings.Contains(err.Error(), "may not combine service_subjects with customers_org_id") {
		t.Fatalf("validate() = %v, want the service_subjects refusal", err)
	}
}
