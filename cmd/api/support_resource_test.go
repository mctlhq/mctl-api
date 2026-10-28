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
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// mctl-api#851: an OAUTH_SUPPORT_RESOURCE that names this API, or that is
// not an https URL, refuses the boot; unset is the default, empty disables.
func TestConfigureSupportResource(t *testing.T) {
	const base = "https://api.example"
	for name, tc := range map[string]struct {
		env     *string
		want    string
		refused bool
	}{
		"unset":      {nil, auth.DefaultSupportResource, false},
		"empty":      {ptr(""), "", false},
		"other host": {ptr(" https://support.example "), "https://support.example", false},
		"base url":   {ptr(base), "", true},
		"base slash": {ptr(base + "/"), "", true},
		"mcp":        {ptr(base + "/mcp"), "", true},
		"audience":   {ptr("https://aud.example"), "", true},
		"http":       {ptr("http://support.example"), "", true},
		"relative":   {ptr("support"), "", true},
		"fragment":   {ptr("https://support.example#x"), "", true},
		"no host":    {ptr("https://"), "", true},
	} {
		t.Run(name, func(t *testing.T) {
			o := auth.NewOAuthServer(base, "id", "secret", []byte("jwt-secret"), nil, auth.NewGitHubValidator(nil))
			o.AccessTokenAudience = "https://aud.example"
			lookup := func(k string) (string, bool) {
				if k != "OAUTH_SUPPORT_RESOURCE" || tc.env == nil {
					return "", false
				}
				return *tc.env, true
			}
			err := configureSupportResource(o, lookup)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted %q", o.SupportResource)
				}
				return
			}
			if err != nil || o.SupportResource != tc.want {
				t.Fatalf("got %q, %v; want %q", o.SupportResource, err, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }
