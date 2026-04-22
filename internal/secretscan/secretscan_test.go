// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package secretscan

import "testing"

func TestScan_DetectsKnownPrefixes(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"github-pat", "authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12", "github-pat"},
		{"github-oauth-token", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12", "github-oauth-token"},
		{"github-user-token", "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12", "github-user-token"},
		{"github-server-token", "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12", "github-server-token"},
		{"github-refresh-token", "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12", "github-refresh-token"},
		{"aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"slack-bot-token", "xoxb-0123456789-abcdef", "slack-token"},
		{"slack-user-token", "xoxp-0123456789-abcdef", "slack-token"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijKLMNOP-_", "jwt"},
		{"rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", "private-key"},
		{"generic-private-key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG...", "private-key"},
		{"openssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...", "private-key"},
		{"ec-private-key", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...", "private-key"},
		{"generic-secret-assignment", `SECRET=abcdefghijklmnopqrstuvwx`, "generic-credential-assignment"},
		{"generic-api-key-assignment", `api_key: abcdefghijklmnopqrstuvwx`, "generic-credential-assignment"},
		{"generic-api-key-dash", `API-KEY=abcdefghijklmnopqrstuvwx`, "generic-credential-assignment"},
		{"generic-password", `password = abcdefghijklmnopqrstuvwx`, "generic-credential-assignment"},
		{"generic-bearer", `bearer abcdefghijklmnopqrstuvwx`, ""}, // no ":" or "=" — not matched
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := Scan([]byte(tc.content))
			if tc.want == "" {
				if found {
					t.Fatalf("expected no match, got %q for content %q", got, tc.content)
				}
				return
			}
			if !found {
				t.Fatalf("expected pattern %q, got no match", tc.want)
			}
			if got != tc.want {
				t.Fatalf("expected pattern %q, got %q", tc.want, got)
			}
		})
	}
}

func TestScan_DoesNotFlagBenignContent(t *testing.T) {
	benign := []string{
		"",
		"# SKILL.md\n\nThis skill teaches the agent to call `mctl_list_services`.\n",
		"Use the API to fetch data. See the docs for details.",
		"short=abc",                         // too short for generic pattern
		"ghp_tooshort",                      // wrong length for github-pat
		"AKIA123",                           // too short for aws-access-key-id
		"eyJ.eyJ.sig",                       // JWT-ish but too short to match the regex
		"-----BEGIN CERTIFICATE-----\n...",  // a cert header is not a private-key header
	}
	for _, s := range benign {
		if name, found := Scan([]byte(s)); found {
			t.Fatalf("unexpected match %q on benign content %q", name, s)
		}
	}
}
