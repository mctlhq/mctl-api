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
	"context"
	"strings"
	"testing"
)

// A ZITADEL machine user signing in with its own key gets the project id in
// aud, not the client id the entry enforces (mctl-api#963).
const (
	saClientID  = "client-id"
	saProjectID = "393608017200809685"
	saMachine   = "398760566723708319"
)

func subjectAudienceProvider(sub string, aud []string, enforcement AudienceEnforcement) error {
	spec := OIDCProviderSpec{
		Name: "zitadel", Issuer: "https://auth", Audiences: []string{saClientID}, AudienceEnforcement: enforcement,
		SubjectAudiences: map[string][]string{saMachine: {saProjectID}},
	}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://auth", Audience: aud, Claims: map[string]any{"sub": sub}}}
	_, err := newOIDCProviderForTest(spec, fv).Verify(context.Background(), "tok")
	return err
}

func TestSubjectAudienceAcceptedForThatSubjectOnly(t *testing.T) {
	if err := subjectAudienceProvider(saMachine, []string{saProjectID}, AudienceEnforce); err != nil {
		t.Fatalf("the machine user's project audience must be accepted: %v", err)
	}
	// Anyone else holding a token with the project audience, which every
	// ZITADEL client can ask for, is refused.
	for _, sub := range []string{"398760566723708318", "", saMachine + " ", "other"} {
		if err := subjectAudienceProvider(sub, []string{saProjectID}, AudienceEnforce); err == nil {
			t.Fatalf("subject %q must not get the machine user's audience", sub)
		}
	}
	// The subject alone grants nothing: a wrong audience is still refused.
	if err := subjectAudienceProvider(saMachine, []string{"other"}, AudienceEnforce); err == nil {
		t.Fatal("the machine user with a foreign audience must be refused")
	}
	// The entry's own audience still works for every subject.
	if err := subjectAudienceProvider("other", []string{saClientID}, AudienceEnforce); err != nil {
		t.Fatalf("the entry's audience must still be accepted: %v", err)
	}
}

func TestSubjectAudiencesParsedAndValidated(t *testing.T) {
	ok := `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"` + saMachine + `":["` + saProjectID + `"]}}]`
	entries, err := ParseOIDCProviders(ok)
	if err != nil {
		t.Fatalf("valid subject_audiences refused: %v", err)
	}
	if got := entries[0].spec().SubjectAudiences[saMachine]; len(got) != 1 || got[0] != saProjectID {
		t.Fatalf("subject_audiences did not reach the spec: %v", got)
	}
	// subject_claim email is valid on its own, and sub stated explicitly is
	// the default: only the combination of a mutable claim and
	// subject_audiences is refused.
	for _, raw := range []string{
		`[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_claim":"email"}]`,
		`[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_claim":"sub","subject_audiences":{"s":["p"]}}]`,
	} {
		if _, err := ParseOIDCProviders(raw); err != nil {
			t.Fatalf("valid entry refused: %s: %v", raw, err)
		}
	}
	for name, raw := range map[string]string{
		"empty map":       `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{}}]`,
		"empty subject":   `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"":["p"]}}]`,
		"padded subject":  `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{" s":["p"]}}]`,
		"no audience":     `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"s":[]}}]`,
		"blank audience":  `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"s":[" "]}}]`,
		"padded audience": `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"s":[" p"]}}]`,
		"dex slot":        `[{"name":"dex","issuer":"https://dex","audiences":["c"],"subject_audiences":{"s":["p"]}}]`,
		"mutable claim":   `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_claim":"email","subject_audiences":{"s":["p"]}}]`,
	} {
		if _, err := ParseOIDCProviders(raw); err == nil || !strings.Contains(err.Error(), "subject") {
			t.Errorf("%s: want a subject_audiences refusal, got %v", name, err)
		}
	}
}
