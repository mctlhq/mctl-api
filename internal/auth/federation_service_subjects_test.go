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

const (
	ssProject = "project-audience"
	ssClient  = "client-id"
	ssMachine = "machine-subject-1"
	ssHuman   = "human-subject-1"
)

func serviceSubjectVerify(t *testing.T, spec OIDCProviderSpec, sub string, aud []string, extra map[string]any) (*Verified, error) {
	t.Helper()
	claims := map[string]any{"sub": sub}
	for k, v := range extra {
		claims[k] = v
	}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://auth", Audience: aud, Claims: claims}}
	return newOIDCProviderForTest(spec, fv).Verify(context.Background(), "tok")
}

func serviceSubjectSpec() OIDCProviderSpec {
	return OIDCProviderSpec{
		Name: "zitadel", Issuer: "https://auth", Audiences: []string{ssClient}, AudienceEnforcement: AudienceEnforce,
		ServiceSubjects: map[string]string{ssMachine: ssProject},
	}
}

func TestServiceSubjectResolvesToServiceKind(t *testing.T) {
	v, err := serviceSubjectVerify(t, serviceSubjectSpec(), ssMachine, []string{ssProject}, nil)
	if err != nil {
		t.Fatalf("listed machine subject with its pinned audience refused: %v", err)
	}
	if v.Identity.Kind != KindService || v.Identity.Provider != "zitadel" || v.Identity.Subject != ssMachine {
		t.Fatalf("identity = %+v, want kind service", v.Identity)
	}
}

func TestServiceSubjectNeverGrantedToOthers(t *testing.T) {
	spec := serviceSubjectSpec()
	// A human of the same issuer with the entry's own audience stays human.
	v, err := serviceSubjectVerify(t, spec, ssHuman, []string{ssClient}, nil)
	if err != nil || v.Identity.Kind != KindHuman {
		t.Fatalf("human = %+v, %v; want kind human", v, err)
	}
	// Nothing in the token's claims can promote a subject that is not listed.
	for name, extra := range map[string]map[string]any{
		"kind claim":    {"kind": "service"},
		"groups claim":  {"groups": []any{"service"}},
		"service claim": {"service": true},
	} {
		v, err := serviceSubjectVerify(t, spec, ssHuman, []string{ssClient}, extra)
		if err != nil || v.Identity.Kind != KindHuman {
			t.Fatalf("%s: = %+v, %v; want kind human", name, v, err)
		}
	}
	// A near-miss subject is not the listed one (exact match only).
	for _, sub := range []string{ssMachine + " ", " " + ssMachine, strings.ToUpper(ssMachine), ssMachine + "2", ""} {
		v, err := serviceSubjectVerify(t, spec, sub, []string{ssClient}, nil)
		if err == nil && v.Identity.Kind == KindService {
			t.Fatalf("subject %q must not resolve to service", sub)
		}
	}
	// The listed subject holding a human-flavoured (entry) audience is not
	// the pinned one: it is refused, never silently downgraded or promoted.
	if v, err := serviceSubjectVerify(t, spec, ssMachine, []string{ssClient}, nil); err == nil {
		t.Fatalf("service subject with the entry audience instead of the pinned one must be refused, got %+v", v.Identity)
	}
}

func TestServiceSubjectWrongAudienceRefused(t *testing.T) {
	for _, enf := range []AudienceEnforcement{AudienceEnforce, AudienceAudit} {
		spec := serviceSubjectSpec()
		spec.AudienceEnforcement = enf
		for _, aud := range [][]string{{"other"}, {}, nil, {ssClient}} {
			if v, err := serviceSubjectVerify(t, spec, ssMachine, aud, nil); err == nil {
				t.Fatalf("enforcement %q aud %v: service subject without the pinned audience accepted: %+v", enf, aud, v.Identity)
			}
		}
	}
}

func TestServiceSubjectPinnedAudienceDoesNotWidenOthers(t *testing.T) {
	// The pinned audience is accepted for the listed subject only.
	if _, err := serviceSubjectVerify(t, serviceSubjectSpec(), ssHuman, []string{ssProject}, nil); err == nil {
		t.Fatal("another subject must not be accepted on the machine user's pinned audience")
	}
}

func TestServiceSubjectCarriesNoGroups(t *testing.T) {
	spec := serviceSubjectSpec()
	spec.GrantGroups = true
	v, err := serviceSubjectVerify(t, spec, ssMachine, []string{ssProject}, map[string]any{"groups": []any{"some-tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Claims.Groups) != 0 {
		t.Fatalf("a service subject must carry no groups, got %v", v.Claims.Groups)
	}
	// The human path of the same entry still gets its granted groups.
	v, err = serviceSubjectVerify(t, spec, ssHuman, []string{ssClient}, map[string]any{"groups": []any{"some-tenant"}})
	if err != nil || len(v.Claims.Groups) != 1 {
		t.Fatalf("human groups = %+v, %v; want preserved", v, err)
	}
}

func TestServiceSubjectUnsetKeepsTodaysBehaviour(t *testing.T) {
	spec := serviceSubjectSpec()
	spec.ServiceSubjects = nil
	v, err := serviceSubjectVerify(t, spec, ssMachine, []string{ssClient}, nil)
	if err != nil || v.Identity.Kind != KindHuman {
		t.Fatalf("unset service_subjects: %+v, %v; want human", v, err)
	}
	if _, err := serviceSubjectVerify(t, spec, ssMachine, []string{ssProject}, nil); err == nil {
		t.Fatal("unset service_subjects must not accept the project audience")
	}
}

func TestServiceSubjectsComposeWithSubjectAudiences(t *testing.T) {
	// The orchestrator path (subject_audiences, stays human) is untouched.
	spec := serviceSubjectSpec()
	spec.SubjectAudiences = map[string][]string{"orchestrator": {ssProject}}
	v, err := serviceSubjectVerify(t, spec, "orchestrator", []string{ssProject}, nil)
	if err != nil || v.Identity.Kind != KindHuman {
		t.Fatalf("orchestrator = %+v, %v; want human via subject_audiences", v, err)
	}
	v, err = serviceSubjectVerify(t, spec, ssMachine, []string{ssProject}, nil)
	if err != nil || v.Identity.Kind != KindService {
		t.Fatalf("machine = %+v, %v; want service", v, err)
	}
}

func TestServiceSubjectsParsed(t *testing.T) {
	ok := `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m1":"p"}}]`
	entries, err := ParseOIDCProviders(ok)
	if err != nil {
		t.Fatalf("valid service_subjects refused: %v", err)
	}
	if got := entries[0].spec().ServiceSubjects["m1"]; got != "p" {
		t.Fatalf("service_subjects did not reach the spec: %v", got)
	}
	// Unset: the field stays nil.
	entries, err = ParseOIDCProviders(`[{"name":"zitadel","issuer":"https://auth","audiences":["c"]}]`)
	if err != nil || entries[0].spec().ServiceSubjects != nil {
		t.Fatalf("unset = %v, %v", entries, err)
	}
}

func TestServiceSubjectsRefusedAtBoot(t *testing.T) {
	for name, raw := range map[string]string{
		"empty map":            `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{}}]`,
		"empty subject":        `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"":"p"}}]`,
		"padded subject":       `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{" m":"p"}}]`,
		"wildcard subject":     `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"*":"p"}}]`,
		"wildcard glob":        `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m*":"p"}}]`,
		"empty audience":       `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m":""}}]`,
		"padded audience":      `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m":" p"}}]`,
		"audience list":        `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m":["p"]}}]`,
		"array instead of map": `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":["m"]}]`,
		"null":                 `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":null}]`,
		"duplicate subject":    `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m":"p","m":"q"}}]`,
		"dex slot":             `[{"name":"dex","issuer":"https://dex","audiences":["c"],"service_subjects":{"m":"p"}}]`,
		"mutable claim":        `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_claim":"email","service_subjects":{"m":"p"}}]`,
		"kind service entry":   `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"kind":"service","service_subjects":{"m":"p"}}]`,
		"kind agent entry":     `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"kind":"agent","service_subjects":{"m":"p"}}]`,
		"customers entry":      `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"customers_org_id":"123","service_subjects":{"m":"p"}}]`,
		"unknown field":        `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subject":{"m":"p"}}]`,
		"unknown nested":       `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"service_subjects":{"m":"p"},"service_kind":"x"}]`,
	} {
		if _, err := ParseOIDCProviders(raw); err == nil {
			t.Errorf("%s: want a boot refusal, got none", name)
		}
	}
	// A subject that is also a human-flavoured subject_audiences key is
	// ambiguous: one subject cannot be both a human exception and a service.
	amb := `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"subject_audiences":{"m":["p"]},"service_subjects":{"m":"p"}}]`
	if _, err := ParseOIDCProviders(amb); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("subject in subject_audiences and service_subjects: want an ambiguity refusal, got %v", err)
	}
}

func TestServiceSubjectNeverACustomer(t *testing.T) {
	// A spec built in code (not through the parser) that combines a customers
	// organization with a service subject still refuses the token.
	spec := serviceSubjectSpec()
	spec.CustomersOrgID = "123"
	if v, err := serviceSubjectVerify(t, spec, ssMachine, []string{ssProject}, nil); err == nil {
		t.Fatalf("service subject on a customers entry accepted: %+v", v.Identity)
	}
}
