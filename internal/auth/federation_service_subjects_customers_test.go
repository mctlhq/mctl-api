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
	"context"
	"errors"
	"strings"
	"testing"
)

// service_subjects together with customers_org_id on one entry (owner
// decision 2026-11-17, after the 4.166.0 rollout crash loop). The rule under
// test: an exact service subject on its pinned audience is kind service
// without a resourceowner claim and never a customer; every other subject of
// the entry keeps the customers enforcement. Each test below is named by the
// mutation that must turn it red (see docs/federation.md "Threat model").

const (
	cuOrg      = testCustomersOrg
	cuProject  = "290000000000000000"
	cuClient   = "290000000000000001@mctl"
	cuMachine  = "290000000000000077"
	cuHuman    = "290000000000000042"
	cuIssuer   = "https://auth.example.test"
	cuIssuer2  = "https://other.example.test"
	cuOtherOrg = "395272528420931999"
)

func customersServiceSpec() OIDCProviderSpec {
	return OIDCProviderSpec{
		Name: "zitadel", Issuer: cuIssuer, Audiences: []string{cuClient}, AudienceEnforcement: AudienceEnforce,
		CustomersOrgID:  cuOrg,
		ServiceSubjects: map[string]string{cuMachine: cuProject},
	}
}

func cuVerify(spec OIDCProviderSpec, iss, sub string, aud []string, claims map[string]any) (*Verified, error) {
	c := map[string]any{"sub": sub}
	for k, v := range claims {
		c[k] = v
	}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: iss, Audience: aud, Claims: c}}
	return newOIDCProviderForTest(spec, fv).Verify(context.Background(), "tok")
}

// Mutation: restore the blanket refusal in validServiceSubjects.
func TestCustomersOrgWithServiceSubjectsParses(t *testing.T) {
	raw := `[{"name":"zitadel","issuer":"` + cuIssuer + `","audiences":["` + cuClient + `"],"customers_org_id":"` + cuOrg + `","service_subjects":{"` + cuMachine + `":"` + cuProject + `"}}]`
	entries, err := ParseOIDCProviders(raw)
	if err != nil {
		t.Fatalf("customers_org_id with service_subjects refused: %v", err)
	}
	spec := entries[0].spec()
	if spec.CustomersOrgID != cuOrg || spec.ServiceSubjects[cuMachine] != cuProject {
		t.Fatalf("spec = %+v, want both carried", spec)
	}
}

// Mutation: drop the resourceowner check for ordinary users (skip the customers
// block for everyone), or make the service branch require resourceowner.
func TestCustomersEntryServiceSubjectNeedsNoResourceOwner(t *testing.T) {
	v, err := cuVerify(customersServiceSpec(), cuIssuer, cuMachine, []string{cuProject}, nil)
	if err != nil {
		t.Fatalf("machine user JWT-profile token (no resourceowner claim) refused: %v", err)
	}
	if v.Identity.Kind != KindService || v.Identity.Customer != nil || v.Identity.Subject != cuMachine || v.Identity.Provider != "zitadel" {
		t.Fatalf("identity = %+v, want kind service, no customer", v.Identity)
	}
}

func TestCustomersEntryOrdinaryUsersKeepCustomerEnforcement(t *testing.T) {
	spec := customersServiceSpec()
	// No resourceowner claim: still refused (not silently a human).
	_, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, nil)
	if !errors.Is(err, ErrResourceOwnerUnknown) {
		t.Fatalf("user without resourceowner: err = %v, want ErrResourceOwnerUnknown", err)
	}
	// Empty and non-string resourceowner: same.
	for _, owner := range []any{"", 7, nil} {
		if _, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, map[string]any{ClaimResourceOwnerID: owner}); !errors.Is(err, ErrResourceOwnerUnknown) {
			t.Fatalf("owner %#v: err = %v, want ErrResourceOwnerUnknown", owner, err)
		}
	}
	// A user of another organization (an operator): human, not a customer.
	v, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, map[string]any{ClaimResourceOwnerID: cuOtherOrg})
	if err != nil || v.Identity.Kind != KindHuman || v.Identity.Customer != nil {
		t.Fatalf("other-org user = %+v, %v; want human, no customer", v, err)
	}
	// A customers-org user: customer proof still read, kind human.
	v, err = cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, customerClaims(nil))
	if err != nil || v.Identity.Kind != KindHuman || v.Identity.Customer == nil || v.Identity.Customer.GitHubID != "268260640" {
		t.Fatalf("customer = %+v, %v; want human with the proven GitHub id", v, err)
	}
	// An unproven customers-org user is still refused.
	if _, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, customerClaims(map[string]any{ClaimCustomerGitHubID: nil})); !errors.Is(err, ErrCustomerUnproven) {
		t.Fatalf("unproven customer: err = %v, want ErrCustomerUnproven", err)
	}
}

// Mutation: grant a customers identity to the service subject (run the
// customers block for it).
func TestCustomersEntryServiceSubjectNeverACustomer(t *testing.T) {
	spec := customersServiceSpec()
	spec.GrantGroups = true
	for name, claims := range map[string]map[string]any{
		"resourceowner of the customers org":    {ClaimResourceOwnerID: cuOrg},
		"full customer claims (github id)":      customerClaims(nil),
		"customer claims with google subject":   customerClaims(map[string]any{ClaimCustomerGitHubID: nil, ClaimCustomerGitHubLogin: nil, ClaimCustomerIdP: "google", ClaimCustomerGoogleSub: "123456789012345678901"}),
		"hook refusal marker":                   {ClaimResourceOwnerID: cuOrg, ClaimCustomerRefused: "x"},
		"resourceowner of another organization": {ClaimResourceOwnerID: cuOtherOrg},
	} {
		v, err := cuVerify(spec, cuIssuer, cuMachine, []string{cuProject}, claims)
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if v.Identity.Kind != KindService || v.Identity.Customer != nil {
			t.Errorf("%s: identity = %+v, want service and never a customer", name, v.Identity)
		}
	}
}

// Mutation: apply grant_groups to the service subject.
func TestCustomersEntryServiceSubjectCarriesNoGroups(t *testing.T) {
	spec := customersServiceSpec()
	spec.GrantGroups = true
	claims := map[string]any{"groups": []any{"some-tenant", "admins"}, ClaimResourceOwnerID: cuOrg}
	v, err := cuVerify(spec, cuIssuer, cuMachine, []string{cuProject}, claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Claims.Groups) != 0 {
		t.Fatalf("service subject carries groups %v, want none even with grant_groups", v.Claims.Groups)
	}
	// Control: the same entry still grants a human the group (admins stripped).
	v, err = cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, map[string]any{"groups": []any{"some-tenant", "admins"}, ClaimResourceOwnerID: cuOtherOrg})
	if err != nil || len(v.Claims.Groups) != 1 || v.Claims.Groups[0] != "some-tenant" {
		t.Fatalf("human groups = %+v, %v; want [some-tenant]", v, err)
	}
}

// Mutation: drop the pinned-audience check.
func TestCustomersEntryServiceSubjectNeedsItsPinnedAudience(t *testing.T) {
	for _, enf := range []AudienceEnforcement{AudienceEnforce, AudienceAudit} {
		spec := customersServiceSpec()
		spec.AudienceEnforcement = enf
		for name, aud := range map[string][]string{
			"the entry's normal audience": {cuClient},
			"another audience":            {"other"},
			"no audience":                 nil,
		} {
			for _, claims := range []map[string]any{nil, {ClaimResourceOwnerID: cuOrg}} {
				if v, err := cuVerify(spec, cuIssuer, cuMachine, aud, claims); err == nil {
					t.Errorf("%s/%s: accepted as %+v, want refusal", enf, name, v.Identity)
				}
			}
		}
	}
}

// A human whose sub equals a service subject but with a wrong audience, and
// near-miss / sub-aud confusion: never service.
func TestCustomersEntryServiceSubjectEscalationAttempts(t *testing.T) {
	spec := customersServiceSpec()
	// The pinned audience is accepted for the listed subject only.
	if v, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuProject}, nil); err == nil {
		t.Fatalf("another subject accepted on the pinned audience: %+v", v.Identity)
	}
	if v, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuProject}, customerClaims(nil)); err == nil {
		t.Fatalf("a customer accepted on the pinned audience: %+v", v.Identity)
	}
	// Exact match only: padded, cased, suffixed, empty subjects.
	for _, sub := range []string{cuMachine + " ", " " + cuMachine, cuMachine + "0", cuMachine[:len(cuMachine)-1], ""} {
		v, err := cuVerify(spec, cuIssuer, sub, []string{cuProject}, nil)
		if err == nil {
			t.Errorf("subject %q accepted as %+v", sub, v.Identity)
		}
	}
	// sub/aud confusion: the subject placed in aud, the audience placed in sub.
	if v, err := cuVerify(spec, cuIssuer, cuProject, []string{cuMachine}, nil); err == nil {
		t.Fatalf("swapped sub/aud accepted: %+v", v.Identity)
	}
	if v, err := cuVerify(spec, cuIssuer, cuProject, []string{cuProject}, nil); err == nil {
		t.Fatalf("sub equal to the pinned audience accepted: %+v", v.Identity)
	}
	// Claims cannot promote anyone to service or name a subject.
	for name, extra := range map[string]map[string]any{
		"kind claim":         {"kind": "service"},
		"service claim":      {"service": true},
		"azp claim":          {"azp": cuMachine},
		"client_id":          {"client_id": cuMachine},
		"preferred_username": {"preferred_username": cuMachine},
	} {
		v, err := cuVerify(spec, cuIssuer, cuHuman, []string{cuClient}, mergeClaims(extra, map[string]any{ClaimResourceOwnerID: cuOtherOrg}))
		if err != nil || v.Identity.Kind != KindHuman {
			t.Errorf("%s: = %+v, %v; want human", name, v, err)
		}
	}
	// The machine user's sub does not become a customer via a customers token
	// naming it as display/login: it stays service, customer nil (covered
	// above); a customers-org token without the pinned audience is a customer
	// only if it is not the service subject.
	v, err := cuVerify(spec, cuIssuer, cuMachine, []string{cuProject}, customerClaims(nil))
	if err != nil || v.Identity.Kind != KindService {
		t.Fatalf("= %+v, %v", v, err)
	}
}

func mergeClaims(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// Through the registry built from the parsed entry: the listed subject
// resolves to service, and a token naming another issuer is claimed by no
// provider. (The signed-token path is in internal/api.)
func TestCustomersEntryRegistryIssuerBoundary(t *testing.T) {
	raw := `[{"name":"zitadel","issuer":"` + cuIssuer + `","audiences":["` + cuClient + `"],"customers_org_id":"` + cuOrg + `","service_subjects":{"` + cuMachine + `":"` + cuProject + `"}}]`
	good := &oidcVerifiedToken{Issuer: cuIssuer, Audience: []string{cuProject}, Claims: map[string]any{"sub": cuMachine}}
	r := buildZitadelRegistry(t, raw, map[string]*oidcVerifiedToken{cuIssuer: good})
	v, err := r.Verify(context.Background(), fakeJWT(cuIssuer))
	if err != nil || v.Identity.Kind != KindService || v.Identity.Customer != nil {
		t.Fatalf("registry: %+v, %v; want service", v, err)
	}
	// Wrong issuer: the token claims another issuer; nothing claims it.
	if v, err := r.Verify(context.Background(), fakeJWT(cuIssuer2)); err == nil {
		t.Fatalf("token with an unconfigured issuer accepted: %+v", v.Identity)
	}
}

func TestServiceSubjectOnTwoEntriesRefused(t *testing.T) {
	raw := `[` +
		`{"name":"zitadel","issuer":"` + cuIssuer + `","audiences":["a"],"customers_org_id":"` + cuOrg + `","service_subjects":{"` + cuMachine + `":"p"}},` +
		`{"name":"other","issuer":"` + cuIssuer2 + `","audiences":["b"],"service_subjects":{"` + cuMachine + `":"p"}}]`
	if _, err := ParseOIDCProviders(raw); err == nil || !strings.Contains(err.Error(), "both entry") {
		t.Fatalf("same service subject on two entries: err = %v, want refusal", err)
	}
	// Distinct subjects on two entries are fine.
	ok := strings.Replace(raw, `"service_subjects":{"`+cuMachine+`":"p"}}]`, `"service_subjects":{"another-machine":"p"}}]`, 1)
	if _, err := ParseOIDCProviders(ok); err != nil {
		t.Fatalf("distinct subjects refused: %v", err)
	}
}

func TestCustomersEntryKeepsOtherServiceSubjectGuards(t *testing.T) {
	pre := `[{"name":"zitadel","issuer":"https://auth","audiences":["c"],"customers_org_id":"123",`
	for name, tail := range map[string]string{
		"padded subject":            `"service_subjects":{" m":"p"}}]`,
		"empty audience":            `"service_subjects":{"m":""}}]`,
		"wildcard":                  `"service_subjects":{"m*":"p"}}]`,
		"empty map":                 `"service_subjects":{}}]`,
		"also in subject_audiences": `"subject_audiences":{"m":["p"]},"service_subjects":{"m":"p"}}]`,
		"mutable subject claim":     `"subject_claim":"email","service_subjects":{"m":"p"}}]`,
	} {
		if _, err := ParseOIDCProviders(pre + tail); err == nil {
			t.Errorf("%s: want a boot refusal with customers_org_id, got none", name)
		}
	}
}
