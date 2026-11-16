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
	"errors"
	"strings"
	"testing"
)

const testCustomersOrg = "395272528420931285"

func customerClaims(over map[string]any) map[string]any {
	c := map[string]any{
		ClaimResourceOwnerID:     testCustomersOrg,
		ClaimCustomerOrg:         "customers",
		ClaimCustomerIdP:         "github",
		ClaimCustomerGitHubID:    "268260640",
		ClaimCustomerGitHubLogin: "mctl-reviewer",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func TestReadCustomerProof(t *testing.T) {
	got, err := ReadCustomerProof(customerClaims(nil), testCustomersOrg)
	if err != nil || got == nil || got.GitHubID != "268260640" || got.GitHubLogin != "mctl-reviewer" {
		t.Fatalf("customer = %+v, %v", got, err)
	}
	if id := got.Identity(); id.Provider != ProviderGitHub || id.Subject != "268260640" || id.Kind != KindHuman {
		t.Fatalf("GitHub identity = %+v", id)
	}

	other, err := ReadCustomerProof(customerClaims(map[string]any{ClaimResourceOwnerID: "1"}), testCustomersOrg)
	if err != nil || other != nil {
		t.Fatalf("another organization = %+v, %v; want nil, nil", other, err)
	}

	// Could not observe the organization: never "not customers".
	for _, owner := range []any{nil, "", 42} {
		_, err := ReadCustomerProof(customerClaims(map[string]any{ClaimResourceOwnerID: owner}), testCustomersOrg)
		if owner == nil {
			c := customerClaims(nil)
			delete(c, ClaimResourceOwnerID)
			_, err = ReadCustomerProof(c, testCustomersOrg)
		}
		if !errors.Is(err, ErrResourceOwnerUnknown) {
			t.Fatalf("owner %v: err = %v, want ErrResourceOwnerUnknown", owner, err)
		}
	}

	unproven := map[string]map[string]any{
		"hook refused":         {ClaimCustomerRefused: "login_reserved"},
		"hook did not run":     {ClaimCustomerOrg: nil, ClaimCustomerIdP: nil, ClaimCustomerGitHubID: nil, ClaimCustomerGitHubLogin: nil},
		"no github id":         {ClaimCustomerGitHubID: nil},
		"github id not digits": {ClaimCustomerGitHubID: "12a"},
		"github id leading 0":  {ClaimCustomerGitHubID: "0123"},
		"github id a number":   {ClaimCustomerGitHubID: 268260640.0},
		"no login":             {ClaimCustomerGitHubLogin: nil},
		"login not GitHub's":   {ClaimCustomerGitHubLogin: "bob@mctl.ai"},
		"login too long":       {ClaimCustomerGitHubLogin: strings.Repeat("a", 40)},
		"another idp":          {ClaimCustomerIdP: "google"},
		"another org claim":    {ClaimCustomerOrg: "admins"},
	}
	for name, over := range unproven {
		t.Run(name, func(t *testing.T) {
			got, err := ReadCustomerProof(customerClaims(over), testCustomersOrg)
			if !errors.Is(err, ErrCustomerUnproven) || got != nil {
				t.Fatalf("got %+v, %v; want ErrCustomerUnproven", got, err)
			}
		})
	}

	if _, err := ReadCustomerProof(customerClaims(nil), ""); err == nil {
		t.Fatal("no configured organization must not read as \"not a customer\"")
	}
}

const zitadelCustomersEntry = `[{"name":"zitadel","issuer":"` + zitadelIssuer + `","audiences":["` + zitadelClientID + `"],"customers_org_id":"` + testCustomersOrg + `"}]`

// The bearer path: a customers token becomes an identity carrying its
// GitHub proof, with no groups; a token that does not name its
// organization, or a customers token without its GitHub proof, is refused.
func TestZitadelEntryWithCustomersOrg(t *testing.T) {
	verify := func(claims map[string]any) (*Verified, error) {
		r := buildZitadelRegistry(t, zitadelCustomersEntry, map[string]*oidcVerifiedToken{
			zitadelIssuer: zitadelToken([]string{zitadelClientID}, claims),
		})
		return r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	}

	v, err := verify(customerClaims(map[string]any{"groups": []any{"admins", "acme"}}))
	if err != nil {
		t.Fatalf("customer token refused: %v", err)
	}
	if v.Identity.Customer == nil || v.Identity.Customer.GitHubID != "268260640" {
		t.Fatalf("identity = %+v, want the customer's GitHub proof", v.Identity)
	}
	if len(v.Claims.Groups) != 0 {
		t.Fatalf("groups = %v: a customer's ZITADEL groups grant nothing", v.Claims.Groups)
	}
	if u := userFromVerified(v); u.oidcCustomer == nil {
		t.Fatal("the request user lost the customer proof")
	} else if id, _ := u.Identity(); id.Customer == nil {
		t.Fatal("the resolver would not see the customer proof")
	}

	admin, err := verify(map[string]any{ClaimResourceOwnerID: "393497610436019469"})
	if err != nil || admin.Identity.Customer != nil {
		t.Fatalf("another organization = %+v, %v; want a plain identity", admin, err)
	}

	if _, err := verify(nil); !errors.Is(err, ErrResourceOwnerUnknown) {
		t.Fatalf("token without its organization: err = %v, want ErrResourceOwnerUnknown", err)
	}
	if _, err := verify(customerClaims(map[string]any{ClaimCustomerGitHubID: nil})); !errors.Is(err, ErrCustomerUnproven) {
		t.Fatalf("customers token without github id: err = %v, want ErrCustomerUnproven", err)
	}
}

// Without customers_org_id the entry behaves as before: no organization
// is required and no customer proof is read.
func TestZitadelEntryWithoutCustomersOrgIgnoresCustomerClaims(t *testing.T) {
	r := buildZitadelRegistry(t, zitadelEntry, map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelClientID}, customerClaims(nil)),
	})
	v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	if err != nil || v.Identity.Customer != nil {
		t.Fatalf("verified = %+v, %v", v, err)
	}
}

func TestParseOIDCProvidersValidatesCustomersOrgID(t *testing.T) {
	if _, err := ParseOIDCProviders(zitadelCustomersEntry); err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	for _, bad := range []string{
		`[{"name":"zitadel","issuer":"https://a","audiences":["x"],"customers_org_id":"customers"}]`,
		`[{"name":"zitadel","issuer":"https://a","audiences":["x"],"kind":"service","customers_org_id":"123"}]`,
	} {
		if _, err := ParseOIDCProviders(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// Even an entry that grants groups grants a customer none: a customer's
// access comes from its principal alone.
func TestZitadelCustomerGetsNoGroupsEvenWhenTheEntryGrantsThem(t *testing.T) {
	entry := `[{"name":"zitadel","issuer":"` + zitadelIssuer + `","audiences":["` + zitadelClientID + `"],"grant_groups":true,"customers_org_id":"` + testCustomersOrg + `"}]`
	verify := func(claims map[string]any) *Verified {
		r := buildZitadelRegistry(t, entry, map[string]*oidcVerifiedToken{
			zitadelIssuer: zitadelToken([]string{zitadelClientID}, claims),
		})
		v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
		if err != nil {
			t.Fatalf("token refused: %v", err)
		}
		return v
	}
	if v := verify(customerClaims(map[string]any{"groups": []any{"acme"}})); len(v.Claims.Groups) != 0 {
		t.Fatalf("customer groups = %v, want none", v.Claims.Groups)
	}
	// The same claim on another organization's user is still granted, so
	// the test above is not passing for want of a groups claim.
	if v := verify(map[string]any{ClaimResourceOwnerID: "1", "groups": []any{"acme"}}); len(v.Claims.Groups) != 1 {
		t.Fatalf("other organization groups = %v, want [acme]", v.Claims.Groups)
	}
}

func googleClaims(over map[string]any) map[string]any {
	c := map[string]any{
		ClaimResourceOwnerID:   testCustomersOrg,
		ClaimCustomerOrg:       "customers",
		ClaimCustomerIdP:       "google",
		ClaimCustomerGoogleSub: "109876543210987654321",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

// A Google proof (mctl-api#1079) is read only where it is enabled, keys the
// principal on the Google subject, and never mixes with GitHub claims.
func TestReadCustomerProofGoogle(t *testing.T) {
	got, err := ReadCustomerProofWith(googleClaims(nil), testCustomersOrg, true)
	if err != nil || got == nil || got.Provider != ProviderGoogle || got.GoogleSub != "109876543210987654321" || got.GitHubID != "" {
		t.Fatalf("Google proof = %+v, %v", got, err)
	}
	if id := got.Identity(); id.Provider != ProviderGoogle || id.Subject != "109876543210987654321" || id.Issuer != "" || id.Display != "" || id.Kind != KindHuman {
		t.Fatalf("Google identity = %+v", id)
	}
	// Dark by default: the GitHub-only reader and a disabled one refuse it.
	if _, err := ReadCustomerProof(googleClaims(nil), testCustomersOrg); !errors.Is(err, ErrCustomerUnproven) {
		t.Fatalf("ReadCustomerProof(google) = %v, want ErrCustomerUnproven", err)
	}
	if _, err := ReadCustomerProofWith(googleClaims(nil), testCustomersOrg, false); !errors.Is(err, ErrCustomerUnproven) {
		t.Fatalf("Google disabled = %v, want ErrCustomerUnproven", err)
	}
	for name, over := range map[string]map[string]any{
		"no subject":         {ClaimCustomerGoogleSub: nil},
		"empty subject":      {ClaimCustomerGoogleSub: ""},
		"non-numeric":        {ClaimCustomerGoogleSub: "abc"},
		"numeric type":       {ClaimCustomerGoogleSub: 123},
		"too long":           {ClaimCustomerGoogleSub: strings.Repeat("1", 65)},
		"with GitHub id":     {ClaimCustomerGitHubID: "268260640"},
		"with GitHub login":  {ClaimCustomerGitHubLogin: "mctl-reviewer"},
		"hook refused":       {ClaimCustomerRefused: "ambiguous_identity"},
		"other customer org": {ClaimCustomerOrg: "admins"},
	} {
		if p, err := ReadCustomerProofWith(googleClaims(over), testCustomersOrg, true); !errors.Is(err, ErrCustomerUnproven) {
			t.Errorf("%s: %+v, %v; want ErrCustomerUnproven", name, p, err)
		}
	}
	// A GitHub token carrying a Google subject is refused too, Google on
	// or off.
	for _, google := range []bool{false, true} {
		if p, err := ReadCustomerProofWith(customerClaims(map[string]any{ClaimCustomerGoogleSub: "1"}), testCustomersOrg, google); !errors.Is(err, ErrCustomerUnproven) {
			t.Errorf("GitHub token with a Google subject (google=%v): %+v, %v", google, p, err)
		}
	}
	// GitHub proofs are unchanged with Google on.
	if p, err := ReadCustomerProofWith(customerClaims(nil), testCustomersOrg, true); err != nil || p.Provider != ProviderGitHub || p.GitHubID != "268260640" {
		t.Fatalf("GitHub proof with Google on = %+v, %v", p, err)
	}
	// A proof of no known provider yields no provider, never a guess.
	if id := (CustomerProof{GitHubID: "1", GoogleSub: "2"}).Identity(); id.Provider != "" || id.Subject != "" {
		t.Fatalf("unknown provider identity = %+v", id)
	}
}

// "google" is a reserved provider name: no MCTL_OIDC_PROVIDERS entry may
// mint into the Google customer namespace.
func TestGoogleProviderNameIsReserved(t *testing.T) {
	_, err := ParseOIDCProviders(`[{"name":"google","issuer":"https://accounts.google.com","audiences":["x"]}]`)
	if err == nil || !strings.Contains(err.Error(), "google") {
		t.Fatalf("ParseOIDCProviders(google) = %v, want a refusal", err)
	}
}

// The bearer path accepts a Google customer only on the entry of the
// customers organization the registry was told has a Google IdP.
func TestZitadelEntryGoogleCustomer(t *testing.T) {
	verify := func(googleOrg string) (*Verified, error) {
		r := buildZitadelRegistryWith(t, FederationProvidersConfig{OIDCProvidersRaw: zitadelCustomersEntry, CustomersGoogleOrgID: googleOrg},
			map[string]*oidcVerifiedToken{zitadelIssuer: zitadelToken([]string{zitadelClientID}, googleClaims(nil))})
		return r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	}
	v, err := verify(testCustomersOrg)
	if err != nil || v.Identity.Customer == nil || v.Identity.Customer.Provider != ProviderGoogle || len(v.Claims.Groups) != 0 {
		t.Fatalf("Google customer = %+v, %v; want its Google proof", v, err)
	}
	if u := userFromVerified(v); u.oidcCustomer == nil || u.oidcCustomer.GoogleSub == "" {
		t.Fatal("the request user lost the Google proof")
	}
	for _, org := range []string{"", "1"} {
		if _, err := verify(org); !errors.Is(err, ErrCustomerUnproven) {
			t.Fatalf("Google org %q: err = %v, want ErrCustomerUnproven", org, err)
		}
	}
}
