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
	if id := got.GitHubIdentity(); id.Provider != ProviderGitHub || id.Subject != "268260640" || id.Kind != KindHuman {
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
