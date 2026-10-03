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
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// mctl-api#434: ZITADEL enters the federation registry as one more
// MCTL_OIDC_PROVIDERS entry (docs/federation.md "ZITADEL"). These tests run
// the documented entry through the real parse + BuildFederationRegistry +
// Registry.Verify path, with only the network-bound signature check faked
// through the newOIDCProviderFn seam.

const (
	zitadelIssuer    = "https://auth.mctl.ai"
	zitadelClientID  = "290000000000000001@mctl"
	zitadelProjectID = "290000000000000000"
	testDexIssuer    = "https://ops.example/api/dex"
)

// zitadelEntry is the entry docs/federation.md tells an operator to add. It
// deliberately sets no audience_enforcement and no grant_groups: the
// defaults are what the rollout relies on.
const zitadelEntry = `[{"name":"zitadel","issuer":"` + zitadelIssuer + `","audiences":["` + zitadelClientID + `"]}]`

// buildZitadelRegistry builds the production registry from raw, with the Dex
// shim configured as it is in production, and every OIDC provider's
// signature check replaced by tokens[issuer].
func buildZitadelRegistry(t *testing.T, raw string, tokens map[string]*oidcVerifiedToken) *Registry {
	t.Helper()
	orig := newOIDCProviderFn
	t.Cleanup(func() { newOIDCProviderFn = orig })
	newOIDCProviderFn = func(_ context.Context, spec OIDCProviderSpec) (*oidcProvider, error) {
		fv := fakeOIDCVerifier{tok: tokens[spec.Issuer]}
		if fv.tok == nil {
			fv.err = errors.New("signature check failed")
		}
		return newOIDCProviderForTest(spec, fv), nil
	}
	r, err := BuildFederationRegistry(context.Background(), FederationProvidersConfig{
		OIDCProvidersRaw: raw, DexIssuerURL: testDexIssuer, DexClientID: "mctl-api",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildFederationRegistry: %v", err)
	}
	return r
}

func zitadelToken(aud []string, claims map[string]any) *oidcVerifiedToken {
	c := map[string]any{"sub": "290000000000000042", "preferred_username": "alice@mctl.auth.mctl.ai", "email": "alice@example.com"}
	for k, v := range claims {
		c[k] = v
	}
	return &oidcVerifiedToken{Issuer: zitadelIssuer, Audience: aud, Claims: c}
}

func TestParseOIDCProvidersAcceptsZitadelEntryWithEnforcingDefaults(t *testing.T) {
	entries, err := ParseOIDCProviders(zitadelEntry)
	if err != nil {
		t.Fatalf("documented ZITADEL entry refused: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	spec := entries[0].spec().withDefaults()
	if spec.AudienceEnforcement != AudienceEnforce {
		t.Fatalf("audience_enforcement default = %q, want %q", spec.AudienceEnforcement, AudienceEnforce)
	}
	if spec.SkipAudienceCheck {
		t.Fatal("an MCTL_OIDC_PROVIDERS entry must never skip the audience check")
	}
	if spec.GrantGroups {
		t.Fatal("grant_groups must default to false")
	}
	if spec.Kind != KindHuman {
		t.Fatalf("kind default = %q, want %q", spec.Kind, KindHuman)
	}
}

// Regression test for the "enforced audience" half of mctl-api#434: a token
// ZITADEL really signed, but minted for another client (here: only the
// project id, or another app's client id), is refused -- not counted and
// let through as the audit canary would. Verified to fail when the enforce
// branch in oidcProvider.Verify is removed, or when withDefaults stops
// defaulting audience_enforcement to "enforce".
func TestZitadelEntryRefusesForeignAudience(t *testing.T) {
	cases := []struct {
		name string
		aud  []string
	}{
		{"project id only", []string{zitadelProjectID}},
		{"another application's client id", []string{zitadelProjectID, "290000000000000099@mctl"}},
		{"no audience at all", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := buildZitadelRegistry(t, zitadelEntry, map[string]*oidcVerifiedToken{
				zitadelIssuer: zitadelToken(tc.aud, nil),
			})
			invalidBefore := testutil.ToFloat64(federationVerifications.WithLabelValues("zitadel", "invalid"))
			rejectedBefore := testutil.ToFloat64(federationAudienceRejected.WithLabelValues("zitadel"))
			mismatchBefore := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("zitadel"))

			v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
			if err == nil {
				t.Fatalf("token with aud %v accepted as %+v, want refusal", tc.aud, v.Identity)
			}
			if got := testutil.ToFloat64(federationVerifications.WithLabelValues("zitadel", "invalid")) - invalidBefore; got != 1 {
				t.Fatalf("federation_token_verifications_total{zitadel,invalid} delta = %v, want 1", got)
			}
			if got := testutil.ToFloat64(federationAudienceRejected.WithLabelValues("zitadel")) - rejectedBefore; got != 1 {
				t.Fatalf("federation_audience_rejected_total{zitadel} delta = %v, want 1", got)
			}
			if got := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("zitadel")) - mismatchBefore; got != 0 {
				t.Fatalf("federation_audience_mismatch_total{zitadel} delta = %v, want 0 (enforce, not audit)", got)
			}
		})
	}
}

// A token whose aud holds the configured client (ZITADEL also lists the
// project id) is accepted, keyed on (zitadel, ZITADEL issuer, sub), and the
// Dex shim keeps serving Dex tokens next to it.
func TestZitadelEntryAcceptsConfiguredClientAlongsideDexShim(t *testing.T) {
	r := buildZitadelRegistry(t, zitadelEntry, map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelProjectID, zitadelClientID}, nil),
		testDexIssuer: {Issuer: testDexIssuer, Audience: []string{"mctl-api"}, Claims: map[string]any{"sub": "CgVhbGljZQ", "preferred_username": "alice", "groups": []any{"admins"}}},
	})
	if len(r.jwt) != 2 {
		t.Fatalf("jwt providers = %d, want 2 (zitadel + dex shim)", len(r.jwt))
	}

	okBefore := testutil.ToFloat64(federationVerifications.WithLabelValues("zitadel", "ok"))
	v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	if err != nil {
		t.Fatalf("ZITADEL token for the configured client refused: %v", err)
	}
	if got := testutil.ToFloat64(federationVerifications.WithLabelValues("zitadel", "ok")) - okBefore; got != 1 {
		t.Fatalf("federation_token_verifications_total{zitadel,ok} delta = %v, want 1", got)
	}
	u := userFromVerified(v)
	id, ok := u.Identity()
	want := Identity{Provider: "zitadel", Issuer: zitadelIssuer, Subject: "290000000000000042", Display: "alice@mctl.auth.mctl.ai", Kind: KindHuman}
	if !ok || id != want {
		t.Fatalf("Identity() = %+v (ok=%v), want %+v", id, ok, want)
	}
	if _, isGitHub := u.GitHubLogin(); isGitHub {
		t.Fatal("a ZITADEL identity must never read as a GitHub-proven login")
	}

	dv, err := r.Verify(context.Background(), fakeJWT(testDexIssuer))
	if err != nil {
		t.Fatalf("Dex token refused next to a ZITADEL entry: %v", err)
	}
	if dv.Identity.Provider != ProviderDex || !userFromVerified(dv).IsAdmin() {
		t.Fatalf("Dex shim behaviour changed: %+v", dv)
	}
}

// Groups or roles asserted by ZITADEL must not grant tenant or admin access
// until mctl-api#377 moves authorization onto principals.
func TestZitadelEntryWithholdsGroupsByDefault(t *testing.T) {
	claims := map[string]any{
		"groups":                            []any{"acme", "admins"},
		"urn:zitadel:iam:org:project:roles": map[string]any{"admins": map[string]any{"1": "mctl"}},
	}
	r := buildZitadelRegistry(t, zitadelEntry, map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelClientID}, claims),
	})
	before := testutil.ToFloat64(federationGroupsWithheld.WithLabelValues("zitadel"))
	v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	if err != nil {
		t.Fatal(err)
	}
	u := userFromVerified(v)
	if len(u.Groups) != 0 {
		t.Fatalf("Groups = %v, want none", u.Groups)
	}
	if u.IsAdmin() || u.HasTenantAccess("acme") {
		t.Fatal("a ZITADEL token's groups must not grant admin or tenant access")
	}
	if got := testutil.ToFloat64(federationGroupsWithheld.WithLabelValues("zitadel")) - before; got != 1 {
		t.Fatalf("federation_groups_withheld_total{zitadel} delta = %v, want 1", got)
	}

	// The roles claim, pointed at explicitly, is withheld the same way.
	rolesEntry := `[{"name":"zitadel","issuer":"` + zitadelIssuer + `","audiences":["` + zitadelClientID + `"],"groups_claim":"urn:zitadel:iam:org:project:roles"}]`
	r = buildZitadelRegistry(t, rolesEntry, map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelClientID}, claims),
	})
	v, err = r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if u := userFromVerified(v); len(u.Groups) != 0 || u.IsAdmin() {
		t.Fatalf("roles claim reached authorization: Groups = %v", u.Groups)
	}
}

// grant_groups is an explicit opt-in, and even then never confers admin.
func TestOIDCEntryGrantGroupsOptInStillStripsAdmins(t *testing.T) {
	raw := `[{"name":"zitadel","issuer":"` + zitadelIssuer + `","audiences":["` + zitadelClientID + `"],"grant_groups":true}]`
	r := buildZitadelRegistry(t, raw, map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelClientID}, map[string]any{"groups": []any{"acme", "admins"}}),
	})
	v, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer))
	if err != nil {
		t.Fatal(err)
	}
	u := userFromVerified(v)
	if !u.HasTenantAccess("acme") || u.IsAdmin() {
		t.Fatalf("Groups = %v, want [acme] without admin", u.Groups)
	}
}

// Without a ZITADEL entry nothing changes: only the Dex shim is built, and a
// ZITADEL-issued token is unclaimed (401), never routed anywhere.
func TestNoZitadelEntryKeepsCurrentBehaviour(t *testing.T) {
	r := buildZitadelRegistry(t, "", map[string]*oidcVerifiedToken{
		zitadelIssuer: zitadelToken([]string{zitadelClientID}, nil),
	})
	if len(r.jwt) != 1 || r.jwt[0].Name() != ProviderDex {
		t.Fatalf("jwt providers = %v, want only the dex shim", r.jwt)
	}
	if _, err := r.Verify(context.Background(), fakeJWT(zitadelIssuer)); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("err = %v, want ErrNoProvider", err)
	}
}
