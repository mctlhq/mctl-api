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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ─── fakes ──────────────────────────────────────────────────────────────────

// fakeProvider is a hand-rolled Provider (and issuerNamer) for exercising
// Registry construction and routing without a real JWT/JWKS.
type fakeProvider struct {
	name   string
	issuer string
	claims func(tokenShape) bool
	verify func(context.Context, string) (*Verified, error)
	calls  int
}

func (f *fakeProvider) Name() string       { return f.name }
func (f *fakeProvider) issuerName() string { return f.issuer }
func (f *fakeProvider) Claims(t tokenShape) bool {
	if f.claims != nil {
		return f.claims(t)
	}
	return false
}
func (f *fakeProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	f.calls++
	if f.verify != nil {
		return f.verify(ctx, raw)
	}
	return nil, ErrNoProvider
}

func matchIssuer(iss string) func(tokenShape) bool {
	return func(t tokenShape) bool { return t.jwt && normalizeIssuer(t.iss) == normalizeIssuer(iss) }
}

// fakeJWT builds a syntactically-valid, unsigned JWT shape carrying the given
// unverified iss claim -- enough for isJWT/jwtIssuer routing, never enough
// to pass real signature verification.
func fakeJWT(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `"}`))
	return header + "." + payload + ".sig"
}

// ─── T3: registry construction refuses ─────────────────────────────────────

func TestRegistryRefusesDuplicateProviderName(t *testing.T) {
	a := &fakeProvider{name: "acme", issuer: "https://issuer-a", claims: matchIssuer("https://issuer-a")}
	b := &fakeProvider{name: "acme", issuer: "https://issuer-b", claims: matchIssuer("https://issuer-b")}
	if _, err := NewRegistry(nil, []Provider{a, b}, nil); err == nil {
		t.Fatal("expected refusal on duplicate provider name")
	}
}

func TestRegistryRefusesDuplicateIssuer(t *testing.T) {
	a := &fakeProvider{name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer")}
	b := &fakeProvider{name: "other", issuer: "https://issuer", claims: matchIssuer("https://issuer")}
	if _, err := NewRegistry(nil, []Provider{a, b}, nil); err == nil {
		t.Fatal("expected refusal on duplicate normalized issuer")
	}
}

func TestRegistryRefusesDuplicateIssuerWithTrailingSlash(t *testing.T) {
	a := &fakeProvider{name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer")}
	b := &fakeProvider{name: "other", issuer: "https://issuer/", claims: matchIssuer("https://issuer/")}
	if _, err := NewRegistry(nil, []Provider{a, b}, nil); err == nil {
		t.Fatal("expected refusal: issuer and issuer/ normalize to the same issuer")
	}
}

// Reserved names: github, service, dev, agent -- always; telegram, portal
// because they are registered surfaceid surface names. "dex" is deliberately
// NOT reserved: it is how an operator replaces the legacy shim (design.md).
func TestRegistryRefusesReservedAndSurfaceNames(t *testing.T) {
	for _, name := range []string{"github", "service", "dev", "agent", "telegram", "portal"} {
		p := &fakeProvider{name: name, issuer: "https://issuer-" + name, claims: matchIssuer("https://issuer-" + name)}
		if _, err := NewRegistry(nil, []Provider{p}, nil); err == nil {
			t.Fatalf("expected refusal for name %q", name)
		}
	}
}

// The one modelled exception: the local-OAuth provider may declare
// namespace "github" because it is that provider, not a stand-in.
func TestRegistryAllowsLocalOAuthProviderNamedGithub(t *testing.T) {
	oauth := &OAuthServer{BaseURL: "https://api.mctl.ai"}
	p := newLocalOAuthProvider(oauth)
	if _, err := NewRegistry(nil, []Provider{p}, nil); err != nil {
		t.Fatalf("local-oauth provider refused: %v", err)
	}
}

// The opaque GitHub PAT provider is also named "github" -- a different
// provider in a different bucket (opaque vs. JWT), so the two coexisting is
// not a duplicate name (they are never both candidates for the same token).
func TestRegistryAllowsGitHubOpaqueAlongsideLocalOAuthJWT(t *testing.T) {
	oauth := &OAuthServer{BaseURL: "https://api.mctl.ai"}
	jwtP := newLocalOAuthProvider(oauth)
	opaqueP := newGitHubProvider(NewGitHubValidator(nil), nil)
	if _, err := NewRegistry(nil, []Provider{jwtP}, []Provider{opaqueP}); err != nil {
		t.Fatalf("github PAT + local-oauth refused: %v", err)
	}
}

func TestRegistryRefusesTwoOpaqueProviders(t *testing.T) {
	a := &fakeProvider{name: "opaque-a"}
	b := &fakeProvider{name: "opaque-b"}
	if _, err := NewRegistry(nil, nil, []Provider{a, b}); err == nil {
		t.Fatal("expected refusal on two opaque providers: nothing to route on")
	}
}

func TestParseOIDCProvidersRejectsEmptyAudiences(t *testing.T) {
	if _, err := ParseOIDCProviders(`[{"name":"acme","issuer":"https://issuer"}]`); err == nil {
		t.Fatal("expected refusal for missing audiences")
	}
}

func TestParseOIDCProvidersRejectsInvalidEnforcement(t *testing.T) {
	raw := `[{"name":"acme","issuer":"https://issuer","audiences":["a"],"audience_enforcement":"sometimes"}]`
	if _, err := ParseOIDCProviders(raw); err == nil {
		t.Fatal("expected refusal for invalid audience_enforcement")
	}
}

func TestParseOIDCProvidersRejectsInvalidKind(t *testing.T) {
	raw := `[{"name":"acme","issuer":"https://issuer","audiences":["a"],"kind":"robot"}]`
	if _, err := ParseOIDCProviders(raw); err == nil {
		t.Fatal("expected refusal for invalid kind")
	}
}

func TestParseOIDCProvidersRejectsDuplicateNameAndIssuer(t *testing.T) {
	dupName := `[{"name":"a","issuer":"https://i1","audiences":["x"]},{"name":"a","issuer":"https://i2","audiences":["x"]}]`
	if _, err := ParseOIDCProviders(dupName); err == nil {
		t.Fatal("expected refusal for duplicate name")
	}
	dupIssuer := `[{"name":"a","issuer":"https://i","audiences":["x"]},{"name":"b","issuer":"https://i","audiences":["x"]}]`
	if _, err := ParseOIDCProviders(dupIssuer); err == nil {
		t.Fatal("expected refusal for duplicate issuer")
	}
}

func TestParseOIDCProvidersUnsetMeansNone(t *testing.T) {
	entries, err := ParseOIDCProviders("")
	if err != nil || entries != nil {
		t.Fatalf("entries=%v err=%v, want nil, nil", entries, err)
	}
}

// ─── T4: non-impersonation ──────────────────────────────────────────────────

func TestMisbehavingProviderNamespaceIsRefused(t *testing.T) {
	before := testutil.ToFloat64(federationContractViolations.WithLabelValues("acme"))
	bad := &fakeProvider{
		name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer"),
		verify: func(context.Context, string) (*Verified, error) {
			// A hostile or misconfigured provider tries to mint the service
			// namespace it does not own.
			return &Verified{Identity: Identity{Provider: ProviderService, Subject: ServiceUserID, Kind: KindService}}, nil
		},
	}
	r, err := NewRegistry(nil, []Provider{bad}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, verr := r.Verify(context.Background(), fakeJWT("https://issuer"))
	if !errors.Is(verr, ErrProviderContractViolation) {
		t.Fatalf("expected ErrProviderContractViolation, got %v", verr)
	}
	if got := testutil.ToFloat64(federationContractViolations.WithLabelValues("acme")) - before; got != 1 {
		t.Fatalf("federation_provider_contract_violations_total delta = %v, want 1", got)
	}
}

func TestMisbehavingProviderEmptySubjectIsRefused(t *testing.T) {
	bad := &fakeProvider{
		name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer"),
		verify: func(context.Context, string) (*Verified, error) {
			return &Verified{Identity: Identity{Provider: "acme", Subject: "", Kind: KindHuman}}, nil
		},
	}
	r, err := NewRegistry(nil, []Provider{bad}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, verr := r.Verify(context.Background(), fakeJWT("https://issuer")); !errors.Is(verr, ErrProviderContractViolation) {
		t.Fatalf("expected ErrProviderContractViolation, got %v", verr)
	}
}

func TestMisbehavingProviderInvalidKindIsRefused(t *testing.T) {
	bad := &fakeProvider{
		name: "acme", issuer: "https://issuer", claims: matchIssuer("https://issuer"),
		verify: func(context.Context, string) (*Verified, error) {
			return &Verified{Identity: Identity{Provider: "acme", Subject: "s", Kind: "root"}}, nil
		},
	}
	r, err := NewRegistry(nil, []Provider{bad}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, verr := r.Verify(context.Background(), fakeJWT("https://issuer")); !errors.Is(verr, ErrProviderContractViolation) {
		t.Fatalf("expected ErrProviderContractViolation, got %v", verr)
	}
}

// Delegation-shaped claims never reach *User: Verified/Claims have no field
// for them, so a provider cannot express "speaking for someone else" even if
// its token carries act/on_behalf_of.
func TestDelegationShapedClaimsProduceNoActingPrincipal(t *testing.T) {
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{
		Issuer: "https://issuer", Audience: []string{"aud"},
		Claims: map[string]any{"sub": "real-subject", "act": "attacker", "on_behalf_of": "victim"},
	}}
	spec := OIDCProviderSpec{Name: "acme", Issuer: "https://issuer", Audiences: []string{"aud"}, AudienceEnforcement: AudienceEnforce}
	p := newOIDCProviderForTest(spec, fv)
	v, err := p.Verify(context.Background(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	if v.Identity.Subject != "real-subject" {
		t.Fatalf("subject = %q", v.Identity.Subject)
	}
	u := userFromVerified(v)
	if got := u.ActingPrincipal(); got != "" {
		t.Fatalf("ActingPrincipal() = %q, want empty", got)
	}
	if _, ok := u.RelaySurface(); ok {
		t.Fatal("RelaySurface() claims a surface for a non-relayed user")
	}
}

// ─── T5: routing ────────────────────────────────────────────────────────────

func TestUnclaimedJWTIsUnclaimedAndInvokesNoProvider(t *testing.T) {
	p := &fakeProvider{name: "acme", issuer: "https://issuer-a", claims: matchIssuer("https://issuer-a"),
		verify: func(context.Context, string) (*Verified, error) {
			return &Verified{Identity: Identity{Provider: "acme", Subject: "s", Kind: KindHuman}}, nil
		},
	}
	r, err := NewRegistry(nil, []Provider{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(federationVerifications.WithLabelValues("none", "unclaimed"))
	_, verr := r.Verify(context.Background(), fakeJWT("https://nobody-claims-this"))
	if !errors.Is(verr, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", verr)
	}
	if p.calls != 0 {
		t.Fatalf("verifier invoked %d times for an unclaimed token", p.calls)
	}
	if got := testutil.ToFloat64(federationVerifications.WithLabelValues("none", "unclaimed")) - before; got != 1 {
		t.Fatalf("unclaimed counter delta = %v, want 1", got)
	}
}

func TestCrossProviderSignatureIsRefusedNotRerouted(t *testing.T) {
	a := &fakeProvider{name: "a", issuer: "https://issuer-a", claims: matchIssuer("https://issuer-a"),
		verify: func(context.Context, string) (*Verified, error) { return nil, errors.New("bad signature") }}
	b := &fakeProvider{name: "b", issuer: "https://issuer-b", claims: matchIssuer("https://issuer-b"),
		verify: func(context.Context, string) (*Verified, error) {
			return &Verified{Identity: Identity{Provider: "b", Subject: "s", Kind: KindHuman}}, nil
		}}
	r, err := NewRegistry(nil, []Provider{a, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The unverified iss claims provider a's issuer; a's Verify refuses it.
	if _, verr := r.Verify(context.Background(), fakeJWT("https://issuer-a")); verr == nil {
		t.Fatal("expected refusal")
	}
	if b.calls != 0 {
		t.Fatalf("token claiming issuer a was re-routed to b (%d calls)", b.calls)
	}
	if a.calls != 1 {
		t.Fatalf("provider a called %d times, want 1", a.calls)
	}
}

func TestStaticProvidersTriedBeforeJWTRouting(t *testing.T) {
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	svc := newServiceTokenProvider(func() string { return "svc-token-123" })
	r, err := NewRegistry([]Provider{svc}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, verr := r.Verify(context.Background(), "svc-token-123")
	if verr != nil || v.Identity.Subject != ServiceUserID {
		t.Fatalf("v=%+v err=%v", v, verr)
	}
}

// ─── T6: audience ───────────────────────────────────────────────────────────

type fakeOIDCVerifier struct {
	tok *oidcVerifiedToken
	err error
}

func (f fakeOIDCVerifier) Verify(context.Context, string) (*oidcVerifiedToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tok, nil
}

func TestOIDCAudienceEnforceRefusesWrongAudience(t *testing.T) {
	spec := OIDCProviderSpec{Name: "dex", Issuer: "https://dex", Audiences: []string{"mctl-api"}, AudienceEnforcement: AudienceEnforce}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex", Audience: []string{"other"}, Claims: map[string]any{"sub": "u1"}}}
	p := newOIDCProviderForTest(spec, fv)
	if _, err := p.Verify(context.Background(), "tok"); err == nil {
		t.Fatal("expected refusal on wrong audience in enforce mode")
	}
}

func TestOIDCAudienceAuditAcceptsAndCountsMismatch(t *testing.T) {
	before := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("dex-audit-test"))
	spec := OIDCProviderSpec{Name: "dex-audit-test", Issuer: "https://dex", Audiences: []string{"mctl-api"}, AudienceEnforcement: AudienceAudit}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex", Audience: []string{"other"}, Claims: map[string]any{"sub": "u1"}}}
	p := newOIDCProviderForTest(spec, fv)
	v, err := p.Verify(context.Background(), "tok")
	if err != nil {
		t.Fatalf("audit mode must accept a mismatched audience: %v", err)
	}
	if v.Identity.Subject != "u1" {
		t.Fatalf("subject = %q", v.Identity.Subject)
	}
	if got := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("dex-audit-test")) - before; got != 1 {
		t.Fatalf("mismatch counter delta = %v, want 1", got)
	}
}

func TestOIDCAudienceMatchNeitherRefusesNorCounts(t *testing.T) {
	before := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("dex-match-test"))
	spec := OIDCProviderSpec{Name: "dex-match-test", Issuer: "https://dex", Audiences: []string{"mctl-api"}, AudienceEnforcement: AudienceEnforce}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex", Audience: []string{"mctl-api"}, Claims: map[string]any{"sub": "u1"}}}
	p := newOIDCProviderForTest(spec, fv)
	if _, err := p.Verify(context.Background(), "tok"); err != nil {
		t.Fatalf("matched audience must be accepted: %v", err)
	}
	if got := testutil.ToFloat64(federationAudienceMismatch.WithLabelValues("dex-match-test")) - before; got != 0 {
		t.Fatalf("mismatch counter delta = %v, want 0", got)
	}
}

func TestOIDCLegacyShimSkipsAudienceCheckAndCounts(t *testing.T) {
	before := testutil.ToFloat64(federationAudienceCheckSkipped.WithLabelValues("dex-skip-test"))
	spec := OIDCProviderSpec{Name: "dex-skip-test", Issuer: "https://dex", SkipAudienceCheck: true}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex", Audience: nil, Claims: map[string]any{"sub": "u1"}}}
	p := newOIDCProviderForTest(spec, fv)
	if _, err := p.Verify(context.Background(), "tok"); err != nil {
		t.Fatalf("skip-audience mode must accept any audience: %v", err)
	}
	if got := testutil.ToFloat64(federationAudienceCheckSkipped.WithLabelValues("dex-skip-test")) - before; got != 1 {
		t.Fatalf("skip counter delta = %v, want 1", got)
	}
}

// ─── Dex claims-mapping characterization (T1/T2, A6) ───────────────────────

// A Dex-shaped token yields exactly the *User DexVerifier.Verify produces
// today (oidc.go:190-215): username falls back preferred_username -> email
// -> sub, dexIssuer/dexSubject are set from the verified issuer and the raw
// sub claim, and Identity() then reports (dex, issuer, sub).
func TestDexShapedTokenMapsIdentically(t *testing.T) {
	cases := []struct {
		name     string
		claims   map[string]any
		wantUser string
	}{
		{"preferred_username wins", map[string]any{"sub": "CgVhbGljZQ", "preferred_username": "alice", "email": "alice@example.com", "groups": []any{"team-a"}}, "alice"},
		{"falls back to email", map[string]any{"sub": "CgVhbGljZQ", "email": "alice@example.com", "groups": []any{"team-a"}}, "alice@example.com"},
		{"falls back to sub", map[string]any{"sub": "CgVhbGljZQ", "groups": []any{"team-a"}}, "CgVhbGljZQ"},
	}
	spec := OIDCProviderSpec{Name: ProviderDex, Issuer: "https://dex.example", AudienceEnforcement: AudienceEnforce, SkipAudienceCheck: true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex.example", Claims: c.claims}}
			p := newOIDCProviderForTest(spec, fv)
			v, err := p.Verify(context.Background(), "tok")
			if err != nil {
				t.Fatal(err)
			}
			u := userFromVerified(v)
			if u.ID != c.wantUser {
				t.Fatalf("ID = %q, want %q", u.ID, c.wantUser)
			}
			if !reflect.DeepEqual(u.Groups, []string{"team-a"}) {
				t.Fatalf("Groups = %v", u.Groups)
			}
			if u.dexIssuer != "https://dex.example" || u.dexSubject != "CgVhbGljZQ" {
				t.Fatalf("dexIssuer=%q dexSubject=%q", u.dexIssuer, u.dexSubject)
			}
			id, ok := u.Identity()
			if !ok || id.Provider != ProviderDex || id.Issuer != "https://dex.example" || id.Subject != "CgVhbGljZQ" {
				t.Fatalf("Identity() = %+v", id)
			}
		})
	}
}

// A generic (non-dex, non-github, non-service) MCTL_OIDC_PROVIDERS entry's
// verified identity round-trips through userFromVerified and User.Identity()
// with the provider's own namespace, issuer, subject and kind -- proving the
// P1 fix that such a user is now identity-bearing (previously
// userFromVerified's default case dropped every discriminator and
// Identity() had no case for it, so AttachPrincipal could never resolve or
// disable it).
func TestGenericOIDCProviderIdentityRoundTrips(t *testing.T) {
	spec := OIDCProviderSpec{Name: "acme", Issuer: "https://acme.example", Audiences: []string{"aud"}, AudienceEnforcement: AudienceEnforce, Kind: KindHuman}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{
		Issuer: "https://acme.example", Audience: []string{"aud"},
		Claims: map[string]any{"sub": "u-123", "preferred_username": "bob"},
	}}
	p := newOIDCProviderForTest(spec, fv)
	v, err := p.Verify(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	u := userFromVerified(v)
	if u.ID != "bob" {
		t.Fatalf("ID = %q, want %q", u.ID, "bob")
	}
	id, ok := u.Identity()
	if !ok {
		t.Fatal("Identity() ok = false, want true for a generic OIDC user")
	}
	want := Identity{Provider: "acme", Issuer: "https://acme.example", Subject: "u-123", Display: "bob", Kind: KindHuman}
	if id != want {
		t.Fatalf("Identity() = %+v, want %+v", id, want)
	}
}

// A generic OIDC provider's groups claim has "admins" stripped (P2 fix:
// docs/federation.md and requirements.md promise this proposal does not
// change who counts as an admin, but the shared oidcProvider.Verify code
// path is now reachable by any operator-configured MCTL_OIDC_PROVIDERS
// entry). The Dex slot is exempt and keeps "admins" unfiltered, matching
// DexVerifier.Verify's pre-existing behaviour bit-for-bit.
func TestGenericOIDCProviderStripsAdminsGroupButDexKeepsIt(t *testing.T) {
	claims := map[string]any{"sub": "u-123", "preferred_username": "bob", "groups": []any{"admins", "team-a"}}

	genericSpec := OIDCProviderSpec{Name: "acme", Issuer: "https://acme.example", Audiences: []string{"aud"}, AudienceEnforcement: AudienceEnforce}
	genericFV := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://acme.example", Audience: []string{"aud"}, Claims: claims}}
	genericP := newOIDCProviderForTest(genericSpec, genericFV)
	gv, err := genericP.Verify(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	genericUser := userFromVerified(gv)
	if reflect.DeepEqual(genericUser.Groups, []string{"admins", "team-a"}) {
		t.Fatal("generic OIDC provider must not keep the admins group")
	}
	if genericUser.IsAdmin() {
		t.Fatal("generic OIDC provider must not be able to mint an admin user")
	}
	if !reflect.DeepEqual(genericUser.Groups, []string{"team-a"}) {
		t.Fatalf("Groups = %v, want [team-a] (admins stripped, team-a kept)", genericUser.Groups)
	}

	dexSpec := OIDCProviderSpec{Name: ProviderDex, Issuer: "https://dex.example", AudienceEnforcement: AudienceEnforce, SkipAudienceCheck: true, LegacyDexGroups: true}
	dexFV := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://dex.example", Claims: claims}}
	dexP := newOIDCProviderForTest(dexSpec, dexFV)
	dv, err := dexP.Verify(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	dexUser := userFromVerified(dv)
	if !dexUser.IsAdmin() {
		t.Fatal("dex compatibility broken: admins group must still confer admin")
	}
	if !reflect.DeepEqual(dexUser.Groups, []string{"admins", "team-a"}) {
		t.Fatalf("dex Groups = %v, want [admins team-a] unfiltered", dexUser.Groups)
	}
}

// A provider merely named "dex" -- exactly what ParseOIDCProviders allows an
// operator's own MCTL_OIDC_PROVIDERS entry to be, since "dex" is
// deliberately left out of reservedProviderNames -- does not by its name get
// the unfiltered-admins behaviour. Only LegacyDexGroups grants that, and
// BuildFederationRegistry sets it only for "dex" on DEX_ISSUER_URL
// (TestBuildFederationRegistryDexSlot).
func TestOperatorNamedDexProviderStripsAdminsGroup(t *testing.T) {
	claims := map[string]any{"sub": "u-123", "preferred_username": "bob", "groups": []any{"admins", "team-a"}}
	spec := OIDCProviderSpec{Name: ProviderDex, Issuer: "https://acme.example", Audiences: []string{"aud"}, AudienceEnforcement: AudienceEnforce}
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://acme.example", Audience: []string{"aud"}, Claims: claims}}
	p := newOIDCProviderForTest(spec, fv)
	v, err := p.Verify(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	u := userFromVerified(v)
	if u.IsAdmin() {
		t.Fatal("operator-named dex provider (not the legacy shim) must not confer admin")
	}
	if !reflect.DeepEqual(u.Groups, []string{"team-a"}) {
		t.Fatalf("Groups = %v, want [team-a] (admins stripped)", u.Groups)
	}
}

// TestBuildFederationRegistryDexSlot pins BuildFederationRegistry's
// shim-vs-explicit composition through the newOIDCProviderFn seam (no live
// issuer): which provider serves the "dex" namespace, and which one keeps
// Dex's unfiltered "admins" (LegacyDexGroups).
func TestBuildFederationRegistryDexSlot(t *testing.T) {
	const dexIssuer = "https://ops.example/api/dex"
	entry := func(name, issuer string) string {
		return `{"name":"` + name + `","issuer":"` + issuer + `","audiences":["mctl-api"],"audience_enforcement":"audit"}`
	}
	cases := []struct {
		name        string
		raw         string
		failIssuer  string // the fake constructor fails for this issuer
		wantErr     string
		wantDex     bool // a provider named "dex" is registered
		wantIssuer  string
		wantLegacy  bool
		wantJWTSize int
	}{
		{name: "no entries: shim synthesized, legacy groups on",
			wantDex: true, wantIssuer: dexIssuer, wantLegacy: true, wantJWTSize: 1},
		{name: "explicit dex on the Dex issuer (audit canary): replaces shim, keeps admins",
			raw: "[" + entry("dex", dexIssuer) + "]", wantDex: true, wantIssuer: dexIssuer, wantLegacy: true, wantJWTSize: 1},
		{name: "explicit dex on another issuer (documented replacement): boots, admins filtered",
			raw: "[" + entry("dex", "https://idp.example") + "]", wantDex: true, wantIssuer: "https://idp.example", wantLegacy: false, wantJWTSize: 1},
		{name: "another name on the Dex issuer: refused, never re-namespaced",
			raw: "[" + entry("corp", dexIssuer) + "]", wantErr: "both claim issuer"},
		{name: "one entry's init fails: that provider omitted, no boot refusal",
			raw: "[" + entry("dex", dexIssuer) + "," + entry("corp", "https://down.example") + "]", failIssuer: "https://down.example",
			wantDex: true, wantIssuer: dexIssuer, wantLegacy: true, wantJWTSize: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := newOIDCProviderFn
			t.Cleanup(func() { newOIDCProviderFn = orig })
			newOIDCProviderFn = func(_ context.Context, spec OIDCProviderSpec) (*oidcProvider, error) {
				if spec.Issuer == tc.failIssuer {
					return nil, errors.New("issuer unreachable")
				}
				return newOIDCProviderForTest(spec, nil), nil
			}
			r, err := BuildFederationRegistry(context.Background(), FederationProvidersConfig{
				OIDCProvidersRaw: tc.raw, DexIssuerURL: dexIssuer, DexClientID: "mctl-api",
			}, nil, nil, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(r.jwt) != tc.wantJWTSize {
				t.Fatalf("jwt providers = %d, want %d", len(r.jwt), tc.wantJWTSize)
			}
			var dex *oidcProvider
			for _, p := range r.jwt {
				if op, ok := p.(*oidcProvider); ok && op.Name() == ProviderDex {
					dex = op
				}
			}
			if (dex != nil) != tc.wantDex {
				t.Fatalf("dex provider present = %v, want %v", dex != nil, tc.wantDex)
			}
			if dex == nil {
				return
			}
			if dex.issuerName() != tc.wantIssuer {
				t.Fatalf("dex issuer = %q, want %q", dex.issuerName(), tc.wantIssuer)
			}
			if dex.spec.LegacyDexGroups != tc.wantLegacy {
				t.Fatalf("dex LegacyDexGroups = %v, want %v", dex.spec.LegacyDexGroups, tc.wantLegacy)
			}
		})
	}
}

// ─── T1/T2/T11: characterization against the pre-registry chain, and kill
// switch parity ─────────────────────────────────────────────────────────────

// runMiddleware runs Middleware once, with the federation kill switch either
// set or not, and returns the *User it minted (nil if the request was
// refused).
func runMiddleware(t *testing.T, disabled bool, v *GitHubValidator, resolver TenantResolver, oauth *OAuthServer, token string) *User {
	t.Helper()
	if disabled {
		t.Setenv("MCTL_FEDERATION_DISABLED", "true")
	} else {
		t.Setenv("MCTL_FEDERATION_DISABLED", "")
	}
	var got *User
	h := Middleware(v, resolver, nil, oauth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = UserFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

// usersEqual compares every field T1 lists, including the unexported
// discriminators (this file is package auth, so they are visible).
func usersEqual(a, b *User) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ID == b.ID &&
		reflect.DeepEqual(a.Groups, b.Groups) &&
		a.service == b.service &&
		a.githubLogin == b.githubLogin &&
		a.usageWriter == b.usageWriter &&
		a.surface == b.surface &&
		a.githubID == b.githubID &&
		a.dexIssuer == b.dexIssuer &&
		a.dexSubject == b.dexSubject &&
		a.dev == b.dev
}

func TestCharacterization_ServiceSurfaceUsageWriterGitHubDev(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", tgToken)
	t.Setenv("MCTL_SURFACE_PORTAL_TOKEN", portalToken)
	t.Setenv("MCTL_USAGE_WRITER_TOKEN", usageWriterToken32)

	v := NewGitHubValidator(nil)
	v.cache["gho_alice"] = &githubUserInfo{Login: "alice", ID: 4242, CachedAt: time.Now()}

	cases := []struct {
		name  string
		token string
	}{
		{"service", "svc-token-123"},
		{"surface telegram", tgToken},
		{"surface portal", portalToken},
		{"usage writer", usageWriterToken32},
		{"github", "gho_alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := runMiddleware(t, true, v, nil, nil, c.token)
			neu := runMiddleware(t, false, v, nil, nil, c.token)
			if !usersEqual(old, neu) {
				t.Fatalf("old=%+v new=%+v", old, neu)
			}
			if old == nil {
				t.Fatal("token unexpectedly refused")
			}
			oldID, oldOK := old.Identity()
			newID, newOK := neu.Identity()
			if oldOK != newOK || oldID != newID {
				t.Fatalf("Identity(): old=%+v(%v) new=%+v(%v)", oldID, oldOK, newID, newOK)
			}
		})
	}
}

func TestCharacterization_DevMode(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "false")
	old := runMiddleware(t, true, NewGitHubValidator(nil), nil, nil, "")
	neu := runMiddleware(t, false, NewGitHubValidator(nil), nil, nil, "")
	if !usersEqual(old, neu) {
		t.Fatalf("old=%+v new=%+v", old, neu)
	}
}

func TestCharacterization_LocalOAuthJWT(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	oauth := &OAuthServer{BaseURL: "https://api.mctl.ai", JWTSecret: []byte("test-secret-key-material")}
	tok, err := oauth.IssueJWT("alice", []string{"team-a"})
	if err != nil {
		t.Fatal(err)
	}
	old := runMiddleware(t, true, NewGitHubValidator(nil), nil, oauth, tok)
	neu := runMiddleware(t, false, NewGitHubValidator(nil), nil, oauth, tok)
	if !usersEqual(old, neu) {
		t.Fatalf("old=%+v new=%+v", old, neu)
	}
	if old == nil || old.ID != "alice" {
		t.Fatalf("user = %+v", old)
	}
}

// T11: with the kill switch set, every characterization case above already
// takes the pre-registry chain (disabled=true); this test additionally
// pins that unsetting/resetting the switch does not leak state across
// requests within one Middleware build.
func TestKillSwitchParity(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_FEDERATION_DISABLED", "true")
	u := runMiddleware(t, true, NewGitHubValidator(nil), nil, nil, "svc-token-123")
	if u == nil || !u.IsService() {
		t.Fatalf("kill switch: user = %+v", u)
	}
	for _, v := range []string{"false", "f", "0", "no", "off", ""} {
		if federationKillSwitchOn(v) {
			t.Fatalf("federationKillSwitchOn(%q) = true, want false", v)
		}
	}
	for _, v := range []string{"true", "1", "yes", "on", "disabled"} {
		if !federationKillSwitchOn(v) {
			t.Fatalf("federationKillSwitchOn(%q) = false, want true", v)
		}
	}
}
