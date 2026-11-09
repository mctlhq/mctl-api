package auth

import (
	"context"
	"errors"
	"testing"
)

type signInPrincipals map[string]string

func (s signInPrincipals) ResolvePrincipal(_ context.Context, id Identity) (string, error) {
	if p, ok := s[id.Subject]; ok {
		return p, nil
	}
	return "", ErrIdentityRefused
}

func TestUserForSignIn(t *testing.T) {
	pr := signInPrincipals{"z-admin": "prn_admin", "z-orch": "prn_orch"}
	authz := &PrincipalAuthz{Admins: map[string]bool{"prn_admin": true}}
	human := Identity{Provider: "zitadel", Issuer: "https://auth.example", Subject: "z-admin", Display: "admin", Kind: KindHuman}

	u, err := UserForSignIn(context.Background(), human, pr, authz)
	if err != nil || !u.IsAdmin() || u.IsService() || u.PrincipalID() != "prn_admin" {
		t.Fatalf("admin sign-in = %+v, %v", u, err)
	}

	t.Setenv(orchestratorDevLoopProviderEnv, "zitadel")
	t.Setenv(orchestratorDevLoopSubjectEnv, "z-orch")
	refused := map[string]Identity{
		"service kind": {Provider: "zitadel", Issuer: "https://auth.example", Subject: "z-admin", Kind: KindService},
		"customer":     {Provider: "zitadel", Issuer: "https://auth.example", Subject: "z-admin", Kind: KindHuman, Customer: &CustomerProof{}},
		"reserved":     {Provider: ProviderGitHub, Issuer: "https://auth.example", Subject: "z-admin", Kind: KindHuman},
		"dex":          {Provider: ProviderDex, Issuer: "https://auth.example", Subject: "z-admin", Kind: KindHuman},
		"no subject":   {Provider: "zitadel", Issuer: "https://auth.example", Kind: KindHuman},
		"orchestrator": {Provider: "zitadel", Issuer: "https://auth.example", Subject: "z-orch", Kind: KindHuman},
		"no principal": {Provider: "zitadel", Issuer: "https://auth.example", Subject: "z-unknown", Kind: KindHuman},
	}
	for name, id := range refused {
		if u, err := UserForSignIn(context.Background(), id, pr, authz); !errors.Is(err, ErrSignInRefused) || u != nil {
			t.Errorf("%s: = %+v, %v; want ErrSignInRefused", name, u, err)
		}
	}
	if _, err := UserForSignIn(context.Background(), human, nil, authz); !errors.Is(err, ErrSignInRefused) {
		t.Errorf("no resolver = %v, want refused", err)
	}
	// A non-admin without a membership source cannot be decided: refused,
	// never served as an unknown caller.
	authz.Admins = map[string]bool{}
	if _, err := UserForSignIn(context.Background(), human, pr, authz); !errors.Is(err, ErrSignInRefused) {
		t.Errorf("undecidable = %v, want refused", err)
	}
}
