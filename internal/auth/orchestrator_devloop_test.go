package auth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func zitadelMachine(subject string) *Verified {
	return &Verified{
		Identity: Identity{Provider: "zitadel", Issuer: "https://auth.example", Subject: subject, Display: "orchestrator", Kind: KindHuman},
		// A machine user's token may carry any groups; none may reach the principal.
		Claims: Claims{Groups: []string{"admins", "some-tenant"}},
	}
}

func TestOrchestratorDevLoop_MappedOnlyForTheConfiguredIdentity(t *testing.T) {
	t.Setenv(orchestratorDevLoopProviderEnv, "zitadel")
	t.Setenv(orchestratorDevLoopSubjectEnv, "3300000000000001")

	u := userFromVerified(zitadelMachine("3300000000000001"))
	if !u.IsOrchestratorDevLoop() || u.ID != OrchestratorDevLoopUserID {
		t.Fatalf("configured identity: got %+v, want the orchestrator principal", u)
	}
	if u.IsAdmin() || len(u.Groups) != 0 || u.IsService() || u.IsAgent() {
		t.Fatalf("orchestrator must hold no groups, admin, service or agent standing: %+v", u)
	}
	id, ok := u.Identity()
	if !ok || id.Kind != KindService || id.Provider != "zitadel" || id.Subject != "3300000000000001" || id.Display != OrchestratorDevLoopUserID {
		t.Fatalf("identity: got %+v %v", id, ok)
	}

	for name, v := range map[string]*Verified{
		"other subject":  zitadelMachine("3300000000000002"),
		"other provider": {Identity: Identity{Provider: "other", Issuer: "https://auth.example", Subject: "3300000000000001", Kind: KindHuman}},
		"customer":       {Identity: Identity{Provider: "zitadel", Issuer: "https://auth.example", Subject: "3300000000000001", Kind: KindHuman, Customer: &CustomerProof{}}},
	} {
		if got := userFromVerified(v); got.IsOrchestratorDevLoop() {
			t.Errorf("%s: mapped to the orchestrator principal", name)
		}
	}
}

func TestOrchestratorDevLoop_OffUnlessFullyAndValidlyConfigured(t *testing.T) {
	for name, env := range map[string][2]string{
		"unset":            {"", ""},
		"provider only":    {"zitadel", ""},
		"subject only":     {"", "3300000000000001"},
		"service provider": {ProviderService, "3300000000000001"},
		"dex provider":     {ProviderDex, "3300000000000001"},
		"github provider":  {ProviderGitHub, "3300000000000001"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(orchestratorDevLoopProviderEnv, env[0])
			t.Setenv(orchestratorDevLoopSubjectEnv, env[1])
			if IsOrchestratorDevLoopIdentity(Identity{Provider: env[0], Subject: env[1]}) {
				t.Fatalf("mapping on for %q/%q", env[0], env[1])
			}
		})
	}
}

// A misconfiguration is logged once, not on every OIDC request that judges it.
func TestOrchestratorDevLoop_MisconfigurationLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	t.Setenv(orchestratorDevLoopProviderEnv, "zitadel-logonce-test")
	t.Setenv(orchestratorDevLoopSubjectEnv, "")
	for i := 0; i < 3; i++ {
		IsOrchestratorDevLoopIdentity(Identity{Provider: "zitadel-logonce-test"})
	}
	if n := strings.Count(buf.String(), "half-configured"); n != 1 {
		t.Fatalf("logged %d times, want 1:\n%s", n, buf.String())
	}
}
