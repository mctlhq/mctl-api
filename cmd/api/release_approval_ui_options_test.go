package main

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const testDeciderPRN = "prn_AAAAAAAAAAAAAAAAAAAAAAAAA1"

// The release approval page (mctl-api#1022 S2) is on only with the flag and
// every part it needs, deciders included, and off, silently, without the flag.
func TestReleaseApprovalOptionsGating(t *testing.T) {
	const providers = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`
	full := func() (config, releaseApprovalUIEnv) {
		return config{SelfURL: "https://api.example", OIDCProvidersRaw: providers, ZitadelLinkProvider: "zitadel"},
			releaseApprovalUIEnv{Enabled: true, ClientID: "id", ClientSecret: "secret",
				Deciders: []string{testDeciderPRN}, RequiredAMR: []string{"mfa"}}
	}
	var pr auth.PrincipalResolver = principals.NewResolver(&principals.Store{}, nil, false)
	authz := &auth.PrincipalAuthz{Admins: map[string]bool{}}
	var flow flowstore.Store = &flowstore.PostgresStore{}

	c, env := full()
	o := releaseApprovalOptions(c, env, pr, authz, flow, true, true)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ClientID != "id" ||
		o.BaseURL != "https://api.example" || strings.Join(o.Deciders, ",") != testDeciderPRN || strings.Join(o.RequiredAMR, ",") != "mfa" {
		t.Fatalf("full config: %+v, want the page on", o)
	}
	type parts struct {
		c              *config
		env            *releaseApprovalUIEnv
		pr             *auth.PrincipalResolver
		az             **auth.PrincipalAuthz
		flow           *flowstore.Store
		ledger, grants *bool
	}
	off := map[string]func(p parts){
		"flag off":                func(p parts) { p.env.Enabled = false },
		"id without secret":       func(p parts) { p.env.ClientSecret = "" },
		"secret without id":       func(p parts) { p.env.ClientID = "" },
		"no deciders":             func(p parts) { p.env.Deciders = nil },
		"decider not a principal": func(p parts) { p.env.Deciders = []string{testDeciderPRN, "dmitrii"} },
		"no self URL":             func(p parts) { p.c.SelfURL = "" },
		"no principal store":      func(p parts) { *p.pr = nil },
		"not principal mode":      func(p parts) { *p.az = nil },
		"no flow store":           func(p parts) { *p.flow = nil },
		"no work-items store":     func(p parts) { *p.ledger = false },
		"no release grant routes": func(p parts) { *p.grants = false },
		"federation disabled":     func(p parts) { p.c.FederationDisabled = true },
		"no provider entry":       func(p parts) { p.c.ZitadelLinkProvider = "other" },
	}
	for name, mutate := range off {
		c, env := full()
		p, a, f, l, g := pr, authz, flow, true, true
		mutate(parts{&c, &env, &p, &a, &f, &l, &g})
		if o := releaseApprovalOptions(c, env, p, a, f, l, g); o != nil {
			t.Errorf("%s: %+v, want nil", name, o)
		}
	}
}

func TestReleaseApprovalUIEnvFromOS(t *testing.T) {
	t.Setenv("RELEASE_APPROVAL_UI_ENABLED", "true")
	t.Setenv("RELEASE_APPROVAL_DECIDERS", " "+testDeciderPRN+" ,, ")
	t.Setenv("RELEASE_APPROVAL_REQUIRED_AMR", "")
	env := releaseApprovalUIEnvFromOS()
	if !env.Enabled || strings.Join(env.Deciders, ",") != testDeciderPRN || strings.Join(env.RequiredAMR, ",") != "mfa" {
		t.Fatalf("env %+v", env)
	}
	t.Setenv("RELEASE_APPROVAL_UI_ENABLED", "1")
	t.Setenv("RELEASE_APPROVAL_REQUIRED_AMR", "mfa,hwk")
	env = releaseApprovalUIEnvFromOS()
	if env.Enabled || strings.Join(env.RequiredAMR, ",") != "mfa,hwk" {
		t.Fatalf("env %+v", env)
	}
}
