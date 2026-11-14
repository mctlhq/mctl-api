package main

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// The deploy approval page (mctl-api#1026) is on only with the flag and every
// part it needs, and off, silently, without the flag.
func TestDeployApprovalOptionsGating(t *testing.T) {
	const providers = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`
	full := func() (config, deployApprovalUIEnv) {
		return config{SelfURL: "https://api.example", OIDCProvidersRaw: providers, ZitadelLinkProvider: "zitadel"},
			deployApprovalUIEnv{Enabled: true, ClientID: "id", ClientSecret: "secret"}
	}
	var pr auth.PrincipalResolver = principals.NewResolver(&principals.Store{}, nil, false)
	authz := &auth.PrincipalAuthz{Admins: map[string]bool{}}
	var flow flowstore.Store = &flowstore.PostgresStore{}

	c, env := full()
	o := deployApprovalOptions(c, env, pr, authz, flow, true, true)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ClientID != "id" ||
		o.ClientSecret != "secret" || o.BaseURL != "https://api.example" || o.Principals != pr || o.Authz != authz || o.Flow != flow {
		t.Fatalf("full config: %+v, want the page on", o)
	}
	type parts struct {
		c             *config
		env           *deployApprovalUIEnv
		pr            *auth.PrincipalResolver
		az            **auth.PrincipalAuthz
		flow          *flowstore.Store
		ledger, plans *bool
	}
	off := map[string]func(p parts){
		"flag off":            func(p parts) { p.env.Enabled = false },
		"id without secret":   func(p parts) { p.env.ClientSecret = "" },
		"secret without id":   func(p parts) { p.env.ClientID = "" },
		"no self URL":         func(p parts) { p.c.SelfURL = "" },
		"no principal store":  func(p parts) { *p.pr = nil },
		"not principal mode":  func(p parts) { *p.az = nil },
		"no flow store":       func(p parts) { *p.flow = nil },
		"no work-items store": func(p parts) { *p.ledger = false },
		"no deploy plans":     func(p parts) { *p.plans = false },
		"federation disabled": func(p parts) { p.c.FederationDisabled = true },
		"no provider entry":   func(p parts) { p.c.ZitadelLinkProvider = "other" },
		"malformed providers": func(p parts) { p.c.OIDCProvidersRaw = "{" },
	}
	for name, mutate := range off {
		c, env := full()
		p, a, f, l, pl := pr, authz, flow, true, true
		mutate(parts{&c, &env, &p, &a, &f, &l, &pl})
		if o := deployApprovalOptions(c, env, p, a, f, l, pl); o != nil {
			t.Errorf("%s: %+v, want nil", name, o)
		}
	}
}
