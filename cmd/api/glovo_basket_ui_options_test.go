package main

import (
	"context"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

type stubBasketView struct{}

func (stubBasketView) BasketApproval(context.Context, string) (*mctlapi.GlovoBasketApprovalSnapshot, error) {
	return nil, mctlapi.ErrGlovoBasketApprovalNotFound
}

// The Glovo basket approval page (mctl-api#1006) is on only with the flag and
// every part it needs, and off, silently, without the flag.
func TestGlovoBasketApprovalOptionsGating(t *testing.T) {
	const providers = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`
	full := func() (config, glovoBasketUIEnv) {
		return config{SelfURL: "https://api.example", OIDCProvidersRaw: providers, ZitadelLinkProvider: "zitadel"},
			glovoBasketUIEnv{Enabled: true, ClientID: "id", ClientSecret: "secret"}
	}
	var pr auth.PrincipalResolver = principals.NewResolver(&principals.Store{}, nil, false)
	authz := &auth.PrincipalAuthz{Admins: map[string]bool{}}
	var view mctlapi.GlovoBasketApprovalView = stubBasketView{}

	c, env := full()
	o := glovoBasketApprovalOptions(c, env, pr, authz, view)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ClientID != "id" ||
		o.ClientSecret != "secret" || o.BaseURL != "https://api.example" || o.Principals != pr || o.Authz != authz || o.View != view {
		t.Fatalf("full config: %+v, want the page on", o)
	}
	type parts struct {
		c    *config
		env  *glovoBasketUIEnv
		pr   *auth.PrincipalResolver
		az   **auth.PrincipalAuthz
		view *mctlapi.GlovoBasketApprovalView
	}
	off := map[string]func(p parts){
		"flag off":            func(p parts) { p.env.Enabled = false },
		"id without secret":   func(p parts) { p.env.ClientSecret = "" },
		"no client":           func(p parts) { p.env.ClientID, p.env.ClientSecret = "", "" },
		"no self URL":         func(p parts) { p.c.SelfURL = "" },
		"no principal store":  func(p parts) { *p.pr = nil },
		"not principal mode":  func(p parts) { *p.az = nil },
		"no basket view":      func(p parts) { *p.view = nil },
		"federation disabled": func(p parts) { p.c.FederationDisabled = true },
		"no provider entry":   func(p parts) { p.c.ZitadelLinkProvider = "other" },
		"malformed providers": func(p parts) { p.c.OIDCProvidersRaw = "{" },
	}
	for name, mutate := range off {
		c, env := full()
		p, a, v := pr, authz, view
		mutate(parts{&c, &env, &p, &a, &v})
		if o := glovoBasketApprovalOptions(c, env, p, a, v); o != nil {
			t.Errorf("%s: %+v, want nil", name, o)
		}
	}
}
