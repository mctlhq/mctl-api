package main

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

func basketEnv(v string, set bool) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if k == "GLOVO_BASKET_MCP_ENABLED" {
			return v, set
		}
		return "", false
	}
}

// Dark by default, and fail closed when switched on without its
// dependencies: the boot is refused, never a half-mounted route.
func TestConfigureGlovoBasket(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		v   string
		set bool
	}{{"", false}, {"", true}, {"false", true}, {"0", true}} {
		r, page, err := configureGlovoBasket(ctx, glovoBasketDeps{}, basketEnv(c.v, c.set))
		if r != nil || page != nil || err != nil {
			t.Errorf("%q set=%v: %v %v, want dark", c.v, c.set, r, err)
		}
	}
	if _, _, err := configureGlovoBasket(ctx, glovoBasketDeps{}, basketEnv("yes please", true)); err == nil {
		t.Error("a malformed flag was accepted")
	}
	enabled := &api.GlovoRoutes{Enabled: true, Resolver: &scope.Resolver{}}
	for name, d := range map[string]glovoBasketDeps{
		"nothing":        {},
		"glovo disabled": {Glovo: &api.GlovoRoutes{Resolver: &scope.Resolver{}}},
		"no resolver":    {Glovo: &api.GlovoRoutes{Enabled: true}},
		"no oauth":       {Glovo: enabled},
	} {
		if r, _, err := configureGlovoBasket(ctx, d, basketEnv("true", true)); err == nil || r != nil {
			t.Errorf("%s: %v %v, want a refused boot", name, r, err)
		}
	}
}

// The approval page decides basket approvals: switched on without the basket
// MCP, the boot is refused, and the page is never built over nothing.
func TestConfigureGlovoBasketUIRequiresTheMCP(t *testing.T) {
	ctx := context.Background()
	built := false
	d := glovoBasketDeps{UIEnabled: true, Page: func(api.GlovoBasketApprovalView) *api.GlovoBasketApprovalPageOptions {
		built = true
		return &api.GlovoBasketApprovalPageOptions{BaseURL: "https://api.example"}
	}}
	for _, c := range []struct {
		v   string
		set bool
	}{{"", false}, {"false", true}} {
		r, page, err := configureGlovoBasket(ctx, d, basketEnv(c.v, c.set))
		if err == nil || r != nil || page != nil {
			t.Errorf("UI on, MCP %q set=%v: %v %v %v, want a refused boot", c.v, c.set, r, page, err)
		}
	}
	if built {
		t.Error("the page was built without the basket MCP")
	}
	d.UIEnabled = false
	if r, page, err := configureGlovoBasket(ctx, d, basketEnv("", false)); r != nil || page != nil || err != nil {
		t.Errorf("both off: %v %v %v, want dark", r, page, err)
	}
}

// approval_url exists exactly when the page is mounted, under its origin.
func TestBasketMCPConfigLinksOnlyAMountedPage(t *testing.T) {
	if c := basketMCPConfig(nil, nil, nil); c.ApprovalPageBaseURL != "" {
		t.Errorf("no page: %q", c.ApprovalPageBaseURL)
	}
	if c := basketMCPConfig(nil, nil, &api.GlovoBasketApprovalPageOptions{BaseURL: "https://api.example"}); c.ApprovalPageBaseURL != "https://api.example" {
		t.Errorf("mounted page: %q", c.ApprovalPageBaseURL)
	}
}
