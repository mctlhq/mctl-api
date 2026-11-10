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
		r, err := configureGlovoBasket(ctx, glovoBasketDeps{}, basketEnv(c.v, c.set))
		if r != nil || err != nil {
			t.Errorf("%q set=%v: %v %v, want dark", c.v, c.set, r, err)
		}
	}
	if _, err := configureGlovoBasket(ctx, glovoBasketDeps{}, basketEnv("yes please", true)); err == nil {
		t.Error("a malformed flag was accepted")
	}
	enabled := &api.GlovoRoutes{Enabled: true, Resolver: &scope.Resolver{}}
	for name, d := range map[string]glovoBasketDeps{
		"nothing":        {},
		"glovo disabled": {Glovo: &api.GlovoRoutes{Resolver: &scope.Resolver{}}},
		"no resolver":    {Glovo: &api.GlovoRoutes{Enabled: true}},
		"no oauth":       {Glovo: enabled},
	} {
		if r, err := configureGlovoBasket(ctx, d, basketEnv("true", true)); err == nil || r != nil {
			t.Errorf("%s: %v %v, want a refused boot", name, r, err)
		}
	}
}
