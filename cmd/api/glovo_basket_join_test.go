// Copyright 2026 MCTL Authors
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

package main

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
)

type nopApprovals struct{}

func (nopApprovals) RequestApprovalFromSnapshot(context.Context, glovobasket.Owner, glovobasket.SnapshotApprovalInput, time.Duration) (*glovobasket.ApprovalRequest, error) {
	return nil, nil
}

type nopPrincipals struct{}

func (nopPrincipals) ResolvePrincipal(context.Context, auth.Identity) (string, error) { return "", nil }

func basketJoinDeps() *glovoBasketJoinDeps {
	return &glovoBasketJoinDeps{Tokens: auth.NewOAuthServer("https://api.example", "", "", []byte("x"), nil, nil),
		Principals: nopPrincipals{}, Resolver: &scope.Resolver{}, Approvals: nopApprovals{}, PageBaseURL: "https://api.example"}
}

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// Fail closed: only an exact true with the full service identity and every
// dependency mounts the routes; anything else is off, with an error for the
// log whenever a value was set but wrong.
func TestConfigureGlovoBasketJoin(t *testing.T) {
	full := map[string]string{"GLOVO_BASKET_JOIN_ENABLED": "true",
		"GLOVO_BASKET_JOIN_SERVICE_PROVIDER": "glovo-basket-svc", "GLOVO_BASKET_JOIN_SERVICE_SUBJECT": "svc-1"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range full {
			m[a] = b
		}
		if v == "<unset>" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	g, err := configureGlovoBasketJoin(envOf(full), basketJoinDeps())
	if err != nil || g == nil || !g.Enabled || g.ServiceProvider != "glovo-basket-svc" || g.ServiceSubject != "svc-1" || g.Handler == nil {
		t.Fatalf("full: %+v %v", g, err)
	}
	for name, c := range map[string]struct {
		env     map[string]string
		deps    *glovoBasketJoinDeps
		wantErr bool
	}{
		"unset":            {with("GLOVO_BASKET_JOIN_ENABLED", "<unset>"), basketJoinDeps(), false},
		"false":            {with("GLOVO_BASKET_JOIN_ENABLED", "false"), basketJoinDeps(), false},
		"unparseable":      {with("GLOVO_BASKET_JOIN_ENABLED", "yes"), basketJoinDeps(), true},
		"one":              {with("GLOVO_BASKET_JOIN_ENABLED", "1"), basketJoinDeps(), true},
		"no provider":      {with("GLOVO_BASKET_JOIN_SERVICE_PROVIDER", "<unset>"), basketJoinDeps(), true},
		"blank subject":    {with("GLOVO_BASKET_JOIN_SERVICE_SUBJECT", "  "), basketJoinDeps(), true},
		"reserved":         {with("GLOVO_BASKET_JOIN_SERVICE_PROVIDER", "service"), basketJoinDeps(), true},
		"reserved dex":     {with("GLOVO_BASKET_JOIN_SERVICE_PROVIDER", auth.ProviderDex), basketJoinDeps(), true},
		"basket mcp off":   {full, nil, true},
		"http page origin": {full, func() *glovoBasketJoinDeps { d := basketJoinDeps(); d.PageBaseURL = "http://api.example"; return d }(), true},
		"no principals":    {full, func() *glovoBasketJoinDeps { d := basketJoinDeps(); d.Principals = nil; return d }(), true},
	} {
		g, err := configureGlovoBasketJoin(envOf(c.env), c.deps)
		if g != nil || (err != nil) != c.wantErr {
			t.Errorf("%s: routes %+v err %v (want error %v)", name, g, err, c.wantErr)
		}
	}
}
