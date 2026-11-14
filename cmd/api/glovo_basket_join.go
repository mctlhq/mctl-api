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
	"errors"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovobasketjoin"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
)

// glovoBasketJoinDeps is what the basket join API is built over: the basket
// MCP's store and resolver (so it exists only when the basket MCP is on),
// the OAuth server that verifies subject tokens, and the principal store.
type glovoBasketJoinDeps struct {
	Tokens      glovojoin.TokenValidator
	Principals  auth.PrincipalResolver
	Resolver    glovojoin.ScopeResolver
	Approvals   glovobasketjoin.Approvals
	PageBaseURL string
}

// configureGlovoBasketJoin builds the basket join routes for the separate
// Glovo basket service. It is dark and fails closed: the routes are mounted
// only when GLOVO_BASKET_JOIN_ENABLED is exactly true, the one service
// identity is named (GLOVO_BASKET_JOIN_SERVICE_PROVIDER, a federated
// provider of kind service, and GLOVO_BASKET_JOIN_SERVICE_SUBJECT) and every
// dependency is there. Anything else leaves them unmounted (404); a value
// that is set but wrong is returned as an error for the boot log, never as
// a reason to mount with a default and never as a refused boot, so a typo in
// a dark flag cannot take the API down.
func configureGlovoBasketJoin(lookup func(string) (string, bool), d *glovoBasketJoinDeps) (*api.GlovoBasketJoinRoutes, error) {
	v, _ := lookup("GLOVO_BASKET_JOIN_ENABLED")
	switch strings.TrimSpace(v) {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fmt.Errorf("GLOVO_BASKET_JOIN_ENABLED %q must be true or false; basket join stays off", v)
	}
	provider, _ := lookup("GLOVO_BASKET_JOIN_SERVICE_PROVIDER")
	subject, _ := lookup("GLOVO_BASKET_JOIN_SERVICE_SUBJECT")
	provider, subject = strings.TrimSpace(provider), strings.TrimSpace(subject)
	switch {
	case provider == "" || subject == "":
		return nil, errors.New("GLOVO_BASKET_JOIN_ENABLED=true requires GLOVO_BASKET_JOIN_SERVICE_PROVIDER and GLOVO_BASKET_JOIN_SERVICE_SUBJECT; basket join stays off")
	case auth.IsReservedProviderName(provider):
		return nil, fmt.Errorf("GLOVO_BASKET_JOIN_SERVICE_PROVIDER %q is a built-in identity namespace, not a federated service provider; basket join stays off", provider)
	case d == nil:
		return nil, errors.New("GLOVO_BASKET_JOIN_ENABLED=true requires GLOVO_BASKET_MCP_ENABLED=true; basket join stays off")
	}
	svc := &glovobasketjoin.Service{Tokens: d.Tokens, Principals: d.Principals, Resolver: d.Resolver,
		Approvals: d.Approvals, ApprovalPageBaseURL: d.PageBaseURL}
	if err := svc.Validate(); err != nil {
		return nil, fmt.Errorf("%w; basket join stays off", err)
	}
	return &api.GlovoBasketJoinRoutes{Enabled: true, ServiceProvider: provider, ServiceSubject: subject, Handler: svc.Handler()}, nil
}
