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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// glovoBasketDeps is what the basket MCP needs from the rest of the boot.
type glovoBasketDeps struct {
	OAuth  *auth.OAuthServer
	Glovo  *api.GlovoRoutes
	Pool   *pgxpool.Pool
	Ledger *workitems.Store
	// UIEnabled is GLOVO_BASKET_UI_ENABLED: the owner approval page
	// (mctl-api#1007) decides basket approvals, so switching it on without
	// the basket MCP is a refused boot, not a page with nothing behind it.
	UIEnabled bool
	// Page builds the approval page's options over the basket store's view,
	// or returns nil when the page stays off (it logs what is missing). It
	// is called only when the basket MCP is on.
	Page func(view api.GlovoBasketApprovalView) *api.GlovoBasketApprovalPageOptions
}

// configureGlovoBasket wires the Glovo basket MCP (mctl-api#1006). It is dark:
// GLOVO_BASKET_MCP_ENABLED unset or false returns nil and mounts nothing.
// Set to true, every dependency must be present (the Glovo pilot with its
// resolver, the Glovo pool, the work-items ledger, a Glovo resource that is
// an https .../mcp URL) and both schemas must verify; otherwise the boot is
// refused. It never applies a schema.
//
// The approval page is built here, over the same store, so that
// glovo_request_approval returns an approval_url exactly when the page is
// mounted: its BaseURL is the URL's origin.
func configureGlovoBasket(ctx context.Context, d glovoBasketDeps, lookup func(string) (string, bool)) (*api.GlovoBasketRoutes, *api.GlovoBasketApprovalPageOptions, error) {
	routes, page, err := configureGlovoBasketMCP(ctx, d, lookup)
	if err == nil && routes == nil && d.UIEnabled {
		return nil, nil, errors.New("GLOVO_BASKET_UI_ENABLED=true requires GLOVO_BASKET_MCP_ENABLED=true: the page decides basket approvals")
	}
	return routes, page, err
}

func configureGlovoBasketMCP(ctx context.Context, d glovoBasketDeps, lookup func(string) (string, bool)) (*api.GlovoBasketRoutes, *api.GlovoBasketApprovalPageOptions, error) {
	raw, set := lookup("GLOVO_BASKET_MCP_ENABLED")
	if !set || strings.TrimSpace(raw) == "" {
		return nil, nil, nil
	}
	on, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("GLOVO_BASKET_MCP_ENABLED: %w", err)
	}
	if !on {
		return nil, nil, nil
	}
	switch {
	case d.Glovo == nil || !d.Glovo.Enabled || d.Glovo.Resolver == nil:
		return nil, nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires GLOVO_ENABLED=true with its team grants")
	case d.OAuth == nil || !d.OAuth.GlovoReady():
		return nil, nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires a ready Glovo OAuth resource")
	case d.Pool == nil:
		return nil, nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires the Glovo database pool")
	case d.Ledger == nil:
		return nil, nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires the work-items ledger (WORK_ITEMS_DB_URL)")
	}
	res, err := url.Parse(d.OAuth.GlovoResource)
	if err != nil || res.Scheme != "https" || res.Host == "" || res.Path != "/mcp" || res.RawQuery != "" || res.Fragment != "" {
		return nil, nil, fmt.Errorf("GLOVO_BASKET_MCP_ENABLED=true requires the Glovo resource to be https://<host>/mcp, got %q", d.OAuth.GlovoResource)
	}
	if err := workitems.VerifyGlovoApprovalSchema(ctx, d.Pool); err != nil {
		return nil, nil, fmt.Errorf("glovo basket: approval schema: %w", err)
	}
	if err := glovobasket.VerifySchema(ctx, d.Pool); err != nil {
		return nil, nil, fmt.Errorf("glovo basket: %w", err)
	}
	store := &glovobasket.PGStore{Pool: d.Pool}
	var page *api.GlovoBasketApprovalPageOptions
	if d.Page != nil {
		page = d.Page(api.NewGlovoBasketApprovalView(store))
	}
	h, err := glovobasket.NewHandler(basketMCPConfig(store, d.Glovo.Resolver, page))
	if err != nil {
		return nil, nil, err
	}
	pool := d.Pool
	return &api.GlovoBasketRoutes{
		Host: res.Hostname(), Resource: d.OAuth.GlovoResource, MCP: h, Payloads: store,
		Decisions: &workitems.GlovoBasketDecisions{
			Reader: pool,
			Begin:  func(ctx context.Context) (pgx.Tx, error) { return pool.Begin(ctx) },
			// Every decision re-proves both schemas, like the order kind's
			// receipt.Ready: the aar_ and binding guards, then the basket's.
			ReadyFn: func(ctx context.Context) error {
				if err := workitems.VerifyGlovoApprovalSchema(ctx, pool); err != nil {
					return err
				}
				return glovobasket.VerifySchema(ctx, pool)
			},
		},
	}, page, nil
}

// basketMCPConfig is the basket MCP's configuration. approval_url points at
// the approval page only when the page is mounted (page non-nil); its origin
// is the page's BaseURL, the same SELF_URL the page signs people in under.
func basketMCPConfig(store glovobasket.Store, resolver *scope.Resolver, page *api.GlovoBasketApprovalPageOptions) glovobasket.Config {
	cfg := glovobasket.Config{Store: store, Resolver: resolver}
	if page != nil {
		cfg.ApprovalPageBaseURL = page.BaseURL
	}
	return cfg
}
