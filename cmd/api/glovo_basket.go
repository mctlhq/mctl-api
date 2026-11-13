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
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// glovoBasketDeps is what the basket MCP needs from the rest of the boot.
type glovoBasketDeps struct {
	OAuth  *auth.OAuthServer
	Glovo  *api.GlovoRoutes
	Pool   *pgxpool.Pool
	Ledger *workitems.Store
	// ApprovalPageBaseURL is the API's public https origin when the owner
	// approval page (mctl-api#1007) is mounted, else empty: only then does
	// glovo_request_approval return an approval_url.
	ApprovalPageBaseURL string
}

// configureGlovoBasket wires the Glovo basket MCP (mctl-api#1006). It is dark:
// GLOVO_BASKET_MCP_ENABLED unset or false returns nil and mounts nothing.
// Set to true, every dependency must be present (the Glovo pilot with its
// resolver, the Glovo pool, the work-items ledger, a Glovo resource that is
// an https .../mcp URL) and both schemas must verify; otherwise the boot is
// refused. It never applies a schema.
func configureGlovoBasket(ctx context.Context, d glovoBasketDeps, lookup func(string) (string, bool)) (*api.GlovoBasketRoutes, error) {
	raw, set := lookup("GLOVO_BASKET_MCP_ENABLED")
	if !set || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	on, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("GLOVO_BASKET_MCP_ENABLED: %w", err)
	}
	if !on {
		return nil, nil
	}
	switch {
	case d.Glovo == nil || !d.Glovo.Enabled || d.Glovo.Resolver == nil:
		return nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires GLOVO_ENABLED=true with its team grants")
	case d.OAuth == nil || !d.OAuth.GlovoReady():
		return nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires a ready Glovo OAuth resource")
	case d.Pool == nil:
		return nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires the Glovo database pool")
	case d.Ledger == nil:
		return nil, errors.New("GLOVO_BASKET_MCP_ENABLED=true requires the work-items ledger (WORK_ITEMS_DB_URL)")
	}
	res, err := url.Parse(d.OAuth.GlovoResource)
	if err != nil || res.Scheme != "https" || res.Host == "" || res.Path != "/mcp" || res.RawQuery != "" || res.Fragment != "" {
		return nil, fmt.Errorf("GLOVO_BASKET_MCP_ENABLED=true requires the Glovo resource to be https://<host>/mcp, got %q", d.OAuth.GlovoResource)
	}
	if err := workitems.VerifyGlovoApprovalSchema(ctx, d.Pool); err != nil {
		return nil, fmt.Errorf("glovo basket: approval schema: %w", err)
	}
	if err := glovobasket.VerifySchema(ctx, d.Pool); err != nil {
		return nil, fmt.Errorf("glovo basket: %w", err)
	}
	store := &glovobasket.PGStore{Pool: d.Pool}
	h, err := glovobasket.NewHandler(glovobasket.Config{Store: store, Resolver: d.Glovo.Resolver,
		ApprovalPageBaseURL: d.ApprovalPageBaseURL})
	if err != nil {
		return nil, err
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
	}, nil
}
