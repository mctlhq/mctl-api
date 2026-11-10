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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// defaultGlovoNonSelectable is GLOVO_NON_SELECTABLE_TENANTS when unset: only
// the platform's own system tenant. `labs` is selectable by an allowlisted
// member who chooses it explicitly; nothing ever picks it by default.
const defaultGlovoNonSelectable = "admins"

// glovoEnabled parses GLOVO_ENABLED: unset or empty is false, and anything
// but true/false is a refused boot, so a typo never reads as on or off.
func glovoEnabled(lookup func(string) (string, bool)) (bool, error) {
	v, _ := lookup("GLOVO_ENABLED")
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, fmt.Errorf("GLOVO_ENABLED %q must be true or false", v)
}

// glovoTeamGrantDeps is what GLOVO_ENABLED=true needs; every field is checked
// so a missing one refuses the boot instead of leaving the feature half on.
type glovoTeamGrantDeps struct {
	OAuth           *auth.OAuthServer
	RefreshStore    *refreshstore.PostgresStore
	Membership      scope.MembershipReader
	ExplicitOAuthDB bool
	// ProveBridgeHook is the boot-time proof that bridge_commands and the
	// runtime grants exist on the Glovo pool; nil means proveBridgeHookTables.
	ProveBridgeHook func(ctx context.Context, q dbq.Querier) error
}

// configureGlovoTeamGrants wires the team grant store, the live eligibility
// reader and the kill switch. With GLOVO_ENABLED unset it does nothing, so
// every OAuth flow stays exactly as it was. It returns the Glovo store (for
// the allowlist routes) and the synthetic connection routes' configuration
// when enabled.
func configureGlovoTeamGrants(ctx context.Context, d glovoTeamGrantDeps, lookup func(string) (string, bool)) (*glovo.Store, *api.GlovoRoutes, error) {
	enabled, err := glovoEnabled(lookup)
	if err != nil || !enabled {
		return nil, nil, err
	}
	o := d.OAuth
	switch {
	case o == nil:
		return nil, nil, errors.New("GLOVO_ENABLED=true needs the OAuth server")
	case o.GlovoResource == "":
		return nil, nil, errors.New("GLOVO_ENABLED=true needs GLOVO_MCP_RESOURCE")
	case !o.PrincipalMode:
		return nil, nil, errors.New("GLOVO_ENABLED=true needs TENANT_AUTHZ_MODE=principal")
	case d.RefreshStore == nil:
		return nil, nil, errors.New("GLOVO_ENABLED=true needs the Postgres refresh store, not the in-memory one")
	case !d.ExplicitOAuthDB:
		return nil, nil, errors.New("GLOVO_ENABLED=true needs an explicit OAUTH_DB_URL")
	case d.Membership == nil:
		return nil, nil, errors.New("GLOVO_ENABLED=true needs the principal membership reader")
	}
	val := func(k string) string { v, _ := lookup(k); return strings.TrimSpace(v) }
	glovoURL := postgresURL(val("GLOVO_DB_URL"))
	if glovoURL == "" {
		return nil, nil, errors.New("GLOVO_ENABLED=true needs an explicit GLOVO_DB_URL")
	}
	runtimeRole, migrationRole := val("GLOVO_DB_RUNTIME_ROLE"), val("GLOVO_DB_MIGRATION_ROLE")
	if runtimeRole == "" || migrationRole == "" {
		return nil, nil, errors.New("GLOVO_ENABLED=true needs GLOVO_DB_RUNTIME_ROLE and GLOVO_DB_MIGRATION_ROLE")
	}
	pool, err := pgshared.Open(ctx, glovoURL)
	if err != nil {
		return nil, nil, fmt.Errorf("glovo store: connect: %w", err)
	}
	prove := d.ProveBridgeHook
	if prove == nil {
		prove = proveBridgeHookTables
	}
	realHook, err := decideRealRevocationHook(ctx, pool, lookup, prove)
	if err != nil {
		pgshared.Release(pool)
		return nil, nil, err
	}
	store, err := glovo.NewStore(ctx, pool, runtimeRole, migrationRole, glovoStoreOptions(realHook)...)
	if err != nil {
		pgshared.Release(pool)
		return nil, nil, err
	}
	if err := assertControlHook(realHook, store); err != nil {
		pgshared.Release(pool)
		return nil, nil, err
	}
	grants, err := teamgrant.NewPostgresStore(d.RefreshStore.Pool())
	if err != nil {
		pgshared.Release(pool)
		return nil, nil, err
	}
	// Empty is unset: a blank Helm value must not drop the default exclusion.
	nonSel := val("GLOVO_NON_SELECTABLE_TENANTS")
	if nonSel == "" {
		nonSel = defaultGlovoNonSelectable
	}
	o.TeamGrants = grants
	elig := &scope.Eligibility{Membership: d.Membership, Allowlist: store, NonSelectable: scope.NonSelectable(nonSel)}
	o.TeamEligibility = elig
	o.GlovoEnabled = true
	routes := &api.GlovoRoutes{
		Enabled: true, ResourceConfigured: o.GlovoResource != "", WorkerConfigured: auth.GlovoWorkerConfigured(),
		Store:    store,
		Resolver: &scope.Resolver{Grants: grants, Elig: elig, Resource: o.GlovoResource, Ready: o.GlovoReady},
		Connect:  &connect.Service{Store: store, HandoffBaseURL: val("GLOVO_SYNTHETIC_HANDOFF_BASE_URL")},
		ReadyTTL: 5 * time.Second,
	}
	return store, routes, nil
}

// glovoStoreOptions is the production configuration of the Glovo store. The
// end purger (mctl-api#961) removes a connection's unconsumed handoff
// references when it ends, and is required so the readiness probe reports
// not_ready instead of serving without it.
//
// With the control routes enabled the hook is bridge.CancelOpenForConnections,
// which cancels the open bridge commands of an ended connection; otherwise it
// is the synthetic no-op, which must never satisfy the write-fence conditions.
func glovoStoreOptions(controlEnabled bool) []glovo.Option {
	hook := glovo.RevocationHook(syntheticRevocationHook)
	if controlEnabled {
		hook = bridge.CancelOpenForConnections
	}
	return []glovo.Option{
		glovo.WithExplicitURL(true), glovo.WithRevocationHook(hook),
		glovo.WithEndPurger(glovo.PurgeHandoffRefs), glovo.WithEndPurgerRequired(true),
		glovo.WithLockTimeout(5 * time.Second),
	}
}

// syntheticRevocationHook is the revocation hook of the synthetic provider: it
// holds no secret, cookie or consumer credential, so there is nothing to
// release when a connection ends. A real provider replaces it.
func syntheticRevocationHook(context.Context, pgx.Tx, []string, string) error { return nil }

// assertControlHook is the startup assertion of mctl-api#985: with the control
// routes on, the installed hook must be the one that cancels open bridge
// commands, not merely a non-nil one.
func assertControlHook(controlEnabled bool, s *glovo.Store) error {
	if controlEnabled && !s.RevocationHookIs(bridge.CancelOpenForConnections) {
		return errors.New("MCTL_GLOVO_CONTROL_ENABLED=true needs bridge.CancelOpenForConnections as the revocation hook")
	}
	return nil
}

// decideRealRevocationHook is the one place that chooses the connection-end
// hook. The real hook (bridge.CancelOpenForConnections) runs SELECT ... FOR
// UPDATE on bridge_commands inside every connection-ending transaction, and an
// error there rolls the whole end back, so it is installed only when
// MCTL_GLOVO_CONTROL_ENABLED is on AND the build gate is open AND prove shows
// the table and its grants on this pool. A proof that fails with the flag and
// the gate on refuses the boot; it never falls back to the synthetic hook. With
// the flag off or the gate closed (every release build) prove is not called and
// the #959 lifecycle is untouched.
func decideRealRevocationHook(ctx context.Context, q dbq.Querier, lookup func(string) (string, bool),
	prove func(context.Context, dbq.Querier) error) (bool, error) {
	if !glovoControlEnabled(lookup) || !glovo.ControlDefault.Open {
		return false, nil
	}
	if err := prove(ctx, q); err != nil {
		return false, fmt.Errorf("MCTL_GLOVO_CONTROL_ENABLED=true needs bridge_commands and its runtime grants on the GLOVO_DB_URL pool, refusing to boot: %w", err)
	}
	return true, nil
}

// proveBridgeHookTables is the default proof: the bridge schema was applied and
// the runtime role holds exactly the grants the hook and the fence need.
func proveBridgeHookTables(ctx context.Context, q dbq.Querier) error {
	migrated, err := bridge.SchemaMigrated(ctx, q)
	if err != nil {
		return err
	}
	if !migrated {
		return errors.New("the bridge schema is not applied")
	}
	return bridge.VerifyRuntimeGrants(ctx, q)
}

// glovoControlEnabled reads MCTL_GLOVO_CONTROL_ENABLED leniently: only "true"
// is on, and a malformed value is rejected by configureGlovoControl.
func glovoControlEnabled(lookup func(string) (string, bool)) bool {
	v, _ := lookup("MCTL_GLOVO_CONTROL_ENABLED")
	return strings.EqualFold(strings.TrimSpace(v), "true")
}

// glovoAllowlist avoids a typed-nil interface: with the Glovo store absent
// the allowlist routes answer 503.
func glovoAllowlist(s *glovo.Store) api.GlovoAllowlist {
	if s == nil {
		return nil
	}
	return s
}
