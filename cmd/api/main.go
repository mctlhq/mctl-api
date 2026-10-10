// Copyright 2025 MCTL Authors
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/alerts"
	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argoarchive"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/clientstore"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/dburl"
	"github.com/mctlhq/mctl-api/internal/delegation"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/erpactsites"
	"github.com/mctlhq/mctl-api/internal/events"
	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/ghtoken"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/k8s"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
	"github.com/mctlhq/mctl-api/internal/loki"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/principals"
	"github.com/mctlhq/mctl-api/internal/roadmap"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/usage"
	"github.com/mctlhq/mctl-api/internal/vault"
	"github.com/mctlhq/mctl-api/internal/workitems"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Vendor-neutral tracing: W3C propagation always, OTLP export only when an
	// OTEL_EXPORTER_OTLP_* endpoint is set. A setup failure never blocks start.
	var otelShutdown func(context.Context) error
	if tel, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "mctl-api"}); err != nil {
		slog.Warn("telemetry setup failed; tracing export disabled", "error", err)
	} else {
		otelShutdown = tel.Shutdown
		slog.Info("telemetry initialised", "exporting", tel.Exporting)
	}

	// One signal registration for the whole process, established before
	// anything that can block — the Dex verifier below makes a network call,
	// and a SIGTERM landing there used to kill the process by default
	// disposition with nothing logged.
	//
	// It has to be a single root rather than one registration per phase: a
	// second, independent signal.Notify would only ever see a *second* signal,
	// and Kubernetes sends exactly one SIGTERM before SIGKILL at the end of
	// terminationGracePeriodSeconds. A signal delivered during startup would
	// then be recorded nowhere, the process would finish booting and start
	// serving, and the drain would never run.
	//
	// Released explicitly on each of main's early exits rather than by defer:
	// os.Exit does not run deferred functions (gocritic exitAfterDefer).
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	cfg := loadConfig()
	if err := cfg.validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		stopSignals()
		os.Exit(1)
	}

	// Initialize components.
	registry := operations.NewRegistry()

	checkCredentialSource("gitops-clone", cfg.GitOpsToken)
	checkCredentialSource("actions-dispatch", cfg.GitOpsActionsToken)
	gitReader := gitops.NewReader(cfg.GitOpsRepoURL, cfg.GitOpsBranch, cfg.GitOpsLocalPath, cfg.GitOpsToken, cfg.GitOpsSSHKeyPath, cfg.GitOpsSSHKnownHostsPath)
	// Scrape-time gauge (never written from a "stale" branch, so it always
	// reflects the current state and needs no reset path): backs
	// OAUTH_GROUPS_MAX_STALENESS alerting and the "Authorization group
	// freshness" behaviour documented in README.md. -1 while the checkout
	// has never synced, so that is distinguishable from "just synced".
	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "mctl_api_gitops_last_sync_age_seconds",
		Help: "Seconds since the gitops checkout's last successful sync; -1 while it has never synced.",
	}, func() float64 {
		last := gitReader.LastSync()
		if last.IsZero() {
			return -1
		}
		return time.Since(last).Seconds()
	}))

	// Dex JWT verifier (optional — disabled if DEX_ISSUER_URL is unset or unreachable).
	var dexVerifier *auth.DexVerifier
	if cfg.DexIssuerURL != "" {
		dv, dexErr := auth.NewDexVerifier(rootCtx, cfg.DexIssuerURL, cfg.DexClientID)
		if dexErr != nil {
			slog.Warn("dex OIDC init failed — JWT auth disabled", "issuer", cfg.DexIssuerURL, "error", dexErr)
		} else {
			dexVerifier = dv
			slog.Info("dex OIDC initialized", "issuer", cfg.DexIssuerURL, "clientID", cfg.DexClientID)
		}
	}

	// Auth middleware: validates GitHub tokens or Dex JWTs.
	ghValidator := auth.NewGitHubValidator(cfg.AdminUsers)

	// One budget shared by every optional store below, because the stores are
	// initialised sequentially: with a per-store budget and all four pointed at
	// the same unreachable AUDIT_DB_URL, each would burn a full ladder in turn
	// and hold up the listener for four times as long as any single one of them
	// promises. The deadline is global, so the worst case is what it says it
	// is, whether one store is configured or four.
	//
	// Derived from rootCtx, so a SIGTERM arriving mid-retry cuts the wait short
	// *and* still drives the shutdown below.
	//
	// None of the four constructors retain this context: each uses it for
	// pgxpool.New and the schema Exec, then keeps only the pool. So it is safe
	// to release it once the last store is built.
	initCtx, cancelInit := context.WithTimeout(rootCtx, storeInitBudget)
	// Every store below that is configured but fails init is recorded here,
	// and GET /readyz answers 503 while any is (mctl-api#387): such a store
	// stays nil for the pod's lifetime, so a pod that reported ready with it
	// would serve 503s (or an in-memory fallback) until someone restarted it.
	storeFailures := &storeInitFailures{}

	// OAuth 2.0 server. Under OAUTH_UPSTREAM=github (the default) it is
	// optional, disabled when OAUTH_GITHUB_CLIENT_ID is unset; zitadel and
	// both are explicit choices that validate() already refused to boot
	// without their configuration (mctl-api#467).
	var oauthServer *auth.OAuthServer
	if cfg.oauthEnabled() {
		oauthServer = auth.NewOAuthServer(
			cfg.SelfURL,
			cfg.OAuthGitHubClientID,
			cfg.OAuthGitHubClientSecret,
			[]byte(cfg.OAuthJWTSecret),
			cfg.OAuthAllowedRedirectURIs,
			ghValidator,
		)
		oauthServer.TenantResolver = gitReader
		oauthServer.AccessTokenTTL = cfg.OAuthTokenTTL
		oauthServer.RefreshTokenTTL = cfg.OAuthRefreshTokenTTL
		// Unset/0 = strict mode off: a stale checkout is used and alerted on
		// via the gauge above, not failed (mctl-api#411, README.md
		// "Authorization group freshness"). GroupsDegradedGrace is
		// deliberately left at 0, which OAuthServer resolves to
		// AccessTokenTTL -- the bound requirements.md names.
		oauthServer.GroupsMaxStaleness = parseDuration(os.Getenv("OAUTH_GROUPS_MAX_STALENESS"), 0)
		oauthServer.GroupsCacheTTL = parseDuration(os.Getenv("OAUTH_GROUPS_CACHE_TTL"), 30*time.Second)
		// Static public clients for counterparts that cannot register
		// dynamically (the Cloudflare MCP portal). Seeded before the first
		// request and never evicted, so the client id a portal stored keeps
		// working across pod restarts, which the in-memory DCR registry
		// cannot promise. A bad value is a refused boot, like any other
		// invalid configuration above; the value itself was already parsed
		// by config.validate, so this decode cannot fail.
		pre, err := parsePreregisteredClients(cfg.OAuthPreregisteredClientsRaw)
		if err != nil {
			slog.Error("invalid configuration", "error", err)
			stopSignals()
			os.Exit(1)
		}
		for _, c := range pre {
			if err := oauthServer.AddPreregisteredClient(c.ClientID, c.ClientName, c.RedirectURIs); err != nil {
				slog.Error("invalid configuration", "error", fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: %w", err))
				stopSignals()
				os.Exit(1)
			}
		}
		slog.Info("OAuth 2.0 server enabled", "upstream", cfg.oauthUpstreamMode(), "base_url", cfg.SelfURL, "redirect_uris", cfg.OAuthAllowedRedirectURIs, "token_ttl", cfg.OAuthTokenTTL, "preregistered_clients", oauthServer.PreregisteredClientCount(), "groups_max_staleness", oauthServer.GroupsMaxStaleness, "groups_cache_ttl", oauthServer.GroupsCacheTTL)

		// Persistent refresh-token store: prefer OAUTH_DB_URL, fall back to AUDIT_DB_URL.
		// When available, refresh tokens survive pod restarts; without it the in-memory
		// fallback is used (tokens lost on restart — the original band-aid behaviour).
		if oauthDBURL := postgresURL(envOr("OAUTH_DB_URL", os.Getenv("AUDIT_DB_URL"))); oauthDBURL != "" {
			rs, rsErr := initStore(initCtx, storeFailures, "oauth refresh", func(ctx context.Context) (*refreshstore.PostgresStore, error) {
				return refreshstore.NewPostgresStore(ctx, oauthDBURL)
			})
			if rsErr != nil {
				// Recorded in storeFailures by initStore, which keeps GET /readyz
				// at 503 for the life of this pod (mctl-api#387): it does not
				// serve on an in-memory fallback.
				slog.Error("oauth refresh store init failed; pod will report not-ready (GET /readyz 503) until restarted", "error", rsErr)
			} else {
				oauthServer.RefreshStore = rs
				go func() {
					ticker := time.NewTicker(15 * time.Minute)
					defer ticker.Stop()
					for range ticker.C {
						if err := rs.GC(); err != nil {
							slog.Warn("oauth refresh store gc failed", "error", err)
						}
					}
				}()
			}
			// Persistent RFC 7591 registrations, same database (mctl-api#395).
			// A client that registers once and caches its client_id -- the
			// Cloudflare MCP portal in automatic mode -- keeps resolving across
			// rollouts. Only a deployment with no database at all uses the
			// in-memory registry, which every restart forgets.
			cs, csErr := initStore(initCtx, storeFailures, "oauth clients", func(ctx context.Context) (*clientstore.PostgresStore, error) {
				return clientstore.NewPostgresStore(ctx, oauthDBURL)
			})
			if csErr != nil {
				// As above: recorded in storeFailures, so the pod stays
				// not-ready rather than serving on the in-memory registry.
				slog.Error("oauth client store init failed; pod will report not-ready (GET /readyz 503) until restarted", "error", csErr)
			} else {
				oauthServer.ClientStore = cs
				go func() {
					ticker := time.NewTicker(15 * time.Minute)
					defer ticker.Stop()
					for range ticker.C {
						if err := oauthServer.GCPersistedClients(); err != nil {
							slog.Warn("oauth client store gc failed", "error", err)
						}
					}
				}()
			}
			// Pending authorizations and authorization codes, same database.
			// Shared across replicas: authorize, the upstream callback and
			// the token exchange may each reach a different pod.
			fs, fsErr := initStore(initCtx, storeFailures, "oauth flow", func(ctx context.Context) (*flowstore.PostgresStore, error) {
				return flowstore.NewPostgresStore(ctx, oauthDBURL)
			})
			if fsErr != nil {
				// As above: recorded in storeFailures, so the pod stays
				// not-ready rather than serving on per-pod memory.
				slog.Error("oauth flow store init failed; pod will report not-ready (GET /readyz 503) until restarted", "error", fsErr)
			} else {
				oauthServer.FlowStore = fs
				go func() {
					ticker := time.NewTicker(5 * time.Minute)
					defer ticker.Stop()
					for range ticker.C {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						if err := fs.GC(ctx); err != nil {
							slog.Warn("oauth flow store gc failed", "error", err)
						}
						cancel()
					}
				}()
			}
		}
	}

	// Canonical principals, phase 1 (mctl-api#373). The store shares the
	// surface identity database (SURFACE_IDENTITY_DB_URL, else AUDIT_DB_URL)
	// because a redeemed link is mirrored into it in the same transaction.
	// Without a store every caller simply has no principal id; nothing
	// authorizes on it yet.
	var (
		principalStore    *principals.Store
		principalResolver auth.PrincipalResolver
		principalCache    *principals.Resolver
	)
	principalDBURL := postgresURL(os.Getenv("SURFACE_IDENTITY_DB_URL"))
	if principalDBURL == "" {
		principalDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	switch {
	case killSwitchOn(os.Getenv("PRINCIPALS_DISABLED")):
		slog.Warn("PRINCIPALS_DISABLED is set; callers carry no canonical principal id")
	case principalDBURL == "":
		slog.Warn("no SURFACE_IDENTITY_DB_URL or AUDIT_DB_URL; callers carry no canonical principal id")
	default:
		ps, psErr := initStore(initCtx, storeFailures, "principals", func(ctx context.Context) (*principals.Store, error) {
			return principals.NewStore(ctx, principalDBURL)
		})
		if psErr != nil {
			slog.Error("principal store init failed; callers carry no canonical principal id", "error", psErr)
		} else {
			principalStore = ps
			defer ps.Close()
			principalCache = principals.NewResolver(ps, githubIDLookup(), os.Getenv("AUTH_REQUIRED") == "false")
			principalResolver = principalCache
		}
	}

	// Federation registry (mctl-api#374, slice A): the static-secret
	// providers, the local-OAuth provider, the GitHub PAT provider, any
	// explicit MCTL_OIDC_PROVIDERS entries, and the legacy Dex shim (unless
	// an explicit entry is named "dex"). A construction failure
	// here is one of the conditions requirements.md says must refuse boot
	// (a malformed MCTL_OIDC_PROVIDERS value, or a registry invariant
	// violated by the combined provider set); an unreachable OIDC issuer at
	// boot is not one of them and is only logged (BuildFederationRegistry).
	// With MCTL_FEDERATION_DISABLED on, none of this runs: the kill switch is
	// the rollback for exactly these refusals, so it must reach the
	// pre-registry chain instead of crash-looping on them.
	federationRegistry, fedErr := buildFederationRegistry(rootCtx, cfg, ghValidator, gitReader, oauthServer)
	if fedErr != nil {
		slog.Error("invalid configuration", "error", fmt.Errorf("MCTL_OIDC_PROVIDERS: %w", fedErr))
		if principalStore != nil {
			principalStore.Close()
		}
		stopSignals()
		os.Exit(1) //nolint:gocritic // exitAfterDefer: principalStore, the one deferred close above, is closed explicitly just before this exit
	}

	// Agent run tokens (mctl-api#376) resolve through the work-items store,
	// which initializes later in startup than auth.Middleware is built
	// (it needs AUDIT_DB_URL/env parsing that happens further down, and
	// nothing before this point depends on it). agentRunResolver defers to
	// whatever store main wires into it below, once that store exists,
	// strictly before the server starts serving -- so there is no window
	// where a request could observe the holder before its store is set.
	agentRunResolver := &agentRunResolverHolder{}

	authMiddleware := auth.Middleware(ghValidator, gitReader, dexVerifier, oauthServer,
		auth.WithPrincipalResolver(principalResolver), auth.WithFederationRegistry(federationRegistry),
		auth.WithAgentRunResolver(agentRunResolver))

	argoClient := argocd.NewClient(cfg.ArgoCDURL, cfg.ArgoCDToken)

	var auditLog audit.Log
	if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		pgLog, pgErr := initStore(initCtx, storeFailures, "audit log", func(ctx context.Context) (*audit.PostgresLogger, error) {
			return audit.NewPostgresLogger(ctx, dbURL)
		})
		if pgErr != nil {
			slog.Error("postgres audit log init failed, falling back to in-memory (audit trail will NOT be persisted)", "error", pgErr)
			auditLog = audit.NewLogger()
		} else {
			auditLog = pgLog
		}
	} else {
		auditLog = audit.NewLogger()
	}

	// Alert store (optional — enabled when ALERT_DB_URL or AUDIT_DB_URL is set).
	var alertStore *alerts.Store
	if alertDBURL := postgresURL(os.Getenv("ALERT_DB_URL")); alertDBURL != "" {
		as, asErr := initStore(initCtx, storeFailures, "alert", func(ctx context.Context) (*alerts.Store, error) {
			return alerts.NewStore(ctx, alertDBURL)
		})
		if asErr != nil {
			slog.Error("alert store init failed; alert and incident endpoints will return 503", "error", asErr)
		} else {
			alertStore = as
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		as, asErr := initStore(initCtx, storeFailures, "alert", func(ctx context.Context) (*alerts.Store, error) {
			return alerts.NewStore(ctx, dbURL)
		})
		if asErr != nil {
			slog.Error("alert store init failed (using AUDIT_DB_URL); alert and incident endpoints will return 503", "error", asErr)
		} else {
			alertStore = as
		}
	}

	// Lifecycle ownership (optional — enabled when LIFECYCLE_DB_URL or
	// AUDIT_DB_URL is set). A nil store makes the lifecycle endpoints 503,
	// which callers must treat as "unknown" and never as "unowned": a store
	// outage that read as "nobody owns this" would license a second actor to
	// act, which is the failure this whole surface exists to prevent.
	var lifecycleStore *lifecycle.Store
	lifecycleDBURL := postgresURL(os.Getenv("LIFECYCLE_DB_URL"))
	if lifecycleDBURL == "" {
		lifecycleDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	if lifecycleDBURL != "" {
		ls, lsErr := initStore(initCtx, storeFailures, "lifecycle ownership", func(ctx context.Context) (*lifecycle.Store, error) {
			return lifecycle.NewStore(ctx, lifecycleDBURL)
		})
		if lsErr != nil {
			slog.Error("lifecycle ownership store init failed; lifecycle endpoints will return 503", "error", lsErr)
		} else {
			lifecycleStore = ls
		}
	}

	// Roadmap read model (mctl-api#333). A second gitops.Reader on the
	// generated roadmap-state branch of mctlhq/.github: mctl-api only reads
	// the published RoadmapPublication, it never runs the evaluator. The
	// repository is public, so no credential is needed; ROADMAP_STATE_TOKEN
	// exists for a private fork. ROADMAP_STATE_DISABLED (any value but false/0/no/off) turns it off and
	// the roadmap endpoints answer 503.
	var roadmapGit *gitops.Reader
	var roadmapReader *roadmap.Reader
	if !killSwitchOn(os.Getenv("ROADMAP_STATE_DISABLED")) {
		roadmapGit = gitops.NewReader(
			envOr("ROADMAP_STATE_REPO_URL", "https://github.com/mctlhq/.github.git"),
			envOr("ROADMAP_STATE_BRANCH", "roadmap-state"),
			envOr("ROADMAP_STATE_LOCAL_PATH", "/tmp/roadmap-state"),
			ghtoken.Static(os.Getenv("ROADMAP_STATE_TOKEN")), "", "",
		)
		roadmapReader = roadmap.NewReader(roadmapGit)
	}
	// ROADMAP_WAVE_MAX_AGE (mctl-api#334): how old the latest publication may
	// be when a wave executes. Invalid turns wave execution off rather than
	// running it against a bound nobody meant.
	roadmapWaveMaxAge, err := parseWaveMaxAge(os.Getenv("ROADMAP_WAVE_MAX_AGE"))
	if err != nil {
		slog.Error("invalid ROADMAP_WAVE_MAX_AGE; roadmap wave execution is off", "error", err)
		roadmapWaveMaxAge = -1
	}

	// Model usage / cost ledger (mctl-api#266, ADR-012). Optional — enabled
	// when USAGE_DB_URL or AUDIT_DB_URL is set. A nil store makes the usage
	// endpoints 503; see requireUsageAdmin for why that must not degrade to an
	// empty result.
	//
	// The pricing catalog is loaded from a file named by USAGE_PRICING_CATALOG
	// rather than compiled in: a published rate is a fact about the world with
	// an effective date, and a wrong constant silently produces plausible
	// money. With no catalog the ledger still records every token count and
	// stores whatever cost a producer supplies — it simply derives none of its
	// own, which is the honest behaviour when the rates are unknown.
	var usageStore *usage.Store
	usageDBURL := postgresURL(os.Getenv("USAGE_DB_URL"))
	if usageDBURL == "" {
		usageDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	if usageDBURL != "" {
		var pricing *usage.Catalog
		if path := os.Getenv("USAGE_PRICING_CATALOG"); path != "" {
			pc, pcErr := usage.LoadCatalogFile(path)
			if pcErr != nil {
				// Refusing to start would take the whole API down over a
				// rate card; recording usage without derived cost is strictly
				// better than recording nothing.
				slog.Error("usage pricing catalog failed to load; usage will be recorded without calculated cost", "error", pcErr)
			} else {
				pricing = pc
			}
		}
		us, usErr := initStore(initCtx, storeFailures, "usage ledger", func(ctx context.Context) (*usage.Store, error) {
			return usage.NewStore(ctx, usageDBURL, pricing)
		})
		if usErr != nil {
			slog.Error("usage ledger store init failed; usage endpoints will return 503", "error", usErr)
		} else {
			usageStore = us
		}
	}

	// Human-input delivery ledger (mctl-api#261). Optional — enabled when
	// HUMAN_INPUT_DB_URL or AUDIT_DB_URL is set. Without it the response
	// endpoint is 503: an answer that could be neither deduplicated nor
	// redelivered after a Temporal outage must not be taken at all. There is
	// deliberately no in-memory fallback, which would be wrong as soon as
	// two replicas run.
	var humanInputLedger humaninput.Ledger
	humanInputDBURL := postgresURL(os.Getenv("HUMAN_INPUT_DB_URL"))
	if humanInputDBURL == "" {
		humanInputDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	if humanInputDBURL != "" {
		hl, hlErr := initStore(initCtx, storeFailures, "human-input ledger", func(ctx context.Context) (*humaninput.PostgresLedger, error) {
			return humaninput.NewPostgresLedger(ctx, humanInputDBURL)
		})
		if hlErr != nil {
			slog.Error("human-input ledger init failed; human-input responses will return 503", "error", hlErr)
		} else {
			humanInputLedger = hl
			defer hl.Close()
		}
	}

	// Work-items store (workitem/v1, mctl-api#349). Optional — enabled when
	// WORK_ITEMS_DB_URL or AUDIT_DB_URL is set, unless WORK_ITEMS_DISABLED is.
	// The kill switch leaves the store nil without touching the shared
	// AUDIT_DB_URL other stores depend on. Nil makes every /api/v1/work-items
	// route answer 503.
	var workItemsStore *workitems.Store
	workItemsDBURL := postgresURL(os.Getenv("WORK_ITEMS_DB_URL"))
	if workItemsDBURL == "" {
		workItemsDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	switch {
	case killSwitchOn(os.Getenv("WORK_ITEMS_DISABLED")):
		slog.Warn("WORK_ITEMS_DISABLED is set; /api/v1/work-items and /api/v1/action-approvals routes will return 503")
	case workItemsDBURL == "":
		slog.Warn("no WORK_ITEMS_DB_URL or AUDIT_DB_URL; /api/v1/work-items and /api/v1/action-approvals routes will return 503")
	default:
		ws, wsErr := initStore(initCtx, storeFailures, "work items", func(ctx context.Context) (*workitems.Store, error) {
			return workitems.NewStore(ctx, workItemsDBURL)
		})
		if wsErr != nil {
			slog.Error("work-items store init failed; /api/v1/work-items and /api/v1/action-approvals routes will return 503", "error", wsErr)
		} else {
			workItemsStore = ws
			defer ws.Close()
			// Wired in before the server starts serving; see the comment on
			// agentRunResolver's declaration above.
			agentRunResolver.store = ws
		}
	}

	// Execution-evidence store (mctl-api#409, Tier B of
	// evidence.mctl.ai/v1alpha1). Same shape as the work-items store:
	// EVIDENCE_DB_URL, else AUDIT_DB_URL, with a kill switch. Nil makes
	// every /api/v1/evidence* route (and GET /api/v1/work-items/{id}/evidence)
	// answer 503, never an empty list.
	var evidenceStore *evidence.Store
	evidenceDBURL := postgresURL(os.Getenv("EVIDENCE_DB_URL"))
	if evidenceDBURL == "" {
		evidenceDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	switch {
	case killSwitchOn(os.Getenv("EVIDENCE_DISABLED")):
		slog.Warn("EVIDENCE_DISABLED is set; /api/v1/evidence* routes will return 503")
	case evidenceDBURL == "":
		slog.Warn("no EVIDENCE_DB_URL or AUDIT_DB_URL; /api/v1/evidence* routes will return 503")
	default:
		es, esErr := initStore(initCtx, storeFailures, "evidence", func(ctx context.Context) (*evidence.Store, error) {
			return evidence.NewStore(ctx, evidenceDBURL)
		})
		if esErr != nil {
			slog.Error("evidence store init failed; /api/v1/evidence* routes will return 503", "error", esErr)
		} else {
			evidenceStore = es
			defer es.Close()
			// Best-effort correlation only, never a foreign key
			// (docs/work-context-contract.md "ID scheme"): a nil
			// workItemsStore (disabled, or not configured) simply leaves
			// every derived projection empty rather than resolving nothing
			// through a nil pointer.
			if workItemsStore != nil {
				evidenceStore.SetResolver(workItemsStore)
			}
			startEvidenceRetentionSweep(rootCtx, evidenceStore)
		}
	}

	// Surface identity links (mctl-api#350). Same shape as the work-items
	// store: SURFACE_IDENTITY_DB_URL, else AUDIT_DB_URL, with a kill switch.
	// SURFACE_LINK_TTL (a Go duration, e.g. 2160h) gives new links an
	// expiry; unset means a link lasts until revoked. Nil answers 503, and a
	// surface principal can then relay for no one.
	var surfaceIDs *surfaceid.Store
	surfaceDBURL := postgresURL(os.Getenv("SURFACE_IDENTITY_DB_URL"))
	if surfaceDBURL == "" {
		surfaceDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
	}
	linkTTL, ttlErr := parseLinkTTL(os.Getenv("SURFACE_LINK_TTL"))
	switch {
	case killSwitchOn(os.Getenv("SURFACE_IDENTITY_DISABLED")):
		slog.Warn("SURFACE_IDENTITY_DISABLED is set; /api/v1/surface-identities routes will return 503")
	case ttlErr != nil:
		slog.Error("invalid SURFACE_LINK_TTL; surface identities disabled", "error", ttlErr)
	case surfaceDBURL == "":
		slog.Warn("no SURFACE_IDENTITY_DB_URL or AUDIT_DB_URL; /api/v1/surface-identities routes will return 503")
	default:
		ss, ssErr := initStore(initCtx, storeFailures, "surface identities", func(ctx context.Context) (*surfaceid.Store, error) {
			return surfaceid.NewStore(ctx, surfaceDBURL, linkTTL)
		})
		if ssErr != nil {
			slog.Error("surface identity store init failed; routes will return 503", "error", ssErr)
		} else {
			surfaceIDs = ss
			defer ss.Close()
			if principalStore != nil {
				// Same database by construction: both resolve
				// SURFACE_IDENTITY_DB_URL, else AUDIT_DB_URL.
				ss.SetMirror(principalStore)
			}
		}
	}

	// Delegation grants for agent principals (mctl-api#376 slice B):
	// X-MCTL-On-Behalf-Of resolves through the same two stores above. Built
	// from typed-nil-safe interface values -- a nil *workitems.Store or
	// *surfaceid.Store assigned directly to the interface fields would leave
	// a non-nil interface wrapping a nil pointer, which StoreResolver's own
	// nil checks would never see as nil. Either half missing simply makes
	// its kinds answer 503 delegation_unavailable, never a refusal.
	var delegationItems delegation.WorkItemSource
	if workItemsStore != nil {
		delegationItems = workItemsStore
	}
	var delegationLinks delegation.SurfaceLinkSource
	if surfaceIDs != nil {
		delegationLinks = surfaceIDs
	}
	delegationResolver := delegation.NewStoreResolver(delegationItems, delegationLinks)

	// Agent registry (optional — enabled when AGENT_REGISTRY_DB_URL or AUDIT_DB_URL is set).
	// Inbound events for Claude Remote (mctlhq/.github#87): GitHub pull request
	// webhooks are accepted into a Postgres outbox and relayed to platform
	// Valkey Streams. Enabled only when the webhook secret, the Valkey URL and a
	// database are all configured; otherwise the webhook answers 401/503.
	var githubEventOutbox *events.Outbox
	var githubEventRelay *events.Relay
	if cfg.GitHubWebhookSecret != "" && cfg.EventsValkeyURL != "" {
		eventsDBURL := postgresURL(os.Getenv("EVENTS_DB_URL"))
		if eventsDBURL == "" {
			eventsDBURL = postgresURL(os.Getenv("AUDIT_DB_URL"))
		}
		valkey, vkErr := events.NewClient(cfg.EventsValkeyURL, cfg.EventsValkeyPassword, 5*time.Second)
		switch {
		case vkErr != nil:
			slog.Error("events valkey config invalid; github webhook will return 503", "error", vkErr)
		case eventsDBURL == "":
			slog.Error("no EVENTS_DB_URL or AUDIT_DB_URL; github webhook will return 503")
		default:
			ob, obErr := initStore(initCtx, storeFailures, "event outbox", func(ctx context.Context) (*events.Outbox, error) {
				return events.NewOutbox(ctx, eventsDBURL)
			})
			if obErr != nil {
				slog.Error("event outbox init failed; github webhook will return 503", "error", obErr)
			} else {
				githubEventOutbox = ob
				githubEventRelay = events.NewRelay(ob, valkey, true)
				go githubEventRelay.Run(rootCtx)
				slog.Info("github event outbox enabled", "stream", events.DefaultStream)
			}
		}
	}

	var agentRegistryStore *agentregistry.Store
	if agentRegistryDBURL := postgresURL(os.Getenv("AGENT_REGISTRY_DB_URL")); agentRegistryDBURL != "" {
		ars, arsErr := initStore(initCtx, storeFailures, "agent registry", func(ctx context.Context) (*agentregistry.Store, error) {
			return agentregistry.NewStore(ctx, agentRegistryDBURL)
		})
		if arsErr != nil {
			slog.Error("agent registry store init failed; agent registry endpoints will return 503", "error", arsErr)
		} else {
			agentRegistryStore = ars
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		ars, arsErr := initStore(initCtx, storeFailures, "agent registry", func(ctx context.Context) (*agentregistry.Store, error) {
			return agentregistry.NewStore(ctx, dbURL)
		})
		if arsErr != nil {
			slog.Error("agent registry store init failed (using AUDIT_DB_URL); agent registry endpoints will return 503", "error", arsErr)
		} else {
			agentRegistryStore = ars
		}
	}

	// Custom domains registry (optional — enabled when DOMAINS_DB_URL or
	// AUDIT_DB_URL is set). mctl-api owns this table directly; it no longer
	// proxies to Backstage's custom-domains plugin.
	var domainStore *domains.Store
	if domainsDBURL := postgresURL(os.Getenv("DOMAINS_DB_URL")); domainsDBURL != "" {
		ds, dsErr := initStore(initCtx, storeFailures, "domains", func(ctx context.Context) (*domains.Store, error) {
			return domains.NewStore(ctx, domainsDBURL)
		})
		if dsErr != nil {
			slog.Error("domains store init failed; /api/v1/domains* will return 503", "error", dsErr)
		} else {
			domainStore = ds
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		ds, dsErr := initStore(initCtx, storeFailures, "domains", func(ctx context.Context) (*domains.Store, error) {
			return domains.NewStore(ctx, dbURL)
		})
		if dsErr != nil {
			slog.Error("domains store init failed (using AUDIT_DB_URL); /api/v1/domains* will return 503", "error", dsErr)
		} else {
			domainStore = ds
		}
	}
	domainVerifier := domains.NewVerifier(cfg.DNSResolverAddr)

	// Only the init deadline is released here; rootCtx stays live for the rest
	// of the process. Releasing the timeout early keeps its timer from firing
	// against a context nothing is waiting on any more.
	cancelInit()

	// A signal delivered while a store was retrying has already cancelled
	// rootCtx. Booting on regardless would mean a pod that was told to stop
	// starts serving traffic instead, and is then SIGKILLed at the end of the
	// grace period with no drain — so stop here, before the listener exists.
	if err := rootCtx.Err(); err != nil {
		slog.Info("shutdown signalled during startup; exiting before serving", "reason", err)
		stopSignals()
		return
	}

	// Temporal client for DevLoopWorkflow (optional — enabled when
	// TEMPORAL_ADDRESS is set). Same graceful-degradation pattern as
	// agentRegistryStore above: mctl_trigger_issue's use_temporal path
	// simply stays unavailable (503) rather than failing startup, since
	// today's direct-Argo-submission path is unaffected either way.
	// Declared as the mctlapi.DevLoopClient interface, not the concrete
	// *temporalclient.Client, and left as its zero value (nil interface) on
	// every path that doesn't assign a real client below. Assigning a nil
	// *temporalclient.Client pointer to an interface-typed field would
	// produce a non-nil interface wrapping a nil pointer — requireTemporalAdmin's
	// `h.opts.TemporalClient == nil` check would then wrongly see "configured".
	// GitHub Actions dispatcher (optional — enabled when GITOPS_ACTIONS_TOKEN
	// is set). Same nil-interface discipline as devLoopClient below: the
	// field is left as its zero value when unconfigured, because assigning a
	// nil *ghactions.Dispatcher to an interface-typed field would produce a
	// non-nil interface wrapping a nil pointer and the handler's
	// "not configured" branch would never fire.
	var workflowDispatcher mctlapi.WorkflowDispatcher
	if cfg.GitOpsActionsToken != nil {
		workflowDispatcher = ghactions.New(cfg.GitOpsActionsToken)
	} else {
		slog.Warn("no dispatch credential configured; the Cloudflare portal server-auth apply cannot be dispatched",
			"want", "GITHUB_APP_TOKEN_FILE or GITOPS_ACTIONS_TOKEN",
			"route", "POST /api/v1/cloudflare/portal/server-auth/apply")
	}

	var devLoopClient mctlapi.DevLoopClient
	if temporalAddress := os.Getenv("TEMPORAL_ADDRESS"); temporalAddress != "" {
		temporalNamespace := os.Getenv("TEMPORAL_NAMESPACE")
		if temporalNamespace == "" {
			temporalNamespace = "mctl-agents"
		}
		tc, tcErr := temporalclient.New(temporalAddress, temporalNamespace)
		if tcErr != nil {
			slog.Warn("temporal client init failed", "error", tcErr)
		} else {
			devLoopClient = tc
			defer tc.Close()
		}
	}

	executor := operations.NewExecutor()

	// MCP server for SSE transport (embedded in this process).
	// Tools make REST calls back to this server using the caller's token (forwarded via context).
	// Use localhost to avoid hairpin routing and public egress issues; the
	// caller-facing text mctl_whoami shows comes from publicBaseURL below.
	mcpSrv := mctlmcp.NewInProcessServer(cfg.Port, publicBaseURL(cfg, oauthServer))

	// Kubernetes quota client (optional — fails gracefully outside cluster).
	var quotaReader mctlapi.QuotaReader
	if qc, qErr := k8s.NewQuotaClient(); qErr != nil {
		slog.Warn("k8s quota client unavailable, resource usage will be empty", "error", qErr)
	} else {
		quotaReader = qc
	}

	// Loki log client (optional — enabled when LOKI_URL is set).
	var logQuerier mctlapi.LogQuerier
	if lokiURL := os.Getenv("LOKI_URL"); lokiURL != "" {
		logQuerier = loki.NewClient(lokiURL)
		slog.Info("loki log querying enabled", "url", lokiURL)
	}

	// Argo Workflows step-log archive (optional — enabled when the object
	// store is configured). Separate from Loki: Loki only ingests
	// long-lived service pods, never Argo step pods.
	var workflowLogArchive mctlapi.WorkflowLogArchive
	if ep, bucket := os.Getenv("ARGO_LOGS_R2_ENDPOINT"), os.Getenv("ARGO_LOGS_R2_BUCKET"); ep != "" && bucket != "" {
		accessKey := os.Getenv("ARGO_LOGS_R2_ACCESS_KEY")
		secretKey := os.Getenv("ARGO_LOGS_R2_SECRET_KEY")
		if accessKey == "" || secretKey == "" {
			slog.Warn("workflow log archive endpoint set but credentials are missing, archived step logs disabled")
		} else {
			workflowLogArchive = argoarchive.NewClient(ep, bucket, accessKey, secretKey)
			slog.Info("workflow log archive enabled", "endpoint", ep, "bucket", bucket)
		}
	}

	// Vault client (optional — used for onboarding secret preflight).
	// Kubernetes auth is preferred: the pod proves its identity with its own
	// projected ServiceAccount token and Vault issues a short-lived
	// credential it can re-mint. The static token stays supported as a
	// fallback, but it is the mode that broke Backstage in production when
	// the token was revoked with nothing to renew it (2026-08-01).
	var vaultReader mctlapi.VaultReader
	switch {
	case cfg.VaultAddr != "" && cfg.VaultKubernetesRole != "":
		tokens := vault.NewKubernetesTokenProvider(vault.KubernetesAuthOptions{
			VaultAddr: cfg.VaultAddr,
			Role:      cfg.VaultKubernetesRole,
			AuthPath:  cfg.VaultKubernetesAuthPath,
		})
		vaultReader = vault.NewClientWithTokenProvider(cfg.VaultAddr, tokens)
		slog.Info("vault client enabled", "addr", cfg.VaultAddr, "auth", "kubernetes", "role", cfg.VaultKubernetesRole)
	case cfg.VaultAddr != "" && cfg.VaultToken != "":
		vaultReader = vault.NewClient(cfg.VaultAddr, cfg.VaultToken)
		slog.Info("vault client enabled", "addr", cfg.VaultAddr, "auth", "static-token")
	}

	// ERPact site tools (mctl-api#486): off unless the deployer token can be
	// read from Vault. The token lives at Vault path teams/erpact/deployer
	// (property DEPLOYER_API_TOKEN), read directly through vaultReader
	// rather than through an ExternalSecret into an env var. The
	// cluster-wide vault-backend ClusterSecretStore (which mctl-api-secrets
	// uses for every other env-var secret) is deliberately denied all of
	// secret/data/teams/* (see mctl-gitops
	// vault-policy-external-secrets-read.hcl): any tenant path readable
	// there would be readable by every other tenant's namespace too.
	// Reading it here instead needs only a narrow Vault policy on the
	// mctl-api Kubernetes auth role for this one path
	// (vault-policy-mctl-api-erpact-deployer-read.hcl).
	erpactDeployer := newErpactDeployer(vaultReader, cfg.ErpactDeployerURL)

	gitopsReady := func(ctx context.Context) error {
		if gitReader.LastSync().IsZero() {
			return fmt.Errorf("never synced")
		}
		if _, err := gitReader.ListTenants(); err != nil {
			return err
		}
		return nil
	}

	var postgresReady mctlapi.ReadyCheck
	if pinger, ok := auditLog.(interface{ Ping(context.Context) error }); ok {
		postgresReady = pinger.Ping
	}

	var dexReady mctlapi.ReadyCheck
	if dexVerifier != nil {
		dexReady = mctlapi.HTTPReady(strings.TrimRight(cfg.DexIssuerURL, "/") + "/.well-known/openid-configuration")
	}

	var vaultReady mctlapi.ReadyCheck
	if checker, ok := vaultReader.(interface{ Health(context.Context) error }); ok {
		vaultReady = checker.Health
	}

	trustedProxies, tpErr := mctlapi.ParseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if tpErr != nil {
		slog.Warn("TRUSTED_PROXY_CIDRS parse failed; X-Forwarded-For will not be trusted", "error", tpErr)
	}

	var draining atomic.Bool

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:                       registry,
		GitReader:                      gitReader,
		ComponentSourceRepos:           gitReader,
		ArgoCD:                         argoClient,
		AuditLog:                       auditLog,
		Executor:                       executor,
		AuthMiddleware:                 authMiddleware,
		MCPServer:                      mcpSrv,
		QuotaReader:                    quotaReader,
		LogQuerier:                     logQuerier,
		WorkflowLogArchive:             workflowLogArchive,
		BackstageURL:                   cfg.BackstageURL,
		BackstageToken:                 cfg.BackstageToken,
		BackstageInternalURL:           cfg.BackstageInternalURL,
		BackstageGithubAppConnectToken: cfg.BackstageGithubAppConnectToken,
		AllowedOrigins:                 cfg.AllowedOrigins,
		OAuthServer:                    oauthServer,
		IdentityLink:                   identityLinkOptions(cfg, principalStore, principalCache, oauthServer, ghValidator),
		OAuthUpstream:                  cfg.oauthUpstreamMode(),
		OAuthZitadel:                   oauthZitadelOptions(cfg, principalStore, oauthServer),
		AlertStore:                     alertStore,
		AgentRegistry:                  agentRegistryStore,
		Lifecycle:                      lifecycleStore,
		Roadmap:                        roadmapReader,
		RoadmapWaveMaxAge:              roadmapWaveMaxAge,
		Usage:                          usageStore,
		Evidence:                       evidenceStore,
		DomainStore:                    domainStore,
		DomainVerifier:                 domainVerifier,
		PlatformDomain:                 cfg.PlatformDomain,
		ErpactDeployer:                 erpactDeployer,
		TemporalClient:                 devLoopClient,
		HumanInputLedger:               humanInputLedger,
		WorkItems:                      workItemsStore,
		SurfaceIdentities:              surfaceIDs,
		TenantResolver:                 gitReader,
		Principals:                     principalResolver,
		Delegation:                     delegationResolver,
		WorkflowDispatcher:             workflowDispatcher,
		GitopsReady:                    gitopsReady,
		PostgresReady:                  postgresReady,
		DexReady:                       dexReady,
		VaultReady:                     vaultReady,
		StoreInitFailures:              storeFailures.List,
		Draining:                       draining.Load,
		ArgoWebhookSecret:              cfg.ArgoWebhookSecret,
		GitHubWebhookSecret:            cfg.GitHubWebhookSecret,
		GitHubWebhookOwners:            cfg.GitHubWebhookOwners,
		GitHubEventOutbox:              githubEventOutboxOption(githubEventOutbox),
		GitHubEventNotify:              githubEventNotify(githubEventRelay),
		OAuthRegistrationToken:         cfg.OAuthRegistrationToken,
		TrustedProxyCIDRs:              trustedProxies,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start gitops reader refresh loop. Derived from rootCtx so the loop stops
	// on the same signal that starts the drain, rather than running through it.
	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	go gitReader.RefreshLoop(ctx, 60*time.Second)
	if principalStore != nil {
		go backfillPrincipals(ctx, principalStore, gitReader)
	}
	if roadmapGit != nil {
		// The publication changes at most every couple of hours; freshness is
		// the capture time it carries, not how often this pulls.
		go roadmapGit.RefreshLoop(ctx, 5*time.Minute)
	}

	// Close out audit rows the Argo completion webhook cannot reach. The hook's
	// HMAC secret exists only in the argo-workflows namespace, so operations
	// that run in a tenant namespace (deploy-service, provision-database,
	// retire-service, previews, scaling, rollbacks) never send one.
	go mctlapi.StartAuditReconciler(ctx, auditLog, executor, registry)

	// Start server.
	go func() {
		slog.Info("mctl-api starting",
			"port", cfg.Port,
			"gitops", cfg.GitOpsLocalPath,
			"authRequired", os.Getenv("AUTH_REQUIRED") != "false",
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown, driven by the same root registration that guarded
	// startup — so the FIRST signal drains, whenever it arrives.
	<-rootCtx.Done()
	draining.Store(true)

	// Restore default disposition: a second SIGTERM during a slow drain should
	// kill the process outright rather than be swallowed by a handler that has
	// already done its job.
	stopSignals()
	slog.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	if otelShutdown != nil {
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := otelShutdown(flushCtx); err != nil {
			slog.Warn("telemetry flush error", "error", err)
		}
	}
}

// githubAppTokenFileEnv names the file holding a GitHub App installation
// token, mounted from the Secret that rotate-github-app-tokens re-syncs.
//
// One file serves both credentials below because one App installation backs
// both: mctl-agents (id 4450852), which already reaches mctlhq/mctl-gitops.
// Both grants were measured on the live installation before wiring this,
// because a file that wins over an explicitly configured GITOPS_ACTIONS_TOKEN
// must be known to do the job that variable was doing:
//
//	POST .../git/refs                              -> 422 (contents:write)
//	POST .../workflows/<absent>.yml/dispatches     -> 404 (actions:write)
//
// A 422 or 404 there means the permission check passed and only the object was
// missing; the narrow PAT returns 403 to both, which is the control that makes
// those readings mean something. Do not take a 200 on a GET as evidence of
// either — reachability is not grant.
//
// The contents:write half is a deliberate trade, taken with the alternative
// measured: the installation carries it across 25 repositories, where the
// clone alone needs contents:read on one. A dedicated App would have kept
// the narrower grant; sharing this one avoids standing up a second App and
// its key rotation, and it is what the operator chose. The consequence to
// remember when reading an incident: a compromise of this process is a
// compromise of write access to every repository that installation covers,
// and mctl-api and mctl-agents now share a failure domain — a revoked key
// or a removed installation takes out both. See mctlhq/mctl-api#307.
const githubAppTokenFileEnv = "GITHUB_APP_TOKEN_FILE" //nolint:gosec // G101: the name of an environment variable, not a credential — the value it points at is read from the file it names

// checkCredentialSource resolves a source once at startup so a wrong path or
// wrong file mode is diagnosed by name, instead of as a Ready probe that never
// passes and a per-tick refresh error.
//
// It logs rather than exiting. A read failure here is usually a deployment
// mistake, but it can also be a volume that has not been projected yet, and
// crash-looping a process that would have recovered on the next tick trades a
// clear message for an outage. The startup line is the diagnosis; the retry is
// still the behaviour.
func checkCredentialSource(name string, s ghtoken.Source) {
	if s == nil {
		return
	}
	if _, err := s(); err != nil {
		slog.Error("configured GitHub credential could not be read at startup; the pod will keep retrying but will not work until this is fixed",
			"credential", name, "file", os.Getenv(githubAppTokenFileEnv), "error", err)
	}
}

// gitOpsTokenSource picks the credential for the HTTPS clone.
//
// The mounted file wins when present. The environment variables remain as the
// fallback for local runs and for the interim fine-grained PAT provisioned in
// mctlhq/mctl-gitops#1229, which does not rotate and so is safe to read once.
func gitOpsTokenSource() ghtoken.Source {
	return ghtoken.FirstOf(
		ghtoken.File(os.Getenv(githubAppTokenFileEnv)),
		ghtoken.Static(os.Getenv("GITOPS_REPO_TOKEN")),
		ghtoken.Static(os.Getenv("GITHUB_TOKEN")),
	)
}

// actionsTokenSource picks the credential that starts workflow_dispatch runs.
func actionsTokenSource() ghtoken.Source {
	return ghtoken.FirstOf(
		ghtoken.File(os.Getenv(githubAppTokenFileEnv)),
		ghtoken.Static(os.Getenv("GITOPS_ACTIONS_TOKEN")),
	)
}

type config struct {
	Port            string
	GitOpsRepoURL   string
	GitOpsBranch    string
	GitOpsLocalPath string
	// GitOpsToken is the credential for the HTTPS clone. A source rather than
	// a string: when it comes from a GitHub App installation token the value
	// lives 60 minutes and is re-minted every 30, so it must be re-read, not
	// captured at startup. See internal/ghtoken.
	GitOpsToken ghtoken.Source
	// GitOpsActionsToken starts workflow_dispatch runs in mctl-gitops.
	//
	// It WAS a separate credential from GitOpsToken on purpose: that one
	// clones over HTTPS and needs contents:read, while this one needs
	// actions:write and nothing else, and sharing would widen "can read the
	// repository" into "can start any workflow in it" without anyone noticing
	// in a values file.
	//
	// Under GITHUB_APP_TOKEN_FILE they are the same value: one installation
	// backs both, so setting githubAppTokenSecret in a values file is exactly
	// the widening that warning described. That is now a known trade rather
	// than an accident — the reasoning and the measurements are on
	// githubAppTokenFileEnv above. The separation still holds on the
	// environment-variable fallback.
	GitOpsActionsToken      ghtoken.Source
	GitOpsSSHKeyPath        string // Path to SSH key for SSH auth (optional, takes precedence)
	GitOpsSSHKnownHostsPath string // Path to a known_hosts file for SSH host-key pinning (optional; empty uses the shipped default)
	ArgoCDURL               string
	ArgoCDToken             string
	// ErpactDeployerURL configures the mctl-api#486 stopgap
	// (internal/erpactsites). The deployer token is read directly from
	// Vault (teams/erpact/deployer), not from env -- see its construction
	// near vaultReader above. No vault reader configured is how the
	// feature is switched off entirely.
	ErpactDeployerURL    string
	GitHubOrg            string
	AdminUsers           []string
	BackstageURL         string
	BackstageToken       string
	BackstageInternalURL string
	// BackstageGithubAppConnectToken authorizes calls to Backstage's
	// github-app-connect plugin (repos list/sync/install-url), scoped
	// separately from BackstageToken (which now only authorizes
	// notifyBackstage's tenant catalog sync) so the two credentials can be
	// rotated and leaked independently of each other.
	BackstageGithubAppConnectToken string
	// PlatformDomain is the platform's own domain (e.g. "mctl.ai"). Custom
	// domain registration rejects any hostname equal to or ending in
	// "."+PlatformDomain — those stay GitOps-only via ingress.hosts.
	PlatformDomain string
	// DNSResolverAddr is the host:port of the recursive resolver used to
	// verify custom domain TXT/CNAME records. Defaults to a public resolver
	// so results do not depend on cluster split-horizon DNS.
	DNSResolverAddr string
	// Dex OIDC issuer for JWT validation (dual-token auth alongside GitHub tokens).
	// No default: Dex is being retired (mctlhq/mctl-gitops#1500 phase 4). Unset
	// means no Dex verifier, no legacy "dex" federation shim and no Dex
	// readiness check, so Dex can be removed once the deployment stops setting
	// it without /readyz failing on a dead issuer.
	DexIssuerURL string
	// DexClientID is the expected audience for Dex JWTs. If empty, audience check is skipped.
	DexClientID string
	// OIDCProvidersRaw is MCTL_OIDC_PROVIDERS as read: a JSON array of
	// additional federation providers (mctl-api#374), parsed and validated
	// by auth.ParseOIDCProviders. Unset or blank means only the legacy Dex
	// shim (DexIssuerURL/DexClientID above) applies.
	OIDCProvidersRaw string
	// GitHubActionsOIDCRaw is MCTL_GITHUB_ACTIONS_OIDC (mctl-api#530): the
	// GitHub Actions OIDC provider for CI deploys, parsed by
	// auth.ParseGitHubActionsOIDC. Unset means the provider is off.
	GitHubActionsOIDCRaw string
	// FederationDisabled is MCTL_FEDERATION_DISABLED (mctl-api#374's kill
	// switch). While it is on, MCTL_OIDC_PROVIDERS is neither validated nor
	// built into a registry, and auth.Middleware runs the pre-registry chain.
	FederationDisabled bool
	// SelfURL is the public base URL used in MCP SSE endpoint advertisement.
	SelfURL string
	// AllowedOrigins is a list of origins permitted by CORS policy.
	AllowedOrigins []string
	// OAuth 2.0 server settings for Claude.ai custom connector support.
	OAuthGitHubClientID     string
	OAuthGitHubClientSecret string
	// OAuthUpstreamRaw is OAUTH_UPSTREAM as read (github, zitadel, both;
	// empty is github), parsed by validate (mctl-api#467). The ZITADEL
	// upstream has its own confidential client, not the link client, and
	// takes its issuer from the MCTL_OIDC_PROVIDERS entry OAuthZitadelProvider
	// names, the one the link flow writes identities for.
	OAuthUpstreamRaw         string
	OAuthZitadelClientID     string
	OAuthZitadelClientSecret string
	OAuthZitadelProvider     string
	// ZITADEL client of the identity link flow (mctl-api#435): a
	// confidential web app; both empty keeps the browser flow off.
	// ZitadelLinkProvider names the MCTL_OIDC_PROVIDERS entry whose issuer
	// the linked identity must carry.
	ZitadelLinkClientID      string
	ZitadelLinkClientSecret  string
	ZitadelLinkProvider      string
	OAuthJWTSecret           string
	OAuthAllowedRedirectURIs []string
	// OAuthPreregisteredClientsRaw is the OAUTH_PREREGISTERED_CLIENTS value as
	// read; it is parsed by parsePreregisteredClients at startup and a
	// malformed value refuses the boot rather than silently seeding nothing.
	OAuthPreregisteredClientsRaw string
	OAuthTokenTTL                time.Duration
	OAuthRefreshTokenTTL         time.Duration
	VaultAddr                    string
	VaultToken                   string
	VaultKubernetesRole          string
	VaultKubernetesAuthPath      string
	ArgoWebhookSecret            string
	GitHubWebhookSecret          string
	GitHubWebhookOwners          []string
	EventsValkeyURL              string
	EventsValkeyPassword         string
	OAuthRegistrationToken       string
	TrustedProxyCIDRs            string
}

func loadConfig() config {
	admins := os.Getenv("ADMIN_USERS") // comma-separated GitHub logins
	var adminList []string
	if admins != "" {
		for _, a := range strings.Split(admins, ",") {
			if a = strings.TrimSpace(a); a != "" {
				adminList = append(adminList, a)
			}
		}
	}

	var origins []string
	if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
	} else {
		// Default: allow localhost origins for local development.
		// In production, set ALLOWED_ORIGINS to your domain list.
		origins = []string{
			"http://localhost:*",
			"http://127.0.0.1:*",
			"https://claude.ai",
			"https://glama.ai",
		}
		slog.Warn("ALLOWED_ORIGINS not set, using localhost-only defaults")
	}

	var oauthRedirectURIs []string
	if raw := os.Getenv("OAUTH_ALLOWED_REDIRECT_URIS"); raw != "" {
		for _, u := range strings.Split(raw, ",") {
			if u = strings.TrimSpace(u); u != "" {
				oauthRedirectURIs = append(oauthRedirectURIs, u)
			}
		}
	} else {
		// Default: allow common MCP clients to work without configuration.
		// Entries ending with "/*" use prefix matching for dynamic callback paths.
		oauthRedirectURIs = []string{
			"https://glama.ai/mcp/inspector/oauth/callback",
			"https://smithery.ai/mcp/inspector/oauth/callback",
			"https://chatgpt.com/connector/oauth/*",
		}
		slog.Warn("OAUTH_ALLOWED_REDIRECT_URIS not set, using default common tool redirect URIs")
	}

	return config{
		Port:                           envOr("PORT", "8080"),
		GitOpsRepoURL:                  envOr("GITOPS_REPO_URL", "https://github.com/mctlhq/mctl-gitops.git"),
		GitOpsBranch:                   envOr("GITOPS_BRANCH", "main"),
		GitOpsLocalPath:                envOr("GITOPS_LOCAL_PATH", "/tmp/mctl-gitops"),
		GitOpsToken:                    gitOpsTokenSource(),
		GitOpsActionsToken:             actionsTokenSource(),
		GitOpsSSHKeyPath:               os.Getenv("GITOPS_SSH_KEY_PATH"),
		GitOpsSSHKnownHostsPath:        os.Getenv("GITOPS_SSH_KNOWN_HOSTS_PATH"),
		ArgoCDURL:                      envOr("ARGOCD_URL", "https://ops.mctl.ai"),
		ErpactDeployerURL:              envOr("ERPACT_DEPLOYER_URL", "http://erpact-deployer.erpact.svc.cluster.local:8000"),
		ArgoCDToken:                    os.Getenv("ARGOCD_TOKEN"),
		GitHubOrg:                      envOr("GITHUB_ORG", "mctlhq"),
		AdminUsers:                     adminList,
		BackstageURL:                   os.Getenv("BACKSTAGE_URL"),
		BackstageToken:                 os.Getenv("BACKSTAGE_TOKEN"),
		BackstageInternalURL:           envOr("BACKSTAGE_INTERNAL_URL", "http://backstage.backstage.svc.cluster.local:7007"),
		PlatformDomain:                 envOr("PLATFORM_DOMAIN", "mctl.ai"),
		DNSResolverAddr:                envOr("DNS_RESOLVER_ADDR", "1.1.1.1:53"),
		BackstageGithubAppConnectToken: os.Getenv("BACKSTAGE_GITHUB_APP_CONNECT_TOKEN"),
		DexIssuerURL:                   os.Getenv("DEX_ISSUER_URL"),
		DexClientID:                    os.Getenv("DEX_CLIENT_ID"),
		OIDCProvidersRaw:               os.Getenv("MCTL_OIDC_PROVIDERS"),
		GitHubActionsOIDCRaw:           os.Getenv("MCTL_GITHUB_ACTIONS_OIDC"),
		FederationDisabled:             killSwitchOn(os.Getenv("MCTL_FEDERATION_DISABLED")),
		SelfURL:                        envOr("SELF_URL", "https://api.mctl.ai"),
		AllowedOrigins:                 origins,
		OAuthGitHubClientID:            os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubClientSecret:        os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthUpstreamRaw:               os.Getenv("OAUTH_UPSTREAM"),
		OAuthZitadelClientID:           os.Getenv("OAUTH_ZITADEL_CLIENT_ID"),
		OAuthZitadelClientSecret:       os.Getenv("OAUTH_ZITADEL_CLIENT_SECRET"),
		OAuthZitadelProvider:           envOr("OAUTH_ZITADEL_PROVIDER", "zitadel"),
		ZitadelLinkClientID:            os.Getenv("ZITADEL_LINK_CLIENT_ID"),
		ZitadelLinkClientSecret:        os.Getenv("ZITADEL_LINK_CLIENT_SECRET"),
		ZitadelLinkProvider:            envOr("ZITADEL_LINK_PROVIDER", "zitadel"),
		OAuthJWTSecret:                 os.Getenv("OAUTH_JWT_SECRET"),
		OAuthAllowedRedirectURIs:       oauthRedirectURIs,
		OAuthPreregisteredClientsRaw:   os.Getenv("OAUTH_PREREGISTERED_CLIENTS"),
		OAuthTokenTTL:                  parseDuration(os.Getenv("OAUTH_TOKEN_TTL"), time.Hour),
		OAuthRefreshTokenTTL:           parseDuration(os.Getenv("OAUTH_REFRESH_TOKEN_TTL"), 30*24*time.Hour),
		VaultAddr:                      os.Getenv("VAULT_ADDR"),
		VaultToken:                     os.Getenv("VAULT_TOKEN"),
		VaultKubernetesRole:            os.Getenv("VAULT_KUBERNETES_ROLE"),
		VaultKubernetesAuthPath:        os.Getenv("VAULT_KUBERNETES_AUTH_PATH"),
		ArgoWebhookSecret:              os.Getenv("ARGO_WEBHOOK_SECRET"),
		GitHubWebhookSecret:            os.Getenv("GITHUB_WEBHOOK_SECRET"),
		GitHubWebhookOwners:            splitCSV(envOr("GITHUB_WEBHOOK_OWNERS", "mctlhq")),
		EventsValkeyURL:                os.Getenv("EVENTS_VALKEY_URL"),
		EventsValkeyPassword:           os.Getenv("EVENTS_VALKEY_PASSWORD"),
		OAuthRegistrationToken:         os.Getenv("OAUTH_REGISTRATION_TOKEN"),
		TrustedProxyCIDRs:              os.Getenv("TRUSTED_PROXY_CIDRS"),
	}
}

// postgresURL requires TLS to CNPG unless ALLOW_INSECURE_DB is set.
// The returned string is never logged — it may contain credentials.
func postgresURL(raw string) string {
	if raw == "" {
		return ""
	}
	out, err := dburl.EnforceTLS(raw)
	if err != nil {
		slog.Error("postgres url tls enforce failed; refusing plaintext fallback")
		return ""
	}
	if out != raw {
		slog.Info("postgres connection upgraded to require TLS")
	}
	return out
}

// publicBaseURL is the caller-facing base URL shown by mctl_whoami. When the
// OAuth server is enabled it IS the issuer the caller's token was verified
// against -- read it from there rather than re-deriving it from config, so the
// two cannot name different deployments. With OAuth disabled there is no
// issuer, and cfg.SelfURL is the only public URL the process knows.
func publicBaseURL(cfg config, oauth *auth.OAuthServer) string {
	if oauth != nil && oauth.BaseURL != "" {
		return oauth.BaseURL
	}
	return cfg.SelfURL
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const (
	// One store's ladder: 250ms + 500ms + 1s + 2s + 4s = 7.75s of waiting
	// across 6 attempts.
	storeInitAttempts = 6

	// The ceiling on ALL optional store init combined, not on any one store.
	// The stores are built sequentially, so without a shared deadline four of
	// them pointed at the same dead database would each run their own ladder
	// and stall the listener for roughly four times as long.
	//
	// 8s leaves a lone store its full ladder while keeping the process
	// listening before the readiness probe's first check at
	// initialDelaySeconds: 10 (helm/templates/deployment.yaml), so the probe
	// gets an answer on schedule instead of a pod that looks hung. Since
	// mctl-api#387 that answer is "not ready" while any configured store
	// failed: a degraded pod no longer reports ready.
	storeInitBudget = 8 * time.Second

	// The one attempt a store gets when the shared budget ran out before its
	// turn (mctl-api#387). A reachable database answers in milliseconds, and
	// a refusal (connection limit, auth) comes back just as fast; this only
	// bounds a store whose database does not answer at all.
	storeInitLastChance = time.Second
)

// A var, not a const, only so tests can shrink it — nothing at runtime writes it.
var storeInitBaseDelay = 250 * time.Millisecond

// agentRunResolverHolder lets auth.Middleware capture an auth.AgentRunResolver
// before its backing *workitems.Store exists: Middleware is built early in
// main(), the work-items store later (mctl-api#376). main sets store exactly
// once, before the server starts serving; ResolveAgentRun on a nil store
// answers auth.ErrAgentRunNotFound, the same as an unresolvable token, which
// is what every request sees until the store is wired in.
type agentRunResolverHolder struct {
	store *workitems.Store
}

func (h *agentRunResolverHolder) ResolveAgentRun(ctx context.Context, token string) (*auth.AgentRun, error) {
	if h.store == nil {
		return nil, auth.ErrAgentRunNotFound
	}
	return h.store.ResolveAgentRunToken(ctx, token)
}

// initStore opens an optional Postgres-backed store, retrying a failed attempt
// instead of giving up on the first one.
//
// Every one of these stores connects and runs CREATE TABLE IF NOT EXISTS during
// init, and init happens exactly once, here in main(), within milliseconds of
// the process starting. A pod whose network is still settling loses that race
// and gets "connection refused" — after which the store stays nil for the whole
// life of the pod, because nothing ever tries again, and the warning is printed
// once at startup so later logs look clean. That is how this service ran with
// its alert endpoints returning 503, its agent registry disabled and its audit
// trail in memory rather than on disk (#166): the failure was one lost race,
// the outage was the absence of a second attempt.
//
// Retrying is safe: opening a pool and CREATE TABLE IF NOT EXISTS are both
// idempotent. Every error is retried, not just connection refusals — telling a
// transient network error from a permanent one by inspecting the message is
// exactly the kind of guess that produced the five-month silence, and the cost
// of being wrong is one bounded delay at startup.
//
// Every call site is a configured store, so a failure is recorded in failures
// and keeps the pod out of readiness (mctl-api#387); a nil failures records
// nothing (tests).
func initStore[T any](ctx context.Context, failures *storeInitFailures, name string, newStore func(context.Context) (T, error)) (T, error) {
	store, err := initStoreAttempts(ctx, name, newStore)
	if err != nil && failures != nil {
		failures.record(name)
	}
	return store, err
}

func initStoreAttempts[T any](ctx context.Context, name string, newStore func(context.Context) (T, error)) (T, error) {
	var zero T
	delay := storeInitBaseDelay
	for attempt := 1; ; attempt++ {
		// Checked before the attempt, not only in the wait below: the deadline
		// is shared with the other stores, so by the time a later one is
		// reached it may already be spent. Without this the loop would still
		// run its full count of doomed attempts against a context that can
		// never succeed — which is the multiplication this budget exists to
		// prevent, just faster.
		if err := ctx.Err(); err != nil {
			// Except for the first attempt of a store that found the shared
			// budget already spent by an earlier one (mctl-api#387: three
			// stores failed "before attempt 1" without ever trying). It gets
			// one bounded last-chance attempt of its own, so a transient
			// failure that cost an earlier store its ladder cannot starve
			// every later store too. Only on an expired deadline: a cancelled
			// context is a shutdown signal and must stop here.
			if attempt == 1 && errors.Is(err, context.DeadlineExceeded) {
				return lastChanceInit(ctx, name, newStore)
			}
			return zero, fmt.Errorf("before attempt %d: %w", attempt, err)
		}
		store, err := newStore(ctx)
		if err == nil {
			if attempt > 1 {
				slog.Info("store init succeeded on retry", "store", name, "attempts", attempt)
			}
			return store, nil
		}
		if attempt >= storeInitAttempts {
			return zero, fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		slog.Warn("store init failed, retrying", "store", name, "attempt", attempt, "retry_in", delay, "error", err)
		// Checked before the select, not only inside it: when both cases are
		// ready, select picks at random, so an already-cancelled context could
		// lose to an expired timer and buy one more doomed attempt. Rare, but
		// nondeterministic — and a test that passes by scheduler luck is worth
		// less than no test.
		if err := ctx.Err(); err != nil {
			return zero, fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("after %d attempts: %w", attempt, ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// lastChanceInit is the single attempt a store gets when the shared budget
// was already spent before its turn. Bounded by storeInitLastChance, so the
// worst case stays "the budget, plus one short attempt per remaining store".
// Detached from ctx's (expired) deadline but not from its values; the
// constructors do not retain the context (see initCtx in main).
func lastChanceInit[T any](ctx context.Context, name string, newStore func(context.Context) (T, error)) (T, error) {
	var zero T
	attemptCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeInitLastChance)
	defer cancel()
	store, err := newStore(attemptCtx)
	if err != nil {
		return zero, fmt.Errorf("last-chance attempt after the shared budget was spent: %w", err)
	}
	slog.Info("store init succeeded on its last-chance attempt", "store", name)
	return store, nil
}

// storeInitFailures is the set of configured stores whose init failed. It is
// written only during startup and read by every /readyz call.
type storeInitFailures struct {
	mu    sync.Mutex
	names []string
}

func (f *storeInitFailures) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names = append(f.names, name)
}

// List returns a copy of the failed store names, in init order.
func (f *storeInitFailures) List() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.names...)
}

// maxOAuthTokenTTL is the ceiling on OAUTH_TOKEN_TTL. An access token is what
// an attacker keeps when one leaks, and its TTL is the only thing bounding how
// long they keep it — this endpoint has no revocation for access tokens, so
// there is no way to cut a leak short other than waiting it out. 24h leaves
// room for a deployment that wants a working day without a renewal; it is not
// an endorsement of values near it. Clients renew silently with the
// refresh_token grant, so a long access token buys nothing.
//
// The sibling service learned this the expensive way: mctl-telegram had no
// ceiling here either, a deployment set 8760h, and the resulting year-long
// admin-scoped token leaked and could not be revoked without rotating the
// signing key for every user at once.
const maxOAuthTokenTTL = 24 * time.Hour

// validate rejects configuration that would produce a working but unsafe
// server. Called from main immediately after loadConfig; loadConfig itself
// stays total so it remains usable from tests.
func (c config) validate() error {
	// Only enforced when the OAuth server is actually constructed — the same
	// gate main uses at the NewOAuthServer call. OAUTH_TOKEN_TTL governs
	// nothing on a deployment that never issues tokens, and refusing to start
	// the whole API over a leftover env var that cannot affect anything is out
	// of proportion to the mistake. The value is still rejected the moment
	// OAuth is switched on, which is a deliberate change and exactly when the
	// operator wants to hear about it.
	//
	// OAUTH_PREREGISTERED_CLIENTS is the other way round, checked whether or not OAuth is enabled:
	// the README promises a malformed value refuses startup, and a value that
	// is read but never looked at would make that promise conditional on a
	// second variable the operator may not be thinking about.
	pre, err := parsePreregisteredClients(c.OAuthPreregisteredClientsRaw)
	if err != nil {
		return err
	}
	// The shape rules live with the registry; run them here against a
	// throwaway server so a bad callback refuses this boot, not the one after
	// OAuth is switched on.
	var probe auth.OAuthServer
	for _, p := range pre {
		if err := probe.AddPreregisteredClient(p.ClientID, p.ClientName, p.RedirectURIs); err != nil {
			return fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: %w", err)
		}
	}
	if err := c.validateOAuthUpstream(); err != nil {
		return err
	}
	oauthEnabled := c.oauthEnabled()
	if oauthEnabled && c.OAuthTokenTTL > maxOAuthTokenTTL {
		return fmt.Errorf("OAUTH_TOKEN_TTL must not exceed %v, got %v — clients renew "+
			"silently with the refresh_token grant, and access tokens cannot be revoked, "+
			"so a longer lifetime only widens the window on a leak", maxOAuthTokenTTL, c.OAuthTokenTTL)
	}

	// MCTL_OIDC_PROVIDERS (mctl-api#374): shape-validated here, in the same
	// style as OAUTH_PREREGISTERED_CLIENTS above, so a malformed value or an
	// entry missing audiences/naming a reserved provider refuses this boot
	// rather than the one after a second variable is also set. The full
	// registry (this plus the legacy Dex shim and the built-in providers) is
	// built for real in main(), which is where a duplicate against the
	// local-OAuth or Dex provider would also be caught. Skipped while
	// MCTL_FEDERATION_DISABLED is on, so the kill switch can roll back a
	// value that would otherwise refuse boot.
	if c.FederationDisabled {
		return nil
	}
	if _, err := auth.ParseOIDCProviders(c.OIDCProvidersRaw); err != nil {
		return err
	}
	if _, err := auth.ParseGitHubActionsOIDC(c.GitHubActionsOIDCRaw); err != nil {
		return err
	}
	return nil
}

// oauthUpstreamMode is the parsed OAUTH_UPSTREAM. validate has already
// refused an unknown value, so the fallback is never taken in main.
func (c config) oauthUpstreamMode() mctlapi.OAuthUpstreamMode {
	m, err := mctlapi.ParseOAuthUpstreamMode(c.OAuthUpstreamRaw)
	if err != nil {
		return mctlapi.OAuthUpstreamGitHub
	}
	return m
}

// oauthEnabled is the gate for constructing the OAuth server. github keeps
// the pre-#467 rule; zitadel and both were validated complete.
func (c config) oauthEnabled() bool {
	if c.OAuthJWTSecret == "" {
		return false
	}
	if c.oauthUpstreamMode() == mctlapi.OAuthUpstreamGitHub {
		return c.OAuthGitHubClientID != ""
	}
	return true
}

// validateOAuthUpstream refuses a boot whose OAUTH_UPSTREAM is unknown, or
// names an upstream whose configuration is incomplete: selecting zitadel or
// both is a deliberate change, and a half-configured sign-in must not come
// up. The MCTL_OIDC_PROVIDERS entry is read even while
// MCTL_FEDERATION_DISABLED is on, because sign-in needs only its issuer.
func (c config) validateOAuthUpstream() error {
	mode, err := mctlapi.ParseOAuthUpstreamMode(c.OAuthUpstreamRaw)
	if err != nil {
		return err
	}
	if mode == mctlapi.OAuthUpstreamGitHub {
		return nil
	}
	var missing []string
	if c.OAuthJWTSecret == "" {
		missing = append(missing, "OAUTH_JWT_SECRET")
	}
	if c.OAuthZitadelClientID == "" || c.OAuthZitadelClientSecret == "" {
		missing = append(missing, "OAUTH_ZITADEL_CLIENT_ID and OAUTH_ZITADEL_CLIENT_SECRET (both)")
	}
	if mode == mctlapi.OAuthUpstreamBoth && (c.OAuthGitHubClientID == "" || c.OAuthGitHubClientSecret == "") {
		missing = append(missing, "OAUTH_GITHUB_CLIENT_ID and OAUTH_GITHUB_CLIENT_SECRET (both, for the GitHub option)")
	}
	if _, err := c.oauthZitadelProvider(); err != nil {
		missing = append(missing, err.Error())
	}
	// Sign-in reads linked rows by provider entry name, and linking writes
	// them under ZITADEL_LINK_PROVIDER: two names would boot cleanly and then
	// answer every sign-in "not linked", which re-linking cannot clear.
	if c.OAuthZitadelProvider != c.ZitadelLinkProvider {
		missing = append(missing, fmt.Sprintf("OAUTH_ZITADEL_PROVIDER (%q) to equal ZITADEL_LINK_PROVIDER (%q), the entry linking writes under", c.OAuthZitadelProvider, c.ZitadelLinkProvider))
	}
	if len(missing) > 0 {
		return fmt.Errorf("OAUTH_UPSTREAM=%s needs %s", mode, strings.Join(missing, "; "))
	}
	return nil
}

// oauthZitadelProvider is the MCTL_OIDC_PROVIDERS entry the ZITADEL upstream
// signs in against. Its identities are matched to linked rows by (iss, sub),
// as the link flow writes them, so an entry that keys identities on another
// claim is refused rather than silently matching nothing.
func (c config) oauthZitadelProvider() (auth.OIDCProviderConfigEntry, error) {
	entries, err := auth.ParseOIDCProviders(c.OIDCProvidersRaw)
	if err != nil {
		return auth.OIDCProviderConfigEntry{}, err
	}
	for i := range entries {
		e := &entries[i]
		if e.Name != c.OAuthZitadelProvider {
			continue
		}
		if e.SubjectClaim != "" && e.SubjectClaim != "sub" {
			return auth.OIDCProviderConfigEntry{}, fmt.Errorf("MCTL_OIDC_PROVIDERS entry %q to key identities on sub, not %q", e.Name, e.SubjectClaim)
		}
		return *e, nil
	}
	return auth.OIDCProviderConfigEntry{}, fmt.Errorf("an MCTL_OIDC_PROVIDERS entry named %q (OAUTH_ZITADEL_PROVIDER)", c.OAuthZitadelProvider)
}

// oauthZitadelOptions wires the ZITADEL upstream when OAUTH_UPSTREAM selects
// it. A missing principal store is not a boot failure (the store may only
// be down): every ZITADEL sign-in then answers 503, never "not linked".
func oauthZitadelOptions(cfg config, store *principals.Store, oauth *auth.OAuthServer) *mctlapi.OAuthZitadelOptions {
	if oauth == nil || cfg.oauthUpstreamMode() == mctlapi.OAuthUpstreamGitHub {
		return nil
	}
	entry, err := cfg.oauthZitadelProvider()
	if err != nil {
		// Unreachable after validate; keep the upstream off rather than half on.
		slog.Error("OAuth ZITADEL upstream disabled", "error", err)
		return nil
	}
	opts := &mctlapi.OAuthZitadelOptions{
		ProviderName: entry.Name, Issuer: entry.Issuer,
		ClientID: cfg.OAuthZitadelClientID, ClientSecret: cfg.OAuthZitadelClientSecret,
	}
	// Assigned only when non-nil: a nil *Store in the interface would not
	// compare equal to nil and would be called.
	if store != nil {
		opts.Store = store
	} else {
		slog.Error("OAuth ZITADEL upstream has no principal store; ZITADEL sign-ins will answer 503")
	}
	slog.Info("OAuth ZITADEL upstream enabled", "provider", entry.Name, "issuer", entry.Issuer)
	return opts
}

// buildFederationRegistry builds the federation registry from cfg, or
// returns (nil, nil) while MCTL_FEDERATION_DISABLED is on: a nil registry
// leaves auth.Middleware on its pre-registry chain, and none of the
// registry's boot refusals can block the rollback.
func buildFederationRegistry(ctx context.Context, cfg config, validator *auth.GitHubValidator, resolver auth.TenantResolver, oauth *auth.OAuthServer) (*auth.Registry, error) {
	if cfg.FederationDisabled {
		slog.Warn("MCTL_FEDERATION_DISABLED is on: federation registry not built, pre-registry auth chain in effect")
		return nil, nil
	}
	return auth.BuildFederationRegistry(ctx, auth.FederationProvidersConfig{
		OIDCProvidersRaw: cfg.OIDCProvidersRaw,
		DexIssuerURL:     cfg.DexIssuerURL,
		DexClientID:      cfg.DexClientID,
		GitHubActionsRaw: cfg.GitHubActionsOIDCRaw,
	}, validator, resolver, oauth)
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// preregisteredClient is one entry of OAUTH_PREREGISTERED_CLIENTS.
//
// There is deliberately no secret field. The server is public-client only:
// the token endpoint authenticates a client by PKCE, never by a credential,
// and the decoder below rejects any key it does not know -- so a value that
// tries to carry one refuses the boot instead of being ignored.
type preregisteredClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// parsePreregisteredClients decodes the JSON array in OAUTH_PREREGISTERED_CLIENTS.
// Unset or blank means no static clients. Shape validation of each entry --
// scheme, fragment, userinfo, duplicates -- happens in AddPreregisteredClient,
// which is where the rules are defined; this function only owns the decoding.
func parsePreregisteredClients(raw string) ([]preregisteredClient, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if raw == "null" {
		// Decodes to a nil slice and would read as "no clients"; it is far
		// more likely a templating accident than a decision.
		return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: null is not a client list (unset the variable for none)")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []preregisteredClient
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: %w", err)
	}
	// Anything after the array is a mistake. dec.More is the wrong probe here:
	// it answers "is there another element", so trailing text that starts
	// with a closing bracket reads as "no" and would be accepted.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: trailing data after the JSON array")
	}
	seen := make(map[string]struct{}, len(out))
	for _, c := range out {
		if c.ClientID == "" {
			return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: an entry has no client_id")
		}
		if _, dup := seen[c.ClientID]; dup {
			return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: client_id %q listed twice", c.ClientID)
		}
		seen[c.ClientID] = struct{}{}
	}
	return out, nil
}

// githubEventOutboxOption keeps a nil *events.Outbox from becoming a non-nil
// interface value, which the webhook handler would then call.
func githubEventOutboxOption(o *events.Outbox) mctlapi.GitHubEventOutbox {
	if o == nil {
		return nil
	}
	return o
}

func githubEventNotify(r *events.Relay) func() {
	if r == nil {
		return nil
	}
	return r.Notify
}

// splitCSV splits a comma-separated list, dropping blanks.
func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// githubIDLookup resolves a GitHub login to its numeric id, with the same
// credential the gitops clone uses (a GitHub App installation token, re-read
// per call).
func githubIDLookup() principals.GitHubIDLookup {
	return principals.NewGitHubIDLookup(&http.Client{Timeout: 15 * time.Second}, "", gitOpsTokenSource())
}

// backfillPrincipals runs the principal backfill once, after the first
// successful gitops sync (mctl-api#373 D6): one human principal per tenant
// member, then a mirror of every live surface link. It is idempotent, so it
// runs on every start; a failure is logged and never blocks serving.
func backfillPrincipals(ctx context.Context, store *principals.Store, reader *gitops.Reader) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for reader.LastSync().IsZero() {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
	logins, err := tenantMemberLogins(reader)
	if err != nil {
		slog.Error("principal backfill skipped: tenant members unreadable", "error", err)
		return
	}
	res, err := store.Backfill(ctx, logins, githubIDLookup())
	if err != nil {
		slog.Error("principal backfill failed", "error", err, "result", res)
		return
	}
	slog.Info("principal backfill done", "logins", res.Logins, "known", res.Known,
		"provisioned", res.Provisioned, "failed", res.Failed, "links_mirrored", res.LinksMirrored, "links_failed", res.LinksFailed)
}

// tenantMemberLogins lists every GitHub login gitops names as a tenant or
// team member.
func tenantMemberLogins(reader *gitops.Reader) ([]string, error) {
	tenants, err := reader.ListTenants()
	if err != nil {
		return nil, err
	}
	var logins []string
	for i := range tenants {
		t := &tenants[i]
		for _, m := range t.Members {
			logins = append(logins, m.UserID)
		}
		for _, team := range t.Teams {
			for _, m := range team.Members {
				logins = append(logins, m.UserID)
			}
		}
	}
	return logins, nil
}

// killSwitchOn reads a kill-switch value (WORK_ITEMS_DISABLED,
// ROADMAP_STATE_DISABLED, PRINCIPALS_DISABLED). It errs toward off: any value except an explicit
// "false"/"f"/"0"/"no"/"off" (or empty) turns the feature off, so a template
// that renders the flag as "false" keeps it on while "yes" or "disabled" never
// silently fails open.
func killSwitchOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "f", "0", "no", "off":
		return false
	}
	return true
}

// parseLinkTTL reads SURFACE_LINK_TTL: empty is no expiry; anything else must
// be a positive Go duration. A malformed value disables the feature rather
// than silently meaning "forever".
func parseLinkTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("SURFACE_LINK_TTL must be positive, got %s", v)
	}
	return d, nil
}

// parseWaveMaxAge reads ROADMAP_WAVE_MAX_AGE: empty means the default, any
// other value must be a positive Go duration.
func parseWaveMaxAge(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return mctlapi.DefaultRoadmapWaveMaxAge, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("ROADMAP_WAVE_MAX_AGE must be positive, got %s", v)
	}
	return d, nil
}

// evidenceRetentionSweepInterval is how often the background sweep checks
// for evidence past EVIDENCE_RETENTION_DAYS. Retention is measured in days,
// so an hourly check is far more often than it needs to be correct and far
// less often than it would need to be to matter for load.
const evidenceRetentionSweepInterval = 1 * time.Hour

// parseEvidenceRetentionDays reads EVIDENCE_RETENTION_DAYS: unset or "0"
// means retain indefinitely (requirements.md "Availability, gaps and
// retention"). A malformed or negative value disables the sweep rather than
// guessing at what was meant.
// maxEvidenceRetentionDays bounds EVIDENCE_RETENTION_DAYS well inside
// time.Duration's range (~106,751 days). Without it a large value wraps the
// days*24h multiplication negative, the purge cutoff lands in the future,
// and the sweep deletes every evidence row.
const maxEvidenceRetentionDays = 36500

func parseEvidenceRetentionDays(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	days, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("EVIDENCE_RETENTION_DAYS must be an integer, got %q", v)
	}
	if days < 0 {
		return 0, fmt.Errorf("EVIDENCE_RETENTION_DAYS must not be negative, got %d", days)
	}
	if days > maxEvidenceRetentionDays {
		return 0, fmt.Errorf("EVIDENCE_RETENTION_DAYS must be at most %d, got %d", maxEvidenceRetentionDays, days)
	}
	return days, nil
}

// startEvidenceRetentionSweep runs a background loop that deletes whole
// evidence rows older than EVIDENCE_RETENTION_DAYS, when that variable is
// set to a positive number of days. Unset or zero (the default) retains
// evidence indefinitely and starts no goroutine at all. The loop stops when
// ctx is done (process shutdown).
func startEvidenceRetentionSweep(ctx context.Context, store *evidence.Store) {
	days, err := parseEvidenceRetentionDays(os.Getenv("EVIDENCE_RETENTION_DAYS"))
	if err != nil {
		slog.Error("invalid EVIDENCE_RETENTION_DAYS; evidence will be retained indefinitely", "error", err)
		return
	}
	if days == 0 {
		return
	}
	maxAge := time.Duration(days) * 24 * time.Hour
	go func() {
		ticker := time.NewTicker(evidenceRetentionSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.PurgeOlderThan(ctx, maxAge)
				if err != nil {
					slog.Error("evidence retention sweep failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("evidence retention sweep purged rows", "count", n, "max_age_days", days)
				}
			}
		}
	}()
}

// identityLinkOptions wires explicit identity linking (mctl-api#435). The
// API side (list, unlink, admin merge) needs only the principal store; the
// browser flow also needs the ZITADEL link client, the federation entry it
// links into, and the GitHub OAuth app. Anything missing leaves that part
// off (503) with one log line saying why, never a failed boot.
func identityLinkOptions(cfg config, store *principals.Store, cache *principals.Resolver, oauth *auth.OAuthServer, gh *auth.GitHubValidator) *mctlapi.IdentityLinkOptions {
	if store == nil {
		return nil
	}
	opts := &mctlapi.IdentityLinkOptions{Store: store, BaseURL: cfg.SelfURL}
	if cache != nil {
		opts.ForgetPrincipals = cache.Forget
	}
	if cfg.ZitadelLinkClientID == "" && cfg.ZitadelLinkClientSecret == "" {
		return opts
	}
	var missing []string
	if cfg.ZitadelLinkClientID == "" || cfg.ZitadelLinkClientSecret == "" {
		missing = append(missing, "ZITADEL_LINK_CLIENT_ID and ZITADEL_LINK_CLIENT_SECRET (both)")
	}
	if oauth == nil || oauth.GitHubClientID == "" {
		missing = append(missing, "the GitHub OAuth server (OAUTH_GITHUB_CLIENT_ID, OAUTH_JWT_SECRET)")
	}
	if gh == nil {
		missing = append(missing, "the GitHub validator")
	}
	if cfg.FederationDisabled {
		missing = append(missing, "the federation registry (MCTL_FEDERATION_DISABLED is on)")
	} else if entries, err := auth.ParseOIDCProviders(cfg.OIDCProvidersRaw); err == nil {
		for i := range entries {
			if entries[i].Name == cfg.ZitadelLinkProvider {
				opts.ProviderName, opts.Issuer = entries[i].Name, entries[i].Issuer
			}
		}
	}
	if opts.Issuer == "" && !cfg.FederationDisabled {
		missing = append(missing, "an MCTL_OIDC_PROVIDERS entry named "+cfg.ZitadelLinkProvider)
	}
	if len(missing) > 0 {
		slog.Error("identity link browser flow disabled", "missing", strings.Join(missing, "; "))
		return opts
	}
	opts.ClientID, opts.ClientSecret = cfg.ZitadelLinkClientID, cfg.ZitadelLinkClientSecret
	opts.GitHubClientID = oauth.GitHubClientID
	opts.ProveGitHub = func(ctx context.Context, code, redirectURI string) (string, int64, error) {
		token, err := mctlapi.ExchangeGitHubCode(ctx, oauth.GitHubClientID, oauth.GitHubClientSecret, code, redirectURI)
		if err != nil {
			return "", 0, err
		}
		return gh.ValidateIdentity(ctx, token)
	}
	slog.Info("identity link browser flow enabled", "provider", opts.ProviderName, "issuer", opts.Issuer)
	return opts
}

// erpactVaultReadTimeout bounds the one startup read of the deployer token.
const erpactVaultReadTimeout = 10 * time.Second

// newErpactDeployer builds the ERPact site-deployer client from the token in
// Vault, or returns nil (feature off) when it cannot. It makes its own
// bounded context on purpose: startup's initCtx is cancelled once the stores
// are built, and a read on it fails with "context canceled" and silently
// disables the feature (seen in prod on 4.69.0).
func newErpactDeployer(reader mctlapi.VaultReader, deployerURL string) mctlapi.ErpactDeployer {
	if reader == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), erpactVaultReadTimeout)
	defer cancel()
	secret, err := reader.ReadKV(ctx, "teams/erpact/deployer")
	if err != nil {
		slog.Warn("erpact deployer token could not be read from vault, erpact site tools disabled", "error", err)
		return nil
	}
	token := secret["DEPLOYER_API_TOKEN"]
	if token == "" {
		slog.Warn("erpact deployer secret has no DEPLOYER_API_TOKEN property, erpact site tools disabled")
		return nil
	}
	slog.Info("erpact deployer client enabled", "url", deployerURL)
	return erpactsites.NewClient(deployerURL, token)
}
