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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/alerts"
	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argoarchive"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/dburl"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/ghtoken"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/k8s"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
	"github.com/mctlhq/mctl-api/internal/loki"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/vault"
	"github.com/mctlhq/mctl-api/internal/vmetrics"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

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

	// OAuth 2.0 server (optional — disabled if OAUTH_GITHUB_CLIENT_ID is unset).
	var oauthServer *auth.OAuthServer
	if cfg.OAuthGitHubClientID != "" && cfg.OAuthJWTSecret != "" {
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
		slog.Info("OAuth 2.0 server enabled", "base_url", cfg.SelfURL, "redirect_uris", cfg.OAuthAllowedRedirectURIs, "token_ttl", cfg.OAuthTokenTTL, "preregistered_clients", oauthServer.PreregisteredClientCount())

		// Persistent refresh-token store: prefer OAUTH_DB_URL, fall back to AUDIT_DB_URL.
		// When available, refresh tokens survive pod restarts; without it the in-memory
		// fallback is used (tokens lost on restart — the original band-aid behaviour).
		if oauthDBURL := postgresURL(envOr("OAUTH_DB_URL", os.Getenv("AUDIT_DB_URL"))); oauthDBURL != "" {
			rs, rsErr := initStore(initCtx, "oauth refresh", func(ctx context.Context) (*refreshstore.PostgresStore, error) {
				return refreshstore.NewPostgresStore(ctx, oauthDBURL)
			})
			if rsErr != nil {
				slog.Error("oauth refresh store init failed; falling back to in-memory (refresh tokens will not survive a restart)", "error", rsErr)
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
		}
	}

	authMiddleware := auth.Middleware(ghValidator, gitReader, dexVerifier, oauthServer)

	argoClient := argocd.NewClient(cfg.ArgoCDURL, cfg.ArgoCDToken)

	var auditLog audit.Log
	if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		pgLog, pgErr := initStore(initCtx, "audit log", func(ctx context.Context) (*audit.PostgresLogger, error) {
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
		as, asErr := initStore(initCtx, "alert", func(ctx context.Context) (*alerts.Store, error) {
			return alerts.NewStore(ctx, alertDBURL)
		})
		if asErr != nil {
			slog.Error("alert store init failed; alert and incident endpoints will return 503", "error", asErr)
		} else {
			alertStore = as
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		as, asErr := initStore(initCtx, "alert", func(ctx context.Context) (*alerts.Store, error) {
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
		ls, lsErr := initStore(initCtx, "lifecycle ownership", func(ctx context.Context) (*lifecycle.Store, error) {
			return lifecycle.NewStore(ctx, lifecycleDBURL)
		})
		if lsErr != nil {
			slog.Error("lifecycle ownership store init failed; lifecycle endpoints will return 503", "error", lsErr)
		} else {
			lifecycleStore = ls
		}
	}

	// Agent registry (optional — enabled when AGENT_REGISTRY_DB_URL or AUDIT_DB_URL is set).
	var agentRegistryStore *agentregistry.Store
	if agentRegistryDBURL := postgresURL(os.Getenv("AGENT_REGISTRY_DB_URL")); agentRegistryDBURL != "" {
		ars, arsErr := initStore(initCtx, "agent registry", func(ctx context.Context) (*agentregistry.Store, error) {
			return agentregistry.NewStore(ctx, agentRegistryDBURL)
		})
		if arsErr != nil {
			slog.Error("agent registry store init failed; agent registry endpoints will return 503", "error", arsErr)
		} else {
			agentRegistryStore = ars
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		ars, arsErr := initStore(initCtx, "agent registry", func(ctx context.Context) (*agentregistry.Store, error) {
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
		ds, dsErr := initStore(initCtx, "domains", func(ctx context.Context) (*domains.Store, error) {
			return domains.NewStore(ctx, domainsDBURL)
		})
		if dsErr != nil {
			slog.Error("domains store init failed; /api/v1/domains* will return 503", "error", dsErr)
		} else {
			domainStore = ds
		}
	} else if dbURL := postgresURL(os.Getenv("AUDIT_DB_URL")); dbURL != "" {
		ds, dsErr := initStore(initCtx, "domains", func(ctx context.Context) (*domains.Store, error) {
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

	// VictoriaMetrics client (optional — used for OpenClaw sizing recommendations).
	var metricsQuerier mctlapi.MetricsQuerier
	if cfg.VictoriaMetricsURL != "" {
		metricsQuerier = vmetrics.NewClient(cfg.VictoriaMetricsURL)
		slog.Info("victoriametrics client enabled", "url", cfg.VictoriaMetricsURL)
	}

	openClawQuota := mctlapi.OpenClawQuotaConfig{
		MaxPerSkillBytes:          parseIntEnv("OPENCLAW_SKILLS_MAX_PER_SKILL_BYTES", 0),
		MaxSkillsPerTenant:        parseIntEnv("OPENCLAW_SKILLS_MAX_PER_TENANT", 0),
		MaxSkillsTotalBytes:       parseIntEnv("OPENCLAW_SKILLS_MAX_TOTAL_BYTES", 0),
		MaxIdentityFilesPerTenant: parseIntEnv("OPENCLAW_IDENTITY_MAX_PER_TENANT", 0),
		MaxIdentityTotalBytes:     parseIntEnv("OPENCLAW_IDENTITY_MAX_TOTAL_BYTES", 0),
		SaveRatePerHour:           parseIntEnv("OPENCLAW_SKILLS_SAVE_RATE_PER_HOUR", 0),
	}

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

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:                       registry,
		GitReader:                      gitReader,
		ArgoCD:                         argoClient,
		AuditLog:                       auditLog,
		Executor:                       executor,
		AuthMiddleware:                 authMiddleware,
		MCPServer:                      mcpSrv,
		QuotaReader:                    quotaReader,
		LogQuerier:                     logQuerier,
		WorkflowLogArchive:             workflowLogArchive,
		VaultReader:                    vaultReader,
		MetricsQuerier:                 metricsQuerier,
		OpenClaw:                       openClawQuota,
		BackstageURL:                   cfg.BackstageURL,
		BackstageToken:                 cfg.BackstageToken,
		BackstageInternalURL:           cfg.BackstageInternalURL,
		BackstageGithubAppConnectToken: cfg.BackstageGithubAppConnectToken,
		AllowedOrigins:                 cfg.AllowedOrigins,
		OAuthServer:                    oauthServer,
		AlertStore:                     alertStore,
		AgentRegistry:                  agentRegistryStore,
		Lifecycle:                      lifecycleStore,
		DomainStore:                    domainStore,
		DomainVerifier:                 domainVerifier,
		PlatformDomain:                 cfg.PlatformDomain,
		TemporalClient:                 devLoopClient,
		WorkflowDispatcher:             workflowDispatcher,
		GitopsReady:                    gitopsReady,
		PostgresReady:                  postgresReady,
		DexReady:                       dexReady,
		VaultReady:                     vaultReady,
		ArgoWebhookSecret:              cfg.ArgoWebhookSecret,
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
			"credential", name, "file", os.Getenv(githubAppTokenFileEnv), "err", err)
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
	GitHubOrg               string
	AdminUsers              []string
	BackstageURL            string
	BackstageToken          string
	BackstageInternalURL    string
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
	DexIssuerURL string
	// DexClientID is the expected audience for Dex JWTs. If empty, audience check is skipped.
	DexClientID string
	// SelfURL is the public base URL used in MCP SSE endpoint advertisement.
	SelfURL string
	// AllowedOrigins is a list of origins permitted by CORS policy.
	AllowedOrigins []string
	// OAuth 2.0 server settings for Claude.ai custom connector support.
	OAuthGitHubClientID      string
	OAuthGitHubClientSecret  string
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
	VictoriaMetricsURL           string
	ArgoWebhookSecret            string
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
		ArgoCDToken:                    os.Getenv("ARGOCD_TOKEN"),
		GitHubOrg:                      envOr("GITHUB_ORG", "mctlhq"),
		AdminUsers:                     adminList,
		BackstageURL:                   os.Getenv("BACKSTAGE_URL"),
		BackstageToken:                 os.Getenv("BACKSTAGE_TOKEN"),
		BackstageInternalURL:           envOr("BACKSTAGE_INTERNAL_URL", "http://backstage.backstage.svc.cluster.local:7007"),
		PlatformDomain:                 envOr("PLATFORM_DOMAIN", "mctl.ai"),
		DNSResolverAddr:                envOr("DNS_RESOLVER_ADDR", "1.1.1.1:53"),
		BackstageGithubAppConnectToken: os.Getenv("BACKSTAGE_GITHUB_APP_CONNECT_TOKEN"),
		DexIssuerURL:                   envOr("DEX_ISSUER_URL", "https://ops.mctl.ai/api/dex"),
		DexClientID:                    os.Getenv("DEX_CLIENT_ID"),
		SelfURL:                        envOr("SELF_URL", "https://api.mctl.ai"),
		AllowedOrigins:                 origins,
		OAuthGitHubClientID:            os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubClientSecret:        os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthJWTSecret:                 os.Getenv("OAUTH_JWT_SECRET"),
		OAuthAllowedRedirectURIs:       oauthRedirectURIs,
		OAuthPreregisteredClientsRaw:   os.Getenv("OAUTH_PREREGISTERED_CLIENTS"),
		OAuthTokenTTL:                  parseDuration(os.Getenv("OAUTH_TOKEN_TTL"), time.Hour),
		OAuthRefreshTokenTTL:           parseDuration(os.Getenv("OAUTH_REFRESH_TOKEN_TTL"), 30*24*time.Hour),
		VaultAddr:                      os.Getenv("VAULT_ADDR"),
		VaultToken:                     os.Getenv("VAULT_TOKEN"),
		VaultKubernetesRole:            os.Getenv("VAULT_KUBERNETES_ROLE"),
		VaultKubernetesAuthPath:        os.Getenv("VAULT_KUBERNETES_AUTH_PATH"),
		VictoriaMetricsURL:             envOr("VICTORIA_METRICS_URL", "http://vmsingle-monitoring-victoria-metrics-k8s-stack.monitoring.svc:8428"),
		ArgoWebhookSecret:              os.Getenv("ARGO_WEBHOOK_SECRET"),
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
	// initialDelaySeconds: 10 (helm/templates/deployment.yaml), so a degraded
	// pod still reports ready on schedule instead of looking hung.
	storeInitBudget = 8 * time.Second
)

// A var, not a const, only so tests can shrink it — nothing at runtime writes it.
var storeInitBaseDelay = 250 * time.Millisecond

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
func initStore[T any](ctx context.Context, name string, newStore func(context.Context) (T, error)) (T, error) {
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
	oauthEnabled := c.OAuthGitHubClientID != "" && c.OAuthJWTSecret != ""
	if oauthEnabled && c.OAuthTokenTTL > maxOAuthTokenTTL {
		return fmt.Errorf("OAUTH_TOKEN_TTL must not exceed %v, got %v — clients renew "+
			"silently with the refresh_token grant, and access tokens cannot be revoked, "+
			"so a longer lifetime only widens the window on a leak", maxOAuthTokenTTL, c.OAuthTokenTTL)
	}
	return nil
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

// parseIntEnv reads a positive integer from the given env var. Returns the
// fallback when the var is unset, empty, non-numeric, or non-positive; zero
// means "use package default" downstream.
func parseIntEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
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
