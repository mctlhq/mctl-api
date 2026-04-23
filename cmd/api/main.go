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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-api/internal/alerts"
	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/k8s"
	"github.com/mctlhq/mctl-api/internal/loki"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/vault"
	"github.com/mctlhq/mctl-api/internal/vmetrics"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := loadConfig()

	// Initialize components.
	registry := operations.NewRegistry()

	gitReader, err := gitops.NewReader(cfg.GitOpsRepoURL, cfg.GitOpsBranch, cfg.GitOpsLocalPath, cfg.GitOpsToken, cfg.GitOpsSSHKeyPath)
	if err != nil {
		slog.Error("failed to initialize gitops reader", "error", err)
		os.Exit(1)
	}

	// Dex JWT verifier (optional — disabled if DEX_ISSUER_URL is unset or unreachable).
	var dexVerifier *auth.DexVerifier
	if cfg.DexIssuerURL != "" {
		dv, dexErr := auth.NewDexVerifier(context.Background(), cfg.DexIssuerURL, cfg.DexClientID)
		if dexErr != nil {
			slog.Warn("dex OIDC init failed — JWT auth disabled", "issuer", cfg.DexIssuerURL, "error", dexErr)
		} else {
			dexVerifier = dv
			slog.Info("dex OIDC initialized", "issuer", cfg.DexIssuerURL, "clientID", cfg.DexClientID)
		}
	}

	// Auth middleware: validates GitHub tokens or Dex JWTs.
	ghValidator := auth.NewGitHubValidator(cfg.AdminUsers)

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
		slog.Info("OAuth 2.0 server enabled", "base_url", cfg.SelfURL, "redirect_uris", cfg.OAuthAllowedRedirectURIs, "token_ttl", cfg.OAuthTokenTTL)
	}

	authMiddleware := auth.Middleware(ghValidator, gitReader, dexVerifier, oauthServer)

	argoClient := argocd.NewClient(cfg.ArgoCDURL, cfg.ArgoCDToken)

	var auditLog audit.Log
	if dbURL := os.Getenv("AUDIT_DB_URL"); dbURL != "" {
		pgLog, pgErr := audit.NewPostgresLogger(context.Background(), dbURL)
		if pgErr != nil {
			slog.Warn("postgres audit log init failed, falling back to in-memory", "error", pgErr)
			auditLog = audit.NewLogger()
		} else {
			auditLog = pgLog
		}
	} else {
		auditLog = audit.NewLogger()
	}

	// Alert store (optional — enabled when ALERT_DB_URL or AUDIT_DB_URL is set).
	var alertStore *alerts.Store
	if alertDBURL := os.Getenv("ALERT_DB_URL"); alertDBURL != "" {
		as, asErr := alerts.NewStore(context.Background(), alertDBURL)
		if asErr != nil {
			slog.Warn("alert store init failed", "error", asErr)
		} else {
			alertStore = as
		}
	} else if dbURL := os.Getenv("AUDIT_DB_URL"); dbURL != "" {
		as, asErr := alerts.NewStore(context.Background(), dbURL)
		if asErr != nil {
			slog.Warn("alert store init failed (using AUDIT_DB_URL)", "error", asErr)
		} else {
			alertStore = as
		}
	}

	executor := operations.NewExecutor()

	// MCP server for SSE transport (embedded in this process).
	// Tools make REST calls back to this server using the caller's token (forwarded via context).
	// Use localhost to avoid hairpin routing and public egress issues.
	mcpSrv := mctlmcp.NewServer("http://localhost:"+cfg.Port, "")

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

	// Vault client (optional — used for onboarding secret preflight).
	var vaultReader mctlapi.VaultReader
	if cfg.VaultAddr != "" && cfg.VaultToken != "" {
		vaultReader = vault.NewClient(cfg.VaultAddr, cfg.VaultToken)
		slog.Info("vault client enabled", "addr", cfg.VaultAddr)
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

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:             registry,
		GitReader:            gitReader,
		ArgoCD:               argoClient,
		AuditLog:             auditLog,
		Executor:             executor,
		AuthMiddleware:       authMiddleware,
		MCPServer:            mcpSrv,
		QuotaReader:          quotaReader,
		LogQuerier:           logQuerier,
		VaultReader:          vaultReader,
		MetricsQuerier:       metricsQuerier,
		OpenClaw:             openClawQuota,
		BackstageURL:         cfg.BackstageURL,
		BackstageToken:       cfg.BackstageToken,
		BackstageInternalURL: cfg.BackstageInternalURL,
		AllowedOrigins:       cfg.AllowedOrigins,
		OAuthServer:          oauthServer,
		AlertStore:           alertStore,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start gitops reader refresh loop.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gitReader.RefreshLoop(ctx, 60*time.Second)

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

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

type config struct {
	Port                 string
	GitOpsRepoURL        string
	GitOpsBranch         string
	GitOpsLocalPath      string
	GitOpsToken          string // GitHub token for HTTPS auth (optional)
	GitOpsSSHKeyPath     string // Path to SSH key for SSH auth (optional, takes precedence)
	ArgoCDURL            string
	ArgoCDToken          string
	GitHubOrg            string
	AdminUsers           []string
	BackstageURL         string
	BackstageToken       string
	BackstageInternalURL string
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
	OAuthTokenTTL            time.Duration
	OAuthRefreshTokenTTL     time.Duration
	VaultAddr                string
	VaultToken               string
	VictoriaMetricsURL       string
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
		Port:                     envOr("PORT", "8080"),
		GitOpsRepoURL:            envOr("GITOPS_REPO_URL", "https://github.com/mctlhq/mctl-gitops.git"),
		GitOpsBranch:             envOr("GITOPS_BRANCH", "main"),
		GitOpsLocalPath:          envOr("GITOPS_LOCAL_PATH", "/tmp/mctl-gitops"),
		GitOpsToken:              envOr("GITOPS_REPO_TOKEN", os.Getenv("GITHUB_TOKEN")),
		GitOpsSSHKeyPath:         os.Getenv("GITOPS_SSH_KEY_PATH"),
		ArgoCDURL:                envOr("ARGOCD_URL", "https://ops.mctl.ai"),
		ArgoCDToken:              os.Getenv("ARGOCD_TOKEN"),
		GitHubOrg:                envOr("GITHUB_ORG", "mctlhq"),
		AdminUsers:               adminList,
		BackstageURL:             os.Getenv("BACKSTAGE_URL"),
		BackstageToken:           os.Getenv("BACKSTAGE_TOKEN"),
		BackstageInternalURL:     envOr("BACKSTAGE_INTERNAL_URL", "http://backstage.backstage.svc.cluster.local:7007"),
		DexIssuerURL:             envOr("DEX_ISSUER_URL", "https://ops.mctl.ai/api/dex"),
		DexClientID:              os.Getenv("DEX_CLIENT_ID"),
		SelfURL:                  envOr("SELF_URL", "https://api.mctl.ai"),
		AllowedOrigins:           origins,
		OAuthGitHubClientID:      os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubClientSecret:  os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthJWTSecret:           os.Getenv("OAUTH_JWT_SECRET"),
		OAuthAllowedRedirectURIs: oauthRedirectURIs,
		OAuthTokenTTL:            parseDuration(os.Getenv("OAUTH_TOKEN_TTL"), time.Hour),
		OAuthRefreshTokenTTL:     parseDuration(os.Getenv("OAUTH_REFRESH_TOKEN_TTL"), 30*24*time.Hour),
		VaultAddr:                os.Getenv("VAULT_ADDR"),
		VaultToken:               os.Getenv("VAULT_TOKEN"),
		VictoriaMetricsURL:       envOr("VICTORIA_METRICS_URL", "http://vmsingle-monitoring-victoria-metrics-k8s-stack.monitoring.svc:8428"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
