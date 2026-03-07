package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/k8s"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
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
	authMiddleware := auth.Middleware(ghValidator, gitReader, dexVerifier)

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

	executor := operations.NewExecutor(cfg.ArgoWorkflowsNamespace)

	// MCP server for SSE transport (embedded in this process).
	// Tools make REST calls back to this server using the caller's token (forwarded via context).
	mcpSrv := mctlmcp.NewServer(cfg.SelfURL, "")

	// Kubernetes quota client (optional — fails gracefully outside cluster).
	var quotaReader mctlapi.QuotaReader
	if qc, qErr := k8s.NewQuotaClient(); qErr != nil {
		slog.Warn("k8s quota client unavailable, resource usage will be empty", "error", qErr)
	} else {
		quotaReader = qc
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
		BackstageURL:         cfg.BackstageURL,
		BackstageToken:       cfg.BackstageToken,
		BackstageInternalURL: cfg.BackstageInternalURL,
		AllowedOrigins:       cfg.AllowedOrigins,
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
	Port                   string
	GitOpsRepoURL          string
	GitOpsBranch           string
	GitOpsLocalPath        string
	GitOpsToken            string // GitHub token for HTTPS auth (optional)
	GitOpsSSHKeyPath       string // Path to SSH key for SSH auth (optional, takes precedence)
	ArgoCDURL              string
	ArgoCDToken            string
	ArgoWorkflowsNamespace string
	GitHubOrg              string
	AdminUsers             []string
	BackstageURL           string
	BackstageToken         string
	BackstageInternalURL   string
	// Dex OIDC issuer for JWT validation (dual-token auth alongside GitHub tokens).
	DexIssuerURL           string
	// DexClientID is the expected audience for Dex JWTs. If empty, audience check is skipped.
	DexClientID            string
	// SelfURL is the public base URL used in MCP SSE endpoint advertisement.
	SelfURL                string
	// AllowedOrigins is a list of origins permitted by CORS policy.
	AllowedOrigins         []string
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
		origins = []string{
			"https://mctl.ai",
			"https://mctl.me",
			"https://app.mctl.ai",
			"https://app.mctl.me",
			"https://ops.mctl.ai",
			"https://ops.mctl.me",
		}
	}

	return config{
		Port:                    envOr("PORT", "8080"),
		GitOpsRepoURL:           envOr("GITOPS_REPO_URL", "https://github.com/mctlhq/mctl-core.git"),
		GitOpsBranch:            envOr("GITOPS_BRANCH", "main"),
		GitOpsLocalPath:         envOr("GITOPS_LOCAL_PATH", "/tmp/mctl-core"),
		GitOpsToken:             os.Getenv("GITOPS_REPO_TOKEN"),
		GitOpsSSHKeyPath:        os.Getenv("GITOPS_SSH_KEY_PATH"),
		ArgoCDURL:               envOr("ARGOCD_URL", "https://ops.mctl.ai"),
		ArgoCDToken:             os.Getenv("ARGOCD_TOKEN"),
		ArgoWorkflowsNamespace:  envOr("ARGO_WORKFLOWS_NAMESPACE", "argo-workflows"),
		GitHubOrg:               envOr("GITHUB_ORG", "mctlhq"),
		AdminUsers:              adminList,
		BackstageURL:            os.Getenv("BACKSTAGE_URL"),
		BackstageToken:          os.Getenv("BACKSTAGE_TOKEN"),
		BackstageInternalURL:    envOr("BACKSTAGE_INTERNAL_URL", "http://backstage.backstage.svc.cluster.local:7007"),
		DexIssuerURL:            envOr("DEX_ISSUER_URL", "https://ops.mctl.ai/api/dex"),
		DexClientID:             os.Getenv("DEX_CLIENT_ID"),
		SelfURL:                 envOr("SELF_URL", "https://api.mctl.ai"),
		AllowedOrigins:          origins,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
