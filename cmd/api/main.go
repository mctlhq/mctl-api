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
		dv, dexErr := auth.NewDexVerifier(context.Background(), cfg.DexIssuerURL)
		if dexErr != nil {
			slog.Warn("dex OIDC init failed — JWT auth disabled", "issuer", cfg.DexIssuerURL, "error", dexErr)
		} else {
			dexVerifier = dv
			slog.Info("dex OIDC initialized", "issuer", cfg.DexIssuerURL)
		}
	}

	// Auth middleware: validates GitHub tokens or Dex JWTs.
	ghValidator := auth.NewGitHubValidator(cfg.GitHubOrg, cfg.AdminUsers)
	authMiddleware := auth.Middleware(ghValidator, gitReader, dexVerifier)

	argoClient := argocd.NewClient(cfg.ArgoCDURL, cfg.ArgoCDToken)
	auditLog := audit.NewLogger()
	executor := operations.NewExecutor(cfg.ArgoWorkflowsNamespace)

	// MCP server for SSE transport (embedded in this process).
	// Tools make REST calls back to this server using the caller's token (forwarded via context).
	mcpSrv := mctlmcp.NewServer(cfg.SelfURL, "")

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:       registry,
		GitReader:      gitReader,
		ArgoCD:         argoClient,
		AuditLog:       auditLog,
		Executor:       executor,
		AuthMiddleware: authMiddleware,
		MCPServer:      mcpSrv,
		BackstageURL:   cfg.BackstageURL,
		BackstageToken: cfg.BackstageToken,
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
	// Dex OIDC issuer for JWT validation (dual-token auth alongside GitHub tokens).
	DexIssuerURL           string
	// SelfURL is the public base URL used in MCP SSE endpoint advertisement.
	SelfURL                string
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
		DexIssuerURL:            envOr("DEX_ISSUER_URL", "https://ops.mctl.ai/api/dex"),
		SelfURL:                 envOr("SELF_URL", "https://api.mctl.ai"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
