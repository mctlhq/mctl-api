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
	"github.com/mctlhq/mctl-api/internal/operations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := loadConfig()

	// Initialize components.
	registry := operations.NewRegistry()

	gitReader, err := gitops.NewReader(cfg.GitOpsRepoURL, cfg.GitOpsBranch, cfg.GitOpsLocalPath)
	if err != nil {
		slog.Error("failed to initialize gitops reader", "error", err)
		os.Exit(1)
	}

	// GitHub auth: validate tokens via GitHub API, resolve tenant groups from gitops.
	ghValidator := auth.NewGitHubValidator(cfg.GitHubOrg, cfg.AdminUsers)
	authMiddleware := auth.Middleware(ghValidator, gitReader)

	argoClient := argocd.NewClient(cfg.ArgoCDURL, cfg.ArgoCDToken)
	auditLog := audit.NewLogger()
	executor := operations.NewExecutor(cfg.ArgoWorkflowsNamespace)

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:      registry,
		GitReader:     gitReader,
		ArgoCD:        argoClient,
		AuditLog:      auditLog,
		Executor:      executor,
		AuthMiddleware: authMiddleware,
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
	ArgoCDURL              string
	ArgoCDToken            string
	ArgoWorkflowsNamespace string
	GitHubOrg              string
	AdminUsers             []string
	BackstageURL           string
	BackstageToken         string
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
		Port:                   envOr("PORT", "8080"),
		GitOpsRepoURL:         envOr("GITOPS_REPO_URL", "https://github.com/mctlhq/mctl-core.git"),
		GitOpsBranch:          envOr("GITOPS_BRANCH", "main"),
		GitOpsLocalPath:       envOr("GITOPS_LOCAL_PATH", "/tmp/mctl-core"),
		ArgoCDURL:             envOr("ARGOCD_URL", "https://ops.mctl.me"),
		ArgoCDToken:           os.Getenv("ARGOCD_TOKEN"),
		ArgoWorkflowsNamespace: envOr("ARGO_WORKFLOWS_NAMESPACE", "argo-workflows"),
		GitHubOrg:             envOr("GITHUB_ORG", "mctlhq"),
		AdminUsers:            adminList,
		BackstageURL:          os.Getenv("BACKSTAGE_URL"),
		BackstageToken:        os.Getenv("BACKSTAGE_TOKEN"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
