package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Handlers holds all API handler dependencies.
type Handlers struct {
	Registry  *operations.Registry
	GitReader *gitops.Reader
	ArgoCD    *argocd.Client
	AuditLog  *audit.Logger
	Executor  *operations.Executor
}

// NewRouter creates the HTTP router with all API routes.
func NewRouter(
	registry *operations.Registry,
	gitReader *gitops.Reader,
	argoClient *argocd.Client,
	auditLog *audit.Logger,
	executor *operations.Executor,
) http.Handler {
	h := &Handlers{
		Registry:  registry,
		GitReader: gitReader,
		ArgoCD:    argoClient,
		AuditLog:  auditLog,
		Executor:  executor,
	}

	r := chi.NewRouter()

	// Middleware.
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * 1000000000)) // 30s
	r.Use(corsMiddleware)
	r.Use(auth.Middleware)

	// Health checks (no auth).
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// API v1.
	r.Route("/api/v1", func(r chi.Router) {
		// Read endpoints (safe, no approval needed).
		r.Get("/tenants", h.ListTenants)
		r.Get("/tenants/{name}", h.GetTenant)
		r.Get("/services", h.ListServices)
		r.Get("/services/{team}/{app}", h.GetService)
		r.Get("/status/{team}/{app}", h.GetServiceStatus)
		r.Get("/workflows", h.ListWorkflows)
		r.Get("/workflows/{name}", h.GetWorkflow)
		r.Get("/resources/{tenant}", h.GetResourceUsage)
		r.Get("/audit", h.ListAudit)

		// Operation registry.
		r.Get("/operations", h.ListOperations)
		r.Get("/operations/{name}", h.GetOperation)

		// Write endpoints (trigger workflows).
		r.Post("/operations/{name}/execute", h.ExecuteOperation)
	})

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
