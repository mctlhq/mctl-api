package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/gitops"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Options holds all dependencies for the API router.
type Options struct {
	Registry       *operations.Registry
	GitReader      *gitops.Reader
	ArgoCD         *argocd.Client
	AuditLog       *audit.Logger
	Executor       *operations.Executor
	AuthMiddleware func(http.Handler) http.Handler
	// MCPServer exposes platform tools over MCP SSE transport at /mcp/sse.
	MCPServer      *mctlmcp.Server
	// SelfURL is the public base URL of this server (e.g. https://api.mctl.ai).
	// Used to configure the MCP SSE endpoint URL returned to clients.
	SelfURL        string
	// Optional Backstage integration for immediate catalog sync.
	BackstageURL   string
	BackstageToken string
}

// Handlers holds all API handler dependencies.
type Handlers struct {
	opts Options
}

// NewRouter creates the HTTP router with all API routes.
func NewRouter(opts Options) http.Handler {
	h := &Handlers{opts: opts}

	r := chi.NewRouter()

	// Infrastructure middleware (no auth).
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	// Health checks (no auth).
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		if opts.AuthMiddleware != nil {
			r.Use(opts.AuthMiddleware)
		}
		r.Use(middleware.Timeout(30 * 1000000000)) // 30s

		r.Route("/api/v1", func(r chi.Router) {
			// Read endpoints (safe, no side effects).
			r.Get("/tenants", h.ListTenants)
			r.Get("/tenants/{name}", h.GetTenant)
			r.Get("/services", h.ListServices)
			r.Get("/services/{team}/{app}", h.GetService)
			r.Get("/status/{team}/{app}", h.GetServiceStatus)
			r.Get("/workflows", h.ListWorkflows)
			r.Get("/workflows/{name}", h.GetWorkflow)
			r.Get("/resources/{tenant}", h.GetResourceUsage)
			r.Get("/audit", h.ListAudit)

			// Operation registry (metadata only).
			r.Get("/operations", h.ListOperations)
			r.Get("/operations/{name}", h.GetOperation)

			// Write endpoints (trigger Argo Workflows).
			r.Post("/operations/{name}/execute", h.ExecuteOperation)
		})

		// MCP SSE transport — remote endpoint for Claude Desktop, Cursor, etc.
		// Clients connect to /mcp/sse with Authorization: Bearer <token>.
		if opts.MCPServer != nil {
			sseServer := opts.MCPServer.NewSSEHandler(opts.SelfURL)
			r.Get("/mcp/sse", sseServer.SSEHandler().ServeHTTP)
			r.Post("/mcp/message", sseServer.MessageHandler().ServeHTTP)
		}
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
