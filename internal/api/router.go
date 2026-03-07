package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Options holds all dependencies for the API router.
type Options struct {
	Registry       *operations.Registry
	GitReader      GitReader
	ArgoCD         ArgoStatusClient
	AuditLog       AuditLog
	Executor       WorkflowExecutor
	AuthMiddleware func(http.Handler) http.Handler
	// MCPServer exposes platform tools over MCP Streamable HTTP at /mcp.
	MCPServer      *mctlmcp.Server
	// Optional Backstage integration for immediate catalog sync.
	BackstageURL   string
	BackstageToken string
	// AllowedOrigins is the list of origins permitted by CORS.
	// If empty, no Access-Control-Allow-Origin header is set (deny all cross-origin).
	AllowedOrigins []string
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
	r.Use(corsMiddleware(opts.AllowedOrigins))

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

		// Global rate limit: 100 requests/minute per user (fallback to per-IP).
		r.Use(httprate.Limit(100, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			if user := auth.UserFromContext(r.Context()); user != nil {
				return "user:" + user.ID, nil
			}
			return httprate.KeyByRealIP(r)
		})))

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

			// Write endpoints (trigger Argo Workflows) — tighter rate limit.
			r.With(httprate.Limit(20, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
				if user := auth.UserFromContext(r.Context()); user != nil {
					return "write:" + user.ID, nil
				}
				return httprate.KeyByRealIP(r)
			}))).Post("/operations/{name}/execute", h.ExecuteOperation)
		})

		// MCP Streamable HTTP transport — single endpoint for Claude Desktop, Cursor, etc.
		// POST /mcp  → send request (can return streaming SSE response)
		// GET  /mcp  → open persistent listen stream (optional, for server-initiated messages)
		// Auth: Authorization: Bearer <token> on every request.
		if opts.MCPServer != nil {
			mcpH := opts.MCPServer.NewStreamableHTTPHandler()
			r.Post("/mcp", mcpH.ServeHTTP)
			r.Get("/mcp", mcpH.ServeHTTP)
			r.Delete("/mcp", mcpH.ServeHTTP)
		}
	})

	return r
}

// corsMiddleware returns middleware that validates the request Origin against
// a list of allowed origins. If the origin matches, it sets the appropriate
// CORS headers. If no origins are configured, all cross-origin requests are denied.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimSpace(o)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
