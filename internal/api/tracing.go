package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// tracingMiddleware starts a server span per request, continuing an incoming
// W3C traceparent. Probe and metrics paths and the long-lived GET /mcp listen stream are filtered out; headers and
// bodies are never captured. The span is renamed to the chi route pattern once
// routing has happened, so path parameters do not explode cardinality.
func tracingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		renamed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if rc := chi.RouteContext(r.Context()); rc != nil {
				if p := rc.RoutePattern(); p != "" {
					trace.SpanFromContext(r.Context()).SetName(r.Method + " " + p)
				}
			}
		})
		return otelhttp.NewHandler(renamed, "http.server",
			otelhttp.WithFilter(func(r *http.Request) bool {
				switch r.URL.Path {
				case "/healthz", "/readyz", "/metrics":
					return false
				case "/mcp":
					// The MCP listen stream stays open for the life of the
					// connection; a span would never end. POST /mcp is traced.
					if r.Method == http.MethodGet {
						return false
					}
				}
				return true
			}),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				// otelhttp re-invokes the formatter after the handler when
				// r.Pattern is set; keep the route pattern in that case.
				if r.Pattern != "" {
					return r.Method + " " + r.Pattern
				}
				return r.Method + " request"
			}),
		)
	}
}
