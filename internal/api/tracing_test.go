package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracingMiddleware(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	oldTP, oldProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer func() { otel.SetTracerProvider(oldTP); otel.SetTextMapPropagator(oldProp) }()

	r := chi.NewRouter()
	r.Use(tracingMiddleware())
	r.Get("/things/{id}", func(w http.ResponseWriter, _ *http.Request) {})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest(http.MethodGet, "/things/42", nil)
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	r.ServeHTTP(httptest.NewRecorder(), req)
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1 (healthz filtered)", len(spans))
	}
	if got := spans[0].SpanContext.TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace id = %s, incoming traceparent not continued", got)
	}
	if spans[0].Name != "GET /things/{id}" {
		t.Fatalf("name = %q", spans[0].Name)
	}
}
