// Package telemetry wires vendor-neutral OpenTelemetry tracing: W3C trace
// context propagation is always on, and spans are exported over OTLP/HTTP only
// when an OTEL_EXPORTER_OTLP_* endpoint is configured. With no endpoint (or
// OTEL_SDK_DISABLED=true) no exporter exists and no network I/O happens, but
// trace ids are still generated and propagated so they can be stored and
// returned.
package telemetry

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation scope used for spans created here.
const TracerName = "github.com/mctlhq/mctl-api"

// Config configures Setup.
type Config struct {
	ServiceName string
	Version     string
	// Getenv overrides os.Getenv (tests).
	Getenv func(string) string
}

// Result describes what Setup installed.
type Result struct {
	// Exporting is true only when an OTLP exporter was created.
	Exporting bool
	// Provider is the installed tracer provider.
	Provider *sdktrace.TracerProvider
	// Shutdown flushes and stops the provider; bounded by ctx.
	Shutdown func(context.Context) error
}

// ExporterEnabled reports whether the environment asks for an OTLP exporter.
func ExporterEnabled(getenv func(string) string) bool {
	if strings.EqualFold(strings.TrimSpace(getenv("OTEL_SDK_DISABLED")), "true") {
		return false
	}
	for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		if strings.TrimSpace(getenv(k)) != "" {
			return true
		}
	}
	return false
}

// Setup installs the global propagator and tracer provider.
func Setup(ctx context.Context, cfg Config) (*Result, error) {
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	name := cfg.ServiceName
	if name == "" {
		name = "mctl-api"
	}
	res, _ := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(name), semconv.ServiceVersion(cfg.Version)))

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	}
	exporting := ExporterEnabled(getenv)
	if exporting {
		exp, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
		// Bounded queue; the batch processor drops (never blocks) when full,
		// so an unreachable Collector cannot slow a request.
		opts = append(opts, sdktrace.WithBatcher(exp,
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithExportTimeout(5*time.Second),
		))
	}
	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetErrorHandler(newRateLimitedErrorHandler(time.Minute))
	return &Result{Exporting: exporting, Provider: tp, Shutdown: tp.Shutdown}, nil
}

type rateLimitedErrorHandler struct {
	every time.Duration
	last  atomic.Int64
}

func newRateLimitedErrorHandler(every time.Duration) *rateLimitedErrorHandler {
	return &rateLimitedErrorHandler{every: every}
}

func (h *rateLimitedErrorHandler) Handle(err error) {
	now := time.Now().UnixNano()
	last := h.last.Load()
	if now-last < int64(h.every) || !h.last.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("otel export error (rate limited)", "error", err)
}

// Tracer returns the package tracer from the global provider.
func Tracer() trace.Tracer { return otel.Tracer(TracerName) }

// TraceIDFrom returns the hex trace id of the span in ctx, or "" if none.
func TraceIDFrom(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.TraceID().IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// TraceparentFrom returns the W3C traceparent for the span in ctx, or "".
func TraceparentFrom(ctx context.Context) string {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ""
	}
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return carrier.Get("traceparent")
}
