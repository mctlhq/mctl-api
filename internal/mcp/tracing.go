package mcp

import (
	"context"
	"net/http"
	"os"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// metaSpanContext returns the remote span context carried by a tools/call
// request's _meta (traceparent / tracestate), or false when absent or invalid.
func metaSpanContext(req mcplib.CallToolRequest) (trace.SpanContext, bool) {
	if req.Params.Meta == nil {
		return trace.SpanContext{}, false
	}
	tp, _ := req.Params.Meta.AdditionalFields["traceparent"].(string)
	if tp == "" {
		return trace.SpanContext{}, false
	}
	carrier := propagation.MapCarrier{"traceparent": tp}
	if ts, ok := req.Params.Meta.AdditionalFields["tracestate"].(string); ok {
		carrier["tracestate"] = ts
	}
	ctx := propagation.TraceContext{}.Extract(context.Background(), carrier)
	sc := trace.SpanContextFromContext(ctx)
	return sc, sc.IsValid()
}

// tracingMiddleware wraps every tool call in a span. Parent selection is
// deterministic: a valid _meta.traceparent always parents the tool span; when
// it is absent or invalid the HTTP-derived context in ctx is used (and a new
// root if there is none). When both are valid and their trace ids differ, the
// HTTP server span is attached as a span link, never as the parent. Tool
// arguments and credentials are never recorded.
func (s *Server) tracingMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		var opts []trace.SpanStartOption
		opts = append(opts, trace.WithSpanKind(trace.SpanKindServer))
		if msc, ok := metaSpanContext(req); ok {
			if hsc := trace.SpanContextFromContext(ctx); hsc.IsValid() && hsc.TraceID() != msc.TraceID() {
				opts = append(opts, trace.WithLinks(trace.Link{SpanContext: hsc}))
			}
			ctx = trace.ContextWithRemoteSpanContext(ctx, msc)
		}
		ctx, span := otel.Tracer(telemetry.TracerName).Start(ctx, "mcp.tools/call "+req.Params.Name, opts...)
		defer span.End()
		attrs := []attribute.KeyValue{
			telemetry.ToolName(req.Params.Name),
			telemetry.MCPMethod("tools/call"),
		}
		if strings.EqualFold(os.Getenv("OTEL_MCTL_RECORD_ENDUSER"), "true") {
			if u := auth.UserFromContext(ctx); u != nil {
				typ := "user"
				if u.IsService() {
					typ = "service"
				}
				attrs = append(attrs, telemetry.ActorID(u.ID), telemetry.ActorType(typ))
			}
		}
		span.SetAttributes(attrs...)

		res, err := next(ctx, req)
		status := "ok"
		if err != nil || (res != nil && res.IsError) {
			status = "error"
			span.SetStatus(codes.Error, "tool call failed")
		}
		span.SetAttributes(telemetry.ToolStatus(status))
		return res, err
	}
}

// tracingTransport starts a client span per loopback REST call and injects
// traceparent. It records only method and status code: no URL, query, header
// or body.
type tracingTransport struct{ base http.RoundTripper }

func (t tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer(telemetry.TracerName).Start(req.Context(), "mctl-api loopback "+req.Method,
		trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	req = req.Clone(ctx)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		span.SetStatus(codes.Error, "request failed")
		return resp, err
	}
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, "server error")
	}
	return resp, nil
}
