package mcp

import (
	"context"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const (
	metaTID = "0af7651916cd43dd8448eb211c80319c"
	httpTID = "4bf92f3577b34da6a3ce929d0e0e4736"
)

func runTool(t *testing.T, httpTP, metaTP string) tracetest.SpanStub {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	old := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(old)

	ctx := context.Background()
	if httpTP != "" {
		ctx = withTP(t, ctx, httpTP)
	}
	req := mcplib.CallToolRequest{}
	req.Params.Name = "mctl_whoami"
	req.Params.Arguments = map[string]any{"secret": "SENTINEL"}
	if metaTP != "" {
		req.Params.Meta = &mcplib.Meta{AdditionalFields: map[string]any{"traceparent": metaTP}}
	}
	s := &Server{}
	_, _ = s.tracingMiddleware(func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return mcplib.NewToolResultText("ok"), nil
	})(ctx, req)
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d", len(spans))
	}
	for _, a := range spans[0].Attributes {
		allowed := false
		for _, k := range telemetry.AllowedKeys() {
			allowed = allowed || string(a.Key) == k
		}
		if !allowed || a.Value.Emit() == "SENTINEL" {
			t.Fatalf("unexpected attribute %v", a)
		}
	}
	return spans[0]
}

func withTP(t *testing.T, ctx context.Context, tp string) context.Context {
	t.Helper()
	tid, _ := trace.TraceIDFromHex(tp[3:35])
	sid, _ := trace.SpanIDFromHex(tp[36:52])
	return trace.ContextWithRemoteSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled, Remote: true}))
}

func TestToolSpanParenting(t *testing.T) {
	metaTP := "00-" + metaTID + "-b7ad6b7169203331-01"
	httpTP := "00-" + httpTID + "-00f067aa0ba902b7-01"

	// _meta wins over a conflicting HTTP header; HTTP is linked, not parent.
	for i := 0; i < 3; i++ {
		sp := runTool(t, httpTP, metaTP)
		if sp.SpanContext.TraceID().String() != metaTID || sp.Parent.SpanID().String() != "b7ad6b7169203331" {
			t.Fatalf("parent not from _meta: %v", sp.Parent)
		}
		if len(sp.Links) != 1 || sp.Links[0].SpanContext.TraceID().String() != httpTID {
			t.Fatalf("expected one link to the HTTP trace, got %v", sp.Links)
		}
	}
	// Valid HTTP, invalid _meta: HTTP wins.
	sp := runTool(t, httpTP, "garbage")
	if sp.SpanContext.TraceID().String() != httpTID || len(sp.Links) != 0 {
		t.Fatalf("expected HTTP parent, got %v", sp.SpanContext)
	}
	// Both invalid: new root.
	sp = runTool(t, "", "garbage")
	if sp.Parent.IsValid() || !sp.SpanContext.TraceID().IsValid() {
		t.Fatalf("expected new root, got %v", sp.Parent)
	}
	// _meta only.
	sp = runTool(t, "", metaTP)
	if sp.SpanContext.TraceID().String() != metaTID {
		t.Fatal("expected _meta parent")
	}
}
