package telemetry

import (
	"context"
	"sort"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestSetupModes(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"no endpoint", map[string]string{}, false},
		{"endpoint", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1"}, true},
		{"traces endpoint", map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:1/v1/traces"}, true},
		{"disabled", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1", "OTEL_SDK_DISABLED": "true"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Setup(context.Background(), Config{Getenv: env(c.env)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Exporting != c.want {
				t.Fatalf("Exporting = %v, want %v", res.Exporting, c.want)
			}
			ctx, span := Tracer().Start(context.Background(), "x")
			if len(TraceIDFrom(ctx)) != 32 || TraceparentFrom(ctx) == "" {
				t.Fatal("trace ids must exist even without an exporter")
			}
			span.End()
			_ = res.Shutdown(context.Background())
		})
	}
}

func TestNoTraceContext(t *testing.T) {
	if TraceIDFrom(context.Background()) != "" || TraceparentFrom(context.Background()) != "" {
		t.Fatal("expected empty")
	}
}

func TestAttrKeysMatchCatalogUnionPending(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range CatalogKeys() {
		seen[k] = true
	}
	for _, k := range PendingCatalogKeys() {
		if seen[k] {
			t.Fatalf("%s in both lists", k)
		}
	}
	all := AllowedKeys()
	if len(all) != len(CatalogKeys())+len(PendingCatalogKeys()) {
		t.Fatal("allowlist is not the union")
	}
	sort.Strings(all)
	want := []string{"mcp.method.name", "mctl.actor.id", "mctl.actor.type", "mctl.argo.workflow.name",
		"mctl.execution.id", "mctl.incident.id", "mctl.operation.name", "mctl.tool.name", "mctl.tool.status",
		"mctl.work_item.id", "mctl.workflow.id", "mctl.workflow.run_id", "mctl.workflow.type"}
	if len(all) != len(want) {
		t.Fatalf("got %v", all)
	}
	for i := range want {
		if all[i] != want[i] {
			t.Fatalf("got %v want %v", all, want)
		}
	}
}
