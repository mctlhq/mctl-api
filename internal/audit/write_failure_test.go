package audit

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPostgresLogger_WriteFailureIsCounted(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u@127.0.0.1:1/x?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	c := WriteFailures.WithLabelValues(OperationSupportRequest)
	before := testutil.ToFloat64(c)
	(&PostgresLogger{pool: pool}).Log(Entry{Operation: OperationSupportRequest, Status: "succeeded"})
	if got := testutil.ToFloat64(c) - before; got != 1 {
		t.Fatalf("counter += %v, want 1", got)
	}
}

func TestLogger_ListSupportAndListExclusion(t *testing.T) {
	l := NewLogger()
	l.Log(Entry{Operation: "deploy"})
	l.Log(Entry{Operation: OperationSupportRequest, Tenant: "a", ViaExecutionID: "we_1"})
	l.Log(Entry{Operation: OperationAgentScopeDenied, Tenant: "a", ViaExecutionID: "we_1"})
	l.Log(Entry{Operation: OperationAgentScopeDenied})
	if got := l.List(0); len(got) != 3 {
		t.Errorf("List = %d, want 3", len(got))
	}
	got, _ := l.ListSupport(context.Background(), SupportFilter{Tenant: "a", Limit: 1})
	if len(got) != 1 || got[0].Operation != OperationAgentScopeDenied {
		t.Errorf("ListSupport limit = %+v", got)
	}
	got, _ = l.ListSupport(context.Background(), SupportFilter{ExecutionID: "we_1"})
	if len(got) != 2 {
		t.Errorf("ListSupport = %d, want 2", len(got))
	}
}
