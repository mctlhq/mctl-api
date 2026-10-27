package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mctl-api#813 against a real PostgreSQL: the tenant column round-trips,
// ListSupport filters by tenant and by execution, newest first and bounded,
// and List keeps support.request rows out of the operations feed.
func TestPostgresLogger_ListSupport(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed audit test")
	}
	ctx := context.Background()
	p, err := NewPostgresLogger(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	suffix := uuid.NewString()[:8]
	tenant, exec, other := "t-"+suffix, "we_"+suffix, "we_other_"+suffix
	var ids []string
	log := func(e Entry) {
		e.ID = uuid.NewString()
		ids = append(ids, e.ID)
		p.Log(e)
		time.Sleep(2 * time.Millisecond) // distinct timestamps for ordering
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = p.pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
		}
		p.pool.Close()
	})

	log(Entry{Operation: OperationSupportRequest, Status: "succeeded", Tenant: tenant, ViaExecutionID: exec,
		PrincipalID: "prn_ALICE", ViaPrincipalID: "prn_AGENT", Parameters: map[string]string{"layer": "rest"}})
	log(Entry{Operation: OperationAgentScopeDenied, Status: "denied", Tenant: tenant, ViaExecutionID: exec})
	log(Entry{Operation: OperationSupportRequest, Status: "succeeded", Tenant: tenant, ViaExecutionID: other})
	log(Entry{Operation: OperationAgentScopeDenied, Status: "denied", ViaExecutionID: exec}) // no tenant: not a support row
	log(Entry{Operation: "deploy-service", Status: "pending", Tenant: tenant, ViaExecutionID: exec})
	log(Entry{Operation: OperationSupportRequest, Status: "succeeded", Tenant: "u-" + suffix, ViaExecutionID: "we_u_" + suffix})

	byTenant, err := p.ListSupport(ctx, SupportFilter{Tenant: tenant, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTenant) != 3 || byTenant[0].ViaExecutionID != other || byTenant[2].Operation != OperationSupportRequest {
		t.Fatalf("by tenant = %+v, want 3 rows newest first", byTenant)
	}
	first := byTenant[2]
	if first.Tenant != tenant || first.PrincipalID != "prn_ALICE" || first.ViaPrincipalID != "prn_AGENT" ||
		first.Parameters["layer"] != "rest" {
		t.Errorf("row did not round-trip: %+v", first)
	}

	byExec, err := p.ListSupport(ctx, SupportFilter{ExecutionID: exec, Limit: 100})
	if err != nil || len(byExec) != 2 || byExec[0].Operation != OperationAgentScopeDenied {
		t.Fatalf("by execution = %+v, %v", byExec, err)
	}
	limited, err := p.ListSupport(ctx, SupportFilter{Tenant: tenant, Limit: 1})
	if err != nil || len(limited) != 1 || limited[0].ViaExecutionID != other {
		t.Fatalf("limit = %+v, %v", limited, err)
	}
	before, err := p.ListSupport(ctx, SupportFilter{Tenant: tenant, Limit: 100, Before: byTenant[0].Timestamp})
	if err != nil || len(before) != 2 {
		t.Fatalf("before = %+v, %v", before, err)
	}

	for _, e := range p.List(500) {
		if e.Operation == OperationSupportRequest {
			t.Fatalf("List returned a support.request row: %+v", e)
		}
	}
}
