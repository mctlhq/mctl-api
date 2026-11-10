package workitems

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

// fakeOrders is the #988 collaborator: it records what BindApproval got.
type fakeOrders struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeOrders) BindApproval(_ context.Context, _ pgx.Tx, sc orders.Scope, a orders.Actor, orderRef, approvalRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s|%s|%s|%s|%s|%s", sc.Tenant, sc.PrincipalID, a.Kind, a.ID, orderRef, approvalRef))
	return f.err
}

// glovoEnv is a split-role scratch database with both schemas applied, the
// work-items store (as in production: the work-items pool), and a pool of the
// Glovo runtime role, which supplies every transaction.
type glovoEnv struct {
	*splitEnv
	rtp    *pgxpool.Pool
	store  *Store
	orders *fakeOrders
}

const (
	testOwner  = "prn_OWNER00000000000000000001"
	testTenant = "acme"
)

func newGlovoEnv(t *testing.T) *glovoEnv {
	t.Helper()
	e := newSplitEnv(t)
	if err := ApplyGlovoApprovalSchema(context.Background(), e.migURL, e.rt, WithWorkItemsRole(e.wi)); err != nil {
		t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
	}
	fo := &fakeOrders{}
	st, err := NewStore(context.Background(), e.wiURL, WithGlovoOrders(fo))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(st.Close)
	return &glovoEnv{splitEnv: e, rtp: e.pool(e.rtURL), store: st, orders: fo}
}

func (g *glovoEnv) tx(t *testing.T, fn func(tx pgx.Tx)) {
	t.Helper()
	tx, err := g.rtp.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	fn(tx)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// glovoFixture is one prepared order: execution, work item and a pending aar_.
type glovoFixture struct {
	in  GlovoApprovalInput
	aar string
}

func randTok(t *testing.T, prefix string, n int) string {
	t.Helper()
	id, err := glovoRandID(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id[:len(prefix)+n]
}

func (g *glovoEnv) prepare(t *testing.T) glovoFixture {
	t.Helper()
	var f glovoFixture
	g.tx(t, func(tx pgx.Tx) {
		wi, we, err := g.store.CreateGlovoExecutionTx(context.Background(), tx, GlovoExecutionInput{
			Tenant: testTenant, OwnerPrincipalID: testOwner, WorkflowID: "wf-" + splitHex(4), Actor: "service:glovo-prepare"})
		if err != nil {
			t.Fatalf("CreateGlovoExecutionTx: %v", err)
		}
		f.in = GlovoApprovalInput{
			Tenant: testTenant, OwnerPrincipalID: testOwner, WorkItemID: wi, ExecutionID: we,
			OrderRef: randTok(t, "ordr_", 26), ConnectionRef: randTok(t, "gcn_", 26), InstallID: "install-1",
			InstallRevision: "3", BasketFingerprint: "sha256:" + strings.Repeat("ab", 32), Provider: "fake",
			ExpiresIn: time.Hour,
		}
		a, created, err := g.store.CreateGlovoApprovalTx(context.Background(), tx, f.in)
		if err != nil || !created {
			t.Fatalf("CreateGlovoApprovalTx: %v created=%v", err, created)
		}
		f.aar = a.ID
	})
	return f
}

func (g *glovoEnv) decide(t *testing.T, f glovoFixture, decision string) *ActionApprovalRequest {
	t.Helper()
	var out *ActionApprovalRequest
	g.tx(t, func(tx pgx.Tx) {
		a, err := g.store.DecideGlovoApprovalTx(context.Background(), tx, ActionDecisionInput{
			ID: f.aar, DecidedBy: "oidc:owner", DecidedByPrincipalID: testOwner, Decision: decision,
			AuthorityBasis: GlovoAuthorityBasis, AuthzMode: "enforce", ContextDigest: f.in.BasketFingerprint, FreshFor: 15 * time.Minute})
		if err != nil {
			t.Fatalf("DecideGlovoApprovalTx: %v", err)
		}
		out = a
	})
	return out
}

func (f glovoFixture) reserveCmd(cmd string) ReserveCommand {
	b := f.in.binding()
	return ReserveCommand{
		CommandID: cmd, Tenant: f.in.Tenant, OwnerPrincipalID: f.in.OwnerPrincipalID, ExecutionID: f.in.ExecutionID,
		OrderRef: f.in.OrderRef, ConnectionRef: f.in.ConnectionRef, InstallRevision: f.in.InstallRevision,
		IntentHash: IntentHash(GlovoIntent(b)), BasketFingerprint: f.in.BasketFingerprint,
	}
}

func newCmdID(t *testing.T) string { return randTok(t, "cmd_", 26) }

// stored reads the row as the superuser-free migration role would: through the
// runtime pool, so the test uses the same grants as production.
func (g *glovoEnv) stored(t *testing.T, id string) (state, command string) {
	t.Helper()
	err := g.rtp.QueryRow(context.Background(), `SELECT a.state, b.command_id FROM public.action_approval_requests a
		JOIN glovo.approval_bindings b ON b.approval_id=a.id WHERE a.id=$1`, id).Scan(&state, &command)
	if err != nil {
		t.Fatal(err)
	}
	return state, command
}
