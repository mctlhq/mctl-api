package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func openExecution(t *testing.T, s *Store, phase string) (*WorkItem, *Execution) {
	t.Helper()
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	exec, _, err := s.AttachExecution(ctx, ExecutionInput{
		Mutation: as("service:mctl-agent"), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "run-1", Phase: phase,
	})
	if err != nil {
		t.Fatalf("AttachExecution: %v", err)
	}
	return w, exec
}

func TestMintAgentRunToken_StoresOnlyAHash(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w, exec := openExecution(t, s, PhaseRunning)

	row, secret, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{
		Agent: "implementer", AgentPrincipalID: "prn_agent1", ExecutionID: exec.ID,
		IssuedByPrincipalID: "prn_service1", Permissions: []string{"usage:write"},
	})
	if err != nil {
		t.Fatalf("MintAgentRunToken: %v", err)
	}
	if !strings.HasPrefix(row.ID, AgentRunTokenIDPrefix) {
		t.Errorf("row.ID = %q, want prefix %q", row.ID, AgentRunTokenIDPrefix)
	}
	if !strings.HasPrefix(secret, auth.AgentRunTokenPrefix) {
		t.Errorf("secret = %q, want prefix %q", secret, auth.AgentRunTokenPrefix)
	}
	if row.WorkItemID != w.ID {
		t.Errorf("row.WorkItemID = %q, want %q (taken from the execution)", row.WorkItemID, w.ID)
	}
	if row.ExpiresAt.Sub(row.CreatedAt) != DefaultAgentRunTokenTTL {
		t.Errorf("default ttl = %v, want %v", row.ExpiresAt.Sub(row.CreatedAt), DefaultAgentRunTokenTTL)
	}

	// No column on the row holds the plaintext or anything derived from it
	// other than the hash the query already matched.
	var count int
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM agent_run_tokens WHERE id = $1", row.ID,
	).Scan(&count); err != nil || count != 1 {
		t.Fatalf("row lookup: count=%d err=%v", count, err)
	}

	run, err := s.ResolveAgentRunToken(ctx, secret)
	if err != nil {
		t.Fatalf("ResolveAgentRunToken: %v", err)
	}
	if run.Agent != "implementer" || run.ExecutionID != exec.ID || run.WorkItemID != w.ID || run.RunID != row.ID {
		t.Fatalf("resolved run = %+v", run)
	}
	if len(run.Permissions) != 1 || run.Permissions[0] != "usage:write" {
		t.Fatalf("resolved permissions = %v", run.Permissions)
	}
}

func TestMintAgentRunToken_RefusesUnknownOrTerminalExecution(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	if _, _, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: "we_does-not-exist"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown execution: err = %v, want ErrNotFound", err)
	}

	_, exec := openExecution(t, s, PhaseSucceeded)
	if _, _, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec.ID}); !errors.Is(err, ErrExecutionTerminal) {
		t.Fatalf("terminal execution: err = %v, want ErrExecutionTerminal", err)
	}
}

func TestMintAgentRunToken_TTLBounds(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	_, exec := openExecution(t, s, PhaseRunning)

	if _, _, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{
		Agent: "implementer", ExecutionID: exec.ID, TTL: MaxAgentRunTokenTTL + time.Hour,
	}); !errors.Is(err, ErrAgentRunTokenTTL) {
		t.Fatalf("over-ceiling ttl: err = %v, want ErrAgentRunTokenTTL", err)
	}

	row, _, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec.ID, TTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("MintAgentRunToken: %v", err)
	}
	if row.ExpiresAt.Sub(row.CreatedAt) != 2*time.Hour {
		t.Errorf("ttl = %v, want 2h", row.ExpiresAt.Sub(row.CreatedAt))
	}
}

func TestResolveAgentRunToken_RefusesUnknownExpiredRevokedAndTerminal(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	if _, err := s.ResolveAgentRunToken(ctx, auth.AgentRunTokenPrefix+"nope"); !errors.Is(err, auth.ErrAgentRunNotFound) {
		t.Fatalf("unknown token: err = %v, want ErrAgentRunNotFound", err)
	}

	_, exec := openExecution(t, s, PhaseRunning)
	row, secret, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAgentRunToken(ctx, secret); err != nil {
		t.Fatalf("a fresh token must resolve: %v", err)
	}

	if err := s.RevokeAgentRunToken(ctx, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAgentRunToken(ctx, secret); !errors.Is(err, auth.ErrAgentRunNotFound) {
		t.Fatalf("revoked token: err = %v, want ErrAgentRunNotFound", err)
	}
	// Revoking twice is not an error.
	if err := s.RevokeAgentRunToken(ctx, row.ID); err != nil {
		t.Fatalf("revoking an already-revoked token must be idempotent: %v", err)
	}

	// A token whose execution has since gone terminal reads as revoked even
	// without ever calling RevokeAgentRunToken (implicit revocation).
	_, exec2 := openExecution(t, s, PhaseRunning)
	_, secret2, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec2.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{
		Mutation: as("service:mctl-agent"), WorkItemID: exec2.WorkItemID, Engine: EngineTemporal, EngineRef: "run-1", Phase: PhaseFailed,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAgentRunToken(ctx, secret2); !errors.Is(err, auth.ErrAgentRunNotFound) {
		t.Fatalf("token bound to a now-terminal execution: err = %v, want ErrAgentRunNotFound", err)
	}
}

func TestMintAgentRunToken_TwoConcurrentMintsForOneExecutionBothSucceedAndAreIndependentlyRevocable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	_, exec := openExecution(t, s, PhaseRunning)

	rowA, secretA, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec.ID})
	if err != nil {
		t.Fatal(err)
	}
	rowB, secretB, err := s.MintAgentRunToken(ctx, MintAgentRunTokenInput{Agent: "implementer", ExecutionID: exec.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rowA.ID == rowB.ID || secretA == secretB {
		t.Fatal("two mints for one execution must be distinct rows and distinct secrets")
	}

	if err := s.RevokeAgentRunToken(ctx, rowA.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAgentRunToken(ctx, secretA); !errors.Is(err, auth.ErrAgentRunNotFound) {
		t.Fatalf("revoked A: err = %v", err)
	}
	if _, err := s.ResolveAgentRunToken(ctx, secretB); err != nil {
		t.Fatalf("B must still resolve after A is revoked: %v", err)
	}
}
