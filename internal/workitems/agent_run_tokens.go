package workitems

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Agent run tokens (mctl-api#376): an execution-scoped credential that makes
// one agent run a first-class, non-admin, per-execution actor instead of the
// one static admin service principal every agent run authenticates as today.
//
// A run token binds exactly three things: the agent, the WorkItemExecution
// it was minted for, and that execution's work item. It deliberately carries
// no subject -- delegation (mctl-api#376 slice B) is a separate mechanism
// layered on top, reading a subject from a grant record it is bound to, never
// from the token itself.

// AgentRunTokenIDPrefix labels an agent run token's row id.
const AgentRunTokenIDPrefix = "art_"

// Bounds on a run token's lifetime (design.md "Execution-scoped credentials").
const (
	DefaultAgentRunTokenTTL = 1 * time.Hour
	MaxAgentRunTokenTTL     = 24 * time.Hour
)

// agentRunTokenSecretBytes is the size of the random secret half of a
// minted token, before base64url encoding.
const agentRunTokenSecretBytes = 32

// Sentinel errors specific to agent run tokens. ErrNotFound (already defined
// for work items) is reused for "no such execution".
var (
	// ErrExecutionTerminal: the named execution has already ended: no run
	// token may be minted for it.
	ErrExecutionTerminal = errors.New("execution has already ended; no run token may be minted for it")
	// ErrAgentRunTokenTTL: a requested ttl_seconds is not in (0, MaxAgentRunTokenTTL].
	ErrAgentRunTokenTTL = errors.New("ttl_seconds must be positive and at most 86400")
)

const agentRunTokenSchema = `
CREATE TABLE IF NOT EXISTS agent_run_tokens (
    id                     TEXT PRIMARY KEY,
    token_hash             BYTEA NOT NULL UNIQUE,
    agent                  TEXT NOT NULL,
    agent_principal_id     TEXT NOT NULL DEFAULT '',
    execution_id           TEXT NOT NULL,
    work_item_id           TEXT NOT NULL,
    permissions            TEXT[] NOT NULL DEFAULT '{}',
    issued_by_principal_id TEXT NOT NULL DEFAULT '',
    created_at             TIMESTAMPTZ NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS agent_run_tokens_execution ON agent_run_tokens (execution_id);
`

// AgentRunToken is one minted run token's durable row. The plaintext secret
// is never stored and never returned again after the mint response.
type AgentRunToken struct {
	ID                  string
	Agent               string
	AgentPrincipalID    string
	ExecutionID         string
	WorkItemID          string
	Permissions         []string
	IssuedByPrincipalID string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
}

// MintAgentRunTokenInput mints one run token bound to one execution.
type MintAgentRunTokenInput struct {
	Agent               string
	AgentPrincipalID    string
	ExecutionID         string
	Permissions         []string
	TTL                 time.Duration
	IssuedByPrincipalID string
}

// MintAgentRunToken validates that ExecutionID names a non-terminal
// execution this store already holds, mints an opaque token, persists only
// its SHA-256 hash, and returns the row plus the plaintext token -- exactly
// once; it is never recoverable afterwards. WorkItemID is taken from the
// execution, never from the caller.
func (s *Store) MintAgentRunToken(ctx context.Context, in MintAgentRunTokenInput) (*AgentRunToken, string, error) {
	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultAgentRunTokenTTL
	}
	if ttl > MaxAgentRunTokenTTL {
		return nil, "", ErrAgentRunTokenTTL
	}

	var workItemID, phase string
	err := s.pool.QueryRow(ctx,
		`SELECT work_item_id, phase FROM work_item_executions WHERE id=$1`, in.ExecutionID,
	).Scan(&workItemID, &phase)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("workitems: mint agent run token: execution %s: %w", in.ExecutionID, ErrNotFound)
	}
	if err != nil {
		return nil, "", fmt.Errorf("workitems: mint agent run token: load execution: %w", err)
	}
	if IsTerminalPhase(phase) {
		return nil, "", fmt.Errorf("workitems: mint agent run token: execution %s: %w", in.ExecutionID, ErrExecutionTerminal)
	}

	secret, err := randomAgentRunSecret()
	if err != nil {
		return nil, "", fmt.Errorf("workitems: mint agent run token: generate secret: %w", err)
	}
	hash := sha256.Sum256([]byte(secret))
	now := s.now()
	row := &AgentRunToken{
		ID: AgentRunTokenIDPrefix + uuid.NewString(), Agent: in.Agent, AgentPrincipalID: in.AgentPrincipalID,
		ExecutionID: in.ExecutionID, WorkItemID: workItemID, Permissions: append([]string(nil), in.Permissions...),
		IssuedByPrincipalID: in.IssuedByPrincipalID, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if row.Permissions == nil {
		row.Permissions = []string{}
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO agent_run_tokens
			(id, token_hash, agent, agent_principal_id, execution_id, work_item_id, permissions,
			 issued_by_principal_id, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		row.ID, hash[:], row.Agent, row.AgentPrincipalID, row.ExecutionID, row.WorkItemID, row.Permissions,
		row.IssuedByPrincipalID, row.CreatedAt, row.ExpiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("workitems: mint agent run token: insert: %w", err)
	}
	return row, secret, nil
}

// randomAgentRunSecret returns a fresh plaintext bearer secret, prefixed so
// auth.Middleware can route to it ahead of every other credential shape.
func randomAgentRunSecret() (string, error) {
	buf := make([]byte, agentRunTokenSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return auth.AgentRunTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// ResolveAgentRunToken authenticates a presented bearer secret: it hashes
// the secret, looks up the row by its unique token_hash, and joins the bound
// execution so a terminal phase reads as revoked even when revoked_at was
// never explicitly set. Implements auth.AgentRunResolver.
//
// Every failure -- unknown hash, explicit revocation, expiry, or a terminal
// execution -- answers auth.ErrAgentRunNotFound, never a more specific
// reason: which one it was is not something a caller presenting a bad
// token should be able to distinguish.
func (s *Store) ResolveAgentRunToken(ctx context.Context, token string) (*auth.AgentRun, error) {
	hash := sha256.Sum256([]byte(token))
	var (
		id, agent, executionID, workItemID string
		permissions                        []string
		expiresAt                          time.Time
		revokedAt                          *time.Time
		phase                              string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT t.id, t.agent, t.execution_id, t.work_item_id, t.permissions, t.expires_at, t.revoked_at,
		        COALESCE(e.phase, '')
		 FROM agent_run_tokens t
		 LEFT JOIN work_item_executions e ON e.id = t.execution_id
		 WHERE t.token_hash = $1`,
		hash[:],
	).Scan(&id, &agent, &executionID, &workItemID, &permissions, &expiresAt, &revokedAt, &phase)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrAgentRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: resolve agent run token: %w", err)
	}
	if revokedAt != nil {
		return nil, auth.ErrAgentRunNotFound
	}
	if !expiresAt.After(s.now()) {
		return nil, auth.ErrAgentRunNotFound
	}
	// phase == "" is a dangling execution_id (the execution's work item was
	// deleted out from under it); treated the same as a terminal phase.
	if phase == "" || IsTerminalPhase(phase) {
		return nil, auth.ErrAgentRunNotFound
	}
	return &auth.AgentRun{
		Agent: agent, ExecutionID: executionID, WorkItemID: workItemID, RunID: id,
		Permissions: append([]string(nil), permissions...),
	}, nil
}

// RevokeAgentRunToken marks one run token revoked. Idempotent: revoking an
// already-revoked or unknown token is not an error, since the caller's goal
// (the token no longer authenticates) already holds.
func (s *Store) RevokeAgentRunToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_run_tokens SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, s.now())
	if err != nil {
		return fmt.Errorf("workitems: revoke agent run token: %w", err)
	}
	return nil
}

// PurgeExpiredAgentRunTokens deletes run tokens that expired more than grace
// ago, and returns how many rows were removed. Short-lived rows: safe to run
// on the same retention schedule as any other sweep.
func (s *Store) PurgeExpiredAgentRunTokens(ctx context.Context, grace time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM agent_run_tokens WHERE expires_at < $1`, s.now().Add(-grace))
	if err != nil {
		return 0, fmt.Errorf("workitems: purge agent run tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
