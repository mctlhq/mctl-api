// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// Command statuses and effect states (CHECK-constrained in bridgeSchema).
const (
	StatusPending   = "pending"
	StatusLeased    = "leased"
	StatusCompleted = "completed"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"

	EffectNone         = "none"
	EffectPermitted    = "permitted"
	EffectSucceeded    = "succeeded"
	EffectFailed       = "failed"
	EffectNotPerformed = "not_performed"
	EffectUnknown      = "unknown"

	// Command kinds of the v1alpha1 schema.
	KindQuote          = "quote"
	KindReadStatus     = "read_status"
	KindPlaceOrderFake = "place_order_fake"
	KindCancelOrder    = "cancel_order_fake"

	DefaultTTL      = 600 * time.Second
	MaxTTL          = 900 * time.Second
	DefaultLeaseTTL = 60 * time.Second
	MaxClaimBatch   = 10

	DefaultExpiryBatch = 100
)

// bridgeSchema is applied on every start, like commerceSchema. It is purely
// additive; nothing existing is altered.
const bridgeSchema = `
CREATE TABLE IF NOT EXISTS bridge_commands (
    command_id         TEXT        PRIMARY KEY,
    execution_id       TEXT        NOT NULL,
    work_item_id       TEXT        NOT NULL,
    workflow_id        TEXT        NOT NULL,
    run_id             TEXT        NOT NULL DEFAULT '',
    tenant             TEXT        NOT NULL,
    owner_principal_id TEXT        NOT NULL,
    tenant_ref         TEXT        NOT NULL,
    principal_ref      TEXT        NOT NULL,
    order_ref          TEXT        NOT NULL,
    connection_ref     TEXT        NOT NULL,
    install_revision   TEXT        NOT NULL,
    provider_ref       TEXT        NOT NULL,
    operation_kind     TEXT        NOT NULL,
    attempt            INTEGER     NOT NULL,
    intent_hash        TEXT        NOT NULL,
    approval_ref       TEXT        NOT NULL DEFAULT '',
    operation_key      TEXT        NOT NULL,
    sequence           BIGINT      NOT NULL,
    payload            JSONB       NOT NULL,
    payload_digest     TEXT        NOT NULL,
    status             TEXT        NOT NULL DEFAULT 'pending',
    cancel_requested   BOOLEAN     NOT NULL DEFAULT false,
    command_nonce      TEXT        NOT NULL,
    lease_nonce        TEXT        NOT NULL DEFAULT '',
    lease_id           TEXT        NOT NULL DEFAULT '',
    lease_epoch        BIGINT      NOT NULL DEFAULT 0,
    lease_token        TEXT        NOT NULL DEFAULT '',
    leased_by          TEXT        NOT NULL DEFAULT '',
    lease_expires_at   TIMESTAMPTZ,
    ttl_seconds        INTEGER     NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    result_digest      TEXT        NOT NULL DEFAULT '',
    result             JSONB,
    effect_state       TEXT        NOT NULL DEFAULT 'none',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT bridge_commands_status_chk CHECK (status IN ('pending','leased','completed','cancelled','expired')),
    CONSTRAINT bridge_commands_effect_chk CHECK (effect_state IN ('none','permitted','succeeded','failed','not_performed','unknown')),
    CONSTRAINT bridge_commands_kind_chk CHECK (operation_kind IN ('quote','read_status','place_order_fake','cancel_order_fake')),
    CONSTRAINT bridge_commands_ttl_chk CHECK (ttl_seconds BETWEEN 1 AND 900),
    CONSTRAINT bridge_commands_approval_chk CHECK (operation_kind NOT IN ('place_order_fake','cancel_order_fake') OR approval_ref <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS bridge_commands_operation_key
    ON bridge_commands (tenant, execution_id, operation_key);
CREATE UNIQUE INDEX IF NOT EXISTS bridge_commands_sequence
    ON bridge_commands (execution_id, sequence);
CREATE INDEX IF NOT EXISTS bridge_commands_claimable
    ON bridge_commands (provider_ref, status, created_at);
CREATE INDEX IF NOT EXISTS bridge_commands_expiry
    ON bridge_commands (expires_at) WHERE status IN ('pending','leased');

CREATE TABLE IF NOT EXISTS bridge_command_transitions (
    id           BIGSERIAL   PRIMARY KEY,
    command_id   TEXT        NOT NULL,
    from_status  TEXT        NOT NULL,
    to_status    TEXT        NOT NULL,
    lease_epoch  BIGINT      NOT NULL DEFAULT 0,
    actor        TEXT        NOT NULL DEFAULT '',
    digest       TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS bridge_command_transitions_cmd
    ON bridge_command_transitions (command_id, id);

CREATE TABLE IF NOT EXISTS bridge_signal_outbox (
    command_id      TEXT        PRIMARY KEY,
    workflow_id     TEXT        NOT NULL,
    run_id          TEXT        NOT NULL DEFAULT '',
    result_digest   TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'pending',
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error_code TEXT        NOT NULL DEFAULT '',
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ,
    CONSTRAINT bridge_signal_outbox_status_chk CHECK (status IN ('pending','sent','unknown'))
);
CREATE INDEX IF NOT EXISTS bridge_signal_outbox_due
    ON bridge_signal_outbox (next_attempt_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS bridge_write_permits (
    command_id    TEXT        PRIMARY KEY,
    operation_key TEXT        NOT NULL,
    approval_ref  TEXT        NOT NULL,
    fence_ref     TEXT        NOT NULL,
    lease_epoch   BIGINT      NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE bridge_write_permits DROP CONSTRAINT IF EXISTS bridge_write_permits_operation_key;
`

var (
	refPatterns = map[string]*regexp.Regexp{
		"execution_id":   regexp.MustCompile(`^we_[A-Za-z0-9]{16,40}$`),
		"work_item_id":   regexp.MustCompile(`^wi_[A-Za-z0-9]{16,40}$`),
		"tenant_ref":     regexp.MustCompile(`^tnr_[A-Za-z0-9]{16,40}$`),
		"principal_ref":  regexp.MustCompile(`^prr_[A-Za-z0-9]{16,40}$`),
		"order_ref":      regexp.MustCompile(`^ordr_[A-Za-z0-9]{16,40}$`),
		"connection_ref": regexp.MustCompile(`^gcn_[A-Za-z0-9]{16,40}$`),
		"approval_ref":   regexp.MustCompile(`^aar_[A-Za-z0-9]{16,40}$`),
		"intent_hash":    regexp.MustCompile(`^sha256:[0-9a-f]{64}$`),
		"provider_ref":   regexp.MustCompile(`^[a-z0-9-]{1,32}$`),
	}
	commandIDPattern = regexp.MustCompile(`^cmd_[A-Za-z0-9]{26}$`)
)

// IsCommandID reports whether s is a well-formed command id.
func IsCommandID(s string) bool { return commandIDPattern.MatchString(s) }

// Caller is the authenticated bridge-provider principal. ProviderRef and
// Tenants come from server-side configuration, never from a request body.
// Tenants is only an upper bound; the tenant and owner of a command are
// always read from its stored row.
//
// Versions is the closed set of wire versions the provider's server-side
// configuration declares. Nil or empty means [WireV1alpha1]; a provider is
// never trusted to filter what it is leased.
type Caller struct {
	ProviderRef string
	Actor       string
	Tenants     []string
	Versions    []string
}

// wireVersions is the effective, never-empty list of Versions.
func (c Caller) wireVersions() []string {
	if len(c.Versions) == 0 {
		return []string{WireV1alpha1}
	}
	return c.Versions
}

// SupportsV1alpha2 reports whether the provider declares the v1alpha2 wire
// version, which also selects the claim/v1alpha2 envelope.
func (c Caller) SupportsV1alpha2() bool {
	for _, v := range c.Versions {
		if v == WireV1alpha2 {
			return true
		}
	}
	return false
}

// ClaimEnvelopeVersion is the envelope schema_version of the claim response
// for this caller.
func (c Caller) ClaimEnvelopeVersion() string {
	if c.SupportsV1alpha2() {
		return ClaimEnvelopeV1alpha2
	}
	return SchemaVersion
}

func (c Caller) allowsTenant(tenant string) bool {
	if len(c.Tenants) == 0 {
		return false
	}
	for _, t := range c.Tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// EnqueueInput is everything a control-plane caller supplies. It has no field
// for an endpoint URL, a token or a session: workflow and run ids come from
// the server-created execution record the control code passes in.
type EnqueueInput struct {
	ExecutionID      string
	WorkItemID       string
	WorkflowID       string
	RunID            string
	Tenant           string
	OwnerPrincipalID string
	TenantRef        string
	PrincipalRef     string
	OrderRef         string
	ConnectionRef    string
	InstallRevision  string
	ProviderRef      string
	Kind             string
	Attempt          int
	IntentHash       string
	ApprovalRef      string
	OperationKey     string
	Sequence         int64
	Payload          json.RawMessage
	TTL              time.Duration
	// WireVersion is "" or WireV1alpha1 (v1alpha1) or WireV1alpha2. v1alpha2 is
	// accepted only for place_order_fake (mctl-agents#1059 write command) on a
	// store with wire versions enabled; read kinds go through EnqueueRead.
	WireVersion string
}

func (in *EnqueueInput) validate() error {
	for name, v := range map[string]string{
		"execution_id": in.ExecutionID, "work_item_id": in.WorkItemID, "tenant_ref": in.TenantRef,
		"principal_ref": in.PrincipalRef, "order_ref": in.OrderRef, "connection_ref": in.ConnectionRef,
		"intent_hash": in.IntentHash, "provider_ref": in.ProviderRef,
	} {
		if !refPatterns[name].MatchString(v) {
			return fmt.Errorf("%w: %s is malformed", ErrInvalidInput, name)
		}
	}
	if in.WorkflowID == "" || in.Tenant == "" || in.OwnerPrincipalID == "" || in.OperationKey == "" || in.InstallRevision == "" {
		return fmt.Errorf("%w: workflow_id, tenant, owner, operation_key and install_revision are required", ErrInvalidInput)
	}
	if in.Attempt < 1 || in.Attempt > 100 || in.Sequence < 0 {
		return fmt.Errorf("%w: attempt or sequence out of range", ErrInvalidInput)
	}
	switch in.Kind {
	case KindQuote, KindReadStatus:
		if in.ApprovalRef != "" && !refPatterns["approval_ref"].MatchString(in.ApprovalRef) {
			return fmt.Errorf("%w: approval_ref is malformed", ErrInvalidInput)
		}
	case KindPlaceOrderFake, KindCancelOrder:
		if !refPatterns["approval_ref"].MatchString(in.ApprovalRef) {
			return fmt.Errorf("%w: a mutating command needs an aar_ approval_ref", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unknown kind", ErrInvalidInput)
	}
	if in.TTL < 0 || in.TTL > MaxTTL {
		return fmt.Errorf("%w: ttl out of range", ErrInvalidInput)
	}
	switch in.WireVersion {
	case "", WireV1alpha1:
	case WireV1alpha2:
		if in.Kind != KindPlaceOrderFake || !refPatterns["approval_ref"].MatchString(in.ApprovalRef) {
			return fmt.Errorf("%w: wire version v1alpha2 is only for place_order_fake with an approval_ref", ErrInvalidDocument)
		}
	default:
		return fmt.Errorf("%w: unknown wire version", ErrInvalidDocument)
	}
	return nil
}

// cmdRow is a bridge_commands row, private to the package.
type cmdRow struct {
	CommandID, ExecutionID, WorkItemID, WorkflowID, RunID, Tenant, OwnerPrincipalID string
	TenantRef, PrincipalRef, OrderRef, ConnectionRef, InstallRevision               string
	ProviderRef, Kind                                                               string
	Attempt                                                                         int
	IntentHash, ApprovalRef, OperationKey                                           string
	Sequence                                                                        int64
	Payload                                                                         json.RawMessage
	PayloadDigest, Status                                                           string
	CancelRequested                                                                 bool
	CommandNonce, LeaseNonce, LeaseID                                               string
	LeaseEpoch                                                                      int64
	LeaseToken, LeasedBy                                                            string
	LeaseExpiresAt                                                                  *time.Time
	TTLSeconds                                                                      int
	ExpiresAt                                                                       time.Time
	ResultDigest                                                                    string
	EffectState                                                                     string
	CreatedAt                                                                       time.Time

	// Extras of the v1alpha2 columns. They are filled only by loadExtras, for
	// read kinds and, on a store with wire versions enabled, for
	// place_order_fake; every other row is wire v1alpha1 with no extras.
	WireVersion, ReadRequestID, InstallRevisionRef string
}

const cmdCols = `command_id, execution_id, work_item_id, workflow_id, run_id, tenant, owner_principal_id,
	tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
	attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, status,
	cancel_requested, command_nonce, lease_nonce, lease_id, lease_epoch, lease_token, leased_by,
	lease_expires_at, ttl_seconds, expires_at, result_digest, effect_state, created_at`

func scanCmd(row pgx.Row) (*cmdRow, error) {
	var c cmdRow
	err := row.Scan(&c.CommandID, &c.ExecutionID, &c.WorkItemID, &c.WorkflowID, &c.RunID, &c.Tenant, &c.OwnerPrincipalID,
		&c.TenantRef, &c.PrincipalRef, &c.OrderRef, &c.ConnectionRef, &c.InstallRevision, &c.ProviderRef, &c.Kind,
		&c.Attempt, &c.IntentHash, &c.ApprovalRef, &c.OperationKey, &c.Sequence, &c.Payload, &c.PayloadDigest, &c.Status,
		&c.CancelRequested, &c.CommandNonce, &c.LeaseNonce, &c.LeaseID, &c.LeaseEpoch, &c.LeaseToken, &c.LeasedBy,
		&c.LeaseExpiresAt, &c.TTLSeconds, &c.ExpiresAt, &c.ResultDigest, &c.EffectState, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// commandDoc is the outward v1alpha1 command projection. It deliberately has
// no field for lease_id, lease_epoch, the private lease_nonce, operation_key,
// tenant name, owner, install revision or workflow ids. The required "nonce"
// is the server-generated command nonce, distinct from the private lease
// nonce.
type commandDoc struct {
	SchemaVersion   string          `json:"schema_version"`
	CommandID       string          `json:"command_id"`
	ExecutionID     string          `json:"execution_id"`
	WorkItemID      string          `json:"work_item_id"`
	Kind            string          `json:"kind"`
	Attempt         int             `json:"attempt"`
	TenantRef       string          `json:"tenant_ref"`
	PrincipalRef    string          `json:"principal_ref"`
	OrderRef        string          `json:"order_ref"`
	ConnectionRef   string          `json:"connection_ref"`
	ApprovalRef     string          `json:"approval_ref,omitempty"`
	IntentHash      string          `json:"intent_hash"`
	Issuer          string          `json:"issuer"`
	Audience        string          `json:"audience"`
	Nonce           string          `json:"nonce"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	TTLSeconds      int             `json:"ttl_seconds"`
	LeaseToken      string          `json:"lease_token,omitempty"`
	CancelRequested bool            `json:"cancel_requested"`
	Payload         json.RawMessage `json:"payload"`
}

func (c *cmdRow) projection(withLease bool) ([]byte, error) {
	if IsReadKind(c.Kind) {
		return c.readProjection(withLease)
	}
	version, v2 := SchemaVersion, c.WireVersion == WireV1alpha2
	if v2 {
		version = WireV1alpha2
	}
	d := commandDoc{
		SchemaVersion: version, CommandID: c.CommandID, ExecutionID: c.ExecutionID, WorkItemID: c.WorkItemID,
		Kind: c.Kind, Attempt: c.Attempt, TenantRef: c.TenantRef, PrincipalRef: c.PrincipalRef, OrderRef: c.OrderRef,
		ConnectionRef: c.ConnectionRef, ApprovalRef: c.ApprovalRef, IntentHash: c.IntentHash, Issuer: "mctl-api",
		Audience: "provider:" + c.ProviderRef, Nonce: c.CommandNonce,
		IssuedAt: c.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: c.ExpiresAt.UTC().Format(time.RFC3339),
		TTLSeconds: c.TTLSeconds, CancelRequested: c.CancelRequested, Payload: c.Payload,
	}
	if withLease {
		d.LeaseToken = c.LeaseToken
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	validate := ValidateCommand
	if v2 {
		validate = ValidateWriteV2Command
	}
	if err := validate(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// readCommandDoc is the outward v1alpha2 read command projection: the #1059
// read binding set and no order, execution, work item or workflow field.
type readCommandDoc struct {
	SchemaVersion      string          `json:"schema_version"`
	CommandID          string          `json:"command_id"`
	RequestID          string          `json:"request_id"`
	Kind               string          `json:"kind"`
	Attempt            int             `json:"attempt"`
	TenantRef          string          `json:"tenant_ref"`
	PrincipalRef       string          `json:"principal_ref"`
	ConnectionRef      string          `json:"connection_ref"`
	InstallRevisionRef string          `json:"install_revision_ref"`
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	Nonce              string          `json:"nonce"`
	IssuedAt           string          `json:"issued_at"`
	ExpiresAt          string          `json:"expires_at"`
	TTLSeconds         int             `json:"ttl_seconds"`
	LeaseToken         string          `json:"lease_token,omitempty"`
	Params             json.RawMessage `json:"params"`
}

func (c *cmdRow) readProjection(withLease bool) ([]byte, error) {
	d := readCommandDoc{
		SchemaVersion: WireV1alpha2, CommandID: c.CommandID, RequestID: c.ReadRequestID, Kind: c.Kind, Attempt: c.Attempt,
		TenantRef: c.TenantRef, PrincipalRef: c.PrincipalRef, ConnectionRef: c.ConnectionRef,
		InstallRevisionRef: c.InstallRevisionRef, Issuer: "mctl-api", Audience: "provider:" + c.ProviderRef,
		Nonce: c.CommandNonce, IssuedAt: c.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: c.ExpiresAt.UTC().Format(time.RFC3339), TTLSeconds: c.TTLSeconds, Params: c.Payload,
	}
	if withLease {
		d.LeaseToken = c.LeaseToken
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if err := ValidateReadCommand(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// needsExtras reports whether a row of kind carries the v1alpha2 columns that
// loadExtras must read. cmdCols/scanCmd never mention them, so a database that
// never ran the migrator keeps a working v1alpha1 bridge.
func (s *Store) needsExtras(kind string) bool {
	return IsReadKind(kind) || (kind == KindPlaceOrderFake && s.WireVersionsEnabled())
}

// loadExtras reads wire_version, read_request_id and install_revision_ref of
// row, when the row's kind needs them.
func (s *Store) loadExtras(ctx context.Context, q Querier, row *cmdRow) error {
	if !s.needsExtras(row.Kind) {
		return nil
	}
	err := q.QueryRow(ctx, `SELECT wire_version, COALESCE(read_request_id,''), COALESCE(install_revision_ref,'')
		FROM bridge_commands WHERE command_id=$1`, row.CommandID).Scan(&row.WireVersion, &row.ReadRequestID, &row.InstallRevisionRef)
	if err != nil {
		return fmt.Errorf("bridge: read extras: %w", err)
	}
	return nil
}

// Store is the bridge store.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time

	releaseOnce sync.Once
	mu          sync.RWMutex
	fence       WriteFence

	wireEnabled atomic.Bool
	readTTL     atomic.Int64 // seconds; 0 means DefaultReadResultTTL
	checker     ConnectionChecker
	erased      atomic.Int64
}

// NewStore connects and applies the additive schema.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("bridge: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("bridge: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, bridgeSchema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("bridge: schema: %w", err)
	}
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }, fence: refusingFence{}}, nil
}

// OpenExistingStore opens a previously migrated bridge database for explicit
// maintenance only. Unlike NewStore, it never executes DDL or attempts to
// bootstrap schema/indexes. This permits a least-privilege maintenance role.
func OpenExistingStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("bridge: maintenance connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("bridge: maintenance ping: %w", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('bridge_commands') IS NOT NULL").Scan(&exists); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("bridge: maintenance schema check: %w", err)
	}
	if !exists {
		pgshared.Release(pool)
		return nil, fmt.Errorf("bridge: maintenance schema missing; migrate before scrubbing")
	}
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }, fence: refusingFence{}}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.releaseOnce.Do(func() { pgshared.Release(s.pool) })
	}
}

// Pool exposes the pool so a control-plane caller can open the transaction it
// passes to Enqueue.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// SetFence installs the #954 physical-write fence. The default refuses every
// permit.
func (s *Store) SetFence(f WriteFence) {
	if f == nil {
		f = refusingFence{}
	}
	s.mu.Lock()
	s.fence = f
	s.mu.Unlock()
}

func (s *Store) currentFence() WriteFence {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fence
}

const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randAlnum(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < 248 { // 248 = 62*4: no modulo bias
				out = append(out, base62[int(b)%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}

func randURL(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func addTransition(ctx context.Context, tx pgx.Tx, id, from, to string, epoch int64, actor, digest string) error {
	_, err := tx.Exec(ctx, `INSERT INTO bridge_command_transitions (command_id, from_status, to_status, lease_epoch, actor, digest)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, from, to, epoch, actor, digest)
	return err
}

// Enqueue inserts a pending command in the caller's transaction, so the
// command and the caller's state change commit or roll back together. It is
// idempotent on (tenant, execution_id, operation_key): a repeat returns the
// existing command id with created=false. The outward projection is validated
// against the vendored schema before anything is written.
func (s *Store) Enqueue(ctx context.Context, tx pgx.Tx, in EnqueueInput) (commandID string, created bool, err error) {
	if err := in.validate(); err != nil {
		return "", false, err
	}
	v2Write := in.WireVersion == WireV1alpha2
	if v2Write && !s.WireVersionsEnabled() {
		return "", false, fmt.Errorf("%w: wire versions are not enabled", ErrReadUnavailable)
	}
	if v2Write {
		// The v1alpha2 place_order_fake payload is the approval basket itself.
		if _, err := checkBasketRules(in.Payload); err != nil {
			return "", false, err
		}
	}
	var existing string
	switch err := tx.QueryRow(ctx, `SELECT command_id FROM bridge_commands WHERE tenant=$1 AND execution_id=$2 AND operation_key=$3`,
		in.Tenant, in.ExecutionID, in.OperationKey).Scan(&existing); {
	case err == nil:
		return existing, false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, fmt.Errorf("bridge: enqueue lookup: %w", err)
	}
	suffix, err := randAlnum(26)
	if err != nil {
		return "", false, fmt.Errorf("bridge: id: %w", err)
	}
	nonce, err := randURL(16)
	if err != nil {
		return "", false, fmt.Errorf("bridge: nonce: %w", err)
	}
	payload := in.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	now := s.now()
	row := &cmdRow{
		CommandID: "cmd_" + suffix, ExecutionID: in.ExecutionID, WorkItemID: in.WorkItemID, TenantRef: in.TenantRef,
		PrincipalRef: in.PrincipalRef, OrderRef: in.OrderRef, ConnectionRef: in.ConnectionRef, ProviderRef: in.ProviderRef,
		Kind: in.Kind, Attempt: in.Attempt, IntentHash: in.IntentHash, ApprovalRef: in.ApprovalRef, CommandNonce: nonce,
		CreatedAt: now, ExpiresAt: now.Add(ttl), TTLSeconds: int(ttl / time.Second), Payload: payload,
	}
	if v2Write {
		row.WireVersion = WireV1alpha2
	}
	if row.TTLSeconds < 1 {
		return "", false, fmt.Errorf("%w: ttl out of range", ErrInvalidInput)
	}
	// Validate before writing: a payload the schema refuses never enters the outbox.
	if _, err := row.projection(false); err != nil {
		return "", false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO bridge_commands (command_id, execution_id, work_item_id, workflow_id, run_id, tenant,
		owner_principal_id, tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
		attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, command_nonce, ttl_seconds,
		expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$25)`,
		row.CommandID, in.ExecutionID, in.WorkItemID, in.WorkflowID, in.RunID, in.Tenant, in.OwnerPrincipalID,
		in.TenantRef, in.PrincipalRef, in.OrderRef, in.ConnectionRef, in.InstallRevision, in.ProviderRef, in.Kind,
		in.Attempt, in.IntentHash, in.ApprovalRef, in.OperationKey, in.Sequence, []byte(payload), sha256Hex(payload),
		nonce, row.TTLSeconds, row.ExpiresAt, now)
	if err != nil {
		return "", false, fmt.Errorf("bridge: enqueue insert: %w", err)
	}
	if v2Write {
		if _, err := tx.Exec(ctx, `UPDATE bridge_commands SET wire_version=$2 WHERE command_id=$1`, row.CommandID, WireV1alpha2); err != nil {
			return "", false, fmt.Errorf("bridge: enqueue wire version: %w", err)
		}
	}
	if err := addTransition(ctx, tx, row.CommandID, "", StatusPending, 0, "control", ""); err != nil {
		return "", false, fmt.Errorf("bridge: enqueue transition: %w", err)
	}
	return row.CommandID, true, nil
}

func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	return s.pool.BeginTx(ctx, pgx.TxOptions{})
}

// finish commits when err is nil and rolls back otherwise, so a refusal never
// leaves a partial write.
func finish(ctx context.Context, tx pgx.Tx, err error) error {
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return fmt.Errorf("bridge: commit: %w", cerr)
	}
	return nil
}

// Claimed is one leased command: the strict v1alpha1 projection including the
// opaque lease token.
type Claimed struct {
	CommandID string
	Command   json.RawMessage
}

// Claim leases up to max due commands of the caller's provider. Selection is
// scoped by provider_ref and tenant upper bound; an expired lease is
// reclaimed under epoch+1 with a rotated private nonce and a new token, which
// fences the previous holder. Commands past expires_at are marked expired
// first. A command is claimable only when no earlier sequence of the same
// execution is still open.
func (s *Store) Claim(ctx context.Context, c Caller, max int, leaseTTL time.Duration) ([]Claimed, error) {
	if c.ProviderRef == "" || len(c.Tenants) == 0 {
		return nil, nil
	}
	if max < 1 || max > MaxClaimBatch {
		max = MaxClaimBatch
	}
	if leaseTTL <= 0 || leaseTTL > MaxTTL {
		leaseTTL = DefaultLeaseTTL
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge: claim begin: %w", err)
	}
	out, err := s.claimTx(ctx, tx, c, max, leaseTTL)
	if err := finish(ctx, tx, err); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) claimTx(ctx context.Context, tx pgx.Tx, c Caller, max int, leaseTTL time.Duration) ([]Claimed, error) {
	// Lazy expiry, scoped to the caller's provider and tenants.
	if _, err := s.expireTx(ctx, tx, c.ProviderRef, c.Tenants, 0, "system"); err != nil {
		return nil, err
	}

	// Three cases, all a predicate of the selection (never a filter on its
	// result, so gated rows cannot fill the batch and starve a claimable
	// v1alpha1 command):
	//  1. wire versions enabled: wire_version = ANY($4), the versions the
	//     caller supports;
	//  2. disabled, but the read schema level is present (rolling deploy or a
	//     failed enable): pinned to wire_version = 'v1alpha1', so a stored
	//     v1alpha2 row is never leased as a plain command and read kinds are
	//     never selected;
	//  3. disabled and no read level: the statement mentions no v1alpha2
	//     column and excludes the read kinds.
	gate, args := ` AND c.operation_kind NOT IN ('read_history','read_preview','read_basket')`, []any{c.ProviderRef, c.Tenants, max}
	if s.WireVersionsEnabled() {
		gate, args = ` AND c.wire_version = ANY($4)`, append(args, c.wireVersions())
	} else if CheckReadLevel(ctx, tx) == nil {
		// The v1alpha2 columns exist although this process has not enabled
		// wire versions (rolling deploy, or a failed enable). Never lease a
		// stored v1alpha2 row as a plain v1alpha1 command.
		gate = ` AND c.wire_version = '` + WireV1alpha1 + `'`
	}
	idRows, err := tx.Query(ctx, `SELECT c.command_id, c.status FROM bridge_commands c
		WHERE c.provider_ref=$1 AND c.tenant = ANY($2) AND c.expires_at > now()
		  AND (c.status='pending' OR (c.status='leased' AND c.lease_expires_at <= now()))`+gate+`
		  AND NOT EXISTS (SELECT 1 FROM bridge_commands p WHERE p.execution_id=c.execution_id
		                  AND p.sequence < c.sequence AND p.status IN ('pending','leased'))
		ORDER BY c.created_at, c.sequence LIMIT $3
		FOR UPDATE OF c SKIP LOCKED`, args...)
	if err != nil {
		return nil, fmt.Errorf("bridge: claim select: %w", err)
	}
	type leaseTarget struct{ id, status string }
	var ids []leaseTarget
	for idRows.Next() {
		var id leaseTarget
		if err := idRows.Scan(&id.id, &id.status); err != nil {
			idRows.Close()
			return nil, fmt.Errorf("bridge: claim scan: %w", err)
		}
		ids = append(ids, id)
	}
	idRows.Close()
	if err := idRows.Err(); err != nil {
		return nil, fmt.Errorf("bridge: claim select: %w", err)
	}

	var out []Claimed
	for _, target := range ids {
		id := target.id
		token, err := randURL(24)
		if err != nil {
			return nil, err
		}
		nonce, err := randURL(24)
		if err != nil {
			return nil, err
		}
		leaseID, err := randURL(16)
		if err != nil {
			return nil, err
		}
		row, err := scanCmd(tx.QueryRow(ctx, `UPDATE bridge_commands SET
				status='leased', lease_epoch=lease_epoch+1,
				effect_state=CASE WHEN effect_state='permitted' THEN 'unknown' ELSE effect_state END, lease_nonce=$2, lease_id=$3, lease_token=$4, leased_by=$5,
				lease_expires_at=LEAST(now() + ($6 * interval '1 second'), expires_at), updated_at=now()
			WHERE command_id=$1 RETURNING `+cmdCols, id, nonce, leaseID, "lt_"+token, c.Actor, int(leaseTTL/time.Second)))
		if err != nil {
			return nil, fmt.Errorf("bridge: claim lease: %w", err)
		}
		if err := s.loadExtras(ctx, tx, row); err != nil {
			return nil, err
		}
		doc, err := row.projection(true)
		if err != nil {
			return nil, err
		}
		if err := addTransition(ctx, tx, id, target.status, StatusLeased, row.LeaseEpoch, c.Actor, ""); err != nil {
			return nil, err
		}
		out = append(out, Claimed{CommandID: id, Command: doc})
	}
	return out, nil
}

// lockOwned locks the command row and returns it, or ErrCommandNotFound when
// it does not exist, belongs to another provider or sits in a tenant outside
// the caller's configured upper bound. The three cases are indistinguishable
// to the caller.
func (s *Store) lockOwned(ctx context.Context, tx pgx.Tx, c Caller, id string) (*cmdRow, error) {
	row, err := scanCmd(tx.QueryRow(ctx, `SELECT `+cmdCols+` FROM bridge_commands WHERE command_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("bridge: lock command: %w", err)
	}
	if row.ProviderRef != c.ProviderRef || !c.allowsTenant(row.Tenant) {
		return nil, ErrCommandNotFound
	}
	if err := s.loadExtras(ctx, tx, row); err != nil {
		return nil, err
	}
	return row, nil
}

func tokenEqual(stored, presented string) bool {
	return stored != "" && subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// leaseLive checks that row is leased under presented token and the lease has
// not run out. It does not read the clock for completed rows.
//
// Precedence: cancelled > stored-expired > not leased (stale) > wrong token
// (stale) > command TTL elapsed (expired) > lease deadline elapsed (stale).
// The token is checked before the TTL so a non-holder cannot probe a command's
// TTL state. A row still stored as leased whose TTL has passed (the sweep only
// runs inside Claim) is reported as expired, not stale.
func (s *Store) leaseLive(row *cmdRow, token string) error {
	switch row.Status {
	case StatusCancelled:
		return ErrCommandCancelled
	case StatusExpired:
		return ErrCommandExpired
	case StatusPending, StatusCompleted:
		return ErrLeaseStale
	}
	if !tokenEqual(row.LeaseToken, token) {
		return ErrLeaseStale
	}
	now := s.now()
	if !row.ExpiresAt.After(now) {
		return ErrCommandExpired
	}
	if row.LeaseExpiresAt == nil || !row.LeaseExpiresAt.After(now) {
		return ErrLeaseStale
	}
	return nil
}

// SubmitOutcome is the answer to a result submission.
type SubmitOutcome struct {
	CommandID    string
	Status       string
	EffectState  string
	ResultDigest string
	Replayed     bool
	// ResultRef is the server-minted res_ of a stored read result; empty for
	// every other command.
	ResultRef string
}

func effectFor(r *Result, prior string) string {
	switch r.ProviderEffect {
	case "applied":
		return EffectSucceeded
	case "unknown":
		return EffectUnknown
	}
	if prior == EffectUnknown {
		// A reclaimed lease may hide a write the previous holder performed.
		return EffectUnknown
	}
	if r.Outcome == "approval_refused" || prior == EffectPermitted {
		return EffectNotPerformed
	}
	return EffectNone
}

// SubmitResult records a provider result exactly once. The body is validated
// against the unchanged v1alpha1 result schema; every private binding (lease
// epoch, nonce, tenant, owner, operation key) is read from the stored row,
// never from the body. The state change is a compare-and-set on status,
// lease epoch and private nonce, and the signal-outbox row is written in the
// same transaction. A replay of the same server-computed digest returns the
// stored outcome; a different digest after completion is result_conflict.
func (s *Store) SubmitResult(ctx context.Context, c Caller, commandID string, body []byte) (*SubmitOutcome, error) {
	// ParseResult selects the schema by the document's schema_version, so a
	// document that fails its own version's schema is invalid_document before
	// any binding check.
	doc, err := parseAnyResult(body)
	if err != nil {
		return nil, err
	}
	if doc.v2 != nil {
		return s.submitReadResult(ctx, c, commandID, doc.v2)
	}
	res := doc.v1
	if res.SchemaVersion != SchemaVersion || res.CommandID != commandID {
		return nil, fmt.Errorf("%w: command_id does not match the route", ErrBindingMismatch)
	}
	digest := res.Digest()
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge: result begin: %w", err)
	}
	out, err := s.submitTx(ctx, tx, c, res, digest)
	if err := finish(ctx, tx, err); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) submitTx(ctx context.Context, tx pgx.Tx, c Caller, res *Result, digest string) (*SubmitOutcome, error) {
	row, err := s.lockOwned(ctx, tx, c, res.CommandID)
	if err != nil {
		return nil, err
	}
	if IsReadKind(row.Kind) {
		// A read kind takes only its stored wire version's result.
		return nil, fmt.Errorf("%w: a read command takes a v1alpha2 result", ErrBindingMismatch)
	}
	if res.ExecutionID != row.ExecutionID || res.Attempt != row.Attempt || res.WorkerIdentity != "provider:"+row.ProviderRef {
		return nil, ErrBindingMismatch
	}
	if !tokenEqual(row.LeaseToken, res.LeaseToken) {
		return nil, ErrLeaseStale
	}
	if row.Status == StatusCompleted {
		if row.ResultDigest == digest {
			return &SubmitOutcome{CommandID: row.CommandID, Status: row.Status, EffectState: row.EffectState, ResultDigest: digest, Replayed: true}, nil
		}
		return nil, ErrResultConflict
	}
	if err := s.leaseLive(row, res.LeaseToken); err != nil {
		return nil, err
	}
	if res.Outcome == "approval_refused" && res.ProviderEffect != "none" {
		return nil, fmt.Errorf("%w: approval_refused requires provider_effect none", ErrResultInconsistent)
	}
	if res.ProviderEffect == "applied" && row.EffectState != EffectPermitted {
		return nil, fmt.Errorf("%w: an applied effect needs an issued write permit", ErrResultInconsistent)
	}
	effect := effectFor(res, row.EffectState)
	stored, err := res.redacted()
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE bridge_commands SET status='completed', result_digest=$2, result=$3, effect_state=$4, updated_at=now()
		WHERE command_id=$1 AND status='leased' AND lease_epoch=$5 AND lease_nonce=$6`,
		row.CommandID, digest, stored, effect, row.LeaseEpoch, row.LeaseNonce)
	if err != nil {
		return nil, fmt.Errorf("bridge: result cas: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrLeaseStale
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bridge_signal_outbox (command_id, workflow_id, run_id, result_digest)
		VALUES ($1,$2,$3,$4)`, row.CommandID, row.WorkflowID, row.RunID, digest); err != nil {
		return nil, fmt.Errorf("bridge: result outbox: %w", err)
	}
	if err := addTransition(ctx, tx, row.CommandID, StatusLeased, StatusCompleted, row.LeaseEpoch, c.Actor, digest); err != nil {
		return nil, err
	}
	return &SubmitOutcome{CommandID: row.CommandID, Status: StatusCompleted, EffectState: effect, ResultDigest: digest}, nil
}

// Cancel stops a pending or leased command in the caller's transaction. A
// leased command is fenced (its result is then refused with command_cancelled
// and no permit is issued); a permitted effect becomes unknown, because the
// provider may already have acted. Cancelling a cancelled command is a no-op;
// a completed one is already_completed.
func (s *Store) Cancel(ctx context.Context, tx pgx.Tx, commandID, actor string) error {
	row, err := scanCmd(tx.QueryRow(ctx, `SELECT `+cmdCols+` FROM bridge_commands WHERE command_id=$1 FOR UPDATE`, commandID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCommandNotFound
	}
	if err != nil {
		return fmt.Errorf("bridge: cancel lock: %w", err)
	}
	switch row.Status {
	case StatusCancelled:
		return nil
	case StatusCompleted, StatusExpired:
		return ErrAlreadyCompleted
	}
	if _, err := tx.Exec(ctx, `UPDATE bridge_commands SET status='cancelled', cancel_requested=true, updated_at=now(),
			effect_state = CASE WHEN effect_state='permitted' THEN 'unknown' ELSE effect_state END
		WHERE command_id=$1`, commandID); err != nil {
		return fmt.Errorf("bridge: cancel: %w", err)
	}
	return addTransition(ctx, tx, commandID, row.Status, StatusCancelled, row.LeaseEpoch, actor, "")
}

// Outcome is the read-back control code uses before any retry.
type Outcome struct {
	CommandID    string          `json:"command_id"`
	Status       string          `json:"status"`
	EffectState  string          `json:"effect_state"`
	ResultDigest string          `json:"result_digest,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
}

// ReadOutcome reads a command's status, effect state and stored result.
func (s *Store) ReadOutcome(ctx context.Context, commandID string) (*Outcome, error) {
	var o Outcome
	var result []byte
	err := s.pool.QueryRow(ctx, `SELECT command_id, status, effect_state, result_digest, result - 'lease_token' FROM bridge_commands WHERE command_id=$1`,
		commandID).Scan(&o.CommandID, &o.Status, &o.EffectState, &o.ResultDigest, &result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("bridge: read outcome: %w", err)
	}
	o.Result = result
	return &o, nil
}

// expireTx moves due pending/leased commands to expired under row locks
// (FOR UPDATE SKIP LOCKED), recording the locked prior status in the
// transition and one expired signal-outbox row. A non-empty provider scopes the
// pass to that provider and the given tenants; an empty provider is the
// unscoped sweep. limit <= 0 means no limit. An expired command that held a
// write permit has an unknown effect, never "none".
func (s *Store) expireTx(ctx context.Context, tx pgx.Tx, provider string, tenants []string, limit int, actor string) (int, error) {
	rows, err := tx.Query(ctx, `WITH due AS (
			SELECT command_id, status AS old_status FROM bridge_commands
			WHERE status IN ('pending','leased') AND expires_at <= now()
			  AND ($1 = '' OR (provider_ref = $1 AND tenant = ANY($2)))
			ORDER BY expires_at, command_id
			LIMIT CASE WHEN $3 > 0 THEN $3 ELSE NULL END
			FOR UPDATE SKIP LOCKED)
		UPDATE bridge_commands b SET status='expired', updated_at=now(),
			effect_state = CASE WHEN b.effect_state='permitted' THEN 'unknown' ELSE b.effect_state END
		FROM due WHERE b.command_id = due.command_id
		RETURNING b.command_id, b.workflow_id, b.run_id, b.lease_epoch, due.old_status, b.operation_kind`, provider, tenants, limit)
	if err != nil {
		return 0, fmt.Errorf("bridge: expire: %w", err)
	}
	type expired struct {
		id, wf, run, old, kind string
		epoch                  int64
	}
	var exp []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.id, &e.wf, &e.run, &e.epoch, &e.old, &e.kind); err != nil {
			rows.Close()
			return 0, fmt.Errorf("bridge: expire scan: %w", err)
		}
		exp = append(exp, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("bridge: expire: %w", err)
	}
	for _, e := range exp {
		if err := addTransition(ctx, tx, e.id, e.old, StatusExpired, e.epoch, actor, ""); err != nil {
			return 0, err
		}
		if IsReadKind(e.kind) {
			// A read has no workflow to signal.
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bridge_signal_outbox (command_id, workflow_id, run_id, result_digest)
			VALUES ($1,$2,$3,'expired') ON CONFLICT (command_id) DO NOTHING`, e.id, e.wf, e.run); err != nil {
			return 0, fmt.Errorf("bridge: expire outbox: %w", err)
		}
	}
	return len(exp), nil
}

// ExpireActor is the transition actor of the background sweep.
const ExpireActor = "system:expiry-sweep"

// ExpireDue expires up to limit due commands across all providers and
// tenants in one short transaction. Rows locked by a concurrent claim, result,
// permit or cancel are skipped and picked up by a later pass.
func (s *Store) ExpireDue(ctx context.Context, limit int) (int, error) {
	if limit < 1 {
		limit = DefaultExpiryBatch
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("bridge: expire begin: %w", err)
	}
	n, err := s.expireTx(ctx, tx, "", nil, limit, ExpireActor)
	if err := finish(ctx, tx, err); err != nil {
		return 0, err
	}
	return n, nil
}

// ExpiryBacklog reports how many commands are past expires_at and still open,
// and the age in seconds of the oldest of them (0 when none).
func (s *Store) ExpiryBacklog(ctx context.Context) (count int64, oldestSeconds float64, err error) {
	err = s.pool.QueryRow(ctx, `SELECT count(*), COALESCE(EXTRACT(EPOCH FROM (now() - min(expires_at))), 0)
		FROM bridge_commands WHERE status IN ('pending','leased') AND expires_at <= now()`).Scan(&count, &oldestSeconds)
	if err != nil {
		return 0, 0, fmt.Errorf("bridge: expiry backlog: %w", err)
	}
	return count, oldestSeconds, nil
}

// ScrubLegacyResultBatch removes lease_token from up to limit stored results
// written before redaction, under FOR UPDATE SKIP LOCKED in one short
// transaction. It is idempotent and restartable; it returns the rows changed
// and the rows still holding a token. It is an operator-invoked maintenance
// step and is never called from NewStore.
func (s *Store) ScrubLegacyResultBatch(ctx context.Context, limit int) (scrubbed int, remaining int64, err error) {
	if limit < 1 {
		limit = 100
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := s.begin(cctx)
	if err != nil {
		return 0, 0, fmt.Errorf("bridge: scrub begin: %w", err)
	}
	tag, err := tx.Exec(cctx, `UPDATE bridge_commands SET result = result - 'lease_token'
		WHERE command_id IN (SELECT command_id FROM bridge_commands
			WHERE result ? 'lease_token' ORDER BY command_id LIMIT $1 FOR UPDATE SKIP LOCKED)`, limit)
	if err != nil {
		_ = tx.Rollback(cctx)
		return 0, 0, fmt.Errorf("bridge: scrub: %w", err)
	}
	if err := finish(cctx, tx, nil); err != nil {
		return 0, 0, err
	}
	if err := s.pool.QueryRow(cctx, `SELECT count(*) FROM bridge_commands WHERE result ? 'lease_token'`).Scan(&remaining); err != nil {
		return int(tag.RowsAffected()), 0, fmt.Errorf("bridge: scrub remaining: %w", err)
	}
	slog.Info("bridge legacy result scrub batch", "scrubbed", tag.RowsAffected(), "remaining", remaining)
	return int(tag.RowsAffected()), remaining, nil
}
