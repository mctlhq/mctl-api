// Copyright 2026 MCTL Authors
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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// DefaultReadResultTTL is the default life of a stored read result.
	DefaultReadResultTTL = 300 * time.Second
	// ReadScope is the scope a fetch must hold.
	ReadScope = "glovo:read"

	readEraseRetention = 24 * time.Hour
)

// EnableWireVersions checks the read level and, on success, lets this store
// enqueue and lease v1alpha2 commands. NewStore never calls it: until it is
// called the store keeps the plain v1alpha1 statements.
func (s *Store) EnableWireVersions(ctx context.Context) error {
	if err := CheckReadLevel(ctx, s.pool); err != nil {
		return err
	}
	s.wireEnabled.Store(true)
	return nil
}

// WireVersionsEnabled reports the flag set by EnableWireVersions.
func (s *Store) WireVersionsEnabled() bool { return s != nil && s.wireEnabled.Load() }

// SetReadResultTTL sets the life of a stored read result, clamped to 1..300 s.
// A non-positive d restores the default.
func (s *Store) SetReadResultTTL(d time.Duration) {
	secs := int64(d / time.Second)
	switch {
	case d <= 0:
		secs = 0
	case secs < 1:
		secs = 1
	case secs > MaxReadTTLSeconds:
		secs = MaxReadTTLSeconds
	}
	s.readTTL.Store(secs)
}

func (s *Store) readTTLSeconds() int {
	if v := s.readTTL.Load(); v > 0 {
		return int(v)
	}
	return int(DefaultReadResultTTL / time.Second)
}

// ReadResultsErased is the number of read result payloads erased since start.
func (s *Store) ReadResultsErased() int64 { return s.erased.Load() }

// ReadEnqueue is everything EnqueueRead needs: the ReadRequest of a read, the
// provider to lease it to and the command TTL.
type ReadEnqueue struct {
	ProviderRef string
	Request     ReadRequest
	TTL         time.Duration
}

// EnqueueRead inserts one read-kind command in the caller's transaction. It
// carries the #1059 read binding set and a server-minted request_id (rdq_),
// no workflow, order, execution or work item, and writes no signal-outbox row.
// It refuses with ErrReadUnavailable below the read schema level.
func (s *Store) EnqueueRead(ctx context.Context, tx pgx.Tx, in ReadEnqueue) (commandID, requestID string, err error) {
	r := in.Request
	if !IsReadKind(string(r.Kind)) {
		return "", "", fmt.Errorf("%w: unknown read kind", ErrInvalidInput)
	}
	if r.Tenant == "" || r.OwnerPrincipalID == "" || r.InstallRevision == "" || r.InstallRevisionRef == "" ||
		!refPatterns["provider_ref"].MatchString(in.ProviderRef) {
		return "", "", fmt.Errorf("%w: tenant, owner, install revision, its ref and the provider are required", ErrInvalidInput)
	}
	if in.TTL < time.Second || in.TTL > MaxReadTTLSeconds*time.Second {
		return "", "", fmt.Errorf("%w: read ttl out of range", ErrInvalidInput)
	}
	if err := CheckReadLevel(ctx, tx); err != nil {
		return "", "", err
	}
	params := r.Params
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	idSuffix, err := randAlnum(26)
	if err != nil {
		return "", "", fmt.Errorf("bridge: id: %w", err)
	}
	reqSuffix, err := randAlnum(26)
	if err != nil {
		return "", "", fmt.Errorf("bridge: id: %w", err)
	}
	nonce, err := randURL(16)
	if err != nil {
		return "", "", fmt.Errorf("bridge: nonce: %w", err)
	}
	now := s.now()
	ttlSeconds := int(in.TTL / time.Second)
	row := &cmdRow{
		CommandID: "cmd_" + idSuffix, TenantRef: r.TenantRef, PrincipalRef: r.PrincipalRef, ConnectionRef: r.ConnectionRef,
		ProviderRef: in.ProviderRef, Kind: string(r.Kind), Attempt: 1, CommandNonce: nonce, CreatedAt: now,
		ExpiresAt: now.Add(in.TTL), TTLSeconds: ttlSeconds, Payload: params, WireVersion: WireV1alpha2,
		ReadRequestID: "rdq_" + reqSuffix, InstallRevisionRef: r.InstallRevisionRef,
	}
	// Validate before writing: params or refs the #1059 schema refuses never
	// enter the table.
	if _, err := row.projection(false); err != nil {
		return "", "", err
	}
	paramsDigest := digestOf(params)
	_, err = tx.Exec(ctx, `INSERT INTO bridge_commands (command_id, execution_id, work_item_id, workflow_id, run_id, tenant,
		owner_principal_id, tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
		attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, command_nonce, ttl_seconds,
		expires_at, created_at, updated_at, wire_version, read_request_id, install_revision_ref)
		VALUES ($1,'','','','',$2,$3,$4,$5,'',$6,$7,$8,$9,1,$10,'',$11,1,$12,$13,$14,$15,$16,$17,$17,$18,$19,$20)`,
		row.CommandID, r.Tenant, r.OwnerPrincipalID, r.TenantRef, r.PrincipalRef, r.ConnectionRef, r.InstallRevision,
		in.ProviderRef, string(r.Kind), paramsDigest, "read:"+row.ReadRequestID, []byte(params), sha256Hex(params),
		nonce, ttlSeconds, row.ExpiresAt, now, WireV1alpha2, row.ReadRequestID, r.InstallRevisionRef)
	if err != nil {
		return "", "", fmt.Errorf("bridge: enqueue read insert: %w", err)
	}
	if err := addTransition(ctx, tx, row.CommandID, "", StatusPending, 0, "control", ""); err != nil {
		return "", "", fmt.Errorf("bridge: enqueue read transition: %w", err)
	}
	return row.CommandID, row.ReadRequestID, nil
}

type storedReadResult struct {
	Kind      string `json:"kind"`
	Digest    string `json:"digest"`
	SizeBytes int    `json:"size_bytes"`
	ResultRef string `json:"result_ref"`
}

func (s *Store) submitReadResult(ctx context.Context, c Caller, commandID string, res *ReadResultDoc) (*SubmitOutcome, error) {
	if res.CommandID != commandID {
		return nil, fmt.Errorf("%w: command_id does not match the route", ErrBindingMismatch)
	}
	digest, err := res.Digest()
	if err != nil {
		return nil, err
	}
	var canon []byte
	if res.Outcome == "succeeded" {
		if canon, err = res.canonicalPayload(); err != nil {
			return nil, err
		}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge: result begin: %w", err)
	}
	out, err := s.submitReadTx(ctx, tx, c, res, digest, canon)
	if err := finish(ctx, tx, err); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) submitReadTx(ctx context.Context, tx pgx.Tx, c Caller, res *ReadResultDoc, digest string, canon []byte) (*SubmitOutcome, error) {
	row, err := s.lockOwned(ctx, tx, c, res.CommandID)
	if err != nil {
		return nil, err
	}
	if !IsReadKind(row.Kind) || res.SchemaVersion != row.WireVersion {
		return nil, fmt.Errorf("%w: the result version does not match the command", ErrBindingMismatch)
	}
	if res.Kind != row.Kind || res.RequestID != row.ReadRequestID || res.Attempt != row.Attempt ||
		res.WorkerIdentity != "provider:"+row.ProviderRef {
		return nil, ErrBindingMismatch
	}
	if !tokenEqual(row.LeaseToken, res.LeaseToken) {
		return nil, ErrLeaseStale
	}
	if row.Status == StatusCompleted {
		if row.ResultDigest != digest {
			return nil, ErrResultConflict
		}
		var ref string
		switch err := tx.QueryRow(ctx, `SELECT result_ref FROM bridge_read_results WHERE command_id=$1`, row.CommandID).Scan(&ref); {
		case err == nil, errors.Is(err, pgx.ErrNoRows):
		default:
			return nil, fmt.Errorf("bridge: result replay lookup: %w", err)
		}
		return &SubmitOutcome{CommandID: row.CommandID, Status: row.Status, EffectState: row.EffectState, ResultDigest: digest, Replayed: true, ResultRef: ref}, nil
	}
	if err := s.leaseLive(row, res.LeaseToken); err != nil {
		return nil, err
	}
	var resultRef string
	if canon != nil {
		suffix, err := randAlnum(26)
		if err != nil {
			return nil, fmt.Errorf("bridge: id: %w", err)
		}
		resultRef = "res_" + suffix
	}
	stored, err := json.Marshal(storedReadResult{Kind: row.Kind, Digest: res.PayloadDigest, SizeBytes: len(canon), ResultRef: resultRef})
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE bridge_commands SET status='completed', result_digest=$2, result=$3, effect_state='none', updated_at=now()
		WHERE command_id=$1 AND status='leased' AND lease_epoch=$4 AND lease_nonce=$5`,
		row.CommandID, digest, stored, row.LeaseEpoch, row.LeaseNonce)
	if err != nil {
		return nil, fmt.Errorf("bridge: result cas: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrLeaseStale
	}
	if canon != nil {
		// The bytes are stored exactly as canonicalized, never as JSONB, so the
		// digest can be re-verified on every fetch.
		if _, err := tx.Exec(ctx, `INSERT INTO bridge_read_results (result_ref, command_id, read_kind, tenant, owner_principal_id,
			tenant_ref, principal_ref, connection_ref, install_revision, data, data_digest, size_bytes, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp(), clock_timestamp() + ($13 * interval '1 second'))`,
			resultRef, row.CommandID, row.Kind, row.Tenant, row.OwnerPrincipalID, row.TenantRef, row.PrincipalRef,
			row.ConnectionRef, row.InstallRevision, canon, res.PayloadDigest, len(canon), s.readTTLSeconds()); err != nil {
			return nil, fmt.Errorf("bridge: result store: %w", err)
		}
	}
	// A read has no workflow: no bridge_signal_outbox row.
	if err := addTransition(ctx, tx, row.CommandID, StatusLeased, StatusCompleted, row.LeaseEpoch, c.Actor, digest); err != nil {
		return nil, err
	}
	return &SubmitOutcome{CommandID: row.CommandID, Status: StatusCompleted, EffectState: EffectNone, ResultDigest: digest, ResultRef: resultRef}, nil
}

// ReadFetch is the in-process request of FetchReadResult. The caller (the #957
// handlers) has already verified the subject token; this store re-checks it.
type ReadFetch struct {
	ResultRef       string
	Tenant          string
	PrincipalID     string
	ConnectionRef   string
	InstallRevision string // decimal #959 revision, never an irv_
	Scopes          []string
}

// FetchReadResult returns the stored canonical bytes of a read result, in
// process only. It is the authoritative binding check for reads. A missing
// row, another tenant and another owner are one indistinguishable
// ErrCommandNotFound.
func (s *Store) FetchReadResult(ctx context.Context, f ReadFetch) (*ReadResult, error) {
	if err := CheckReadLevel(ctx, s.pool); err != nil {
		return nil, err
	}
	var (
		kind, tenant, owner, connRef, revision, digest, commandID string
		data                                                      []byte
		expiresAt                                                 time.Time
		expired                                                   bool
	)
	err := s.pool.QueryRow(ctx, `SELECT command_id, read_kind, tenant, owner_principal_id, connection_ref, install_revision,
		data, data_digest, expires_at, (expires_at <= clock_timestamp()) FROM bridge_read_results WHERE result_ref=$1`, f.ResultRef).
		Scan(&commandID, &kind, &tenant, &owner, &connRef, &revision, &data, &digest, &expiresAt, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read result lookup: %v", ErrReadUnavailable, err)
	}
	if tenant != f.Tenant || owner != f.PrincipalID {
		return nil, ErrCommandNotFound
	}
	if !slices.Contains(f.Scopes, ReadScope) {
		return nil, ErrReadNotAuthorized
	}
	if expired || data == nil {
		return nil, ErrCommandExpired
	}
	if connRef != f.ConnectionRef || revision != f.InstallRevision {
		return nil, ErrBindingMismatch
	}
	live, err := s.currentChecker().Live(ctx, tenant, owner)
	if err != nil {
		var nl *NotLiveError
		if errors.As(err, &nl) {
			return nil, fmt.Errorf("%w: connection %s", ErrBindingMismatch, nl.State)
		}
		return nil, fmt.Errorf("%w: connection check failed", ErrReadUnavailable)
	}
	if live.ConnectionRef != connRef || live.InstallRevision != revision {
		return nil, ErrBindingMismatch
	}
	if !digestEqual(digestOf(data), digest) {
		// Ids and sizes only: never the bytes.
		slog.Error("bridge read result integrity failure", "result_ref", f.ResultRef, "command_id", commandID, "size_bytes", len(data))
		return nil, fmt.Errorf("%w: integrity failure", ErrReadUnavailable)
	}
	return &ReadResult{Kind: ReadKind(kind), ResultRef: f.ResultRef, Digest: digest, Data: data, ExpiresAt: expiresAt}, nil
}

// EraseExpiredReads sets data to NULL on expired read results and deletes the
// rows 24 h after expires_at, in bounded FOR UPDATE SKIP LOCKED batches. A
// database below the read level has nothing to erase and is not an error.
func (s *Store) EraseExpiredReads(ctx context.Context, limit int) (erased, deleted int, err error) {
	if limit < 1 {
		limit = DefaultExpiryBatch
	}
	if cerr := CheckReadLevel(ctx, s.pool); cerr != nil {
		if errors.Is(cerr, ErrReadUnavailable) {
			return 0, 0, nil
		}
		return 0, 0, cerr
	}
	tag, err := s.pool.Exec(ctx, `WITH due AS (
			SELECT result_ref FROM bridge_read_results
			WHERE data IS NOT NULL AND expires_at <= clock_timestamp()
			ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		UPDATE bridge_read_results r SET data = NULL, erased_at = clock_timestamp()
		FROM due WHERE r.result_ref = due.result_ref`, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("bridge: erase reads: %w", err)
	}
	erased = int(tag.RowsAffected())
	s.erased.Add(int64(erased))
	tag, err = s.pool.Exec(ctx, `WITH due AS (
			SELECT result_ref FROM bridge_read_results
			WHERE expires_at <= clock_timestamp() - ($2 * interval '1 second')
			ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		DELETE FROM bridge_read_results r USING due WHERE r.result_ref = due.result_ref`, limit, int(readEraseRetention/time.Second))
	if err != nil {
		return erased, 0, fmt.Errorf("bridge: delete reads: %w", err)
	}
	return erased, int(tag.RowsAffected()), nil
}
