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

package glovojoin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/jcs"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// prepareLockTimeout is the SET LOCAL lock_timeout of the prepare transaction:
// a contended tenant or owner lock is tenant_busy, never a hung request.
const prepareLockTimeout = 5 * time.Second

// maxPrepareAttempts bounds the restart-from-step-1 loop of design 6 (a lost
// preview claim or an idempotent Create that replayed).
const maxPrepareAttempts = 3

// providerGlovo is the provider the approval binding names.
const providerGlovo = "glovo"

// TxBeginner is the shared glovo_runtime pool.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// PrepareConnections is the #959 connection store surface prepare uses.
type PrepareConnections interface {
	LockOwnerShared(ctx context.Context, tx pgx.Tx, tenant, principal string) error
	LiveConnectionTx(ctx context.Context, tx pgx.Tx, owner glovo.Owner) (*glovo.Connection, error)
}

// PrepareOrders is the #988 order store surface prepare uses.
type PrepareOrders interface {
	LookupByIdempotencyKey(ctx context.Context, q dbq.Querier, sc orders.Scope, key string) (*orders.Order, error)
	Create(ctx context.Context, tx pgx.Tx, in orders.CreateInput) (*orders.Order, bool, error)
	Finalize(ctx context.Context, tx pgx.Tx, sc orders.Scope, a orders.Actor, orderRef string, expectedVersion int64, expectedFP string) (*orders.Order, error)
	MintJoinRefTx(ctx context.Context, tx pgx.Tx, kind orders.JoinKind, tenant, principalID, subjectID string) (string, error)
}

// PrepareWork is the #989 work-items surface prepare uses.
type PrepareWork interface {
	CreateGlovoExecutionTx(ctx context.Context, tx pgx.Tx, in workitems.GlovoExecutionInput) (workItemID, executionID string, err error)
	CreateGlovoApprovalTx(ctx context.Context, tx pgx.Tx, in workitems.GlovoApprovalInput) (*workitems.ActionApprovalRequest, bool, error)
	GlovoApprovalStatus(ctx context.Context, q dbq.Querier, tenants []string, id string) (*workitems.GlovoApprovalStatus, error)
}

var (
	_ PrepareConnections = (*glovo.Store)(nil)
	_ PrepareOrders      = (*orders.Store)(nil)
	_ PrepareWork        = (*workitems.Store)(nil)
)

// Preparer runs POST /orders:prepare (design 6, steps 1 to 8). It writes the
// order, the we_, the pending aar_ and the workflow-start row, and makes no
// provider call, no ReadBridge call and no bridge command.
type Preparer struct {
	DB    TxBeginner
	Conns PrepareConnections
	Order PrepareOrders
	Work  PrepareWork
	Now   func() time.Time
}

// PrepareRequest is the verified input of one prepare. Subject carries the
// verified tenant and principal; PreviewID and Key come from the wire body.
type PrepareRequest struct {
	Tenant      string
	PrincipalID string
	PreviewID   string
	Key         string
}

// PrepareResult is the 200 body of /orders:prepare.
type PrepareResult struct {
	OrderID          string
	Fingerprint      string
	ConsentRequestID string
	ExpiresAt        time.Time
	Replayed         bool
}

// WireBody is the fixed-order JSON of the result; a replay renders the same
// stored values, so the bytes are identical.
func (r PrepareResult) WireBody() []byte {
	b, _ := json.Marshal(struct {
		OrderID          string `json:"order_id"`
		Fingerprint      string `json:"fingerprint"`
		ConsentRequestID string `json:"consent_request_id"`
		ExpiresAt        string `json:"expires_at"`
	}{r.OrderID, r.Fingerprint, r.ConsentRequestID, r.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	return b
}

// ControlInputSchemaVersion is the provisional schema version of the control
// workflow input. OPEN-957-11: mctl-agents#1044 owns the real schema, which is
// not vendored yet; this value and ControlLimits are replaced when it lands.
const ControlInputSchemaVersion = "glovo-control-input/v1alpha1"

// ControlLimits are the `limits` members copied from the vendored #1044
// schema defaults. None are invented: until the schema is vendored the object
// is empty (OPEN-957-11).
var ControlLimits = map[string]any{}

// ControlInput is the twelve-member GlovoControlInput of design 6c.
type ControlInput struct {
	SchemaVersion   string         `json:"schema_version"`
	TenantRef       string         `json:"tenant_ref"`
	PrincipalRef    string         `json:"principal_ref"`
	InstallRef      string         `json:"install_ref"`
	InstallRevision int64          `json:"install_revision"`
	ConnectionRef   string         `json:"connection_ref"`
	OrderRef        string         `json:"order_ref"`
	ExecutionID     string         `json:"execution_id"`
	WorkItemID      string         `json:"work_item_id"`
	ApprovalRef     string         `json:"approval_ref"`
	Fingerprint     string         `json:"fingerprint"`
	Limits          map[string]any `json:"limits"`
}

// Canonical returns the RFC 8785 bytes and their sha256 digest.
func (c ControlInput) Canonical() (data []byte, digest string, err error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, "", fmt.Errorf("glovojoin: marshal control input: %w", err)
	}
	data, err = jcs.Canonicalize(raw)
	if err != nil {
		return nil, "", fmt.Errorf("glovojoin: canonicalize control input: %w", err)
	}
	sum := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// WorkflowID is the deterministic workflow id of design 6c.
func WorkflowID(tnr, prr, gin, ordr string) string {
	return "asst-glovo-" + tnr + "-" + prr + "-" + gin + "-" + ordr
}

// RequestHash is the stored digest of the prepare body: another preview under
// the same client key is idempotency_key_reused.
func prepareRequestHash(previewID string) string {
	sum := sha256.Sum256([]byte("glovo-prepare\x00" + previewID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type restart struct{}

func (restart) Error() string { return "glovojoin: prepare restart" }

// toRefusal turns any store error into a Refusal. A lock timeout is
// tenant_busy; an error that carries no Glovo code is unavailable, never a
// success and never an empty answer.
func toRefusal(err error, reason string) *Refusal {
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return &Refusal{Err: ge, Reason: reason}
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return &Refusal{Err: glovo.Refuse(glovo.CodeTenantBusy), Reason: "lock_timeout"}
	}
	return &Refusal{Err: glovo.Refuse(glovo.CodeUnavailable), Reason: "dependency_unavailable:" + reason}
}

// Prepare runs the flow, restarting from step 1 at most maxPrepareAttempts
// times when a concurrent prepare won the preview claim or the order key.
func (p *Preparer) Prepare(ctx context.Context, in PrepareRequest) (*PrepareResult, *Refusal) {
	if in.Tenant == "" || in.PrincipalID == "" || in.PreviewID == "" || in.Key == "" || len(in.Key) > 128 {
		return nil, refusal(glovo.CodeInvalidRequest, "prepare_input")
	}
	for attempt := 0; attempt < maxPrepareAttempts; attempt++ {
		res, err := p.once(ctx, in)
		var r restart
		if errors.As(err, &r) {
			continue
		}
		if err != nil {
			var rf *Refusal
			if errors.As(err, &rf) {
				return nil, rf
			}
			return nil, toRefusal(err, "prepare")
		}
		return res, nil
	}
	return nil, refusal(glovo.CodeUnavailable, "prepare_contended")
}

func (p *Preparer) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Preparer) once(ctx context.Context, in PrepareRequest) (res *PrepareResult, err error) {
	tx, err := p.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, toRefusal(err, "begin")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(prepareLockTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return nil, toRefusal(err, "lock_timeout")
	}
	owner := glovo.Owner{TenantID: in.Tenant, PrincipalID: in.PrincipalID}
	sc := orders.Scope{Tenant: in.Tenant, PrincipalID: in.PrincipalID}

	// Step 1: L1 and L2 shared, then the live connection re-read.
	if err := p.Conns.LockOwnerShared(ctx, tx, in.Tenant, in.PrincipalID); err != nil {
		return nil, toRefusal(err, "lock")
	}
	conn, err := p.Conns.LiveConnectionTx(ctx, tx, owner)
	if err != nil {
		return nil, toRefusal(err, "connection")
	}
	reqHash := prepareRequestHash(in.PreviewID)

	// Step 1b: replay lookup before any write.
	existing, err := p.Order.LookupByIdempotencyKey(ctx, tx, sc, in.Key)
	switch {
	case err == nil:
		return p.replay(ctx, tx, sc, existing, reqHash)
	case !errors.Is(err, glovo.ErrNotFound):
		return nil, toRefusal(err, "idempotency")
	}

	// Step 2: the preview row.
	pv, rf := LoadPreview(ctx, tx, in.PreviewID, in.Tenant, in.PrincipalID, p.now())
	if rf != nil {
		return nil, rf
	}
	if pv.ConsumedOrderRef != "" {
		return nil, refusal(glovo.CodeFingerprintChanged, "preview_consumed")
	}
	if pv.Approval == nil {
		return nil, refusal(glovo.CodeInvalidRequest, "basket_empty")
	}
	if conn.ConnectionID != pv.ConnectionID || conn.InstallID != pv.InstallID || conn.InstallRevision != pv.InstallRevision {
		return nil, refusal(glovo.CodeStaleInstall, "preview_connection_changed")
	}

	// Step 3: the stored basket must still hash to the stored fingerprint.
	_, canonical, perr := basket.Parse(pv.Approval)
	if perr != nil || basket.Fingerprint(canonical) != pv.Fingerprint {
		return nil, refusal(glovo.CodeFingerprintChanged, "preview_fingerprint")
	}

	// Step 4: refs and the deterministic workflow id.
	orderRef := orders.NewOrderRef()
	tnr, err := p.Order.MintJoinRefTx(ctx, tx, orders.JoinTenant, in.Tenant, "", in.Tenant)
	if err != nil {
		return nil, toRefusal(err, "join_ref")
	}
	prr, err := p.Order.MintJoinRefTx(ctx, tx, orders.JoinPrincipal, in.Tenant, in.PrincipalID, in.PrincipalID)
	if err != nil {
		return nil, toRefusal(err, "join_ref")
	}
	wfID := WorkflowID(tnr, prr, pv.InstallID, orderRef)

	// Step 4b: the single-use claim (L2c).
	claimed, err := ClaimPreview(ctx, tx, pv.ID, in.Tenant, in.PrincipalID, orderRef)
	if err != nil {
		return nil, toRefusal(err, "claim")
	}
	if !claimed {
		return nil, restart{}
	}

	// Step 5: the owner's wi_ and we_.
	actor := in.PrincipalID
	wi, we, err := p.Work.CreateGlovoExecutionTx(ctx, tx, workitems.GlovoExecutionInput{
		Tenant: in.Tenant, OwnerPrincipalID: in.PrincipalID, WorkflowID: wfID, Actor: actor,
	})
	if err != nil {
		return nil, toRefusal(err, "execution")
	}

	// Step 6: the order, snapshot 1 and Finalize.
	ownerActor := orders.Actor{Kind: orders.ActorOwner, ID: in.PrincipalID}
	o, replayed, err := p.Order.Create(ctx, tx, orders.CreateInput{
		Scope: sc, Actor: ownerActor, IdempotencyKey: in.Key, RequestHash: reqHash,
		ConnectionID: conn.ConnectionID, InstallID: pv.InstallID, ExpectedInstallRevision: pv.InstallRevision,
		ApprovalBasket: pv.Approval, ExpectedFingerprint: pv.Fingerprint, ExecutionID: we, OrderRef: orderRef,
	})
	if err != nil {
		return nil, toRefusal(err, "order")
	}
	if replayed {
		return nil, restart{}
	}
	fin, err := p.Order.Finalize(ctx, tx, sc, ownerActor, orderRef, o.Version, pv.Fingerprint)
	if err != nil {
		return nil, toRefusal(err, "finalize")
	}
	_ = fin

	// Step 7: the pending aar_ (it binds itself to the order).
	aar, _, err := p.Work.CreateGlovoApprovalTx(ctx, tx, workitems.GlovoApprovalInput{
		Tenant: in.Tenant, OwnerPrincipalID: in.PrincipalID, WorkItemID: wi, ExecutionID: we, OrderRef: orderRef,
		ConnectionRef: conn.ConnectionID, InstallID: pv.InstallID, InstallRevision: strconv.FormatInt(pv.InstallRevision, 10),
		BasketFingerprint: pv.Fingerprint, Provider: providerGlovo, ExpiresIn: GlovoApprovalTTL,
	})
	if err != nil {
		return nil, toRefusal(err, "approval")
	}

	// Step 8: the workflow-start row with the canonical input.
	input, digest, err := ControlInput{
		SchemaVersion: ControlInputSchemaVersion, TenantRef: tnr, PrincipalRef: prr, InstallRef: pv.InstallID,
		InstallRevision: pv.InstallRevision, ConnectionRef: conn.ConnectionID, OrderRef: orderRef, ExecutionID: we,
		WorkItemID: wi, ApprovalRef: aar.ID, Fingerprint: pv.Fingerprint, Limits: ControlLimits,
	}.Canonical()
	if err != nil {
		return nil, toRefusal(err, "control_input")
	}
	now := p.now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.control_starts
 (order_ref, workflow_id, input, input_digest, state, attempts, next_attempt_at, created_at, updated_at)
 VALUES ($1,$2,$3,$4,'pending',0,$5,$5,$5)`, orderRef, wfID, input, digest, now); err != nil {
		return nil, toRefusal(err, "control_start")
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true // the outcome is unknown; never roll back a possibly committed tx
		return nil, toRefusal(err, "commit")
	}
	committed = true
	return &PrepareResult{OrderID: orderRef, Fingerprint: pv.Fingerprint, ConsentRequestID: aar.ID, ExpiresAt: aar.ExpiresAt.UTC()}, nil
}

// replay answers step 1b from the stored order and its aar_, byte for byte.
func (p *Preparer) replay(ctx context.Context, tx pgx.Tx, sc orders.Scope, o *orders.Order, reqHash string) (*PrepareResult, error) {
	if o.RequestHash != reqHash {
		return nil, refusal(glovo.CodeIdempotencyReused, "idempotency_key_reused")
	}
	if o.ApprovalRef == "" || o.FinalBasketFingerprint == "" {
		return nil, refusal(glovo.CodeUnavailable, "replay_incomplete")
	}
	st, err := p.Work.GlovoApprovalStatus(ctx, tx, []string{sc.Tenant}, o.ApprovalRef)
	if err != nil {
		return nil, toRefusal(err, "replay_approval")
	}
	return &PrepareResult{OrderID: o.OrderRef, Fingerprint: o.FinalBasketFingerprint, ConsentRequestID: o.ApprovalRef, ExpiresAt: st.ExpiresAt.UTC(), Replayed: true}, nil
}
