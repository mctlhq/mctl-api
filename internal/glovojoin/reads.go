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
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

// ReadDeadline bounds one provider read (contract timeouts.request_seconds
// is 5; the bridge gets a little less so the HTTP answer is still ours).
const ReadDeadline = 4 * time.Second

// DefaultHistoryLimit is the page size when a client sends none: the #1059
// command requires a limit, the wire body does not.
const DefaultHistoryLimit = 10

// ReadOrders is the #988 join-ref surface the reads need.
type ReadOrders interface {
	MintJoinRefTx(ctx context.Context, tx pgx.Tx, kind orders.JoinKind, tenant, principalID, subjectID string) (string, error)
}

// ReadDB is the shared glovo_runtime pool.
type ReadDB interface {
	TxBeginner
	dbq.Querier
}

// Reader serves the three provider reads of the join facade. It enqueues no
// command and writes nothing to the provider: its only writes are join rows
// (refs, issued history refs and previews).
type Reader struct {
	DB     ReadDB
	Conns  PrepareConnections
	Order  ReadOrders
	Bridge ReadBridge
	Now    func() time.Time
}

func (r *Reader) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// readScope is what a read needs after the short L1/L2 transaction.
type readScope struct {
	conn *glovo.Connection
	req  bridge.ReadRequest
}

// scope re-reads the live connection under L1 and L2 shared, mints the
// opaque refs and releases the locks before the provider read starts, so a
// slow provider never holds a tenant lock.
func (r *Reader) scope(ctx context.Context, sub Subject, kind bridge.ReadKind) (*readScope, *Refusal) {
	if r.Bridge == nil {
		return nil, refusal(glovo.CodeNotReady, "read_bridge_absent")
	}
	tx, err := r.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, toRefusal(err, "begin")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(prepareLockTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return nil, toRefusal(err, "lock_timeout")
	}
	if err := r.Conns.LockOwnerShared(ctx, tx, sub.Tenant, sub.PrincipalID); err != nil {
		return nil, toRefusal(err, "lock")
	}
	conn, err := r.Conns.LiveConnectionTx(ctx, tx, glovo.Owner{TenantID: sub.Tenant, PrincipalID: sub.PrincipalID})
	if err != nil {
		return nil, toRefusal(err, "connection")
	}
	if conn.InstallID != sub.InstallID || conn.InstallRevision != sub.InstallRevision {
		return nil, refusal(glovo.CodeStaleInstall, "connection_install_changed")
	}
	tnr, err := r.Order.MintJoinRefTx(ctx, tx, orders.JoinTenant, sub.Tenant, "", sub.Tenant)
	if err != nil {
		return nil, toRefusal(err, "join_ref")
	}
	prr, err := r.Order.MintJoinRefTx(ctx, tx, orders.JoinPrincipal, sub.Tenant, sub.PrincipalID, sub.PrincipalID)
	if err != nil {
		return nil, toRefusal(err, "join_ref")
	}
	irv, err := r.Order.MintJoinRefTx(ctx, tx, orders.JoinInstallRevision, sub.Tenant, "", fmt.Sprintf("%s:%d", conn.InstallID, conn.InstallRevision))
	if err != nil {
		return nil, toRefusal(err, "join_ref")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, toRefusal(err, "commit")
	}
	return &readScope{conn: conn, req: bridge.ReadRequest{
		Kind: kind, Tenant: sub.Tenant, OwnerPrincipalID: sub.PrincipalID, TenantRef: tnr, PrincipalRef: prr,
		ConnectionRef: conn.ConnectionID, InstallRevision: strconv.FormatInt(conn.InstallRevision, 10), InstallRevisionRef: irv,
		Scopes: sub.Scopes,
	}}, nil
}

func (r *Reader) read(ctx context.Context, sc *readScope, params any) (*bridge.ReadResult, *Refusal) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, refusal(glovo.CodeInvalidRequest, "read_params")
	}
	req := sc.req
	req.Params = raw
	req.Deadline = r.now().Add(ReadDeadline)
	res, err := r.Bridge.Read(ctx, req)
	if err != nil {
		return nil, MapReadError(err)
	}
	if res == nil || len(res.Data) == 0 {
		return nil, refusal(glovo.CodeUnavailable, "read:empty_result")
	}
	return res, nil
}

// History is POST /orders:list. A cursor must be one an earlier history read
// issued to this subject and connection, else 404 not_found with no command.
func (r *Reader) History(ctx context.Context, sub Subject, limit int, cursor string) (HistoryView, *Refusal) {
	if limit == 0 {
		limit = DefaultHistoryLimit
	}
	if limit < 1 || limit > 20 {
		return HistoryView{}, refusal(glovo.CodeInvalidRequest, "history_limit")
	}
	sc, rf := r.scope(ctx, sub, bridge.ReadHistory)
	if rf != nil {
		return HistoryView{}, rf
	}
	params := map[string]any{"limit": limit}
	if cursor != "" {
		ok, err := RefIssued(ctx, r.DB, sub.Tenant, sub.PrincipalID, sc.conn.ConnectionID, RefKindCursor, cursor, r.now())
		if err != nil {
			return HistoryView{}, toRefusal(err, "cursor")
		}
		if !ok {
			return HistoryView{}, refusal(glovo.CodeNotFound, "cursor_not_issued")
		}
		params["cursor"] = cursor
	}
	res, rf := r.read(ctx, sc, params)
	if rf != nil {
		return HistoryView{}, rf
	}
	view, err := ParseHistory(res.Data)
	if err != nil {
		return HistoryView{}, refusal(glovo.CodeUnavailable, "read:history_payload")
	}
	// Record before answering: a ref the client never received must not be
	// usable, and one it received must be.
	if err := RecordIssuedRefs(ctx, r.DB, sub.Tenant, sub.PrincipalID, sc.conn.ConnectionID, view.IssuedPho(), view.NextCursor, r.now()); err != nil {
		return HistoryView{}, toRefusal(err, "record_refs")
	}
	return view, nil
}

// PreviewResult is the 200 body of POST /previews.
type PreviewResult struct {
	PreviewID   string
	Items       []Item
	Unavailable []Item
	Fingerprint string
	ExpiresAt   time.Time
}

// Preview is POST /previews: the pho_ must have been issued to this subject
// and connection (else 404 not_found, no command). A non-empty answer stores
// a single-use preview row; an empty one stores a row with no basket, which
// prepare refuses as basket_empty.
func (r *Reader) Preview(ctx context.Context, sub Subject, pho string) (*PreviewResult, *Refusal) {
	if !phoRE.MatchString(pho) {
		return nil, refusal(glovo.CodeInvalidRequest, "pho_shape")
	}
	sc, rf := r.scope(ctx, sub, bridge.ReadPreview)
	if rf != nil {
		return nil, rf
	}
	ok, err := RefIssued(ctx, r.DB, sub.Tenant, sub.PrincipalID, sc.conn.ConnectionID, RefKindPho, pho, r.now())
	if err != nil {
		return nil, toRefusal(err, "pho")
	}
	if !ok {
		return nil, refusal(glovo.CodeNotFound, "pho_not_issued")
	}
	res, rf := r.read(ctx, sc, map[string]any{"history_order_ref": pho})
	if rf != nil {
		return nil, rf
	}
	view, err := ParsePreview(res.Data)
	if err != nil {
		return nil, refusal(glovo.CodeUnavailable, "read:preview_payload")
	}
	id, err := NewPreviewID()
	if err != nil {
		return nil, toRefusal(err, "preview_id")
	}
	now := r.now().Truncate(time.Millisecond)
	p := Preview{ID: id, Tenant: sub.Tenant, PrincipalID: sub.PrincipalID, ConnectionID: sc.conn.ConnectionID, InstallID: sc.conn.InstallID,
		InstallRevision: sc.conn.InstallRevision, PayloadHash: PayloadHash(res.Data), CreatedAt: now, ExpiresAt: now.Add(PreviewTTL)}
	if !view.Empty {
		p.Approval, p.Fingerprint = view.Approval, view.Fingerprint
	}
	if err := InsertPreview(ctx, r.DB, p); err != nil {
		return nil, toRefusal(err, "preview_store")
	}
	return &PreviewResult{PreviewID: id, Items: view.Items, Unavailable: view.Unavailable, Fingerprint: p.Fingerprint, ExpiresAt: p.ExpiresAt}, nil
}

// Basket is GET /basket.
func (r *Reader) Basket(ctx context.Context, sub Subject) (BasketView, *Refusal) {
	sc, rf := r.scope(ctx, sub, bridge.ReadBasket)
	if rf != nil {
		return BasketView{}, rf
	}
	res, rf := r.read(ctx, sc, map[string]any{})
	if rf != nil {
		return BasketView{}, rf
	}
	view, err := ParseBasket(res.Data)
	if err != nil {
		return BasketView{}, refusal(glovo.CodeUnavailable, "read:basket_payload")
	}
	return view, nil
}
