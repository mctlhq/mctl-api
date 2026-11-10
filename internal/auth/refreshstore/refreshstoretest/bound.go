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

// Package refreshstoretest is an in-memory refreshstore.BoundStore for tests
// of the Glovo team grant flow. Its transaction is a fake that understands
// exactly the two grant statements the code issues on it (ActivateTx and
// CheckTx), applied to a teamgrant.MemoryStore. It proves the order and the
// all-or-nothing behaviour of the callers, not Postgres itself.
package refreshstoretest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
)

// TxGrants is a teamgrant.Transactional store over a MemoryStore.
type TxGrants struct{ *teamgrant.MemoryStore }

// NewTxGrants returns an empty TxGrants.
func NewTxGrants() *TxGrants { return &TxGrants{teamgrant.NewMemoryStore()} }

// SharesRefreshPool marks the store transactional with the Bound store.
func (*TxGrants) SharesRefreshPool() {}

type entry struct {
	clientID string
	sess     refreshstore.Session
	family   uuid.UUID
	rotated  bool
	revoked  bool
}

// Bound is the fake store.
type Bound struct {
	refreshstore.Store
	Grants *TxGrants

	mu         sync.Mutex
	tokens     map[string]*entry
	Events     []string // ordered: "revoke-grant", "revoke-family", ...
	FailBind   error    // returned by InsertBound after the insert, before commit
	FailRevoke error    // RevokeFamily/RevokePrincipal fail, nothing is revoked
}

// NewBound returns a store whose grant store is g.
func NewBound(g *TxGrants) *Bound { return &Bound{Grants: g, tokens: map[string]*entry{}} }

// Live reports how many tokens are neither rotated nor revoked.
func (b *Bound) Live() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.tokens {
		if !e.rotated && !e.revoked {
			n++
		}
	}
	return n
}

// Session returns the stored session of a token.
func (b *Bound) Session(raw string) (refreshstore.Session, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.tokens[raw]
	if !ok {
		return refreshstore.Session{}, false
	}
	return e.sess, true
}

func (b *Bound) Insert(raw, clientID string, sess refreshstore.Session, _ time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[raw] = &entry{clientID: clientID, sess: sess, family: uuid.New()}
	return nil
}

func (b *Bound) InsertBound(ctx context.Context, raw, clientID string, sess refreshstore.Session, _ time.Time, bind func(context.Context, pgx.Tx, uuid.UUID) error) error {
	fam := uuid.New()
	if err := bind(ctx, &tx{b: b}, fam); err != nil {
		return err
	}
	if b.FailBind != nil {
		// Models a failure before commit: the activation is undone.
		b.Grants.Revoke(ctx, sess.TeamGrantID, "rolled_back") //nolint:errcheck
		return b.FailBind
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[raw] = &entry{clientID: clientID, sess: sess, family: fam}
	return nil
}

func (b *Bound) RotateIf(old, next, clientID string, exp time.Time, accept func(refreshstore.Session) error) (refreshstore.Session, error) {
	return b.RotateIfTx(old, next, clientID, exp, func(_ context.Context, _ pgx.Tx, s refreshstore.Session) error {
		if accept == nil {
			return nil
		}
		return accept(s)
	})
}

func (b *Bound) RotateIfTx(old, next, clientID string, _ time.Time, accept func(context.Context, pgx.Tx, refreshstore.Session) error) (refreshstore.Session, error) {
	b.mu.Lock()
	e, ok := b.tokens[old]
	b.mu.Unlock()
	if !ok || e.revoked || e.rotated {
		return refreshstore.Session{}, refreshstore.ErrInvalidToken
	}
	if e.clientID != clientID {
		return refreshstore.Session{}, refreshstore.ErrClientMismatch
	}
	if accept != nil {
		if err := accept(context.Background(), &tx{b: b}, e.sess); err != nil {
			return refreshstore.Session{}, err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e.rotated = true
	b.tokens[next] = &entry{clientID: clientID, sess: e.sess, family: e.family}
	return e.sess, nil
}

func (b *Bound) RevokeFamily(raw, clientID, reason string) error {
	if b.FailRevoke != nil {
		return b.FailRevoke
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.tokens[raw]
	if !ok || (clientID != "" && e.clientID != clientID) {
		return nil
	}
	b.Events = append(b.Events, "revoke-grant")
	_ = b.Grants.RevokeByFamily(context.Background(), e.family.String(), reason)
	b.Events = append(b.Events, "revoke-family")
	for _, o := range b.tokens {
		if o.family == e.family {
			o.revoked = true
		}
	}
	return nil
}

func (b *Bound) RevokePrincipal(prn, reason string) (int64, error) {
	if b.FailRevoke != nil {
		return 0, b.FailRevoke
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Events = append(b.Events, "revoke-grant")
	_ = b.Grants.RevokeByPrincipal(context.Background(), prn, reason)
	b.Events = append(b.Events, "revoke-family")
	fams := map[uuid.UUID]bool{}
	for _, o := range b.tokens {
		if o.sess.PrincipalID == prn && !o.revoked {
			o.revoked = true
			fams[o.family] = true
		}
	}
	return int64(len(fams)), nil
}

func (b *Bound) GC() error { return nil }

// tx is the fake transaction.
type tx struct {
	pgx.Tx
	b *Bound
}

// Exec understands ActivateTx only.
func (t *tx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if !strings.Contains(sql, "SET state = 'active'") || len(args) != 5 {
		return pgconn.CommandTag{}, errors.New("refreshstoretest: unexpected statement")
	}
	fam := args[4].(uuid.UUID)
	if err := t.b.Grants.Activate(args[0].(string), args[1].(string), args[2].(string), args[3].(string), fam.String()); err != nil {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// QueryRow understands CheckTx only.
func (t *tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if !strings.Contains(sql, "FROM oauth_team_grants") || len(args) != 4 {
		return row{err: errors.New("refreshstoretest: unexpected query")}
	}
	g, err := t.b.Grants.Check(ctx, args[0].(string), args[1].(string), args[2].(string), args[3].(string))
	if errors.Is(err, teamgrant.ErrGrantInvalid) {
		return row{err: pgx.ErrNoRows}
	}
	return row{g: g, err: err}
}

type row struct {
	g   teamgrant.Grant
	err error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	vals := []any{r.g.ID, r.g.PrincipalID, r.g.Tenant, r.g.Resource, r.g.ClientID, r.g.RefreshFamilyID, r.g.State, r.g.CreatedAt, r.g.ExpiresAt}
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = vals[i].(string)
		case *time.Time:
			*p = vals[i].(time.Time)
		}
	}
	return nil
}
