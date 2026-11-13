package glovobasket

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// memStore is the in-memory Store of the unit tests. It follows the PG
// store's rules (owner scope, CAS, frozen revisions, one approval per
// revision) and stands in for the ledger with a test-only decide.
type memStore struct {
	mu        sync.Mutex
	baskets   map[string]*memBasket
	approvals map[string]*memApproval
	failReads error
}

type memBasket struct {
	b    Basket
	revs []Revision
}

type memApproval struct {
	ref, basketID, fp, state string
	o                        Owner
	rev                      int64
	expires                  time.Time
}

func newMemStore() *memStore {
	return &memStore{baskets: map[string]*memBasket{}, approvals: map[string]*memApproval{}}
}

var _ Store = (*memStore)(nil)

func (m *memStore) find(o Owner, id string) (*memBasket, error) {
	if m.failReads != nil {
		return nil, unavailable("read basket", m.failReads)
	}
	b := m.baskets[id]
	if b == nil || b.b.Tenant != o.Tenant || b.b.Owner != o.PrincipalID {
		return nil, glovo.ErrNotFound
	}
	return b, nil
}

func (m *memStore) Create(_ context.Context, o Owner, key string, max int) (*Basket, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.baskets {
		if b.b.Tenant == o.Tenant && b.b.Owner == o.PrincipalID {
			if b.b.ClientKey == key {
				out := b.b
				return &out, false, nil
			}
			n++
		}
	}
	if n >= max {
		return nil, false, glovo.Refuse(glovo.CodeRateLimited)
	}
	id, err := newBasketID()
	if err != nil {
		return nil, false, err
	}
	r, _ := price(1, nil, time.Now().UTC())
	b := &memBasket{b: Basket{ID: id, Tenant: o.Tenant, Owner: o.PrincipalID, ClientKey: key, Current: r}, revs: []Revision{r}}
	m.baskets[id] = b
	out := b.b
	return &out, true, nil
}

func (m *memStore) Get(_ context.Context, o Owner, id string) (*Basket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := m.find(o, id)
	if err != nil {
		return nil, err
	}
	out := b.b
	return &out, nil
}

func (m *memStore) Update(_ context.Context, o Owner, id string, expected int64, ops []Op) (*Basket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := m.find(o, id)
	if err != nil {
		return nil, err
	}
	if b.b.Current.Revision != expected {
		return nil, glovo.Refuse(glovo.CodeStaleVersion)
	}
	qty, err := applyOps(b.b.Current.Lines, ops)
	if err != nil {
		return nil, err
	}
	r, err := price(expected+1, qty, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	b.revs = append(b.revs, r)
	b.b.Current = r
	out := b.b
	return &out, nil
}

func (m *memStore) RequestApproval(_ context.Context, o Owner, id string, expected int64, ttl time.Duration) (*ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := m.find(o, id)
	if err != nil {
		return nil, err
	}
	if b.b.Current.Revision != expected {
		return nil, glovo.Refuse(glovo.CodeStaleVersion)
	}
	if err := verifyFrozen(b.b.Current); err != nil {
		return nil, err
	}
	for _, a := range m.approvals {
		if a.basketID == id && a.rev == expected {
			return &ApprovalRequest{ApprovalRef: a.ref, BasketID: id, Revision: a.rev, Fingerprint: a.fp, State: a.state, ExpiresAt: a.expires}, nil
		}
	}
	ref := fmt.Sprintf("aar_mem%04d", len(m.approvals)+1)
	a := &memApproval{ref: ref, basketID: id, fp: b.b.Current.Fingerprint, state: workitems.GlovoBasketStatePending, o: o, rev: expected,
		expires: time.Now().Add(ttl).UTC()}
	m.approvals[ref] = a
	return &ApprovalRequest{ApprovalRef: ref, BasketID: id, Revision: a.rev, Fingerprint: a.fp, State: a.state, ExpiresAt: a.expires, Created: true}, nil
}

func (m *memStore) ApprovalStatus(_ context.Context, o Owner, ref string) (*ApprovalStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads != nil {
		return nil, unavailable("read approval", m.failReads)
	}
	a := m.approvals[ref]
	if a == nil || a.o != o {
		return nil, glovo.ErrNotFound
	}
	b := m.baskets[a.basketID]
	st := &ApprovalStatus{GlovoBasketApprovalStatus: workitems.GlovoBasketApprovalStatus{ApprovalRef: ref, State: a.state,
		BasketID: a.basketID, Revision: a.rev, BasketFingerprint: a.fp, ExpiresAt: a.expires}, CurrentRevision: b.b.Current.Revision}
	st.AuthorizesCurrent = a.state == workitems.GlovoBasketStateApproved && a.rev == b.b.Current.Revision && a.fp == b.b.Current.Fingerprint
	return st, nil
}

func (m *memStore) DecisionPayload(_ context.Context, ref string) (*DecisionPayload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.approvals[ref]
	if a == nil {
		return nil, workitems.ErrApprovalNotFound
	}
	r := m.baskets[a.basketID].revs[a.rev-1]
	return &DecisionPayload{ApprovalRef: ref, BasketID: a.basketID, Revision: a.rev, StoreRef: r.StoreRef, Lines: r.Lines,
		Totals: r.Totals, Fingerprint: r.Fingerprint, Tenant: a.o.Tenant, Owner: a.o.PrincipalID}, nil
}

// decide is the test stand-in for the owner's decision route.
func (m *memStore) decide(ref, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.approvals[ref]
	if a == nil {
		return errors.New("no such approval")
	}
	if a.state != workitems.GlovoBasketStatePending {
		return workitems.ErrApprovalAlreadyDecided
	}
	a.state = state
	return nil
}
