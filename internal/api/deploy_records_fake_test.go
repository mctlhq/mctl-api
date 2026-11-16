package api_test

import (
	"context"
	"errors"
	"sync"

	"github.com/mctlhq/mctl-api/internal/deployplan"
)

// fakeRecordStore reproduces the real store's rules: one record per plan
// and per grant, a status that moves once out of submitting.
type fakeRecordStore struct {
	mu        sync.Mutex
	byID      map[string]*deployplan.Record
	insertErr error
	setErr    error
	getErr    error
}

func newFakeRecordStore() *fakeRecordStore {
	return &fakeRecordStore{byID: map[string]*deployplan.Record{}}
}

func (s *fakeRecordStore) InsertRecord(_ context.Context, r *deployplan.Record) (*deployplan.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.insertErr != nil {
		return nil, s.insertErr
	}
	for _, e := range s.byID {
		if e.PlanID == r.PlanID || e.ApprovalID == r.ApprovalID {
			return nil, deployplan.ErrRecordExists
		}
	}
	c := *r
	s.byID[r.ID] = &c
	out := c
	return &out, nil
}

func (s *fakeRecordStore) SetRecordSubmission(_ context.Context, id, status, workflow string) (*deployplan.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return nil, s.setErr
	}
	r, ok := s.byID[id]
	if !ok || r.Status != deployplan.RecordSubmitting {
		return nil, errors.New("not awaiting submission")
	}
	r.Status, r.Workflow = status, workflow
	out := *r
	return &out, nil
}

func (s *fakeRecordStore) GetRecord(_ context.Context, id string) (*deployplan.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	if r, ok := s.byID[id]; ok {
		out := *r
		return &out, nil
	}
	return nil, deployplan.ErrRecordNotFound
}

func (s *fakeRecordStore) RecordForPlan(_ context.Context, planID string) (*deployplan.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	for _, r := range s.byID {
		if r.PlanID == planID {
			out := *r
			return &out, nil
		}
	}
	return nil, deployplan.ErrRecordNotFound
}

// only returns the single record, failing if there is not exactly one.
func (s *fakeRecordStore) only() (*deployplan.Record, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.byID {
		out := *r
		return &out, len(s.byID)
	}
	return nil, 0
}
