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

package delegation

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// fakeWorkItems is a fully in-memory WorkItemSource: no SQL, no pool.
type fakeWorkItems struct {
	execReq      map[string]Record
	actionApprov map[string]Record
	workItem     map[string]Record
	surfaceBound map[string]bool
	err          error // when set, every method answers this error instead
}

func (f *fakeWorkItems) ExecutionRequestGrant(_ context.Context, itemID, id string) (Record, error) {
	if f.err != nil {
		return Record{}, f.err
	}
	rec, ok := f.execReq[id]
	if !ok {
		return Record{}, ErrNotBound
	}
	if itemID != "" && rec.WorkItemID != itemID {
		return Record{}, ErrNotBound
	}
	return rec, nil
}

func (f *fakeWorkItems) ActionApprovalGrant(_ context.Context, id string) (Record, error) {
	if f.err != nil {
		return Record{}, f.err
	}
	rec, ok := f.actionApprov[id]
	if !ok {
		return Record{}, ErrNotBound
	}
	return rec, nil
}

func (f *fakeWorkItems) WorkItemGrant(_ context.Context, id string) (Record, error) {
	if f.err != nil {
		return Record{}, f.err
	}
	rec, ok := f.workItem[id]
	if !ok {
		return Record{}, ErrNotBound
	}
	return rec, nil
}

func (f *fakeWorkItems) SurfaceRefBound(_ context.Context, itemID, surface, actorExternalID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.surfaceBound[itemID+"|"+surface+"|"+actorExternalID], nil
}

// fakeLinks is a fully in-memory SurfaceLinkSource.
type fakeLinks struct {
	links map[string]struct{ surface, externalID, principal string }
	err   error
}

func (f *fakeLinks) LinkByID(_ context.Context, id string) (string, string, string, error) {
	if f.err != nil {
		return "", "", "", f.err
	}
	l, ok := f.links[id]
	if !ok {
		return "", "", "", surfaceid.ErrLinkNotFound
	}
	return l.surface, l.externalID, l.principal, nil
}

// T1: a run token bound to execution A presenting a grant bound to
// execution B is ErrNotBound, for every kind, each with a bound and an
// unbound case.
func TestStoreResolver_BindingPerKind(t *testing.T) {
	items := &fakeWorkItems{
		execReq: map[string]Record{
			"xr_bound":   {Subject: "github:alice", SubjectPrincipalID: "prn_ALICE", ExecutionID: "we_1", WorkItemID: "wi_1"},
			"xr_unbound": {Subject: "github:alice", SubjectPrincipalID: "prn_ALICE", ExecutionID: "we_9", WorkItemID: "wi_9"},
		},
		actionApprov: map[string]Record{
			"aar_bound":   {Subject: "github:bob", SubjectPrincipalID: "prn_BOB", ExecutionID: "we_1", WorkItemID: "wi_1"},
			"aar_unbound": {Subject: "github:bob", SubjectPrincipalID: "prn_BOB", ExecutionID: "we_9", WorkItemID: "wi_9"},
		},
		workItem: map[string]Record{
			"wi_1": {Subject: "github:carol", SubjectPrincipalID: "prn_CAROL", WorkItemID: "wi_1"},
			"wi_9": {Subject: "github:carol", SubjectPrincipalID: "prn_CAROL", WorkItemID: "wi_9"},
		},
		surfaceBound: map[string]bool{
			"wi_1|telegram|555": true,
		},
	}
	links := &fakeLinks{links: map[string]struct{ surface, externalID, principal string }{
		"sil_x": {"telegram", "555", "github:dave"},
	}}
	r := NewStoreResolver(items, links)
	bound := auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"}

	for _, tc := range []struct {
		name string
		ref  string
		want error
	}{
		{"xr_ bound by execution", "xr_bound", nil},
		{"xr_ unbound", "xr_unbound", ErrNotBound},
		{"aar_ bound", "aar_bound", nil},
		{"aar_ unbound", "aar_unbound", ErrNotBound},
		{"wi_ bound (own id)", "wi_1", nil},
		{"wi_ unbound (a different work item)", "wi_9", ErrNotBound},
		{"sil_ bound via surface ref", "sil_x", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Resolve(context.Background(), tc.ref, bound)
			if tc.want == nil && err != nil {
				t.Fatalf("Resolve(%s) = %v, want nil", tc.ref, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Resolve(%s) = %v, want %v", tc.ref, err, tc.want)
			}
		})
	}
}

// T2: mint context vs grant disagreement. A run token minted on wi_X owned
// by Alice, presenting an xr_ bound to wi_X but requested_by Bob, resolves
// to Bob; the work item's owner never appears in the returned Grant.
func TestStoreResolver_GrantIsTheAuthorityNotTheWorkItemOwner(t *testing.T) {
	items := &fakeWorkItems{
		execReq: map[string]Record{
			"xr_1": {Subject: "github:bob", SubjectPrincipalID: "prn_BOB", WorkItemID: "wi_X"},
		},
		workItem: map[string]Record{
			"wi_X": {Subject: "github:alice", SubjectPrincipalID: "prn_ALICE", WorkItemID: "wi_X"},
		},
	}
	r := NewStoreResolver(items, nil)
	grant, err := r.Resolve(context.Background(), "xr_1", auth.AgentRun{WorkItemID: "wi_X"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if grant.Subject != "github:bob" || grant.SubjectPrincipalID != "prn_BOB" {
		t.Fatalf("grant = %+v, want bob", grant)
	}
	if grant.Subject == "github:alice" || grant.SubjectPrincipalID == "prn_ALICE" {
		t.Fatalf("the work item owner leaked into the grant: %+v", grant)
	}
}

// T3: a grant whose *_principal_id is ” is ErrSubjectUnresolved, never a
// fallback to the adjacent principal string. One case per kind that stores
// a principal id (xr_, aar_, wi_ -- a sil_ grant never carries one from its
// source at all; see TestStoreResolver_SurfaceLinkHasNoStoredPrincipalID).
func TestStoreResolver_EmptyPrincipalIDIsUnresolved(t *testing.T) {
	items := &fakeWorkItems{
		execReq:      map[string]Record{"xr_1": {Subject: "github:alice", SubjectPrincipalID: "", WorkItemID: "wi_1"}},
		actionApprov: map[string]Record{"aar_1": {Subject: "github:alice", SubjectPrincipalID: "", WorkItemID: "wi_1"}},
		workItem:     map[string]Record{"wi_1": {Subject: "github:alice", SubjectPrincipalID: "", WorkItemID: "wi_1"}},
	}
	r := NewStoreResolver(items, nil)
	bound := auth.AgentRun{WorkItemID: "wi_1"}
	for _, ref := range []string{"xr_1", "aar_1", "wi_1"} {
		_, err := r.Resolve(context.Background(), ref, bound)
		if !errors.Is(err, ErrSubjectUnresolved) {
			t.Errorf("Resolve(%s) = %v, want ErrSubjectUnresolved", ref, err)
		}
	}
}

// SurfaceLinkSource stores no principal id at all: Grant.SubjectPrincipalID
// is always "" for a resolved sil_ grant. The gate (internal/api) is where
// this is cross-checked and filled from the live principal resolver
// (design.md B2 step 10) -- not this package's job.
func TestStoreResolver_SurfaceLinkHasNoStoredPrincipalID(t *testing.T) {
	items := &fakeWorkItems{surfaceBound: map[string]bool{"wi_1|telegram|555": true}}
	links := &fakeLinks{links: map[string]struct{ surface, externalID, principal string }{
		"sil_x": {"telegram", "555", "github:dave"},
	}}
	r := NewStoreResolver(items, links)
	grant, err := r.Resolve(context.Background(), "sil_x", auth.AgentRun{WorkItemID: "wi_1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if grant.SubjectPrincipalID != "" {
		t.Fatalf("grant.SubjectPrincipalID = %q, want empty", grant.SubjectPrincipalID)
	}
	if grant.Subject != "github:dave" || grant.Kind != KindSurfaceLink {
		t.Fatalf("grant = %+v", grant)
	}
}

// T4: an unknown ref, an unrecognised prefix, and a ref whose row exists
// but belongs to another run all return the same ErrNotBound; a source
// returning an unexpected error returns ErrUnavailable, never ErrNotBound.
func TestStoreResolver_NotBoundIsOneCodeNeverAnExistenceOracle(t *testing.T) {
	items := &fakeWorkItems{
		execReq: map[string]Record{
			"xr_other_run": {Subject: "github:alice", SubjectPrincipalID: "prn_ALICE", WorkItemID: "wi_other"},
		},
	}
	r := NewStoreResolver(items, nil)
	bound := auth.AgentRun{WorkItemID: "wi_1"}

	for _, ref := range []string{"xr_unknown", "not-a-prefixed-ref", "xr_other_run"} {
		_, err := r.Resolve(context.Background(), ref, bound)
		if !errors.Is(err, ErrNotBound) {
			t.Errorf("Resolve(%s) = %v, want ErrNotBound", ref, err)
		}
	}

	boom := &fakeWorkItems{err: errors.New("dial tcp: connection refused")}
	rb := NewStoreResolver(boom, nil)
	_, err := rb.Resolve(context.Background(), "xr_1", bound)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Resolve with an unreachable store = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, ErrNotBound) {
		t.Fatalf("an unreachable store must never read as ErrNotBound")
	}
}

// T5: a sil_ grant is bound only when SurfaceRefBound is true for the run
// token's work item; a revoked link and an expired link are both
// ErrNotBound.
func TestStoreResolver_SurfaceLinkBindingAndLiveness(t *testing.T) {
	items := &fakeWorkItems{surfaceBound: map[string]bool{"wi_1|telegram|555": true}}
	links := &fakeLinks{links: map[string]struct{ surface, externalID, principal string }{
		"sil_bound":   {"telegram", "555", "github:dave"},
		"sil_unbound": {"telegram", "999", "github:dave"}, // no matching surface ref
	}}
	r := NewStoreResolver(items, links)
	bound := auth.AgentRun{WorkItemID: "wi_1"}

	if _, err := r.Resolve(context.Background(), "sil_bound", bound); err != nil {
		t.Fatalf("bound sil_: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "sil_unbound", bound); !errors.Is(err, ErrNotBound) {
		t.Fatalf("unbound sil_ = %v, want ErrNotBound", err)
	}

	revoked := &fakeLinks{err: surfaceid.ErrLinkRevoked}
	if _, err := NewStoreResolver(items, revoked).Resolve(context.Background(), "sil_x", bound); !errors.Is(err, ErrNotBound) {
		t.Fatalf("revoked link = %v, want ErrNotBound", err)
	}
	expired := &fakeLinks{err: surfaceid.ErrLinkExpired}
	if _, err := NewStoreResolver(items, expired).Resolve(context.Background(), "sil_x", bound); !errors.Is(err, ErrNotBound) {
		t.Fatalf("expired link = %v, want ErrNotBound", err)
	}

	// No links source at all: ErrUnavailable, not a refusal.
	if _, err := NewStoreResolver(items, nil).Resolve(context.Background(), "sil_x", bound); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil links source = %v, want ErrUnavailable", err)
	}
	// No items source: ErrUnavailable too (SurfaceRefBound needs it).
	if _, err := NewStoreResolver(nil, links).Resolve(context.Background(), "sil_bound", bound); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil items source = %v, want ErrUnavailable", err)
	}
}

// A nil WorkItemSource answers ErrUnavailable for xr_/aar_/wi_, never a
// refusal or a silent pass-through.
func TestStoreResolver_NilWorkItemSourceIsUnavailable(t *testing.T) {
	r := NewStoreResolver(nil, nil)
	bound := auth.AgentRun{WorkItemID: "wi_1"}
	for _, ref := range []string{"xr_1", "aar_1", "wi_1"} {
		_, err := r.Resolve(context.Background(), ref, bound)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("Resolve(%s) with nil items = %v, want ErrUnavailable", ref, err)
		}
	}
}
