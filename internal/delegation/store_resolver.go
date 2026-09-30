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

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// StoreResolver is the one concrete Resolver: it dispatches a ref to the
// source that owns its table, from the ref's own prefix.
//
// This file, unlike delegation.go, imports internal/surfaceid: LinkByID
// (SurfaceLinkSource) returns surfaceid's own ErrLinkNotFound /
// ErrLinkRevoked / ErrLinkExpired rather than this package's ErrNotBound,
// because internal/surfaceid cannot import this package (internal/auth
// already imports internal/surfaceid, and this package imports
// internal/auth, so the reverse edge would be a compile-time cycle). This
// package importing internal/surfaceid, instead, carries no such cycle:
// internal/surfaceid imports neither internal/auth nor this package.
type StoreResolver struct {
	items WorkItemSource
	links SurfaceLinkSource
}

// NewStoreResolver builds a StoreResolver. Either dependency may be nil:
// a nil items source answers ErrUnavailable for xr_/aar_/wi_/sil_ (sil_
// needs it too, for the SurfaceRefBound binding check); a nil links source
// answers ErrUnavailable for sil_ only.
func NewStoreResolver(items WorkItemSource, links SurfaceLinkSource) *StoreResolver {
	return &StoreResolver{items: items, links: links}
}

// Resolve implements Resolver.
func (s *StoreResolver) Resolve(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error) {
	kind, ok := classify(ref)
	if !ok {
		return Grant{}, ErrNotBound
	}
	switch kind {
	case KindExecutionRequest:
		return s.resolveExecutionRequest(ctx, ref, bound)
	case KindActionApproval:
		return s.resolveActionApproval(ctx, ref, bound)
	case KindWorkItem:
		return s.resolveWorkItem(ctx, ref, bound)
	case KindSurfaceLink:
		return s.resolveSurfaceLink(ctx, ref, bound)
	default:
		// Unreachable: classify only ever returns one of the kinds above.
		return Grant{}, ErrNotBound
	}
}

// workItemSourceErr maps a WorkItemSource error to this package's two
// possible outcomes: its own ErrNotBound (a not-found row) passes through
// unchanged; any other error (the source is unreachable, a real query
// failure) becomes ErrUnavailable, never ErrNotBound, so a genuine outage is
// never read as "no such grant".
func workItemSourceErr(err error) error {
	if errors.Is(err, ErrNotBound) {
		return ErrNotBound
	}
	return ErrUnavailable
}

// surfaceLinkSourceErr maps a SurfaceLinkSource error (surfaceid's own
// sentinels) the same way: not-found, revoked or expired collapse into this
// package's single ErrNotBound; anything else is ErrUnavailable.
func surfaceLinkSourceErr(err error) error {
	switch {
	case errors.Is(err, surfaceid.ErrLinkNotFound), errors.Is(err, surfaceid.ErrLinkRevoked), errors.Is(err, surfaceid.ErrLinkExpired):
		return ErrNotBound
	default:
		return ErrUnavailable
	}
}

func (s *StoreResolver) resolveExecutionRequest(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error) {
	if s.items == nil {
		return Grant{}, ErrUnavailable
	}
	rec, err := s.items.ExecutionRequestGrant(ctx, bound.WorkItemID, ref)
	if err != nil {
		return Grant{}, workItemSourceErr(err)
	}
	if !boundTo(rec, bound) {
		return Grant{}, ErrNotBound
	}
	if rec.SubjectPrincipalID == "" {
		return Grant{}, ErrSubjectUnresolved
	}
	return Grant{
		Ref: ref, Kind: KindExecutionRequest,
		Subject: rec.Subject, SubjectPrincipalID: rec.SubjectPrincipalID,
		ExecutionID: rec.ExecutionID, WorkItemID: rec.WorkItemID,
	}, nil
}

func (s *StoreResolver) resolveActionApproval(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error) {
	if s.items == nil {
		return Grant{}, ErrUnavailable
	}
	rec, err := s.items.ActionApprovalGrant(ctx, ref)
	if err != nil {
		return Grant{}, workItemSourceErr(err)
	}
	if !boundTo(rec, bound) {
		return Grant{}, ErrNotBound
	}
	if rec.SubjectPrincipalID == "" {
		return Grant{}, ErrSubjectUnresolved
	}
	return Grant{
		Ref: ref, Kind: KindActionApproval,
		Subject: rec.Subject, SubjectPrincipalID: rec.SubjectPrincipalID,
		ExecutionID: rec.ExecutionID, WorkItemID: rec.WorkItemID,
	}, nil
}

func (s *StoreResolver) resolveWorkItem(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error) {
	if s.items == nil {
		return Grant{}, ErrUnavailable
	}
	rec, err := s.items.WorkItemGrant(ctx, ref)
	if err != nil {
		return Grant{}, workItemSourceErr(err)
	}
	if !boundTo(rec, bound) {
		return Grant{}, ErrNotBound
	}
	if rec.SubjectPrincipalID == "" {
		return Grant{}, ErrSubjectUnresolved
	}
	return Grant{
		Ref: ref, Kind: KindWorkItem,
		Subject: rec.Subject, SubjectPrincipalID: rec.SubjectPrincipalID,
		ExecutionID: rec.ExecutionID, WorkItemID: rec.WorkItemID,
	}, nil
}

// resolveSurfaceLink binds a sil_ grant through work_item_surface_refs
// (internal/workitems), the run token's own work item carrying a ref whose
// (surface, actor_external_id) names this link -- a link has neither an
// execution nor a work item id of its own. Its SubjectPrincipalID is left
// "": the gate resolves and cross-checks it (design.md B2 step 10), because
// a link row stores no principal id, only the mirrored identity does.
func (s *StoreResolver) resolveSurfaceLink(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error) {
	if s.links == nil || s.items == nil {
		return Grant{}, ErrUnavailable
	}
	surface, externalID, principal, err := s.links.LinkByID(ctx, ref)
	if err != nil {
		return Grant{}, surfaceLinkSourceErr(err)
	}
	ok, err := s.items.SurfaceRefBound(ctx, bound.WorkItemID, surface, externalID)
	if err != nil {
		return Grant{}, ErrUnavailable
	}
	if !ok {
		return Grant{}, ErrNotBound
	}
	return Grant{
		Ref: ref, Kind: KindSurfaceLink,
		Subject: principal, SubjectPrincipalID: "",
		WorkItemID: bound.WorkItemID,
	}, nil
}
