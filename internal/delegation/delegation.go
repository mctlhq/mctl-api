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

// Package delegation resolves an X-MCTL-On-Behalf-Of grant ref to the
// stored subject it names (mctl-api#376 slice B).
//
// The single rule this package exists to make structural: the mint binds
// the execution and the work item (internal/auth's AgentRun); a grant ref
// only SELECTS a grant already bound to that execution or work item; the
// subject is always read out of the selected grant row. Nothing a caller
// supplies -- no header value, no body field, no token claim -- may ever
// produce a subject. Resolve's signature is the structural proof of that:
// it takes the ref and the token binding and nothing else.
//
// This package is deliberately store-free, the same posture
// internal/auth's AgentRunResolver takes: it defines the types, the
// interfaces and the sentinel errors; internal/workitems and
// internal/surfaceid implement the sources by returning Record and the
// sentinel errors below (never a type from this package's own callers);
// cmd/api/main.go wires the concrete Resolver together. It imports
// internal/auth (for auth.AgentRun) and nothing else from internal/, so a
// source package may safely import this one without creating a cycle.
package delegation

import (
	"context"
	"errors"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Kinds, keyed on the ref's own id prefix.
const (
	KindExecutionRequest = "execution_request" // xr_
	KindActionApproval   = "action_approval"   // aar_
	KindWorkItem         = "work_item"         // wi_
	KindSurfaceLink      = "surface_link"      // sil_
)

// prefixKinds lists every recognised ref prefix, in dispatch order. No
// prefix here is a prefix of another, so classify never has to pick.
var prefixKinds = []struct{ prefix, kind string }{
	{"xr_", KindExecutionRequest},
	{"aar_", KindActionApproval},
	{"wi_", KindWorkItem},
	{"sil_", KindSurfaceLink},
}

// classify maps a ref to the Kind its prefix names, or false for an
// unrecognised prefix.
func classify(ref string) (string, bool) {
	for _, p := range prefixKinds {
		if strings.HasPrefix(ref, p.prefix) {
			return p.kind, true
		}
	}
	return "", false
}

// Grant is a stored record that names a subject and is bound to an
// execution or a work item. Every field comes from a store row: nothing on
// Grant is ever set from the ref itself beyond echoing it back as Ref, or
// from any caller-supplied input.
type Grant struct {
	Ref, Kind string
	// Subject is the namespaced principal string the grant row stored, e.g.
	// "github:alice". Never used to authorize by itself; see
	// SubjectPrincipalID.
	Subject string
	// SubjectPrincipalID is the grant's canonical principal id (prn_...).
	// Never "" in a Grant this package returns for KindExecutionRequest,
	// KindActionApproval or KindWorkItem -- an empty one is refused as
	// ErrSubjectUnresolved before Resolve returns. For KindSurfaceLink it IS
	// "": a surface link stores no principal id of its own (see the
	// SurfaceLinkSource doc comment), and the caller (the gate,
	// mctl-api#376 slice B2) resolves it from the mirrored identity and
	// cross-checks it against Subject.
	SubjectPrincipalID string
	// ExecutionID and WorkItemID are the grant's own binding scope: the
	// execution or work item ANOTHER caller bound this grant to when it was
	// created (an execution request's or action approval's own columns, or
	// a work item's own id). They are never the presenting run token's
	// ids -- those are the bound argument to Resolve.
	ExecutionID string
	WorkItemID  string
}

// Record is the projection a source returns: the four grant fields the
// resolver needs, and no more of the row than that -- deliberately narrower
// than the store's public read payload, so this package never holds a row
// it must not expose (a claim token, an intent hash).
type Record struct {
	Subject, SubjectPrincipalID, ExecutionID, WorkItemID string
}

var (
	// ErrNotBound is returned for an unrecognised ref prefix, a ref whose
	// row does not exist or is not readable, a row that exists but is not
	// bound to the presenting run token's execution or work item, and (for
	// KindSurfaceLink) a revoked or expired link. Deliberately the SAME code
	// for all of these: the endpoint must not become an existence oracle
	// for a record id it does not own.
	ErrNotBound = errors.New("delegation: grant is not bound to this run")
	// ErrSubjectUnresolved is returned when a resolved grant's subject
	// principal id is empty, or (for a github-namespaced check performed by
	// the caller) not resolvable to a GitHub principal. There is
	// deliberately no fallback to the adjacent principal string.
	ErrSubjectUnresolved = errors.New("delegation: grant subject has no principal")
	// ErrUnavailable is returned when a grant source is unconfigured or
	// answers with anything other than "not found": a nil source, or a
	// store error that is not itself ErrNotBound. Never treated as a
	// refusal and never silently proceeds undelegated.
	ErrUnavailable = errors.New("delegation: a grant source is unavailable")
)

// Resolver turns a ref into a Grant bound to the presenting run token.
// Resolve takes the ref and the token binding and NOTHING else: there is
// structurally no argument through which a caller-supplied subject could
// enter.
type Resolver interface {
	Resolve(ctx context.Context, ref string, bound auth.AgentRun) (Grant, error)
}

// WorkItemSource is the narrow read surface internal/workitems.Store
// implements for the resolver: one purpose-built SELECT per grant kind
// that stores its subject with a work item, projecting only Record's
// fields. These are deliberately distinct from the store's public read
// methods (ExecutionRequest, ActionApproval, Get): those return the full
// row and their column lists are a different slice's (D1) to widen.
//
// A not-found row is reported as ErrNotBound, so this package's caller
// never has to import internal/workitems to recognise it.
type WorkItemSource interface {
	// ExecutionRequestGrant projects one work_item_execution_requests row:
	// its requester and the requester's principal id, plus its own
	// execution and work item ids (the binding scope). id is narrowed by
	// itemID when itemID is non-empty, the same AND work_item_id=$2 the
	// store's own getExecutionRequest already applies.
	ExecutionRequestGrant(ctx context.Context, itemID, id string) (Record, error)
	// ActionApprovalGrant projects one action_approval_requests row: who
	// decided it and their principal id, plus its own execution and work
	// item ids.
	ActionApprovalGrant(ctx context.Context, id string) (Record, error)
	// WorkItemGrant projects one work_items row: its owner and the owner's
	// principal id. A work item has no execution id of its own, so
	// Record.ExecutionID is always "".
	WorkItemGrant(ctx context.Context, id string) (Record, error)
	// SurfaceRefBound reports whether itemID carries a work_item_surface_refs
	// row for (surface, actorExternalID) -- the binding for a surface link
	// grant, which otherwise names neither an execution nor a work item of
	// its own.
	SurfaceRefBound(ctx context.Context, itemID, surface, actorExternalID string) (bool, error)
}

// SurfaceLinkSource is the narrow read surface internal/surfaceid.Store
// implements for a KindSurfaceLink grant. A link carries neither a subject
// principal id nor an execution/work-item binding of its own -- its
// binding comes from WorkItemSource.SurfaceRefBound and its principal id
// from the caller's own mirror lookup (auth.AttachPrincipal); LinkByID
// supplies only what a link DOES store: which surface-native identity it
// names, and the (namespaced) principal string it was redeemed for.
//
// LinkByID returns surfaceid's own sentinels (ErrLinkNotFound,
// ErrLinkRevoked, ErrLinkExpired) rather than this package's ErrNotBound:
// internal/auth already imports internal/surfaceid, and this package
// imports internal/auth, so internal/surfaceid returning this package's
// error would be a compile-time cycle. store_resolver.go (this package)
// imports internal/surfaceid, not the reverse, purely to classify these
// three sentinels into ErrNotBound -- that direction carries no cycle.
type SurfaceLinkSource interface {
	LinkByID(ctx context.Context, id string) (surface, externalID, principal string, err error)
}

// boundTo reports whether rec is bound to run. A record that carries its
// own execution id (an ExecutionRequestGrant or ActionApprovalGrant, each
// scoped to the execution that created it) must match that execution id
// exactly -- it does NOT fall back to a work-item-level match, otherwise a
// grant explicitly scoped to execution B would be presentable by any other
// execution A that merely shares B's work item. Only a record with no
// execution id of its own (a WorkItemGrant, which has none) is bound by
// work item id. An empty string never matches an empty string, so two
// unset ids never "agree".
func boundTo(rec Record, run auth.AgentRun) bool {
	if rec.ExecutionID != "" {
		return rec.ExecutionID == run.ExecutionID
	}
	return rec.WorkItemID != "" && rec.WorkItemID == run.WorkItemID
}
