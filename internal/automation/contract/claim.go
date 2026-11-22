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

package contract

import (
	"sync"
	"time"
)

// DefaultTombstoneHorizon is the default minimum time a closed or cleaned-up
// occurrence stays claimed. It must be at least the source replay horizon,
// which is unknown (docs/automation-contract.md, section 2.1).
const DefaultTombstoneHorizon = 30 * 24 * time.Hour

// ClaimStatus is the lifecycle state of an occurrence claim.
type ClaimStatus string

// Claim statuses.
const (
	ClaimClaimed    ClaimStatus = "claimed"
	ClaimBound      ClaimStatus = "bound"
	ClaimClosed     ClaimStatus = "closed"
	ClaimTombstoned ClaimStatus = "tombstoned"
	ClaimFailed     ClaimStatus = "failed"
)

// ClaimKey is the uniqueness key of a claim.
type ClaimKey struct{ Tenant, AuID, OccurrenceKey string }

// ClaimRequest is one admission attempt. RequestHash binds the request body;
// AdmittedVersion is the definition version admitted for this occurrence, kept
// apart from the key. Unavailable models an unreadable claim source.
type ClaimRequest struct {
	ClaimKey
	RequestHash     string
	AdmittedVersion int
	Unavailable     bool
}

// ClaimResult is the outcome of an admitted claim.
type ClaimResult struct {
	WorkItemID      string
	AdmittedVersion int
	Replayed        bool
}

type claimRow struct {
	workItemID      string
	admittedVersion int
	status          ClaimStatus
	requestHash     string
	closedAt        time.Time
}

// ClaimStore models the durable occurrence claim: unique on (tenant, au_id,
// occurrence_key), mapping to wi_id, admitted version, status and request
// hash. All operations run in one critical section.
//
// Claim class: isolated-model. It has no production caller; automation-api-store
// is hard-gated on implementing this claim durably (section 2.1).
type ClaimStore struct {
	mu   sync.Mutex
	rows map[ClaimKey]*claimRow
}

// Claim admits the occurrence. An identical replay returns the original wi_
// and admitted version with Replayed set and never calls mint. A different
// request hash is automation_occurrence_conflict. mint is called at most once
// per key unless a reconciled-failed claim is retried. An unavailable source
// fails closed and mints nothing.
func (s *ClaimStore) Claim(req ClaimRequest, mint func() (string, error)) (ClaimResult, error) {
	if req.Tenant == "" || req.AuID == "" || req.OccurrenceKey == "" || req.RequestHash == "" {
		return ClaimResult{}, fail(CodeInvalid, "claim component is empty")
	}
	if req.Unavailable {
		return ClaimResult{}, fail(CodeAuthorityUnavailable, "claim source unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[ClaimKey]*claimRow{}
	}
	if r, ok := s.rows[req.ClaimKey]; ok && r.status != ClaimFailed {
		if r.requestHash != req.RequestHash {
			return ClaimResult{}, fail(CodeOccurrenceConflict, "%s", req.OccurrenceKey)
		}
		if r.workItemID == "" {
			// Claimed, not yet bound: wait for reconciliation, never mint twice.
			return ClaimResult{}, fail(CodeAuthorityUnavailable, "claim awaiting reconciliation")
		}
		return ClaimResult{WorkItemID: r.workItemID, AdmittedVersion: r.admittedVersion, Replayed: true}, nil
	}
	r := &claimRow{admittedVersion: req.AdmittedVersion, status: ClaimClaimed, requestHash: req.RequestHash}
	s.rows[req.ClaimKey] = r
	id, err := mint()
	if err != nil || id == "" {
		// The row stays claimed without a wi_, as after a crash.
		return ClaimResult{}, fail(CodeAuthorityUnavailable, "mint failed")
	}
	r.workItemID, r.status = id, ClaimBound
	return ClaimResult{WorkItemID: id, AdmittedVersion: r.admittedVersion}, nil
}

// Status reports the status of a claim.
func (s *ClaimStore) Status(k ClaimKey) (ClaimStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[k]
	if !ok {
		return "", false
	}
	return r.status, true
}

// Close records that the WorkItem closed at the given time.
func (s *ClaimStore) Close(k ClaimKey, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[k]; ok && r.status == ClaimBound {
		r.status, r.closedAt = ClaimClosed, at
	}
}

// Cleanup models history cleanup: a closed claim becomes a tombstone, and a
// tombstone older than horizon is dropped. After that a replay is a new
// occurrence (the documented behaviour past the replay horizon).
func (s *ClaimStore) Cleanup(now time.Time, horizon time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, r := range s.rows {
		if r.status == ClaimClosed {
			r.status = ClaimTombstoned
		}
		if r.status == ClaimTombstoned && now.Sub(r.closedAt) >= horizon {
			delete(s.rows, k)
		}
	}
}

// Reconcile resolves a claimed row with no wi_: lookup finds an existing
// WorkItem by external_key. Found binds it, not found marks the row failed,
// and a lookup error is automation_authority_unavailable. It never mints.
func (s *ClaimStore) Reconcile(k ClaimKey, lookup func() (string, bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[k]
	if !ok || r.status != ClaimClaimed || r.workItemID != "" {
		return nil
	}
	id, found, err := lookup()
	if err != nil {
		return fail(CodeAuthorityUnavailable, "reconcile lookup failed")
	}
	if found && id != "" {
		r.workItemID, r.status = id, ClaimBound
		return nil
	}
	r.status = ClaimFailed
	return nil
}
