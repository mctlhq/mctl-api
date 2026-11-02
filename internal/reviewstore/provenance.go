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

package reviewstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// ProvenanceLookup reads the server-written execution provenance
// (workitems.Store). ExecutionProvenance returns workitems.ErrProvenanceAbsent
// only when the store was read and holds no record.
type ProvenanceLookup interface {
	ExecutionProvenance(ctx context.Context, executionID string) (*workitems.Provenance, error)
	LineageAttempts(ctx context.Context, lineageRoot string, attemptIDs []string) (map[string]bool, error)
}

func (s *Store) lookupProvenance(ctx context.Context, executionID string) (*workitems.Provenance, error) {
	if s.provenance == nil {
		return nil, fmt.Errorf("%w: no provenance store", ErrProvenanceUnavailable)
	}
	p, err := s.provenance.ExecutionProvenance(ctx, executionID)
	if err != nil {
		if errors.Is(err, workitems.ErrProvenanceAbsent) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrProvenanceUnavailable, err)
	}
	if p == nil {
		return nil, fmt.Errorf("%w: empty answer", ErrProvenanceUnavailable)
	}
	return p, nil
}

// checkAuthoring verifies the authoring facts of a request against the
// recorded provenance. A worker request must carry all three facts and they
// must match; a manual request is checked only when it asserts attempt or
// lineage facts. The document is never rewritten, only accepted or refused.
func (s *Store) checkAuthoring(ctx context.Context, req reviewreceipts.ReviewRequest) error {
	if req.Mode != reviewreceipts.ModeWorker &&
		len(req.AuthoringAttemptIDs) == 0 && req.AuthoringLineageRoot == "" {
		return nil
	}
	if !strings.HasPrefix(req.AuthoringExecutionID, "we_") {
		return fmt.Errorf("%w: %s is not a work-item execution", ErrAuthoringUnproven, req.AuthoringExecutionID)
	}
	p, err := s.lookupProvenance(ctx, req.AuthoringExecutionID)
	if errors.Is(err, workitems.ErrProvenanceAbsent) {
		return fmt.Errorf("%w: no provenance for %s", ErrAuthoringUnproven, req.AuthoringExecutionID)
	}
	if err != nil {
		return err
	}
	if req.AuthoringLineageRoot != p.LineageRoot {
		return fmt.Errorf("%w: authoring_lineage_root does not match the recorded lineage", ErrAuthoringUnproven)
	}
	if !slices.Contains(req.AuthoringAttemptIDs, p.AttemptID) {
		return fmt.Errorf("%w: authoring_attempt_ids omit the authoring execution's recorded attempt", ErrAuthoringUnproven)
	}
	known, err := s.provenance.LineageAttempts(ctx, p.LineageRoot, req.AuthoringAttemptIDs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProvenanceUnavailable, err)
	}
	for _, id := range req.AuthoringAttemptIDs {
		if !known[id] {
			return fmt.Errorf("%w: attempt %s is not an attempt of the authoring lineage", ErrAuthoringUnproven, id)
		}
	}
	return nil
}

// ProveReviewer returns the server-recorded attempt and lineage of a reviewer
// execution. It accepts no caller-supplied facts and makes no eligibility
// decision: it proves only which attempt and lineage the execution has.
func (s *Store) ProveReviewer(ctx context.Context, executionID string) (attemptID, lineageRoot string, err error) {
	p, err := s.lookupProvenance(ctx, executionID)
	if errors.Is(err, workitems.ErrProvenanceAbsent) {
		return "", "", fmt.Errorf("%w: %s", ErrExecutionUnproven, executionID)
	}
	if err != nil {
		return "", "", err
	}
	return p.AttemptID, p.LineageRoot, nil
}
