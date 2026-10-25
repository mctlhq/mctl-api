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

package securityfindings

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// attemptRow is the locked remediation attempt a mutation works on.
type attemptRow struct {
	ID, OccurrenceID, Tenant string
	Seq                      int
	LandedRevision           string
	LandedArtifact           string
	Outcome                  string
}

func loadAttempt(ctx context.Context, tx pgx.Tx, id string) (*attemptRow, error) {
	var a attemptRow
	err := tx.QueryRow(ctx, `SELECT id, occurrence_id, tenant, seq, landed_revision, landed_artifact_digest, COALESCE(outcome, '')
		FROM security_remediation_attempts WHERE id = $1 FOR UPDATE`, id).
		Scan(&a.ID, &a.OccurrenceID, &a.Tenant, &a.Seq, &a.LandedRevision, &a.LandedArtifact, &a.Outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load attempt: %w", err)
	}
	return &a, nil
}

// bound reports whether a revision and artifact digest match the attempt's
// landed fix: each of the two the attempt has set must match exactly. An
// attempt with no landed fix binds nothing.
func (a *attemptRow) bound(revision, artifact string) bool {
	if a.LandedRevision == "" && a.LandedArtifact == "" {
		return false
	}
	if a.LandedRevision != "" && revision != a.LandedRevision {
		return false
	}
	if a.LandedArtifact != "" && artifact != a.LandedArtifact {
		return false
	}
	return true
}

// Triage moves a new or reopened occurrence to triaged.
func (s *Store) Triage(ctx context.Context, in TriageInput) (*MutationResult, error) {
	if err := in.Actor.validate(); err != nil {
		return nil, err
	}
	scope := "occurrence:" + in.OccurrenceID
	hash := hashJSON(map[string]any{"op": "triage", "reason": in.Reason, "expected": in.ExpectedVersion})
	var out MutationResult
	err := s.withTx(ctx, []string{occurrenceLock(in.OccurrenceID)}, func(tx pgx.Tx) error {
		if r, err := s.replayed(ctx, tx, scope, in.IdempotencyKey, "triage", hash, in.Actor.Principal); err != nil || r != nil {
			if r != nil {
				out = *r
			}
			return err
		}
		occ, err := lockOccurrence(ctx, tx, in.OccurrenceID)
		if err != nil {
			return err
		}
		if err := checkVersion(occ, in.ExpectedVersion); err != nil {
			return err
		}
		to, err := s.move(ctx, tx, occ, ActionTriage, in.Actor, in.Reason, nil, occ.ActiveAttempt)
		if err != nil {
			return err
		}
		out = occ.result()
		out.Transition = to
		return s.remember(ctx, tx, scope, in.IdempotencyKey, "triage", hash, in.Actor.Principal, out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// StartRemediation opens a new attempt on an occurrence, bound to an
// existing WorkItem of the same tenant, and moves it to fixing. At most one
// attempt per occurrence is active, enforced by a partial unique index.
func (s *Store) StartRemediation(ctx context.Context, in StartRemediationInput) (*MutationResult, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	scope := "occurrence:" + in.OccurrenceID
	hash := hashJSON(map[string]any{"op": "start", "work_item": in.WorkItemID, "execution": in.ExecutionID,
		"workflow": in.DevloopWorkflowID, "source": in.StartSource, "expected": in.ExpectedVersion})
	var out MutationResult
	err := s.withTx(ctx, []string{occurrenceLock(in.OccurrenceID)}, func(tx pgx.Tx) error {
		if r, err := s.replayed(ctx, tx, scope, in.IdempotencyKey, "start_remediation", hash, in.Actor.Principal); err != nil || r != nil {
			if r != nil {
				out = *r
			}
			return err
		}
		occ, err := lockOccurrence(ctx, tx, in.OccurrenceID)
		if err != nil {
			return err
		}
		if err := checkVersion(occ, in.ExpectedVersion); err != nil {
			return err
		}
		if occ.State == StateFixing || occ.State == StateAwaitingVerification {
			return ErrAttemptActive
		}
		if _, err := Next(occ.State, ActionStartRemediation); err != nil {
			return err
		}
		if err := s.checkWorkItem(ctx, in.WorkItemID, occ.Tenant); err != nil {
			return err
		}

		// An attempt left behind by an unverifiable result is superseded by
		// the new one, in the same transaction.
		now := s.now()
		if _, err := tx.Exec(ctx, `UPDATE security_remediation_attempts SET outcome = $2, ended_at = $3
			WHERE occurrence_id = $1 AND outcome IS NULL`, occ.ID, OutcomeSuperseded, now); err != nil {
			return fmt.Errorf("securityfindings: supersede attempt: %w", err)
		}

		affected, err := affectedRevisions(ctx, tx, occ.ID)
		if err != nil {
			return err
		}
		attemptID := newID(AttemptIDPrefix)
		if _, err := tx.Exec(ctx, `INSERT INTO security_remediation_attempts
			(id, occurrence_id, tenant, seq, work_item_id, execution_id, devloop_workflow_id, started_by,
			 started_by_principal_id, start_source, affected_revisions, started_at)
			SELECT $1::text, $2::text, $3::text, COALESCE(MAX(seq), 0) + 1, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text, $10::jsonb, $11::timestamptz
			FROM security_remediation_attempts WHERE occurrence_id = $2`,
			attemptID, occ.ID, occ.Tenant, in.WorkItemID, in.ExecutionID, in.DevloopWorkflowID,
			in.Actor.Principal, in.Actor.PrincipalID, in.StartSource, marshal(affected), now); err != nil {
			if isUniqueViolation(err) {
				return ErrAttemptActive
			}
			return fmt.Errorf("securityfindings: create attempt: %w", err)
		}
		to, err := s.move(ctx, tx, occ, ActionStartRemediation, in.Actor, "remediation started",
			map[string]string{"attempt_id": attemptID, "work_item_id": in.WorkItemID}, attemptID)
		if err != nil {
			return err
		}
		out = occ.result()
		out.AttemptID, out.Transition = attemptID, to
		return s.remember(ctx, tx, scope, in.IdempotencyKey, "start_remediation", hash, in.Actor.Principal, out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) checkWorkItem(ctx context.Context, id, tenant string) error {
	if s.workItems == nil {
		return ErrWorkItemsUnavail
	}
	wi, err := s.workItems.Get(ctx, id)
	if err != nil {
		if errors.Is(err, workitems.ErrNotFound) {
			return ErrWorkItemNotFound
		}
		return fmt.Errorf("securityfindings: work item lookup: %w", err)
	}
	if wi.Tenant != tenant {
		return ErrWorkItemNotFound
	}
	return nil
}

// affectedRevisions snapshots the revisions and artifacts at which the
// problem has been observed present.
func affectedRevisions(ctx context.Context, tx pgx.Tx, occurrenceID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT observed_revision, observed_artifact_digest FROM security_observations
		WHERE occurrence_id = $1 AND claimed_action = 'present'`, occurrenceID)
	if err != nil {
		return nil, fmt.Errorf("securityfindings: affected revisions: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var rev, dig string
		if err := rows.Scan(&rev, &dig); err != nil {
			return nil, fmt.Errorf("securityfindings: affected scan: %w", err)
		}
		for _, v := range []string{rev, dig} {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out, rows.Err()
}

// RecordFix records a candidate or landed fix on the active attempt. A landed
// fix moves the occurrence to awaiting_verification, never to resolved.
func (s *Store) RecordFix(ctx context.Context, in RecordFixInput) (*MutationResult, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	occID, _, err := s.AttemptRef(ctx, in.AttemptID)
	if err != nil {
		return nil, err
	}
	scope := "attempt:" + in.AttemptID
	hash := hashJSON(map[string]any{"op": "fix", "candidate": in.CandidateRevision, "landed": in.Landed, "rev": in.LandedRevision,
		"digest": in.LandedArtifactDigest, "ref": in.LandedRef, "expected": in.ExpectedVersion})
	var out MutationResult
	err = s.withTx(ctx, []string{occurrenceLock(occID)}, func(tx pgx.Tx) error {
		if r, err := s.replayed(ctx, tx, scope, in.IdempotencyKey, "record_fix", hash, in.Actor.Principal); err != nil || r != nil {
			if r != nil {
				out = *r
			}
			return err
		}
		occ, err := lockOccurrence(ctx, tx, occID)
		if err != nil {
			return err
		}
		if err := checkVersion(occ, in.ExpectedVersion); err != nil {
			return err
		}
		att, err := loadAttempt(ctx, tx, in.AttemptID)
		if err != nil {
			return err
		}
		if att.Outcome != "" || occ.ActiveAttempt != att.ID {
			return fmt.Errorf("%w: attempt %s is not the active attempt", ErrInvalidTransition, att.ID)
		}
		out = occ.result()
		out.AttemptID = att.ID
		if !in.Landed {
			if occ.State != StateFixing {
				return fmt.Errorf("%w: a candidate fix is recorded while fixing, not in %s", ErrInvalidTransition, occ.State)
			}
			if _, err := tx.Exec(ctx, `UPDATE security_remediation_attempts SET candidate_revision = $2 WHERE id = $1`,
				att.ID, in.CandidateRevision); err != nil {
				return fmt.Errorf("securityfindings: record candidate: %w", err)
			}
			if err := s.appendEvent(ctx, tx, occ.ID, "fix_candidate_recorded", occ.State, occ.State, in.Actor, "",
				map[string]string{"attempt_id": att.ID, "revision": in.CandidateRevision}); err != nil {
				return err
			}
			return s.remember(ctx, tx, scope, in.IdempotencyKey, "record_fix", hash, in.Actor.Principal, out)
		}
		if _, err := Next(occ.State, ActionRecordFix); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE security_remediation_attempts SET
			candidate_revision = CASE WHEN $2 <> '' THEN $2 ELSE candidate_revision END,
			landed_revision = $3, landed_artifact_digest = $4, landed_ref = $5, landed_at = $6
			WHERE id = $1`, att.ID, in.CandidateRevision, in.LandedRevision, in.LandedArtifactDigest, in.LandedRef, s.now()); err != nil {
			return fmt.Errorf("securityfindings: record landed fix: %w", err)
		}
		refs := map[string]string{"attempt_id": att.ID}
		if in.LandedRevision != "" {
			refs["revision"] = in.LandedRevision
		}
		if in.LandedArtifactDigest != "" {
			refs["artifact_digest"] = in.LandedArtifactDigest
		}
		if in.LandedRef != "" {
			refs["landed_ref"] = in.LandedRef
		}
		to, err := s.move(ctx, tx, occ, ActionRecordFix, in.Actor, "fix landed", refs, att.ID)
		if err != nil {
			return err
		}
		out = occ.result()
		out.AttemptID, out.Transition = att.ID, to
		return s.remember(ctx, tx, scope, in.IdempotencyKey, "record_fix", hash, in.Actor.Principal, out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// verificationData is a verification before its strength is derived.
type verificationData struct {
	mechanism         Strength
	result            string
	revision          string
	artifact          string
	refs              []EvidenceRef
	sourceObservation string
	ceiling           Strength
}

func hasRefKind(refs []EvidenceRef, kind string) bool {
	for _, r := range refs {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

// recordVerificationTx is the one place a verification is recorded and its
// consequence applied. The strength is derived here as the lower of the
// declared mechanism and the recorder's ceiling; a pass below the configured
// minimum is recorded and leaves the occurrence awaiting verification; an
// unavailable, error or timeout result never resolves anything.
func (s *Store) recordVerificationTx(ctx context.Context, tx pgx.Tx, occ *occRow, att *attemptRow, d verificationData, actor Actor) (string, string, error) {
	if att.Outcome != "" || occ.ActiveAttempt != att.ID {
		return "", "", fmt.Errorf("%w: attempt %s is not the active attempt", ErrInvalidTransition, att.ID)
	}
	if !att.bound(d.revision, d.artifact) {
		return "", "", ErrNotBound
	}
	derived := MinStrength(d.mechanism, d.ceiling)
	if d.mechanism == StrengthAssuranceReplay && !hasRefKind(d.refs, "assurance_finding") {
		derived = MinStrength(derived, StrengthProviderClaim)
	}
	var action string
	switch d.result {
	case ResultPassed:
		action = ActionVerifyInconclusive
		if derived.AtLeast(s.minStrength) {
			action = ActionVerifyPassed
		}
	case ResultFailed:
		action = ActionVerifyFailed
	case ResultUnverifiable:
		action = ActionVerifyUnverifiable
	default: // unavailable, error, timeout
		action = ActionVerifyInconclusive
	}
	if _, err := Next(occ.State, action); err != nil {
		return "", "", err
	}

	now := s.now()
	verID := newID(VerificationIDPrefix)
	if _, err := tx.Exec(ctx, `INSERT INTO security_verifications
		(id, attempt_id, occurrence_id, mechanism, declared_strength, derived_strength, result, revision, artifact_digest,
		 evidence_refs, recorded_by, recorded_by_principal_id, source_observation_id, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		verID, att.ID, occ.ID, string(d.mechanism), string(d.mechanism), string(derived), d.result, d.revision, d.artifact,
		marshal(nonNilRefs(d.refs)), actor.Principal, actor.PrincipalID, d.sourceObservation, now); err != nil {
		return "", "", fmt.Errorf("securityfindings: record verification: %w", err)
	}

	active := occ.ActiveAttempt
	if action == ActionVerifyPassed {
		if _, err := tx.Exec(ctx, `UPDATE security_remediation_attempts SET outcome = $2, ended_at = $3 WHERE id = $1`,
			att.ID, OutcomeResolved, now); err != nil {
			return "", "", fmt.Errorf("securityfindings: close attempt: %w", err)
		}
		active = ""
	}
	refs := map[string]string{"attempt_id": att.ID, "verification_id": verID, "result": d.result, "derived_strength": string(derived)}
	if d.sourceObservation != "" {
		refs["observation_id"] = d.sourceObservation
	}
	to, err := s.move(ctx, tx, occ, action, actor, "verification "+d.result, refs, active)
	if err != nil {
		return "", "", err
	}
	return to, verID, nil
}

// RecordVerification records a verification of the landed fix on the active
// attempt. The strength is derived from the recorder's ceiling, never from
// request text.
func (s *Store) RecordVerification(ctx context.Context, in RecordVerificationInput) (*MutationResult, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	occID, _, err := s.AttemptRef(ctx, in.AttemptID)
	if err != nil {
		return nil, err
	}
	scope := "attempt:" + in.AttemptID
	hash := hashJSON(map[string]any{"op": "verify", "mechanism": in.Mechanism, "result": in.Result, "rev": in.Revision,
		"digest": in.ArtifactDigest, "refs": in.EvidenceRefs, "expected": in.ExpectedVersion})
	var out MutationResult
	err = s.withTx(ctx, []string{occurrenceLock(occID)}, func(tx pgx.Tx) error {
		if r, err := s.replayed(ctx, tx, scope, in.IdempotencyKey, "record_verification", hash, in.Actor.Principal); err != nil || r != nil {
			if r != nil {
				out = *r
			}
			return err
		}
		occ, err := lockOccurrence(ctx, tx, occID)
		if err != nil {
			return err
		}
		if err := checkVersion(occ, in.ExpectedVersion); err != nil {
			return err
		}
		att, err := loadAttempt(ctx, tx, in.AttemptID)
		if err != nil {
			return err
		}
		to, verID, err := s.recordVerificationTx(ctx, tx, occ, att, verificationData{
			mechanism: in.Mechanism, result: in.Result, revision: in.Revision, artifact: in.ArtifactDigest,
			refs: in.EvidenceRefs, ceiling: in.Ceiling,
		}, in.Actor)
		if err != nil {
			return err
		}
		out = occ.result()
		out.AttemptID, out.VerificationID, out.Transition = att.ID, verID, to
		return s.remember(ctx, tx, scope, in.IdempotencyKey, "record_verification", hash, in.Actor.Principal, out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Dismiss records accepted risk or a false positive, separately from
// technical remediation. The API admits it for a human only; the store
// enforces the reason vocabulary and the authority reference. Any active
// attempt is closed as cancelled_dismissed.
func (s *Store) Dismiss(ctx context.Context, in DismissInput) (*MutationResult, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	scope := "occurrence:" + in.OccurrenceID
	hash := hashJSON(map[string]any{"op": "dismiss", "reason": in.Reason, "authority": in.AuthorityRef, "note": in.Note, "expected": in.ExpectedVersion})
	var out MutationResult
	err := s.withTx(ctx, []string{occurrenceLock(in.OccurrenceID)}, func(tx pgx.Tx) error {
		if r, err := s.replayed(ctx, tx, scope, in.IdempotencyKey, "dismiss", hash, in.Actor.Principal); err != nil || r != nil {
			if r != nil {
				out = *r
			}
			return err
		}
		occ, err := lockOccurrence(ctx, tx, in.OccurrenceID)
		if err != nil {
			return err
		}
		if err := checkVersion(occ, in.ExpectedVersion); err != nil {
			return err
		}
		if _, err := Next(occ.State, ActionDismiss); err != nil {
			return err
		}
		now := s.now()
		refs := map[string]string{"dismissal_reason": in.Reason, "authority_ref": in.AuthorityRef}
		if _, err := tx.Exec(ctx, `UPDATE security_remediation_attempts SET outcome = $2, ended_at = $3
			WHERE occurrence_id = $1 AND outcome IS NULL`, occ.ID, OutcomeCancelledDismissed, now); err != nil {
			return fmt.Errorf("securityfindings: cancel attempt: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE security_occurrences SET dismissal_reason = $2, dismissal_authority_ref = $3, dismissed_by = $4
			WHERE id = $1`, occ.ID, in.Reason, in.AuthorityRef, in.Actor.Principal); err != nil {
			return fmt.Errorf("securityfindings: record dismissal: %w", err)
		}
		reason := in.Reason
		if in.Note != "" {
			reason += ": " + in.Note
		}
		to, err := s.move(ctx, tx, occ, ActionDismiss, in.Actor, reason, refs, "")
		if err != nil {
			return err
		}
		out = occ.result()
		out.Transition = to
		return s.remember(ctx, tx, scope, in.IdempotencyKey, "dismiss", hash, in.Actor.Principal, out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
