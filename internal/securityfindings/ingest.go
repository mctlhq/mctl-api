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
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// IngestBatch records a delivery of observations from one authenticated
// provider. Every item runs in its own transaction and gets its own result,
// so one rejected or duplicate item never drops the others. pc comes from the
// authenticated principal and server configuration, never from the payload.
func (s *Store) IngestBatch(ctx context.Context, pc ProviderContext, batch Batch) ([]ItemResult, error) {
	if pc.Ref == "" {
		return nil, fmt.Errorf("%w: provider ref is required", ErrInvalid)
	}
	if len(batch.Observations) == 0 || len(batch.Observations) > MaxBatchItems {
		return nil, fmt.Errorf("%w: a batch carries 1 to %d observations", ErrInvalid, MaxBatchItems)
	}
	if len(batch.DeliveryID) > maxFieldLen {
		return nil, fmt.Errorf("%w: delivery_id too long", ErrInvalid)
	}
	out := make([]ItemResult, len(batch.Observations))
	for i := range batch.Observations {
		out[i] = s.ingestItem(ctx, pc, batch.DeliveryID, batch.Observations[i])
	}
	return out, nil
}

func rejected(code, msg string) ItemResult {
	return ItemResult{Status: ItemRejected, Code: code, Message: msg}
}

func (s *Store) ingestItem(ctx context.Context, pc ProviderContext, deliveryID string, in ObservationInput) ItemResult {
	if err := in.validate(); err != nil {
		return rejected(CodeInvalid, err.Error())
	}
	if !pc.allowsTenant(in.Tenant) {
		return rejected(CodeTenantDenied, "tenant is not in this provider's configuration")
	}
	ident, err := CanonicalizeIdentity(pc.Ref, in.Identity, in.Aliases)
	if err != nil {
		return rejected(CodeInvalid, err.Error())
	}
	subject, err := NormalizeSubject(in.Subject, ident.RuleID)
	if err != nil {
		return rejected(CodeInvalid, err.Error())
	}
	if err := checkSubjectStrength(subject); err != nil {
		return rejected(CodeSubjectTooWeak, "subject needs a repository or resource and a package, path, location or artifact identity")
	}
	fingerprint := Fingerprint(subject)

	// The hash is the dedup key within one provider. delivery_id is part of
	// it but never a key by itself: several findings in one delivery have
	// distinct hashes, and redelivery of the same content repeats it.
	hash := hashJSON(map[string]string{
		"identity_key":        ident.Key,
		"subject_fingerprint": fingerprint,
		"source_finding_id":   in.SourceFindingID,
		"claimed_action":      in.ClaimedAction,
		"observed_revision":   in.ObservedRevision,
		"observed_artifact":   in.ObservedArtifactDigest,
		"delivery_id":         deliveryID,
		"evidence_digest":     hashJSON(in.EvidenceRefs),
	})

	locks := make([]string, 0, len(ident.Keys))
	for _, k := range ident.Keys {
		locks = append(locks, "security-finding:"+in.Tenant+":"+k)
	}

	var res ItemResult
	err = s.withTx(ctx, locks, func(tx pgx.Tx) error {
		var execErr error
		res, execErr = s.ingestTx(ctx, tx, pc, deliveryID, in, ident, subject, fingerprint, hash)
		return execErr
	})
	switch {
	case err == nil:
		return res
	case errors.Is(err, ErrAliasConflict):
		return rejected(CodeAliasConflict, "aliases resolve to different existing findings; nothing was merged")
	case errors.Is(err, ErrInvalid):
		return rejected(CodeInvalid, err.Error())
	default:
		slog.Error("security observation ingest failed", "provider", pc.Ref, "error", err)
		return rejected(CodeInternal, "the observation could not be recorded; retry the delivery")
	}
}

func (s *Store) ingestTx(ctx context.Context, tx pgx.Tx, pc ProviderContext, deliveryID string, in ObservationInput,
	ident CanonicalIdentity, subject Subject, fingerprint, hash string) (ItemResult, error) {
	now := s.now()

	// Redelivery: same provider, same content (including delivery id).
	var dupObs, dupOcc, dupFinding string
	err := tx.QueryRow(ctx, `SELECT o.id, o.occurrence_id, c.finding_id
		FROM security_observations o JOIN security_occurrences c ON c.id = o.occurrence_id
		WHERE o.provider_ref = $1 AND o.observation_hash = $2`, pc.Ref, hash).Scan(&dupObs, &dupOcc, &dupFinding)
	if err == nil {
		return ItemResult{Status: ItemDuplicate, FindingID: dupFinding, OccurrenceID: dupOcc, ObservationID: dupObs}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ItemResult{}, fmt.Errorf("securityfindings: duplicate lookup: %w", err)
	}

	actor := Actor{Principal: "provider:" + pc.Ref, PrincipalID: pc.PrincipalID, Source: "provider:" + pc.Ref}

	// Resolve the finding by any alias.
	rows, err := tx.Query(ctx, `SELECT DISTINCT finding_id FROM security_finding_aliases
		WHERE tenant = $1 AND alias_key = ANY($2)`, in.Tenant, ident.Keys)
	if err != nil {
		return ItemResult{}, fmt.Errorf("securityfindings: alias lookup: %w", err)
	}
	var found []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return ItemResult{}, fmt.Errorf("securityfindings: alias scan: %w", err)
		}
		found = append(found, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ItemResult{}, fmt.Errorf("securityfindings: alias rows: %w", err)
	}
	if len(found) > 1 {
		return ItemResult{}, ErrAliasConflict
	}

	var findingID string
	if len(found) == 1 {
		findingID = found[0]
		if _, err := tx.Exec(ctx, `UPDATE security_findings SET last_observed_at = $2 WHERE id = $1`, findingID, now); err != nil {
			return ItemResult{}, fmt.Errorf("securityfindings: touch finding: %w", err)
		}
	} else {
		findingID = newID(FindingIDPrefix)
		if _, err := tx.Exec(ctx, `INSERT INTO security_findings
			(id, tenant, identity_kind, identity_key, created_at, last_observed_at, schema_version)
			VALUES ($1, $2, $3, $4, $5, $5, $6)`, findingID, in.Tenant, ident.Kind, ident.Key, now, SchemaVersion); err != nil {
			return ItemResult{}, fmt.Errorf("securityfindings: create finding: %w", err)
		}
	}
	for _, k := range ident.Keys {
		if _, err := tx.Exec(ctx, `INSERT INTO security_finding_aliases (tenant, alias_key, finding_id)
			VALUES ($1, $2, $3) ON CONFLICT (tenant, alias_key) DO NOTHING`, in.Tenant, k, findingID); err != nil {
			return ItemResult{}, fmt.Errorf("securityfindings: record alias: %w", err)
		}
	}

	observedAt := now
	if in.ObservedAt != nil && !in.ObservedAt.IsZero() {
		observedAt = in.ObservedAt.UTC()
		if observedAt.After(now.Add(5 * time.Minute)) {
			return ItemResult{}, fmt.Errorf("%w: observed_at is in the future", ErrInvalid)
		}
	}

	// Find or create the occurrence.
	occ := &occRow{FindingID: findingID, Tenant: in.Tenant, Fingerprint: fingerprint}
	created := false
	err = tx.QueryRow(ctx, `SELECT id, state, state_version, COALESCE(active_attempt_id, '')
		FROM security_occurrences WHERE finding_id = $1 AND subject_fingerprint = $2 FOR UPDATE`, findingID, fingerprint).
		Scan(&occ.ID, &occ.State, &occ.Version, &occ.ActiveAttempt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		occ.ID, occ.State, occ.Version = newID(OccurrenceIDPrefix), StateOpen, 1
		if _, err := tx.Exec(ctx, `INSERT INTO security_occurrences
			(id, finding_id, tenant, subject_fingerprint, subject, state, state_version, created_at, updated_at, last_observed_at)
			VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $7, $7)`,
			occ.ID, findingID, in.Tenant, fingerprint, marshal(subject), StateOpen, now); err != nil {
			return ItemResult{}, fmt.Errorf("securityfindings: create occurrence: %w", err)
		}
		if err := s.appendEvent(ctx, tx, occ.ID, "observed", "", StateOpen, actor, "first observation", map[string]string{"provider": pc.Ref}); err != nil {
			return ItemResult{}, err
		}
		created = true
	case err != nil:
		return ItemResult{}, fmt.Errorf("securityfindings: load occurrence: %w", err)
	}

	obsID := newID(ObservationIDPrefix)
	res := ItemResult{Status: ItemCreated, FindingID: findingID, OccurrenceID: occ.ID, ObservationID: obsID}
	if created {
		res.Transition = StateOpen
	}

	// A present observation of a resolved occurrence is a regression when it
	// was observed after the resolution and not at a revision or artifact
	// already known to be affected. Decided before the observation is
	// inserted, so it is judged against earlier evidence only.
	regress := false
	if in.ClaimedAction == ClaimPresent && occ.State == StateResolved {
		regress, err = s.isRegression(ctx, tx, occ.ID, observedAt, in.ObservedRevision, in.ObservedArtifactDigest)
		if err != nil {
			return ItemResult{}, err
		}
	}

	if _, err := tx.Exec(ctx, `INSERT INTO security_observations
		(id, occurrence_id, tenant, provider_ref, observation_hash, delivery_id, source_finding_id, claimed_action,
		 observed_revision, observed_artifact_digest, evidence_refs, evidence_digest, untrusted,
		 observed_at, ingested_at, ingested_by_principal_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		obsID, occ.ID, in.Tenant, pc.Ref, hash, deliveryID, in.SourceFindingID, in.ClaimedAction,
		in.ObservedRevision, in.ObservedArtifactDigest, marshal(nonNilRefs(in.EvidenceRefs)), hashJSON(in.EvidenceRefs),
		marshal(in.Untrusted), observedAt, now, pc.PrincipalID); err != nil {
		return ItemResult{}, fmt.Errorf("securityfindings: record observation: %w", err)
	}

	// Projections and timestamps; never state.
	if in.ClaimedAction == ClaimPresent {
		if _, err := tx.Exec(ctx, `UPDATE security_occurrences SET
			last_observed_at = $2,
			current_affected_revision = CASE WHEN $3 <> '' THEN $3 ELSE current_affected_revision END,
			current_affected_artifact = CASE WHEN $4 <> '' THEN $4 ELSE current_affected_artifact END
			WHERE id = $1`, occ.ID, now, in.ObservedRevision, in.ObservedArtifactDigest); err != nil {
			return ItemResult{}, fmt.Errorf("securityfindings: update projection: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `UPDATE security_occurrences SET last_observed_at = $2 WHERE id = $1`, occ.ID, now); err != nil {
		return ItemResult{}, fmt.Errorf("securityfindings: touch occurrence: %w", err)
	}

	refs := map[string]string{"observation_id": obsID, "provider": pc.Ref}
	switch {
	case regress:
		if in.ObservedRevision != "" {
			refs["revision"] = in.ObservedRevision
		}
		if in.ObservedArtifactDigest != "" {
			refs["artifact_digest"] = in.ObservedArtifactDigest
		}
		to, err := s.move(ctx, tx, occ, ActionRegress, actor, "present again after resolution", refs, "")
		if err != nil {
			return ItemResult{}, err
		}
		res.Transition = to
	case (in.ClaimedAction == ClaimFixed || in.ClaimedAction == ClaimAbsent) &&
		occ.State == StateAwaitingVerification && occ.ActiveAttempt != "":
		to, err := s.verifyFromObservation(ctx, tx, pc, occ, actor, in, obsID)
		if err != nil {
			return ItemResult{}, err
		}
		if to != "" {
			res.Transition = to
		}
	}
	return res, nil
}

func nonNilRefs(r []EvidenceRef) []EvidenceRef {
	if r == nil {
		return []EvidenceRef{}
	}
	return r
}

// isRegression applies the regression rule: observed after the resolving
// attempt ended, and not at a revision or artifact recorded as affected
// before that fix landed.
func (s *Store) isRegression(ctx context.Context, tx pgx.Tx, occurrenceID string, observedAt time.Time, revision, artifact string) (bool, error) {
	var endedAt, landedAt *time.Time
	var snapshot []string
	err := tx.QueryRow(ctx, `SELECT ended_at, landed_at, affected_revisions FROM security_remediation_attempts
		WHERE occurrence_id = $1 AND outcome = 'resolved' ORDER BY seq DESC LIMIT 1`, occurrenceID).Scan(&endedAt, &landedAt, &snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("securityfindings: resolving attempt: %w", err)
	}
	if endedAt == nil || !observedAt.After(*endedAt) {
		return false, nil
	}
	affected := map[string]bool{}
	for _, a := range snapshot {
		affected[a] = true
	}
	cutoff := *endedAt
	if landedAt != nil {
		cutoff = *landedAt
	}
	rows, err := tx.Query(ctx, `SELECT observed_revision, observed_artifact_digest FROM security_observations
		WHERE occurrence_id = $1 AND claimed_action = 'present' AND observed_at <= $2`, occurrenceID, cutoff)
	if err != nil {
		return false, fmt.Errorf("securityfindings: affected revisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rev, dig string
		if err := rows.Scan(&rev, &dig); err != nil {
			return false, fmt.Errorf("securityfindings: affected scan: %w", err)
		}
		affected[rev], affected[dig] = true, true
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("securityfindings: affected rows: %w", err)
	}
	delete(affected, "")
	if revision != "" && affected[revision] {
		return false, nil
	}
	if artifact != "" && affected[artifact] {
		return false, nil
	}
	return true, nil
}

// verifyFromObservation turns a provider's fixed or absent claim into a
// verification when, and only when, it is bound to the landed revision or
// artifact. An unbound claim stays a recorded observation. The strength is
// capped by the provider's configured ceiling.
func (s *Store) verifyFromObservation(ctx context.Context, tx pgx.Tx, pc ProviderContext, occ *occRow, actor Actor, in ObservationInput, obsID string) (string, error) {
	att, err := loadAttempt(ctx, tx, occ.ActiveAttempt)
	if err != nil {
		return "", err
	}
	if !att.bound(in.ObservedRevision, in.ObservedArtifactDigest) {
		return "", nil
	}
	mechanism := StrengthScannerRerunExactRevision
	if in.ClaimedAction == ClaimFixed {
		mechanism = StrengthProviderClaim
	}
	ceiling := pc.MaxStrength
	if ceiling == "" {
		ceiling = StrengthProviderClaim
	}
	to, _, err := s.recordVerificationTx(ctx, tx, occ, att, verificationData{
		mechanism: mechanism, result: ResultPassed, revision: in.ObservedRevision, artifact: in.ObservedArtifactDigest,
		refs: in.EvidenceRefs, sourceObservation: obsID, ceiling: ceiling,
	}, actor)
	return to, err
}
