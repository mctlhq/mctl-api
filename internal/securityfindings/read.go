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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Page limits.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const occurrenceColumns = `id, finding_id, tenant, subject_fingerprint, subject, state, state_version,
	COALESCE(active_attempt_id, ''), current_affected_revision, current_affected_artifact,
	dismissal_reason, dismissal_authority_ref, dismissed_by, created_at, updated_at, last_observed_at`

func scanOccurrence(row pgx.Row) (*Occurrence, error) {
	var o Occurrence
	if err := row.Scan(&o.ID, &o.FindingID, &o.Tenant, &o.SubjectFingerprint, &o.Subject, &o.State, &o.StateVersion,
		&o.ActiveAttemptID, &o.CurrentAffectedRevision, &o.CurrentAffectedArtifact,
		&o.DismissalReason, &o.DismissalAuthorityRef, &o.DismissedBy, &o.CreatedAt, &o.UpdatedAt, &o.LastObservedAt); err != nil {
		return nil, err
	}
	o.CreatedAt, o.UpdatedAt, o.LastObservedAt = o.CreatedAt.UTC(), o.UpdatedAt.UTC(), o.LastObservedAt.UTC()
	return &o, nil
}

func pageSize(n int) int {
	switch {
	case n <= 0:
		return DefaultPageSize
	case n > MaxPageSize:
		return MaxPageSize
	}
	return n
}

// keyset cursor: "<unix nanos>|<id>" over (created_at DESC, id DESC).
func parseCursor(c string) (time.Time, string, error) {
	if c == "" {
		return time.Time{}, "", nil
	}
	ns, id, ok := strings.Cut(c, "|")
	n, err := strconv.ParseInt(ns, 10, 64)
	if !ok || err != nil || id == "" {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	return time.Unix(0, n).UTC(), id, nil
}

func makeCursor(t time.Time, id string) string { return strconv.FormatInt(t.UnixNano(), 10) + "|" + id }

// whereBuilder accumulates a parameterized WHERE clause.
type whereBuilder struct {
	clauses []string
	args    []any
}

func (w *whereBuilder) add(clause string, arg any) {
	w.args = append(w.args, arg)
	w.clauses = append(w.clauses, strings.ReplaceAll(clause, "?", "$"+strconv.Itoa(len(w.args))))
}

func (w *whereBuilder) sql() string {
	if len(w.clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.clauses, " AND ")
}

func (w *whereBuilder) visibility(prefix string, vis Visibility, tenant string) {
	if !vis.All {
		w.add(prefix+"tenant = ANY(?)", append([]string{}, vis.Tenants...))
	}
	if tenant != "" {
		w.add(prefix+"tenant = ?", tenant)
	}
}

func (w *whereBuilder) cursor(c string) error {
	t, id, err := parseCursor(c)
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	w.args = append(w.args, t, id)
	n := len(w.args)
	w.clauses = append(w.clauses, fmt.Sprintf("(created_at, id) < ($%d, $%d)", n-1, n))
	return nil
}

func identityKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if up := strings.ToUpper(raw); cvePattern.MatchString(up) {
		return "cve:" + up
	}
	if lo := strings.ToLower(raw); ghsaPattern.MatchString(lo) {
		return "ghsa:" + lo
	}
	return raw
}

// ListFindings returns the visible findings, newest first. next is the
// cursor of the following page, empty on the last.
func (s *Store) ListFindings(ctx context.Context, vis Visibility, f ListFilter) ([]Finding, string, error) {
	limit := pageSize(f.Limit)
	var w whereBuilder
	w.visibility("", vis, f.Tenant)
	if f.Identity != "" {
		w.add(`(identity_key = ? OR EXISTS (SELECT 1 FROM security_finding_aliases a
			WHERE a.finding_id = security_findings.id AND a.alias_key = ?))`, identityKey(f.Identity))
	}
	if f.State != "" || f.Repository != "" {
		var sub whereBuilder
		sub.args = w.args
		sub.clauses = []string{"o.finding_id = security_findings.id"}
		if f.State != "" {
			sub.add("o.state = ?", f.State)
		}
		if f.Repository != "" {
			sub.add("o.subject->>'repository' = ?", normalizeRepository(f.Repository))
		}
		w.args = sub.args
		w.clauses = append(w.clauses, "EXISTS (SELECT 1 FROM security_occurrences o WHERE "+strings.Join(sub.clauses, " AND ")+")")
	}
	if err := w.cursor(f.Cursor); err != nil {
		return nil, "", err
	}
	q := `SELECT id, tenant, identity_kind, identity_key, created_at, last_observed_at, schema_version
		FROM security_findings` + w.sql() + ` ORDER BY created_at DESC, id DESC LIMIT ` + strconv.Itoa(limit+1)
	rows, err := s.pool.Query(ctx, q, w.args...)
	if err != nil {
		return nil, "", fmt.Errorf("securityfindings: list findings: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Tenant, &f.IdentityKind, &f.IdentityKey, &f.CreatedAt, &f.LastObservedAt, &f.SchemaVersion); err != nil {
			return nil, "", fmt.Errorf("securityfindings: scan finding: %w", err)
		}
		f.CreatedAt, f.LastObservedAt = f.CreatedAt.UTC(), f.LastObservedAt.UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("securityfindings: list findings: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = makeCursor(out[limit-1].CreatedAt, out[limit-1].ID)
	}
	return out, next, nil
}

// GetFinding returns one finding with every occurrence and, under each, its
// observations, remediation attempts, verifications and events. A finding in
// a tenant the caller cannot access is ErrNotFound.
func (s *Store) GetFinding(ctx context.Context, vis Visibility, id string) (*Finding, error) {
	var f Finding
	err := s.pool.QueryRow(ctx, `SELECT id, tenant, identity_kind, identity_key, created_at, last_observed_at, schema_version
		FROM security_findings WHERE id = $1`, id).
		Scan(&f.ID, &f.Tenant, &f.IdentityKind, &f.IdentityKey, &f.CreatedAt, &f.LastObservedAt, &f.SchemaVersion)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !vis.allows(f.Tenant)) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load finding: %w", err)
	}
	f.CreatedAt, f.LastObservedAt = f.CreatedAt.UTC(), f.LastObservedAt.UTC()

	rows, err := s.pool.Query(ctx, `SELECT alias_key FROM security_finding_aliases WHERE finding_id = $1 ORDER BY alias_key`, id)
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load aliases: %w", err)
	}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return nil, fmt.Errorf("securityfindings: scan alias: %w", err)
		}
		f.Aliases = append(f.Aliases, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("securityfindings: load aliases: %w", err)
	}

	orows, err := s.pool.Query(ctx, `SELECT `+occurrenceColumns+` FROM security_occurrences WHERE finding_id = $1 ORDER BY created_at, id`, id)
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load occurrences: %w", err)
	}
	var occs []Occurrence
	for orows.Next() {
		o, err := scanOccurrence(orows)
		if err != nil {
			orows.Close()
			return nil, fmt.Errorf("securityfindings: scan occurrence: %w", err)
		}
		occs = append(occs, *o)
	}
	orows.Close()
	if err := orows.Err(); err != nil {
		return nil, fmt.Errorf("securityfindings: load occurrences: %w", err)
	}
	for i := range occs {
		if err := s.loadHistory(ctx, &occs[i]); err != nil {
			return nil, err
		}
	}
	f.Occurrences = occs
	return &f, nil
}

// ListOccurrences returns visible occurrence summaries, newest first.
func (s *Store) ListOccurrences(ctx context.Context, vis Visibility, f ListFilter) ([]Occurrence, string, error) {
	limit := pageSize(f.Limit)
	var w whereBuilder
	w.visibility("", vis, f.Tenant)
	if f.FindingID != "" {
		w.add("finding_id = ?", f.FindingID)
	}
	if f.State != "" {
		w.add("state = ?", f.State)
	}
	if f.Repository != "" {
		w.add("subject->>'repository' = ?", normalizeRepository(f.Repository))
	}
	if err := w.cursor(f.Cursor); err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+occurrenceColumns+` FROM security_occurrences`+w.sql()+
		` ORDER BY created_at DESC, id DESC LIMIT `+strconv.Itoa(limit+1), w.args...)
	if err != nil {
		return nil, "", fmt.Errorf("securityfindings: list occurrences: %w", err)
	}
	defer rows.Close()
	out := []Occurrence{}
	for rows.Next() {
		o, err := scanOccurrence(rows)
		if err != nil {
			return nil, "", fmt.Errorf("securityfindings: scan occurrence: %w", err)
		}
		out = append(out, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("securityfindings: list occurrences: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = makeCursor(out[limit-1].CreatedAt, out[limit-1].ID)
	}
	return out, next, nil
}

// GetOccurrence returns one occurrence with its full history.
func (s *Store) GetOccurrence(ctx context.Context, vis Visibility, id string) (*Occurrence, error) {
	o, err := scanOccurrence(s.pool.QueryRow(ctx, `SELECT `+occurrenceColumns+` FROM security_occurrences WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !vis.allows(o.Tenant)) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load occurrence: %w", err)
	}
	if err := s.loadHistory(ctx, o); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) loadHistory(ctx context.Context, o *Occurrence) error {
	var q queryer = s.pool

	rows, err := q.Query(ctx, `SELECT id, occurrence_id, provider_ref, observation_hash, delivery_id, source_finding_id, claimed_action,
		observed_revision, observed_artifact_digest, evidence_refs, untrusted, observed_at, ingested_at
		FROM security_observations WHERE occurrence_id = $1 ORDER BY observed_at, ingested_at, id`, o.ID)
	if err != nil {
		return fmt.Errorf("securityfindings: load observations: %w", err)
	}
	for rows.Next() {
		var x Observation
		if err := rows.Scan(&x.ID, &x.OccurrenceID, &x.ProviderRef, &x.ObservationHash, &x.DeliveryID, &x.SourceFindingID, &x.ClaimedAction,
			&x.ObservedRevision, &x.ObservedArtifactDigest, &x.EvidenceRefs, &x.Untrusted, &x.ObservedAt, &x.IngestedAt); err != nil {
			rows.Close()
			return fmt.Errorf("securityfindings: scan observation: %w", err)
		}
		x.ObservedAt, x.IngestedAt = x.ObservedAt.UTC(), x.IngestedAt.UTC()
		o.Observations = append(o.Observations, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("securityfindings: load observations: %w", err)
	}

	rows, err = q.Query(ctx, `SELECT id, occurrence_id, seq, work_item_id, execution_id, devloop_workflow_id, started_by, start_source,
		affected_revisions, candidate_revision, landed_revision, landed_artifact_digest, landed_ref,
		COALESCE(outcome, ''), started_at, landed_at, ended_at
		FROM security_remediation_attempts WHERE occurrence_id = $1 ORDER BY seq`, o.ID)
	if err != nil {
		return fmt.Errorf("securityfindings: load attempts: %w", err)
	}
	for rows.Next() {
		var x Attempt
		if err := rows.Scan(&x.ID, &x.OccurrenceID, &x.Seq, &x.WorkItemID, &x.ExecutionID, &x.DevloopWorkflowID, &x.StartedBy, &x.StartSource,
			&x.AffectedRevisions, &x.CandidateRevision, &x.LandedRevision, &x.LandedArtifactDigest, &x.LandedRef,
			&x.Outcome, &x.StartedAt, &x.LandedAt, &x.EndedAt); err != nil {
			rows.Close()
			return fmt.Errorf("securityfindings: scan attempt: %w", err)
		}
		x.StartedAt = x.StartedAt.UTC()
		x.LandedAt, x.EndedAt = utcPtr(x.LandedAt), utcPtr(x.EndedAt)
		o.Attempts = append(o.Attempts, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("securityfindings: load attempts: %w", err)
	}

	rows, err = q.Query(ctx, `SELECT id, attempt_id, occurrence_id, mechanism, declared_strength, derived_strength, result,
		revision, artifact_digest, evidence_refs, recorded_by, source_observation_id, recorded_at
		FROM security_verifications WHERE occurrence_id = $1 ORDER BY recorded_at, id`, o.ID)
	if err != nil {
		return fmt.Errorf("securityfindings: load verifications: %w", err)
	}
	for rows.Next() {
		var x Verification
		if err := rows.Scan(&x.ID, &x.AttemptID, &x.OccurrenceID, &x.Mechanism, &x.DeclaredStrength, &x.DerivedStrength, &x.Result,
			&x.Revision, &x.ArtifactDigest, &x.EvidenceRefs, &x.RecordedBy, &x.SourceObservationID, &x.RecordedAt); err != nil {
			rows.Close()
			return fmt.Errorf("securityfindings: scan verification: %w", err)
		}
		x.RecordedAt = x.RecordedAt.UTC()
		o.Verifications = append(o.Verifications, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("securityfindings: load verifications: %w", err)
	}

	rows, err = q.Query(ctx, `SELECT occurrence_id, seq, kind, from_state, to_state, actor_principal, actor_principal_id,
		via_principal_id, source, reason, refs, created_at
		FROM security_occurrence_events WHERE occurrence_id = $1 ORDER BY seq`, o.ID)
	if err != nil {
		return fmt.Errorf("securityfindings: load events: %w", err)
	}
	for rows.Next() {
		var x Event
		if err := rows.Scan(&x.OccurrenceID, &x.Seq, &x.Kind, &x.FromState, &x.ToState, &x.ActorPrincipal, &x.ActorPrincipalID,
			&x.ViaPrincipalID, &x.Source, &x.Reason, &x.Refs, &x.CreatedAt); err != nil {
			rows.Close()
			return fmt.Errorf("securityfindings: scan event: %w", err)
		}
		x.CreatedAt = x.CreatedAt.UTC()
		o.Events = append(o.Events, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("securityfindings: load events: %w", err)
	}
	return nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
