package workitems

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Release grant decisions (mctl-api#1022, slice S2).
//
// A release.grant request is decided only on the release approval page, by
// the owner, after a fresh sign-in whose ID token reports a second factor.
// What that sign-in proved is the decision's evidence, and it is stored in
// the row itself, without a schema change:
//
//	reason                 = the evidence, canonical JSON (ReleaseEvidence)
//	decided_context_digest = sha256 over exactly those bytes
//	authority_basis        = ReleaseAuthorityBasis
//
// A reader (the release gate) recomputes the digest and re-reads the
// evidence with ReleaseDecisionOf; a row whose evidence does not reproduce
// its digest, or does not name the artifact the row binds, is not a decision.
// No schema change on purpose: the work-items DDL is moving to a migration
// role (mctl-api#1004), and a new table would mean a schema version bump that
// every non-owner deployment would have to apply first.

const (
	// ReleaseAuthorityBasis is the authority a release grant is approved
	// under: the owner principal list, a fresh sign-in, a second factor.
	ReleaseAuthorityBasis = "release.owner.fresh_mfa"

	// ReleaseEvidenceSchema names the evidence encoding.
	ReleaseEvidenceSchema = "mctl-release-decision/v1"
)

var (
	releaseAMRRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
	releaseClaimsRe = regexp.MustCompile(`^[\x21-\x7e]{1,255}$`)
)

// ReleaseEvidence is what the decider's fresh sign-in proved. Every field is
// from the verified ID token or the page's own configuration, never from a
// request body.
type ReleaseEvidence struct {
	Schema string `json:"schema"`
	// ArgsDigest is the args digest of the request the decider was shown.
	ArgsDigest string `json:"args_digest"`
	// Issuer, Subject and ClientID are the ID token's iss, sub and the
	// client it was issued to (aud, single-valued, equal to azp if present).
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	ClientID string `json:"client_id"`
	// AuthTime is auth_time, the moment of the sign-in.
	AuthTime int64 `json:"auth_time"`
	// AMR is the ID token's amr, sorted and deduplicated.
	AMR []string `json:"amr"`
}

// Validate refuses evidence that is incomplete or not in canonical form.
func (e ReleaseEvidence) Validate() error {
	switch {
	case e.Schema != ReleaseEvidenceSchema:
		return invalid("release evidence schema %q is not %q", e.Schema, ReleaseEvidenceSchema)
	case !releaseDigestRe.MatchString(e.ArgsDigest):
		return invalid("release evidence args digest %q is malformed", e.ArgsDigest)
	case !releaseClaimsRe.MatchString(e.Issuer), !releaseClaimsRe.MatchString(e.Subject), !releaseClaimsRe.MatchString(e.ClientID):
		return invalid("release evidence needs an issuer, subject and client id")
	case e.AuthTime <= 0:
		return invalid("release evidence needs auth_time")
	case len(e.AMR) == 0 || len(e.AMR) > 16:
		return invalid("release evidence needs between 1 and 16 amr values")
	}
	for i, m := range e.AMR {
		if !releaseAMRRe.MatchString(m) {
			return invalid("release evidence amr value %q is malformed", m)
		}
		if i > 0 && e.AMR[i-1] >= m {
			return invalid("release evidence amr is not sorted and unique")
		}
	}
	return nil
}

// Encode is the canonical encoding stored in reason.
func (e ReleaseEvidence) Encode() (string, string, error) {
	if err := e.Validate(); err != nil {
		return "", "", err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", "", fmt.Errorf("workitems: encode release evidence: %w", err)
	}
	sum := sha256.Sum256(b)
	return string(b), "sha256:" + hex.EncodeToString(sum[:]), nil
}

// NormalizeAMR sorts and deduplicates amr values as ReleaseEvidence wants.
func NormalizeAMR(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// ReleaseDecisionInput decides one release.grant request.
type ReleaseDecisionInput struct {
	ID                   string
	DecidedBy            string
	DecidedByPrincipalID string
	Approve              bool
	Evidence             ReleaseEvidence
}

// DecideReleaseApproval decides a pending release.grant request. The row is
// locked, must be a self-consistent release grant (ReleaseArtifactOf), and
// must still carry the args digest the decider was shown; both an approval
// and a rejection record the evidence of the sign-in that made them.
func (s *Store) DecideReleaseApproval(ctx context.Context, in ReleaseDecisionInput) (*ActionApprovalRequest, error) {
	if in.DecidedByPrincipalID == "" {
		return nil, fmt.Errorf("%w: %s", ErrApprovalDeciderUnresolved, in.ID)
	}
	if err := checkText("decided_by", in.DecidedBy, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	reason, digest, err := in.Evidence.Encode()
	if err != nil {
		return nil, err
	}
	if len(reason) > MaxApprovalReasonBytes {
		return nil, invalid("release evidence is longer than %d bytes", MaxApprovalReasonBytes)
	}
	to := ApprovalDenied
	if in.Approve {
		to = ApprovalApproved
	}
	var out *ActionApprovalRequest
	err = s.withTx(ctx, "action-approval:"+in.ID, func(tx pgx.Tx) error {
		cur, err := s.getActionApproval(ctx, tx, in.ID, " FOR UPDATE")
		if err != nil {
			return err
		}
		if cur.ActionKind != ActionKindReleaseGrant {
			return fmt.Errorf("%w: %s", ErrApprovalKindNotSpendable, cur.ID)
		}
		if _, err := ReleaseArtifactOf(cur); err != nil {
			return err
		}
		if cur.ArgsDigest != in.Evidence.ArgsDigest {
			return fmt.Errorf("%w: %s no longer binds what was shown", ErrApprovalTargetMismatch, cur.ID)
		}
		switch cur.State {
		case ApprovalPending:
		case ApprovalExpired:
			return fmt.Errorf("%w: %s expired at %s", ErrApprovalExpired, cur.ID, cur.ExpiresAt.Format(time.RFC3339))
		default:
			return fmt.Errorf("%w: %s is %s", ErrApprovalAlreadyDecided, cur.ID, cur.State)
		}
		now := s.now()
		out, err = scanActionApproval(tx.QueryRow(ctx, `UPDATE action_approval_requests
			SET state=$2, decided_by=$3, decided_at=$4, reason=$5, decided_by_principal_id=$6,
			    decided_context_digest=$7, authority_basis=$8
			WHERE id=$1 AND state='pending' AND action_kind=$9 RETURNING `+actionApprovalColumns,
			cur.ID, to, in.DecidedBy, now, reason, in.DecidedByPrincipalID, digest, ReleaseAuthorityBasis,
			ActionKindReleaseGrant), now)
		if err != nil {
			return fmt.Errorf("workitems: decide release approval: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseDecisionOf reads the evidence of a decided release grant and checks
// it against the row: the stored digest must be the digest of the stored
// evidence, the evidence must be canonical and must name the args digest of
// this row, and the authority basis must be the release one. A pending row
// has no decision (nil, nil).
func ReleaseDecisionOf(a *ActionApprovalRequest) (*ReleaseEvidence, error) {
	if _, err := ReleaseArtifactOf(a); err != nil {
		return nil, err
	}
	if a.State == ApprovalPending || (a.State == ApprovalExpired && a.DecidedAt == nil) {
		return nil, nil
	}
	if a.AuthorityBasis != ReleaseAuthorityBasis {
		return nil, invalid("release grant %s was not decided under %s", a.ID, ReleaseAuthorityBasis)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(a.Reason)))
	dec.DisallowUnknownFields()
	var e ReleaseEvidence
	if err := dec.Decode(&e); err != nil {
		return nil, invalid("release grant %s: evidence unreadable", a.ID)
	}
	reason, digest, err := e.Encode()
	if err != nil {
		return nil, invalid("release grant %s: %v", a.ID, err)
	}
	switch {
	case reason != a.Reason:
		return nil, invalid("release grant %s: evidence is not canonical", a.ID)
	case digest != a.DecidedContextDigest:
		return nil, invalid("release grant %s: evidence does not reproduce its digest", a.ID)
	case e.ArgsDigest != a.ArgsDigest:
		return nil, invalid("release grant %s: evidence names another request", a.ID)
	}
	return &e, nil
}
