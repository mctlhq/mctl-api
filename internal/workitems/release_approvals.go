package workitems

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Release grants (mctl-api#1022, mctlhq/mctl-gitops#2528).
//
// A release.grant approval is the owner's decision that one release of one
// repository may reach production: one version, its tag commit and the image
// digest built from it. The server builds the intent after it has read the
// tag and the image itself; nothing in it comes from a request body.
//
// Like the deploy and Glovo kinds, release kinds live in their own namespace,
// and every generic route refuses them (isDedicatedKind). This slice (S1)
// adds only creation and reading. There is no way yet to decide a release
// grant: the decision belongs to a fresh, MFA-backed sign-in page (S2), and
// until it exists a release request stays pending and grants nothing.
//
// The intent maps onto the generic columns as follows:
//
//	execution_id  = the tag commit (40 hex)
//	target        = <repository>@<version>, e.g. mctlhq/mctl-api@4.163.0
//	artifact_hash = the image manifest digest (sha256:<64 hex>)
//	args_digest   = ReleaseArgsDigest over all of the above
//
// so the record can be verified by a reader who knows only the repository,
// version, commit and digest, without trusting anything else in the row.

const (
	// ActionKindReleaseGrant is the grant of one release to production.
	ActionKindReleaseGrant = "release.grant"

	// releaseKindPrefix is the namespace of release kinds.
	releaseKindPrefix = "release."

	// ReleaseGrantPolicyRuleID and ReleaseGrantPolicyVersion are the policy
	// a release grant is created under (governance.Policies).
	ReleaseGrantPolicyRuleID  = "release.grant.owner"
	ReleaseGrantPolicyVersion = "1"

	// releaseIdempotencyPrefix scopes UNIQUE (requested_by, idempotency_key)
	// to one artifact: one request per repository, version and image digest.
	// A tag moved to another image is another request.
	releaseIdempotencyPrefix = "release-grant:"

	releaseArgsDigestDomain = "mctl-release-grant/v1\n"
)

var (
	releaseRepoRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$`)
	releaseVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	releaseCommitRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releaseDigestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// IsReleaseKind reports whether kind is in the release namespace. The prefix
// is the predicate: "release.other" is refused by the generic paths too.
func IsReleaseKind(kind string) bool { return strings.HasPrefix(kind, releaseKindPrefix) }

// ReleaseArtifact is what a release grant binds.
type ReleaseArtifact struct {
	Repository  string `json:"repository"`
	Version     string `json:"version"`
	TagCommit   string `json:"tag_commit"`
	ImageDigest string `json:"image_digest"`
}

// Validate refuses an artifact that is not in canonical form.
func (a ReleaseArtifact) Validate() error {
	switch {
	case !releaseRepoRe.MatchString(a.Repository):
		return invalid("release repository %q is not a lower-case owner/name", a.Repository)
	case !releaseVersionRe.MatchString(a.Version):
		return invalid("release version %q is not X.Y.Z", a.Version)
	case !releaseCommitRe.MatchString(a.TagCommit):
		return invalid("release tag commit %q is not a full lower-case SHA-1", a.TagCommit)
	case !releaseDigestRe.MatchString(a.ImageDigest):
		return invalid("release image digest %q is not sha256:<64 hex>", a.ImageDigest)
	}
	return nil
}

// ReleaseTarget is the target column of a release grant.
func ReleaseTarget(repository, version string) string { return repository + "@" + version }

// ReleaseArgsDigest is sha256 over a fixed, newline-separated encoding of the
// artifact. None of the fields may contain a newline (Validate), so the
// encoding is unambiguous.
func ReleaseArgsDigest(a ReleaseArtifact) string {
	sum := sha256.Sum256([]byte(releaseArgsDigestDomain +
		"repository=" + a.Repository + "\n" +
		"version=" + a.Version + "\n" +
		"tag_commit=" + a.TagCommit + "\n" +
		"image_digest=" + a.ImageDigest + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ReleaseIdempotencyKey is the idempotency key of the grant request for an
// artifact.
func ReleaseIdempotencyKey(a ReleaseArtifact) string {
	return releaseIdempotencyPrefix + ReleaseTarget(a.Repository, a.Version) + ":" + a.ImageDigest
}

// ReleaseIntent is the intent of the grant for an artifact.
func ReleaseIntent(a ReleaseArtifact) ActionIntent {
	return ActionIntent{
		ExecutionID:   a.TagCommit,
		ActionKind:    ActionKindReleaseGrant,
		Target:        ReleaseTarget(a.Repository, a.Version),
		ArgsDigest:    ReleaseArgsDigest(a),
		PolicyRuleID:  ReleaseGrantPolicyRuleID,
		PolicyVersion: ReleaseGrantPolicyVersion,
		ArtifactHash:  a.ImageDigest,
	}
}

// ReleaseArtifactOf reads the artifact a stored release grant binds and
// checks that the row is self-consistent: the args digest must be the one the
// other columns produce. A row that fails is not a release grant.
func ReleaseArtifactOf(a *ActionApprovalRequest) (ReleaseArtifact, error) {
	if a == nil || a.ActionKind != ActionKindReleaseGrant {
		return ReleaseArtifact{}, invalid("not a %s approval", ActionKindReleaseGrant)
	}
	repo, version, ok := strings.Cut(a.Target, "@")
	if !ok {
		return ReleaseArtifact{}, invalid("release target %q is not repository@version", a.Target)
	}
	art := ReleaseArtifact{Repository: repo, Version: version, TagCommit: a.ExecutionID, ImageDigest: a.ArtifactHash}
	if err := art.Validate(); err != nil {
		return ReleaseArtifact{}, err
	}
	if a.ArgsDigest != ReleaseArgsDigest(art) {
		return ReleaseArtifact{}, invalid("release grant %s: args_digest does not match its artifact", a.ID)
	}
	return art, nil
}

// CreateReleaseApproval stores the pending release.grant request for an
// artifact, or returns the one this requester already holds for it
// (created=false). The caller builds in with ReleaseIntent from an artifact
// it has resolved itself; anything else is refused.
func (s *Store) CreateReleaseApproval(ctx context.Context, art ReleaseArtifact, in ActionApprovalInput) (*ActionApprovalRequest, bool, error) {
	if err := art.Validate(); err != nil {
		return nil, false, err
	}
	switch want := ReleaseIntent(art); {
	case in.ActionIntent != want:
		return nil, false, invalid("a release approval's intent is derived from its artifact")
	case in.IdempotencyKey != ReleaseIdempotencyKey(art):
		return nil, false, invalid("a release approval's idempotency key is derived from its artifact")
	}
	return s.createActionApproval(ctx, in)
}

// ReleaseApprovals lists the release.grant requests for one repository and
// version, newest first, at most limit rows (MaxApprovalList at most).
func (s *Store) ReleaseApprovals(ctx context.Context, repository, version string, limit int) ([]ActionApprovalRequest, error) {
	if !releaseRepoRe.MatchString(repository) || !releaseVersionRe.MatchString(version) {
		return nil, invalid("release grants are listed by a lower-case owner/name and an X.Y.Z version")
	}
	if limit <= 0 || limit > MaxApprovalList {
		limit = MaxApprovalList
	}
	now := s.now()
	rows, err := s.pool.Query(ctx, `SELECT `+actionApprovalColumns+` FROM action_approval_requests
		WHERE action_kind = $1 AND target = $2 ORDER BY created_at DESC, id LIMIT $3`,
		ActionKindReleaseGrant, ReleaseTarget(repository, version), limit)
	if err != nil {
		return nil, fmt.Errorf("workitems: list release approvals: %w", err)
	}
	defer rows.Close()
	out := []ActionApprovalRequest{}
	for rows.Next() {
		a, err := scanActionApproval(rows, now)
		if err != nil {
			return nil, fmt.Errorf("workitems: list release approvals: %w", err)
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("workitems: list release approvals: %w", err)
	}
	return out, nil
}
