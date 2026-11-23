package workitems

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Release window removal (mctl-api, sync-window write path; mctl-gitops
// docs/plans/sync-window-write-path.md, section 6).
//
// A release.window.removal approval is the owner's decision that ONE deny sync
// window may be REMOVED from ONE Argo CD AppProject by a pull request. It is a
// sibling of release.window and shares its shape, but is its own kind, with its
// own policy, authority basis, hash and args-digest domain, so an approval to
// add a window can never be spent as an approval to lift one, or the reverse:
//   - the hash is over {"action":"remove","project":P,"window":W}, which
//     release-window-removal-pr.yml compares (scripts/release-window-insert.py
//     hash-remove); the add hash has no "action" key;
//   - every decide, claim and settle path checks the kind, and the readers
//     (ReleaseWindowOf, ReleaseWindowRemovalOf) each refuse the other's rows.
//
// The window is named exactly as it is stored in the AppProject template, so
// the same canonical form is required as for an addition: applications sorted
// and unique, the shapes the workflow accepts. A window kept in another order
// (one made by hand) is not removable by this tool; the workflow would refuse
// it anyway, because it compares the whole window.
//
// Mapping onto the generic columns is the window's own:
//
//	execution_id  = base_sha, the mctl-gitops main commit the approval is on
//	target        = <project>/<removal id>#<canonical window JSON>
//	artifact_hash = sha256:<removal hash>
//	args_digest   = ReleaseWindowRemovalArgsDigest over all of the above
const (
	// ActionKindReleaseWindowRemoval is the removal of one deny window.
	ActionKindReleaseWindowRemoval = "release.window.removal"

	ReleaseWindowRemovalPolicyRuleID  = "release.window.removal.owner"
	ReleaseWindowRemovalPolicyVersion = "1"

	// ReleaseWindowRemovalAuthorityBasis is the authority a removal is decided
	// under; it differs from the add basis so a reader tells the two apart.
	ReleaseWindowRemovalAuthorityBasis = "release.window.removal.owner.fresh_mfa"

	releaseWindowRemovalIdempotencyPrefix = "release-window-removal:"
	releaseWindowRemovalArgsDigestDomain  = "mctl-release-window-removal/v1\n"
)

var releaseWindowRemovalIDRe = regexp.MustCompile(`^r-[0-9a-f]{12}$`)

// windowRemovalHashBody is the hashed object, in the field order of its
// sorted-key JSON (action, project, window).
type windowRemovalHashBody struct {
	Action  string     `json:"action"`
	Project string     `json:"project"`
	Window  windowBody `json:"window"`
}

// RemovalSHA256 is the hash release-window-removal-pr.yml compares: sha256 over
// {"action":"remove","project":P,"window":W}, hex, no prefix.
func (w ReleaseWindow) RemovalSHA256() (string, error) {
	if err := w.Validate(); err != nil {
		return "", err
	}
	b, err := marshalCompact(windowRemovalHashBody{Action: "remove", Project: w.Project, Window: w.body()})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ReleaseWindowRemovalID is the deterministic id and branch suffix: "r-" and
// the first 12 hex digits of the removal hash. It cannot equal an add id (which
// starts with "w-"), and the hash differs too.
func (w ReleaseWindow) ReleaseWindowRemovalID() (string, error) {
	h, err := w.RemovalSHA256()
	if err != nil {
		return "", err
	}
	return "r-" + h[:12], nil
}

// ReleaseWindowRemovalTarget is the target column.
func ReleaseWindowRemovalTarget(w ReleaseWindow) (string, error) {
	id, err := w.ReleaseWindowRemovalID()
	if err != nil {
		return "", err
	}
	j, err := w.WindowJSON()
	if err != nil {
		return "", err
	}
	return w.Project + "/" + id + "#" + j, nil
}

// ReleaseWindowRemovalArgsDigest is sha256 over a fixed, newline-separated
// encoding of everything the approval binds, in its own domain and with the
// action named, so it can never equal an add digest.
func ReleaseWindowRemovalArgsDigest(w ReleaseWindow) (string, error) {
	h, err := w.RemovalSHA256()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(releaseWindowRemovalArgsDigestDomain +
		"action=remove\n" +
		"project=" + w.Project + "\n" +
		"applications=" + strings.Join(w.Applications, ",") + "\n" +
		"schedule=" + w.Schedule + "\n" +
		"duration=" + w.Duration + "\n" +
		"base_sha=" + w.BaseSHA + "\n" +
		"removal_sha256=" + h + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ReleaseWindowRemovalIdempotencyKey carries base_sha, like the add key: a
// request made on a later main must not replay one the workflow would refuse
// as stale.
func ReleaseWindowRemovalIdempotencyKey(w ReleaseWindow) (string, error) {
	id, err := w.ReleaseWindowRemovalID()
	if err != nil {
		return "", err
	}
	return releaseWindowRemovalIdempotencyPrefix + w.Project + ":" + id + ":" + w.BaseSHA, nil
}

// ReleaseWindowRemovalIntent is the intent of the request.
func ReleaseWindowRemovalIntent(w ReleaseWindow) (ActionIntent, error) {
	target, err := ReleaseWindowRemovalTarget(w)
	if err != nil {
		return ActionIntent{}, err
	}
	digest, err := ReleaseWindowRemovalArgsDigest(w)
	if err != nil {
		return ActionIntent{}, err
	}
	h, err := w.RemovalSHA256()
	if err != nil {
		return ActionIntent{}, err
	}
	return ActionIntent{
		ExecutionID:   w.BaseSHA,
		ActionKind:    ActionKindReleaseWindowRemoval,
		Target:        target,
		ArgsDigest:    digest,
		PolicyRuleID:  ReleaseWindowRemovalPolicyRuleID,
		PolicyVersion: ReleaseWindowRemovalPolicyVersion,
		ArtifactHash:  "sha256:" + h,
	}, nil
}

// ReleaseWindowRemovalOf reads the window a stored release.window.removal
// request binds and checks that the row is self-consistent: the target's id,
// the artifact hash and the args digest must all be the ones the window in the
// target produces. A row that fails, or of another kind, is not a removal.
func ReleaseWindowRemovalOf(a *ActionApprovalRequest) (ReleaseWindow, error) {
	if a == nil || a.ActionKind != ActionKindReleaseWindowRemoval {
		return ReleaseWindow{}, invalid("not a %s approval", ActionKindReleaseWindowRemoval)
	}
	head, raw, ok := strings.Cut(a.Target, "#")
	project, _, ok2 := strings.Cut(head, "/")
	if !ok || !ok2 {
		return ReleaseWindow{}, invalid("release window removal target %q is not <project>/<id>#<window>", a.Target)
	}
	var b windowBody
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return ReleaseWindow{}, invalid("release window removal %s: the window in the target is unreadable", a.ID)
	}
	w := ReleaseWindow{Project: project, Applications: b.Applications, Schedule: b.Schedule, Duration: b.Duration, BaseSHA: a.ExecutionID}
	want, err := ReleaseWindowRemovalIntent(w)
	if err != nil {
		return ReleaseWindow{}, err
	}
	if a.Target != want.Target || a.ArtifactHash != want.ArtifactHash || a.ArgsDigest != want.ArgsDigest {
		return ReleaseWindow{}, invalid("release window removal %s: the row does not reproduce its digests", a.ID)
	}
	return w, nil
}

// CreateReleaseWindowRemovalApproval stores the pending removal request for a
// window, or returns the one this requester already holds for it
// (created=false). The caller builds in with ReleaseWindowRemovalIntent from a
// window whose base_sha it read itself; anything else is refused.
func (s *Store) CreateReleaseWindowRemovalApproval(ctx context.Context, w ReleaseWindow, in ActionApprovalInput) (*ActionApprovalRequest, bool, error) {
	want, err := ReleaseWindowRemovalIntent(w)
	if err != nil {
		return nil, false, err
	}
	key, err := ReleaseWindowRemovalIdempotencyKey(w)
	if err != nil {
		return nil, false, err
	}
	switch {
	case in.ActionIntent != want:
		return nil, false, invalid("a release window removal approval's intent is derived from its window")
	case in.IdempotencyKey != key:
		return nil, false, invalid("a release window removal approval's idempotency key is derived from its window")
	}
	return s.createActionApproval(ctx, in)
}

// DecideReleaseWindowRemovalApproval decides a pending release.window.removal
// request, under the removal authority basis. It refuses a release.window row,
// as DecideReleaseWindowApproval refuses this one.
func (s *Store) DecideReleaseWindowRemovalApproval(ctx context.Context, in ReleaseWindowDecisionInput) (*ActionApprovalRequest, error) {
	return s.decideWindow(ctx, in, windowRemovalSpec)
}

// ReleaseWindowRemovalDecisionOf reads and checks the evidence of a decided
// removal, as ReleaseWindowDecisionOf does for an addition.
func ReleaseWindowRemovalDecisionOf(a *ActionApprovalRequest) (*ReleaseEvidence, error) {
	return windowDecisionOf(a, windowRemovalSpec)
}

// ClaimReleaseWindowRemovalApproval spends an approved removal for one
// dispatch, as ClaimReleaseWindowApproval does for an addition.
func (s *Store) ClaimReleaseWindowRemovalApproval(ctx context.Context, id, caller, intentHash string, reclaimAfter time.Duration) (*ActionApprovalRequest, error) {
	return s.claimWindow(ctx, id, caller, intentHash, reclaimAfter, windowRemovalSpec)
}

// SettleReleaseWindowRemovalApproval ends the claim of a removal.
func (s *Store) SettleReleaseWindowRemovalApproval(ctx context.Context, claim *ActionApprovalRequest, succeeded bool) (*ActionApprovalRequest, error) {
	return s.settleWindow(ctx, claim, succeeded, windowRemovalSpec)
}
