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
	"strings"
)

// Release windows (mctl-api, sync-window write path; proposal issue-2828, 8.2).
//
// A release.window approval is the owner's decision that ONE deny sync window
// may be added to ONE Argo CD AppProject by a pull request. It is a sibling of
// release.grant and lives in the same namespace, so every generic route
// already refuses it (isDedicatedKind). This slice (S1) adds only creation and
// reading; nothing here can decide or spend a window request.
//
// The approval binds exactly what mctl-gitops' release-window-pr.yml checks:
// the workflow rebuilds the window from its inputs, hashes
// {"project":P,"window":W} (scripts/release-window-insert.py hash) and refuses
// unless that equals the approved window_sha256. WindowSHA256 here computes
// the same bytes; release_window_approvals_test.go holds vectors taken from
// the Python script, so the two cannot drift apart unnoticed.
//
// Mapping onto the generic columns:
//
//	execution_id  = base_sha, the mctl-gitops main commit the approval is on
//	target        = <project>/<window_id>#<canonical window JSON>
//	artifact_hash = sha256:<window_sha256>
//	args_digest   = ReleaseWindowArgsDigest over all of the above
//
// The window itself does not fit a dedicated column, so it rides in the
// target (the one roomy column) and ReleaseWindowOf re-derives every other
// column from it: a row whose columns do not reproduce its digests is not a
// release window, the same rule ReleaseArtifactOf applies to a grant.
const (
	// ActionKindReleaseWindow is the addition of one deny window.
	ActionKindReleaseWindow = "release.window"

	// ReleaseWindowPolicyRuleID and ReleaseWindowPolicyVersion are the policy
	// a window request is created under (governance.Policies).
	ReleaseWindowPolicyRuleID  = "release.window.owner"
	ReleaseWindowPolicyVersion = "1"

	// The idempotency key carries base_sha: the hash does not, so a request
	// made on a later main must not replay an older one whose approval the
	// workflow would refuse as stale.
	releaseWindowIdempotencyPrefix = "release-window:"
	releaseWindowArgsDigestDomain  = "mctl-release-window/v1\n"

	// MaxReleaseWindowApplications is the workflow's own bound.
	MaxReleaseWindowApplications = 20
)

var (
	releaseWindowAppRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	releaseWindowScheduleRe = regexp.MustCompile(`^[0-9*/,-]+( [0-9*/,-]+){4}$`)
	releaseWindowDurationRe = regexp.MustCompile(`^([0-9]{1,4}[hm]){1,2}$`)
	releaseWindowSHARe      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releaseWindowIDRe       = regexp.MustCompile(`^w-[0-9a-f]{12}$`)
)

// ReleaseWindowProjects are the AppProjects a window may be added to. Never
// `default`: root-app and argocd-self-managed live there, and a revert PR
// could not apply under a window that matched them.
var ReleaseWindowProjects = []string{"apps", "platform"}

// ReleaseWindow is one deny window request. Applications are exact names in
// sorted order (Validate), because the hash covers the list as given and the
// workflow receives it in this order.
type ReleaseWindow struct {
	Project      string   `json:"project"`
	Applications []string `json:"applications"`
	Schedule     string   `json:"schedule"`
	Duration     string   `json:"duration"`
	BaseSHA      string   `json:"base_sha"`
}

// Validate refuses a window that is not in canonical form. It mirrors the
// workflow's input checks; the workflow, render tool and validator stay the
// authority, this keeps a request from reaching the owner that they would
// refuse.
func (w ReleaseWindow) Validate() error {
	switch {
	case !slices.Contains(ReleaseWindowProjects, w.Project):
		return invalid("release window project %q must be one of %s", w.Project, strings.Join(ReleaseWindowProjects, ", "))
	case len(w.Applications) == 0 || len(w.Applications) > MaxReleaseWindowApplications:
		return invalid("release window needs 1-%d applications", MaxReleaseWindowApplications)
	case !releaseWindowScheduleRe.MatchString(w.Schedule):
		return invalid("release window schedule %q is not a five-field cron", w.Schedule)
	case !releaseWindowDurationRe.MatchString(w.Duration):
		return invalid("release window duration %q must look like 48h, 90m or 1h30m", w.Duration)
	case !releaseWindowSHARe.MatchString(w.BaseSHA):
		return invalid("release window base_sha %q is not a full lower-case SHA-1", w.BaseSHA)
	}
	for i, a := range w.Applications {
		if !releaseWindowAppRe.MatchString(a) {
			return invalid("release window application %q is not an exact Application name", a)
		}
		if i > 0 && w.Applications[i-1] >= a {
			return invalid("release window applications must be sorted and unique")
		}
	}
	return nil
}

// windowBody is the window object the workflow builds, in the field order of
// its sorted-key JSON. Struct order equals key order, so encoding/json emits
// the bytes Python's json.dumps(sort_keys=True, separators=(",", ":")) does.
type windowBody struct {
	Applications []string `json:"applications"`
	Duration     string   `json:"duration"`
	Kind         string   `json:"kind"`
	Schedule     string   `json:"schedule"`
}

type windowHashBody struct {
	Project string     `json:"project"`
	Window  windowBody `json:"window"`
}

func (w ReleaseWindow) body() windowBody {
	return windowBody{Applications: w.Applications, Duration: w.Duration, Kind: "deny", Schedule: w.Schedule}
}

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// WindowJSON is the canonical JSON of the window object, as it appears in the
// target after the '#'.
func (w ReleaseWindow) WindowJSON() (string, error) {
	if err := w.Validate(); err != nil {
		return "", err
	}
	b, err := marshalCompact(w.body())
	return string(b), err
}

// WindowSHA256 is the hash release-window-pr.yml compares: sha256 over
// {"project":P,"window":W}, hex, no prefix.
func (w ReleaseWindow) WindowSHA256() (string, error) {
	if err := w.Validate(); err != nil {
		return "", err
	}
	b, err := marshalCompact(windowHashBody{Project: w.Project, Window: w.body()})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ReleaseWindowID is the deterministic id and branch suffix (design 8.2):
// "w-" and the first 12 hex digits of the window hash. The project is in the
// hash, so the id differs per project.
func (w ReleaseWindow) ReleaseWindowID() (string, error) {
	h, err := w.WindowSHA256()
	if err != nil {
		return "", err
	}
	return "w-" + h[:12], nil
}

// ReleaseWindowTarget is the target column.
func ReleaseWindowTarget(w ReleaseWindow) (string, error) {
	id, err := w.ReleaseWindowID()
	if err != nil {
		return "", err
	}
	j, err := w.WindowJSON()
	if err != nil {
		return "", err
	}
	return w.Project + "/" + id + "#" + j, nil
}

// ReleaseWindowArgsDigest is sha256 over a fixed, newline-separated encoding
// of everything the approval binds. Validate keeps newlines out of every
// field, so the encoding is unambiguous.
func ReleaseWindowArgsDigest(w ReleaseWindow) (string, error) {
	h, err := w.WindowSHA256()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(releaseWindowArgsDigestDomain +
		"project=" + w.Project + "\n" +
		"applications=" + strings.Join(w.Applications, ",") + "\n" +
		"schedule=" + w.Schedule + "\n" +
		"duration=" + w.Duration + "\n" +
		"base_sha=" + w.BaseSHA + "\n" +
		"window_sha256=" + h + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ReleaseWindowIdempotencyKey is the idempotency key of the request.
func ReleaseWindowIdempotencyKey(w ReleaseWindow) (string, error) {
	id, err := w.ReleaseWindowID()
	if err != nil {
		return "", err
	}
	return releaseWindowIdempotencyPrefix + w.Project + ":" + id + ":" + w.BaseSHA, nil
}

// ReleaseWindowIntent is the intent of the request.
func ReleaseWindowIntent(w ReleaseWindow) (ActionIntent, error) {
	target, err := ReleaseWindowTarget(w)
	if err != nil {
		return ActionIntent{}, err
	}
	digest, err := ReleaseWindowArgsDigest(w)
	if err != nil {
		return ActionIntent{}, err
	}
	h, err := w.WindowSHA256()
	if err != nil {
		return ActionIntent{}, err
	}
	return ActionIntent{
		ExecutionID:   w.BaseSHA,
		ActionKind:    ActionKindReleaseWindow,
		Target:        target,
		ArgsDigest:    digest,
		PolicyRuleID:  ReleaseWindowPolicyRuleID,
		PolicyVersion: ReleaseWindowPolicyVersion,
		ArtifactHash:  "sha256:" + h,
	}, nil
}

// ReleaseWindowOf reads the window a stored release.window request binds and
// checks that the row is self-consistent: the target's id, the artifact hash
// and the args digest must all be the ones the window in the target produces.
// A row that fails is not a release window.
func ReleaseWindowOf(a *ActionApprovalRequest) (ReleaseWindow, error) {
	if a == nil || a.ActionKind != ActionKindReleaseWindow {
		return ReleaseWindow{}, invalid("not a %s approval", ActionKindReleaseWindow)
	}
	head, raw, ok := strings.Cut(a.Target, "#")
	project, id, ok2 := strings.Cut(head, "/")
	if !ok || !ok2 {
		return ReleaseWindow{}, invalid("release window target %q is not <project>/<id>#<window>", a.Target)
	}
	var b windowBody
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return ReleaseWindow{}, invalid("release window %s: the window in the target is unreadable", a.ID)
	}
	// The kind is not read back: the target is compared whole with the one the
	// window re-derives (always "deny"), so any other kind fails that check.
	w := ReleaseWindow{Project: project, Applications: b.Applications, Schedule: b.Schedule, Duration: b.Duration, BaseSHA: a.ExecutionID}
	want, err := ReleaseWindowIntent(w)
	if err != nil {
		return ReleaseWindow{}, err
	}
	if !strings.HasPrefix(a.Target, project+"/"+id+"#") || a.Target != want.Target ||
		a.ArtifactHash != want.ArtifactHash || a.ArgsDigest != want.ArgsDigest {
		return ReleaseWindow{}, invalid("release window %s: the row does not reproduce its digests", a.ID)
	}
	return w, nil
}

// CreateReleaseWindowApproval stores the pending release.window request for a
// window, or returns the one this requester already holds for it
// (created=false). The caller builds in with ReleaseWindowIntent from a window
// whose base_sha it read itself; anything else is refused.
func (s *Store) CreateReleaseWindowApproval(ctx context.Context, w ReleaseWindow, in ActionApprovalInput) (*ActionApprovalRequest, bool, error) {
	want, err := ReleaseWindowIntent(w)
	if err != nil {
		return nil, false, err
	}
	key, err := ReleaseWindowIdempotencyKey(w)
	if err != nil {
		return nil, false, err
	}
	switch {
	case in.ActionIntent != want:
		return nil, false, invalid("a release window approval's intent is derived from its window")
	case in.IdempotencyKey != key:
		return nil, false, invalid("a release window approval's idempotency key is derived from its window")
	}
	return s.createActionApproval(ctx, in)
}

// ReleaseWindowApprovals lists the release.window requests for one project
// and window id, newest first, at most limit rows (MaxApprovalList at most).
func (s *Store) ReleaseWindowApprovals(ctx context.Context, project, windowID string, limit int) ([]ActionApprovalRequest, error) {
	if !slices.Contains(ReleaseWindowProjects, project) || !releaseWindowIDRe.MatchString(windowID) {
		return nil, invalid("release windows are listed by project (apps or platform) and a w-<12 hex> window id")
	}
	if limit <= 0 || limit > MaxApprovalList {
		limit = MaxApprovalList
	}
	now := s.now()
	// The prefix is built from two values just validated, so it holds no
	// LIKE metacharacter; the target after '#' is the window JSON.
	rows, err := s.pool.Query(ctx, `SELECT `+actionApprovalColumns+` FROM action_approval_requests
		WHERE action_kind = $1 AND left(target, $2) = $3 ORDER BY created_at DESC, id LIMIT $4`,
		ActionKindReleaseWindow, len(project+"/"+windowID+"#"), project+"/"+windowID+"#", limit)
	if err != nil {
		return nil, fmt.Errorf("workitems: list release window approvals: %w", err)
	}
	defer rows.Close()
	out := []ActionApprovalRequest{}
	for rows.Next() {
		a, err := scanActionApproval(rows, now)
		if err != nil {
			return nil, fmt.Errorf("workitems: list release window approvals: %w", err)
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("workitems: list release window approvals: %w", err)
	}
	return out, nil
}
