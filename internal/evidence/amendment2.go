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

package evidence

// ADR 018 Amendment 2 (mctlhq/mctl-agents#199, contract merged as
// mctlhq/mctl-agents#575): four optional blocks — versions, subject,
// tool_calls, provenance — plus the observation_failed gap code. Every rule
// here mirrors orchestrator/execution_evidence.py (_check_versions,
// _check_subject, _check_tool_call, _check_provenance, _check_gap,
// _required_leaves/_check_required_leaves and ExecutionEvidence.validate)
// and is re-validated on every ingest: Tier B never trusts that a producer
// ran Tier A's seal().

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Subject kinds (Tier A SUBJECT_KINDS and its three subsets).
var (
	subjectKinds = map[string]bool{
		"pull_request": true, "issue": true, "branch": true, "release": true, "work_item": true,
	}
	// shaBoundSubjectKinds name a moving pointer: revision is a required,
	// full lowercase git object id.
	shaBoundSubjectKinds = map[string]bool{"pull_request": true, "branch": true, "release": true}
	// repositorySubjectKinds require subject.repository.
	repositorySubjectKinds = map[string]bool{"pull_request": true, "issue": true, "branch": true, "release": true}
	// numberedSubjectKinds carry a GitHub issue/PR number as subject.ref.
	numberedSubjectKinds = map[string]bool{"pull_request": true, "issue": true}
)

// IsSubjectKind reports whether kind is one of Tier A's SUBJECT_KINDS.
func IsSubjectKind(kind string) bool { return subjectKinds[kind] }

// authorityRank is Tier A's AUTHORITY_RANK: observed > derived > asserted.
// Anything else (including a blank authority on a legacy row) ranks 0.
var authorityRank = map[string]int{"observed": 3, "derived": 2, "asserted": 1}

// AuthorityRank returns the precedence of authority (0 when unknown/blank).
func AuthorityRank(authority string) int { return authorityRank[authority] }

// toolCallKinds is Tier A's TOOL_CALL_KINDS = policy_checkpoint.ACTION_KINDS
// (mctlhq/mctl-agents orchestrator/policy_checkpoint.py), copied verbatim.
var toolCallKinds = map[string]bool{
	"github.issue.comment":        true,
	"mctl.operation.execute":      true,
	"mctl.work_item.write":        true,
	"mcp.tool.call":               true,
	"github.git.push":             true,
	"github.pull_request.create":  true,
	"github.pull_request.merge":   true,
	"github.pull_request.comment": true,
	"github.actions.run.rerun":    true,
	"github.issue.label":          true,
}

var toolCallStatuses = map[string]bool{"succeeded": true, "failed": true, "refused": true, "unknown": true}

// amendment2Blocks are the four blocks whose redacted_out gap must always be
// required (Tier A AMENDMENT_2_BLOCKS).
var amendment2Blocks = map[string]bool{"versions": true, "subject": true, "tool_calls": true, "provenance": true}

// redactableRequiredLeaves are the only required Amendment 2 leaves a
// required redacted_out gap on their block may excuse when blank (Tier A
// REDACTABLE_REQUIRED_LEAVES). subject.ref only for non-numbered kinds.
var redactableRequiredLeaves = map[string]bool{
	"versions.agent": true, "subject.ref": true, "subject.repository": true,
}

// MaxToolCalls bounds tool_calls (Tier A MAX_TOOL_CALLS).
const MaxToolCalls = 256

// Bounds and shapes copied from orchestrator/execution_evidence.py.
const (
	maxSlugLength       = 128
	maxVersionLength    = 128
	maxToolNameLength   = 128
	maxSubjectRefLength = 256
	maxObservedAtLength = 40 // MAX_CREATED_AT_LENGTH
)

var (
	slugPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]*$`)
	toolNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
	sha256Pattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	numberRefPattern  = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
	subjectRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]*$`)
	gitSHAPattern     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	evidenceIDPattern = regexp.MustCompile(`^ev-[0-9a-f]{16}$`)
	// jsonIntegerPattern accepts exactly what Python's json.loads turns into
	// an int (never a float such as 7.0 or 7e0, which _require_int rejects).
	jsonIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

// Block keys (each from_dict's _reject_unknown_keys set).
var (
	versionsKeys = map[string]bool{
		"agent": true, "environment": true, "definition_version": true, "definition_content_hash": true,
		"profile_name": true, "profile_version": true, "profile_content_hash": true, "release_revision": true,
	}
	subjectKeys    = map[string]bool{"kind": true, "repository": true, "ref": true, "revision": true}
	toolCallKeys   = map[string]bool{"kind": true, "name": true, "action_digest": true, "status": true}
	provenanceKeys = map[string]bool{"authority": true, "observed_at": true, "supersedes": true}
)

// versionPins is Tier A's VersionPins.
type versionPins struct {
	Agent, Environment, DefinitionVersion, DefinitionContentHash string
	ProfileName, ProfileVersion, ProfileContentHash              string
	ReleaseRevision                                              *int64
}

func (v versionPins) toDict() map[string]any {
	var rev any
	if v.ReleaseRevision != nil {
		rev = *v.ReleaseRevision
	}
	return map[string]any{
		"agent": v.Agent, "environment": v.Environment,
		"definition_version": v.DefinitionVersion, "definition_content_hash": v.DefinitionContentHash,
		"profile_name": v.ProfileName, "profile_version": v.ProfileVersion,
		"profile_content_hash": v.ProfileContentHash, "release_revision": rev,
	}
}

// SubjectRef is Tier A's SubjectRef: what the evidence is about, bound to
// the exact revision observed. Served on every record that carries one.
type SubjectRef struct {
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Revision   string `json:"revision"`
}

func (s SubjectRef) toDict() map[string]any {
	return map[string]any{"kind": s.Kind, "repository": s.Repository, "ref": s.Ref, "revision": s.Revision}
}

type toolCallRef struct{ Kind, Name, ActionDigest, Status string }

func (c toolCallRef) toDict() map[string]any {
	return map[string]any{"kind": c.Kind, "name": c.Name, "action_digest": c.ActionDigest, "status": c.Status}
}

type provenanceBlock struct{ Authority, ObservedAt, Supersedes string }

func (p provenanceBlock) toDict() map[string]any {
	return map[string]any{"authority": p.Authority, "observed_at": p.ObservedAt, "supersedes": p.Supersedes}
}

// gapInfo is one entry of the envelope's gaps list, read only for the
// Amendment 2 rules. Entries that are not objects are left to the
// pre-amendment pass-through behaviour (they hash as received).
type gapInfo struct {
	Block, Code string
	Required    bool
}

// amendment2 holds the decoded Amendment 2 blocks of one envelope. A nil
// pointer / empty slice means the block is absent (missing, null, or an
// empty tool_calls list), exactly Tier A's from_dict rule.
type amendment2 struct {
	versions   *versionPins
	subject    *SubjectRef
	toolCalls  []toolCallRef
	provenance *provenanceBlock
	gaps       []gapInfo
}

// subjectRedacted reports whether the envelope declares a redacted_out gap
// on subject: such an envelope is not bound to a known subject and is never
// a resolve_current candidate.
func (a *amendment2) subjectRedacted() bool {
	for _, g := range a.gaps {
		if g.Block == "subject" && g.Code == "redacted_out" {
			return true
		}
	}
	return false
}

// stringLeaf reads an optional string leaf: missing -> "", any non-string
// (null included) -> error, matching _require_str(mapping.get(k, ""),
// allow_empty=True).
func stringLeaf(m map[string]any, key, where string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", nil
	}
	s, isString := v.(string)
	if !isString {
		return "", fmt.Errorf("%w: %s.%s must be a string", ErrEvidenceInvalid, where, key)
	}
	return s, nil
}

func blockObject(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a JSON object", ErrEvidenceInvalid, where)
	}
	return m, nil
}

func stringLeaves(m map[string]any, where string, keys ...string) ([]string, error) {
	out := make([]string, len(keys))
	for i, k := range keys {
		s, err := stringLeaf(m, k, where)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// parseAmendment2 decodes the four new blocks and the gaps list from the
// strictly-decoded top-level object. Structure and types only — the
// vocabulary/shape rules are validateAmendment2's.
func parseAmendment2(top map[string]any) (*amendment2, error) {
	a := &amendment2{}
	if raw, ok := top["versions"]; ok && raw != nil {
		m, err := blockObject(raw, "versions")
		if err != nil {
			return nil, err
		}
		if err := rejectUnknownKeys(m, versionsKeys, "versions"); err != nil {
			return nil, err
		}
		s, err := stringLeaves(m, "versions", "agent", "environment", "definition_version",
			"definition_content_hash", "profile_name", "profile_version", "profile_content_hash")
		if err != nil {
			return nil, err
		}
		v := versionPins{Agent: s[0], Environment: s[1], DefinitionVersion: s[2], DefinitionContentHash: s[3],
			ProfileName: s[4], ProfileVersion: s[5], ProfileContentHash: s[6]}
		if rv, present := m["release_revision"]; present && rv != nil {
			n, err := jsonInt64(rv)
			if err != nil {
				return nil, fmt.Errorf("%w: versions.release_revision %s", ErrEvidenceInvalid, err)
			}
			v.ReleaseRevision = &n
		}
		a.versions = &v
	}
	if raw, ok := top["subject"]; ok && raw != nil {
		m, err := blockObject(raw, "subject")
		if err != nil {
			return nil, err
		}
		if err := rejectUnknownKeys(m, subjectKeys, "subject"); err != nil {
			return nil, err
		}
		s, err := stringLeaves(m, "subject", "kind", "repository", "ref", "revision")
		if err != nil {
			return nil, err
		}
		a.subject = &SubjectRef{Kind: s[0], Repository: s[1], Ref: s[2], Revision: s[3]}
	}
	if raw, ok := top["tool_calls"]; ok && raw != nil {
		list, isList := raw.([]any)
		if !isList {
			return nil, fmt.Errorf("%w: tool_calls must be a list", ErrEvidenceInvalid)
		}
		for _, item := range list {
			m, err := blockObject(item, "tool_call")
			if err != nil {
				return nil, err
			}
			if err := rejectUnknownKeys(m, toolCallKeys, "tool_call"); err != nil {
				return nil, err
			}
			s, err := stringLeaves(m, "tool_call", "kind", "name", "action_digest", "status")
			if err != nil {
				return nil, err
			}
			a.toolCalls = append(a.toolCalls, toolCallRef{Kind: s[0], Name: s[1], ActionDigest: s[2], Status: s[3]})
		}
	}
	if raw, ok := top["provenance"]; ok && raw != nil {
		m, err := blockObject(raw, "provenance")
		if err != nil {
			return nil, err
		}
		if err := rejectUnknownKeys(m, provenanceKeys, "provenance"); err != nil {
			return nil, err
		}
		s, err := stringLeaves(m, "provenance", "authority", "observed_at", "supersedes")
		if err != nil {
			return nil, err
		}
		a.provenance = &provenanceBlock{Authority: s[0], ObservedAt: s[1], Supersedes: s[2]}
	}
	if list, ok := top["gaps"].([]any); ok {
		for _, item := range list {
			m, isObj := item.(map[string]any)
			if !isObj {
				continue
			}
			block, _ := m["block"].(string)
			code, _ := m["code"].(string)
			required, _ := m["required"].(bool)
			a.gaps = append(a.gaps, gapInfo{Block: block, Code: code, Required: required})
		}
	}
	return a, nil
}

// jsonInt64 accepts a JSON integer literal within the signed 64-bit range
// (Tier A _require_int plus MAX_RELEASE_REVISION's upper bound).
func jsonInt64(v any) (int64, error) {
	num, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("must be an integer or null, got %T", v)
	}
	lit := num.String()
	if !jsonIntegerPattern.MatchString(lit) {
		return 0, fmt.Errorf("must be an integer or null, got %s", lit)
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("must be within the signed 64-bit range, got %s", lit)
	}
	return n, nil
}

// contentFields renders each present block exactly as Tier A's to_dict()
// does (every key always emitted, blank as "", release_revision as null),
// which is what Tier A's recompute_content_hash() hashes. An absent block
// is not added, so a pre-amendment envelope hashes byte-identically.
func (a *amendment2) addContentFields(fields map[string]any) {
	if a.versions != nil {
		fields["versions"] = a.versions.toDict()
	}
	if a.subject != nil {
		fields["subject"] = a.subject.toDict()
	}
	if len(a.toolCalls) > 0 {
		calls := make([]any, len(a.toolCalls))
		for i, c := range a.toolCalls {
			calls[i] = c.toDict()
		}
		fields["tool_calls"] = calls
	}
	if a.provenance != nil {
		fields["provenance"] = a.provenance.toDict()
	}
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrEvidenceInvalid}, args...)...)
}

// requiredLeaf is one row of Tier A's _required_leaves table.
type requiredLeaf struct {
	leaf, gapBlock, value string
	redactable            bool
	message               string
}

// requiredLeaves is the single table of required Amendment 2 leaves for
// the blocks present (Tier A _required_leaves).
func requiredLeaves(versions *versionPins, subject *SubjectRef, toolCalls []toolCallRef, prov *provenanceBlock) []requiredLeaf {
	var rows []requiredLeaf
	add := func(leaf, gapBlock, value, message string, redactable bool) {
		rows = append(rows, requiredLeaf{leaf: leaf, gapBlock: gapBlock, value: value,
			redactable: redactable && redactableRequiredLeaves[leaf], message: message})
	}
	if versions != nil {
		add("versions.agent", "versions", versions.Agent,
			"versions.agent is required when the versions block is present", true)
		add("versions.definition_content_hash", "versions", versions.DefinitionContentHash,
			"versions.definition_content_hash is required when the versions block is present", true)
	}
	if subject != nil {
		add("subject.kind", "subject", subject.Kind, "subject.kind is required when the subject block is present", true)
		add("subject.ref", "subject", subject.Ref, "subject.ref is required when the subject block is present",
			!numberedSubjectKinds[subject.Kind])
		if repositorySubjectKinds[subject.Kind] {
			add("subject.repository", "subject", subject.Repository,
				"subject.repository is required for a "+subject.Kind+" subject", true)
		}
		if shaBoundSubjectKinds[subject.Kind] {
			add("subject.revision", "subject", subject.Revision,
				"subject.revision is required for a "+subject.Kind+" subject: evidence about a moving "+
					"pointer must name the exact git SHA it observed", true)
		}
	}
	for _, c := range toolCalls {
		add("tool_call.kind", "tool_calls", c.Kind, "tool_call.kind is required", true)
		add("tool_call.action_digest", "tool_calls", c.ActionDigest, "tool_call.action_digest is required", true)
		add("tool_call.status", "tool_calls", c.Status, "tool_call.status is required", true)
	}
	if prov != nil {
		add("provenance.authority", "provenance", prov.Authority,
			"provenance.authority is required when the provenance block is present", true)
		add("provenance.observed_at", "provenance", prov.ObservedAt,
			"provenance.observed_at is required when the provenance block is present", true)
	}
	return rows
}

// checkRequiredLeaves fails on the first blank required leaf, unless the
// row is redactable and a redacted_out gap names its block (Tier A
// _check_required_leaves). skip names leaves a caller exempts (the current
// read exempts subject.revision).
func checkRequiredLeaves(rows []requiredLeaf, redactedBlocks map[string]bool, skip map[string]bool) error {
	for _, row := range rows {
		if row.value != "" || skip[row.leaf] {
			continue
		}
		if row.redactable && redactedBlocks[row.gapBlock] {
			continue
		}
		return invalid("%s", row.message)
	}
	return nil
}

func checkBounded(value string, pattern *regexp.Regexp, maxLen int, where string) error {
	if len(value) > maxLen || !pattern.MatchString(value) {
		return invalid("%s must match %q within %d characters", where, pattern.String(), maxLen)
	}
	return nil
}

type namedLeaf struct{ name, value string }

func checkVersions(v *versionPins) error {
	for _, l := range []namedLeaf{{"agent", v.Agent}, {"environment", v.Environment}, {"profile_name", v.ProfileName}} {
		if l.value != "" {
			if err := checkBounded(l.value, slugPattern, maxSlugLength, "versions."+l.name); err != nil {
				return err
			}
		}
	}
	for _, l := range []namedLeaf{{"definition_version", v.DefinitionVersion}, {"profile_version", v.ProfileVersion}} {
		if l.value != "" {
			if err := checkBounded(l.value, versionPattern, maxVersionLength, "versions."+l.name); err != nil {
				return err
			}
		}
	}
	for _, l := range []namedLeaf{
		{"definition_content_hash", v.DefinitionContentHash}, {"profile_content_hash", v.ProfileContentHash},
	} {
		if l.value != "" && !sha256Pattern.MatchString(l.value) {
			return invalid("versions.%s must be 'sha256:' followed by 64 lowercase hex characters", l.name)
		}
	}
	if v.ReleaseRevision != nil && *v.ReleaseRevision < 0 {
		return invalid("versions.release_revision must be within 0..9223372036854775807 "+
			"(a signed 64-bit integer), got %d", *v.ReleaseRevision)
	}
	return nil
}

func checkRepository(repository string) error {
	if !repositoryPattern.MatchString(repository) {
		return invalid("subject.repository must be 'owner/name', got %q", truncate(repository))
	}
	name := repository[strings.IndexByte(repository, '/')+1:]
	if strings.Contains(name, "..") || strings.Trim(name, ".") == "" {
		return invalid("subject.repository %q must not carry a path fragment", truncate(repository))
	}
	return nil
}

// checkSubject is Tier A's _check_subject: shape only; requiredness is
// checkRequiredLeaves'.
func checkSubject(s *SubjectRef) error {
	if s.Kind != "" && !subjectKinds[s.Kind] {
		return invalid("subject.kind %q is not one of [branch issue pull_request release work_item]", truncate(s.Kind))
	}
	if s.Ref != "" {
		if numberedSubjectKinds[s.Kind] {
			if !numberRefPattern.MatchString(s.Ref) {
				return invalid("subject.ref for a %s must be its number, got %q", s.Kind, truncate(s.Ref))
			}
		} else {
			if err := checkBounded(s.Ref, subjectRefPattern, maxSubjectRefLength, "subject.ref"); err != nil {
				return err
			}
			if strings.Contains(s.Ref, "..") || strings.Contains(s.Ref, "//") || strings.HasSuffix(s.Ref, "/") {
				return invalid("subject.ref %q must not carry a path fragment", truncate(s.Ref))
			}
		}
	}
	if s.Repository != "" {
		if err := checkRepository(s.Repository); err != nil {
			return err
		}
	}
	if s.Revision != "" {
		if shaBoundSubjectKinds[s.Kind] {
			if !gitSHAPattern.MatchString(s.Revision) {
				return invalid("subject.revision for a %s must be a full lowercase git SHA (40 or 64 hex), got %q",
					s.Kind, truncate(s.Revision))
			}
		} else if err := checkBounded(s.Revision, versionPattern, maxVersionLength, "subject.revision"); err != nil {
			return err
		}
	}
	return nil
}

func checkToolCall(c toolCallRef) error {
	if c.Kind != "" && !toolCallKinds[c.Kind] {
		return invalid("tool_call.kind %q is not a governed policy_checkpoint action kind", truncate(c.Kind))
	}
	if c.Name != "" {
		if err := checkBounded(c.Name, toolNamePattern, maxToolNameLength, "tool_call.name"); err != nil {
			return err
		}
	}
	if c.ActionDigest != "" && !sha256Pattern.MatchString(c.ActionDigest) {
		return invalid("tool_call.action_digest must be 'sha256:' followed by 64 lowercase hex characters")
	}
	if c.Status != "" && !toolCallStatuses[c.Status] {
		return invalid("tool_call.status %q is not one of [failed refused succeeded unknown]", truncate(c.Status))
	}
	return nil
}

func checkObservedAt(observedAt string) error {
	if len(observedAt) > maxObservedAtLength || !createdAtPattern.MatchString(observedAt) {
		return invalid("provenance.observed_at must be an ISO8601 UTC timestamp of the form "+
			"YYYY-MM-DDTHH:MM:SS[.ffffff]Z, got %q", truncate(observedAt))
	}
	return nil
}

func checkProvenance(p *provenanceBlock, ownEvidenceID string) error {
	if p.Authority != "" && authorityRank[p.Authority] == 0 {
		return invalid("provenance.authority %q is not one of [observed derived asserted]", truncate(p.Authority))
	}
	if p.ObservedAt != "" {
		if err := checkObservedAt(p.ObservedAt); err != nil {
			return err
		}
	}
	if p.Supersedes != "" {
		if !evidenceIDPattern.MatchString(p.Supersedes) {
			return invalid("provenance.supersedes must be an evidence id ('ev-' followed by 16 lowercase hex "+
				"characters), got %q", truncate(p.Supersedes))
		}
		if p.Supersedes == ownEvidenceID {
			return invalid("provenance.supersedes must not name the envelope itself")
		}
	}
	return nil
}

// validate re-runs every Amendment 2 rule of Tier A's
// ExecutionEvidence.validate() (and _check_gap's observation_failed rule)
// on a received envelope. ownEvidenceID is the envelope's own id, which
// supersedes may not name.
func (a *amendment2) validate(ownEvidenceID string) error {
	redacted := map[string]bool{}
	for _, g := range a.gaps {
		if g.Code == "observation_failed" && !g.Required {
			return invalid("gap %q/observation_failed states an unknown and must be required: "+
				"could-not-observe never leaves an envelope COMPLETE", truncate(g.Block))
		}
		if g.Code == "redacted_out" {
			if amendment2Blocks[g.Block] && !g.Required {
				return invalid("a redacted_out gap on Amendment 2 block %q must be required", g.Block)
			}
			redacted[g.Block] = true
		}
	}
	if err := checkRequiredLeaves(requiredLeaves(a.versions, a.subject, a.toolCalls, a.provenance), redacted, nil); err != nil {
		return err
	}
	if a.versions != nil {
		if err := checkVersions(a.versions); err != nil {
			return err
		}
	}
	if a.subject != nil {
		if err := checkSubject(a.subject); err != nil {
			return err
		}
		if a.provenance == nil {
			return invalid("subject-bound evidence must carry a provenance block (authority, observed_at)")
		}
	}
	if len(a.toolCalls) > MaxToolCalls {
		return invalid("tool_calls holds %d entries, max %d", len(a.toolCalls), MaxToolCalls)
	}
	for _, c := range a.toolCalls {
		if err := checkToolCall(c); err != nil {
			return err
		}
	}
	if a.provenance != nil {
		if err := checkProvenance(a.provenance, ownEvidenceID); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
