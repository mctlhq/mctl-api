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

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADR 018 Amendment 2, Tier B checklist items 1-2: every new block is
// accepted, every rule is re-validated on ingest, and a violation is
// ErrEvidenceInvalid (400 evidence_invalid). Each rule is proven both ways:
// the valid base envelope passes, and the one mutation that breaks exactly
// that rule fails.

const (
	testSHA1 = "4f2c9e1b7a3d5c8e0f6a2b4d6c8e0a1b3c5d7e9f"
	testSHA2 = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"
	testHash = "sha256:8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"
)

// a2Base returns a fresh, valid envelope body (no identity yet) carrying
// all four Amendment 2 blocks, modelled on shepherd-pr-evidence.json.
func a2Base() map[string]any {
	return map[string]any{
		"api_version": APIVersionV1Alpha1,
		"kind":        KindV1Alpha1,
		"created_at":  "2026-10-04T10:00:05Z",
		"execution": map[string]any{
			"execution_id":         "we_01J8ZQK7SHEP0000000000000",
			"runtime_execution_id": "ex-1122334455667788",
			"trace_id":             "dev-loop-mctlhq-mctl-agents-524",
			"work_item_id":         "wi-mctlhq-mctl-agents-524",
		},
		"outcome": map[string]any{"code": "succeeded", "reason_code": "merge-completed"},
		"versions": map[string]any{
			"agent":                   "pr-shepherd",
			"environment":             "shadow",
			"definition_version":      "1",
			"definition_content_hash": "sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1",
			"profile_name":            "pr-shepherd-default",
			"profile_version":         "3",
			"profile_content_hash":    "sha256:f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
			"release_revision":        json.Number("7"),
		},
		"subject": map[string]any{
			"kind": "pull_request", "repository": "mctlhq/mctl-agents", "ref": "524", "revision": testSHA1,
		},
		"tool_calls": []any{map[string]any{
			"kind": "github.pull_request.merge", "name": "merge_pull_request",
			"action_digest": testHash, "status": "succeeded",
		}},
		"provenance": map[string]any{"authority": "observed", "observed_at": "2026-10-04T10:00:00Z", "supersedes": ""},
	}
}

// sealMap fills evidence_id/content_hash by hashing m once through this
// package's own canonicalization (proven against Tier A by the golden
// vectors), so a test isolates exactly one rule.
func sealMap(t *testing.T, m map[string]any) []byte {
	t.Helper()
	m["evidence_id"] = "ev-0000000000000000"
	m["content_hash"] = "sha256:" + strings.Repeat("0", 64)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p, err := parseEnvelope(raw)
	if err != nil {
		// Structurally invalid: return it unsealed, Validate rejects it
		// before the hash comparison anyway.
		return raw
	}
	canonical, err := CanonicalContentJSON(p)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	hash := ContentHash(canonical)
	m["content_hash"] = hash
	m["evidence_id"] = EvidenceIDFor(hash)
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal sealed: %v", err)
	}
	return raw
}

func sub(m map[string]any, block string) map[string]any { return m[block].(map[string]any) }

func TestAmendment2BaseEnvelopeIsValid(t *testing.T) {
	if _, _, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, a2Base())}); err != nil {
		t.Fatalf("Validate(valid Amendment 2 envelope) = %v, want success", err)
	}
}

func TestAmendment2RulesRejectViolations(t *testing.T) {
	gap := func(block, code string, required bool) any {
		return map[string]any{"block": block, "code": code, "required": required}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		// Unknown keys inside each block (checklist item 1).
		{"versions unknown key", func(m map[string]any) { sub(m, "versions")["extra"] = "x" }},
		{"subject unknown key", func(m map[string]any) { sub(m, "subject")["extra"] = "x" }},
		{"tool_call unknown key", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["arguments"] = "x"
		}},
		{"provenance unknown key", func(m map[string]any) { sub(m, "provenance")["extra"] = "x" }},
		// Types.
		{"versions not an object", func(m map[string]any) { m["versions"] = "x" }},
		{"subject not an object", func(m map[string]any) { m["subject"] = []any{} }},
		{"tool_calls not a list", func(m map[string]any) { m["tool_calls"] = map[string]any{} }},
		{"tool_call not an object", func(m map[string]any) { m["tool_calls"] = []any{"x"} }},
		{"provenance not an object", func(m map[string]any) { m["provenance"] = json.Number("1") }},
		{"string leaf is null", func(m map[string]any) { sub(m, "subject")["revision"] = nil }},
		{"string leaf is a number", func(m map[string]any) { sub(m, "versions")["agent"] = json.Number("1") }},
		{"release_revision is a string", func(m map[string]any) { sub(m, "versions")["release_revision"] = "7" }},
		{"release_revision is a float", func(m map[string]any) {
			sub(m, "versions")["release_revision"] = json.Number("7.0")
		}},
		{"release_revision is a bool", func(m map[string]any) { sub(m, "versions")["release_revision"] = true }},
		// _check_versions.
		{"versions.agent missing", func(m map[string]any) { delete(sub(m, "versions"), "agent") }},
		{"versions.definition_content_hash missing", func(m map[string]any) {
			sub(m, "versions")["definition_content_hash"] = ""
		}},
		{"versions.agent not a slug", func(m map[string]any) { sub(m, "versions")["agent"] = "PR Shepherd" }},
		{"versions.environment not a slug", func(m map[string]any) { sub(m, "versions")["environment"] = "-x" }},
		{"versions.profile_name not a slug", func(m map[string]any) { sub(m, "versions")["profile_name"] = "A" }},
		{"versions.agent too long", func(m map[string]any) { sub(m, "versions")["agent"] = strings.Repeat("a", 129) }},
		{"versions.definition_version malformed", func(m map[string]any) {
			sub(m, "versions")["definition_version"] = "v 1"
		}},
		{"versions.profile_version malformed", func(m map[string]any) { sub(m, "versions")["profile_version"] = "_3" }},
		{"versions.definition_content_hash malformed", func(m map[string]any) {
			sub(m, "versions")["definition_content_hash"] = "sha256:D1"
		}},
		{"versions.profile_content_hash malformed", func(m map[string]any) {
			sub(m, "versions")["profile_content_hash"] = "d1d1"
		}},
		{"versions.release_revision negative", func(m map[string]any) {
			sub(m, "versions")["release_revision"] = json.Number("-1")
		}},
		{"versions.release_revision above int64", func(m map[string]any) {
			sub(m, "versions")["release_revision"] = json.Number("9223372036854775808")
		}},
		// _check_subject.
		{"subject.kind missing", func(m map[string]any) { sub(m, "subject")["kind"] = "" }},
		{"subject.kind outside the vocabulary", func(m map[string]any) { sub(m, "subject")["kind"] = "commit" }},
		{"subject.ref missing", func(m map[string]any) { sub(m, "subject")["ref"] = "" }},
		{"subject.ref of a PR is not its number", func(m map[string]any) { sub(m, "subject")["ref"] = "0524" }},
		{"subject.ref of an issue is not its number", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"], s["revision"] = "issue", "abc", ""
		}},
		{"subject.ref branch path fragment", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", "feat/../main"
		}},
		{"subject.ref branch double slash", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", "feat//x"
		}},
		{"subject.ref branch trailing slash", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", "feat/"
		}},
		{"subject.ref branch bad first char", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", "-x"
		}},
		{"subject.ref too long", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", strings.Repeat("a", 257)
		}},
		{"subject.repository missing for a PR", func(m map[string]any) { sub(m, "subject")["repository"] = "" }},
		{"subject.repository missing for an issue", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["repository"], s["revision"] = "issue", "", ""
		}},
		{"subject.repository not owner/name", func(m map[string]any) { sub(m, "subject")["repository"] = "mctlhq" }},
		{"subject.repository name is dots", func(m map[string]any) { sub(m, "subject")["repository"] = "mctlhq/.." }},
		{"subject.repository name has ..", func(m map[string]any) {
			sub(m, "subject")["repository"] = "mctlhq/a..b"
		}},
		{"subject.revision missing for a PR", func(m map[string]any) { sub(m, "subject")["revision"] = "" }},
		{"subject.revision missing for a branch", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"], s["revision"] = "branch", "main", ""
		}},
		{"subject.revision missing for a release", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"], s["revision"] = "release", "1.2.0", ""
		}},
		{"subject.revision abbreviated", func(m map[string]any) { sub(m, "subject")["revision"] = testSHA1[:12] }},
		{"subject.revision uppercase", func(m map[string]any) {
			sub(m, "subject")["revision"] = strings.ToUpper(testSHA1)
		}},
		{"subject.revision 41 hex", func(m map[string]any) { sub(m, "subject")["revision"] = testSHA1 + "a" }},
		{"subject.revision token malformed for an issue", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["revision"] = "issue", "updated at"
		}},
		{"subject without provenance", func(m map[string]any) { delete(m, "provenance") }},
		{"subject with null provenance", func(m map[string]any) { m["provenance"] = nil }},
		// _check_tool_call and MAX_TOOL_CALLS.
		{"tool_call.kind missing", func(m map[string]any) { m["tool_calls"].([]any)[0].(map[string]any)["kind"] = "" }},
		{"tool_call.kind ungoverned", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["kind"] = "github.repo.delete"
		}},
		{"tool_call.action_digest missing", func(m map[string]any) {
			delete(m["tool_calls"].([]any)[0].(map[string]any), "action_digest")
		}},
		{"tool_call.action_digest malformed", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["action_digest"] = "sha256:abc"
		}},
		{"tool_call.status missing", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["status"] = ""
		}},
		{"tool_call.status outside the vocabulary", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["status"] = "timeout"
		}},
		{"tool_call.name malformed", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["name"] = "merge pull request"
		}},
		{"tool_call.name too long", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["name"] = strings.Repeat("a", 129)
		}},
		{"tool_calls over MAX_TOOL_CALLS", func(m map[string]any) {
			calls := make([]any, MaxToolCalls+1)
			for i := range calls {
				calls[i] = map[string]any{"kind": "mcp.tool.call", "name": "", "action_digest": testHash, "status": "unknown"}
			}
			m["tool_calls"] = calls
		}},
		// _check_provenance.
		{"provenance.authority missing", func(m map[string]any) { sub(m, "provenance")["authority"] = "" }},
		{"provenance.authority outside the vocabulary", func(m map[string]any) {
			sub(m, "provenance")["authority"] = "verified"
		}},
		{"provenance.observed_at missing", func(m map[string]any) { delete(sub(m, "provenance"), "observed_at") }},
		{"provenance.observed_at not UTC Z", func(m map[string]any) {
			sub(m, "provenance")["observed_at"] = "2026-10-04T10:00:00+00:00"
		}},
		{"provenance.observed_at 7-digit fraction", func(m map[string]any) {
			sub(m, "provenance")["observed_at"] = "2026-10-04T10:00:00.1234567Z"
		}},
		{"provenance.observed_at impossible instant", func(m map[string]any) {
			sub(m, "provenance")["observed_at"] = "2026-02-30T10:00:00Z"
		}},
		{"provenance.supersedes malformed", func(m map[string]any) {
			sub(m, "provenance")["supersedes"] = "ev-XYZ"
		}},
		// Gap rules.
		{"observation_failed gap not required", func(m map[string]any) {
			m["gaps"] = []any{gap("versions", "observation_failed", false)}
		}},
		{"observation_failed gap on a legacy block not required", func(m map[string]any) {
			m["gaps"] = []any{gap("usage", "observation_failed", false)}
		}},
		{"redacted_out gap on an Amendment 2 block not required", func(m map[string]any) {
			m["gaps"] = []any{gap("tool_calls", "redacted_out", false)}
		}},
		{"a non-required redacted_out gap excuses nothing", func(m map[string]any) {
			sub(m, "subject")["kind"] = "branch"
			sub(m, "subject")["ref"] = ""
			m["gaps"] = []any{gap("subject", "redacted_out", false)}
		}},
		// Only the three free-form leaves are excusable, and only by a
		// redaction gap on their own block.
		{"a redaction gap never excuses a blank revision", func(m map[string]any) {
			sub(m, "subject")["revision"] = ""
			m["gaps"] = []any{gap("subject", "redacted_out", true)}
		}},
		{"a redaction gap never excuses a blank numbered ref", func(m map[string]any) {
			sub(m, "subject")["ref"] = ""
			m["gaps"] = []any{gap("subject", "redacted_out", true)}
		}},
		{"a redaction gap never excuses a blank definition_content_hash", func(m map[string]any) {
			sub(m, "versions")["definition_content_hash"] = ""
			m["gaps"] = []any{gap("versions", "redacted_out", true)}
		}},
		{"a redaction gap never excuses a blank authority", func(m map[string]any) {
			sub(m, "provenance")["authority"] = ""
			m["gaps"] = []any{gap("provenance", "redacted_out", true)}
		}},
		{"a redaction gap never excuses a blank tool_call.status", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["status"] = ""
			m["gaps"] = []any{gap("tool_calls", "redacted_out", true)}
		}},
		{"a redaction gap on another block excuses nothing", func(m map[string]any) {
			sub(m, "versions")["agent"] = ""
			m["gaps"] = []any{gap("subject", "redacted_out", true)}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := a2Base()
			c.mutate(m)
			_, _, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, m)})
			if !errors.Is(err, ErrEvidenceInvalid) {
				t.Fatalf("Validate() = %v, want ErrEvidenceInvalid", err)
			}
		})
	}
}

// supersedes may not name the envelope itself. The id is derived from the
// content, which includes supersedes, so the self-reference has to be
// planted after sealing: Validate must reject it as invalid content, not
// merely as a hash mismatch.
func TestAmendment2SupersedesMayNotNameItself(t *testing.T) {
	m := a2Base()
	raw := sealMap(t, m)
	p, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	p.a2.provenance.Supersedes = p.evidenceID
	if err := p.a2.validate(p.evidenceID); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("validate(supersedes == own id) = %v, want ErrEvidenceInvalid", err)
	}
	p.a2.provenance.Supersedes = "ev-0123456789abcdef"
	if err := p.a2.validate(p.evidenceID); err != nil {
		t.Fatalf("validate(supersedes another id) = %v, want success", err)
	}
}

// The valid side of the rules above: shapes Tier A accepts must be
// accepted here too.
func TestAmendment2RulesAcceptValidShapes(t *testing.T) {
	gap := func(block, code string, required bool) any {
		return map[string]any{"block": block, "code": code, "required": required}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"64-hex SHA-256 object id", func(m map[string]any) {
			sub(m, "subject")["revision"] = strings.Repeat("ab", 32)
		}},
		{"issue without revision", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["revision"] = "issue", ""
		}},
		{"issue with a version token", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["revision"] = "issue", "2026-10-04T10:00:00Z"
		}},
		{"work_item without repository", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["repository"], s["ref"], s["revision"] = "work_item", "", "wi_abc", ""
		}},
		{"branch ref with slashes", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", "feat/199-evidence"
		}},
		{"dot-prefixed repository name", func(m map[string]any) { sub(m, "subject")["repository"] = "mctlhq/.github" }},
		{"no versions block", func(m map[string]any) { delete(m, "versions") }},
		{"null versions", func(m map[string]any) { m["versions"] = nil }},
		{"empty tool_calls", func(m map[string]any) { m["tool_calls"] = []any{} }},
		{"provenance without subject", func(m map[string]any) { delete(m, "subject") }},
		{"null release_revision", func(m map[string]any) { sub(m, "versions")["release_revision"] = nil }},
		{"max release_revision", func(m map[string]any) {
			sub(m, "versions")["release_revision"] = json.Number("9223372036854775807")
		}},
		{"tool_call status unknown", func(m map[string]any) {
			m["tool_calls"].([]any)[0].(map[string]any)["status"] = "unknown"
		}},
		{"every authority", func(m map[string]any) { sub(m, "provenance")["authority"] = "asserted" }},
		{"observed_at with fraction", func(m map[string]any) {
			sub(m, "provenance")["observed_at"] = "2026-10-04T10:00:00.5Z"
		}},
		{"supersedes another id", func(m map[string]any) {
			sub(m, "provenance")["supersedes"] = "ev-0123456789abcdef"
		}},
		{"required observation_failed gap", func(m map[string]any) {
			m["gaps"] = []any{gap("versions", "observation_failed", true)}
		}},
		{"legacy gap code keeps its caller-chosen flag", func(m map[string]any) {
			m["gaps"] = []any{gap("subject", "store_unavailable", false)}
		}},
		// The declarative excusal: a required redacted_out gap on the
		// leaf's own block excuses exactly the three free-form leaves.
		{"redacted versions.agent", func(m map[string]any) {
			sub(m, "versions")["agent"] = ""
			m["gaps"] = []any{gap("versions", "redacted_out", true)}
		}},
		{"redacted branch subject.ref", func(m map[string]any) {
			s := sub(m, "subject")
			s["kind"], s["ref"] = "branch", ""
			m["gaps"] = []any{gap("subject", "redacted_out", true)}
		}},
		{"redacted subject.repository", func(m map[string]any) {
			sub(m, "subject")["repository"] = ""
			m["gaps"] = []any{gap("subject", "redacted_out", true)}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := a2Base()
			c.mutate(m)
			if _, _, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, m)}); err != nil {
				t.Fatalf("Validate() = %v, want success", err)
			}
		})
	}
}

// Absent Amendment 2 blocks are hash-neutral: missing, null and []
// (tool_calls) all hash exactly like a pre-amendment envelope, so every
// legacy vector keeps its identity (Tier A T16).
func TestAmendment2AbsentBlocksAreHashNeutral(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "investigator-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	m["versions"], m["subject"], m["provenance"], m["tool_calls"] = nil, nil, nil, []any{}
	withNulls, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, gotHash, _, err := Validate(IngestInput{EnvelopeBytes: withNulls})
	if err != nil {
		t.Fatalf("Validate(legacy + null/[] new blocks) = %v, want success", err)
	}
	if want := goldenHashes["investigator-evidence.json"]; gotHash != want {
		t.Fatalf("hash = %s, want the legacy %s", gotHash, want)
	}
}

// Each present block enters the hash (dropping one changes the identity),
// and every subject field participates — PR@SHA1 and PR@SHA2 never share
// an evidence_id.
func TestAmendment2BlocksParticipateInTheHash(t *testing.T) {
	hashOf := func(m map[string]any) string {
		t.Helper()
		_, h, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, m)})
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		return h
	}
	base := hashOf(a2Base())
	seen := map[string]string{base: "base"}
	variants := map[string]func(m map[string]any){
		"no versions":         func(m map[string]any) { delete(m, "versions") },
		"no tool_calls":       func(m map[string]any) { delete(m, "tool_calls") },
		"no subject":          func(m map[string]any) { delete(m, "subject") },
		"revision SHA2":       func(m map[string]any) { sub(m, "subject")["revision"] = testSHA2 },
		"other ref":           func(m map[string]any) { sub(m, "subject")["ref"] = "525" },
		"other repository":    func(m map[string]any) { sub(m, "subject")["repository"] = "mctlhq/mctl-api" },
		"derived authority":   func(m map[string]any) { sub(m, "provenance")["authority"] = "derived" },
		"later observed_at":   func(m map[string]any) { sub(m, "provenance")["observed_at"] = "2026-10-04T10:00:01Z" },
		"supersedes":          func(m map[string]any) { sub(m, "provenance")["supersedes"] = "ev-0123456789abcdef" },
		"tool status unknown": func(m map[string]any) { m["tool_calls"].([]any)[0].(map[string]any)["status"] = "unknown" },
		"release_revision 8":  func(m map[string]any) { sub(m, "versions")["release_revision"] = json.Number("8") },
	}
	for name, mutate := range variants {
		m := a2Base()
		mutate(m)
		h := hashOf(m)
		if prev, dup := seen[h]; dup {
			t.Errorf("%s hashes like %s (%s)", name, prev, h)
		}
		seen[h] = name
	}
	// created_at stays excluded.
	m := a2Base()
	m["created_at"] = "2027-01-01T00:00:00Z"
	if h := hashOf(m); h != base {
		t.Errorf("created_at changed the hash: %s vs %s", h, base)
	}
}

// A present block is rebuilt through Tier A's to_dict() shape: a block
// that omits optional keys hashes exactly like one that spells them out as
// ""/null, which is what Tier A's from_dict + recompute_content_hash do.
func TestAmendment2BlocksHashInTheirFullTierAShape(t *testing.T) {
	full := a2Base()
	v := sub(full, "versions")
	v["environment"], v["definition_version"], v["profile_name"] = "", "", ""
	v["profile_version"], v["profile_content_hash"], v["release_revision"] = "", "", nil
	full["tool_calls"].([]any)[0].(map[string]any)["name"] = ""

	sparse := a2Base()
	sparse["versions"] = map[string]any{
		"agent":                   "pr-shepherd",
		"definition_content_hash": v["definition_content_hash"],
	}
	call := sparse["tool_calls"].([]any)[0].(map[string]any)
	delete(call, "name")

	_, hFull, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, full)})
	if err != nil {
		t.Fatal(err)
	}
	_, hSparse, _, err := Validate(IngestInput{EnvelopeBytes: sealMap(t, sparse)})
	if err != nil {
		t.Fatal(err)
	}
	if hFull != hSparse {
		t.Fatalf("sparse block hashes %s, full block %s: a present block must hash in its full Tier A shape", hSparse, hFull)
	}
}
