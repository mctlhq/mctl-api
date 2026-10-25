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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Identity kinds.
const (
	IdentityCVE  = "cve"
	IdentityGHSA = "ghsa"
	IdentityRule = "rule"
)

var (
	cvePattern    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	ghsaPattern   = regexp.MustCompile(`^ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)
	digestPattern = regexp.MustCompile(`^[a-z0-9]+:[0-9a-f]{32,128}$`)
)

// CanonicalIdentity is the normalized problem identity of one observation.
type CanonicalIdentity struct {
	Kind string
	// Key is the canonical key, e.g. "cve:CVE-2024-1234".
	Key string
	// Keys is every key (canonical and aliases), sorted and unique. Findings
	// are matched on any of them.
	Keys []string
	// RuleID is set only when Kind is rule.
	RuleID string
}

// classify normalizes one identity string to (kind, key, ruleID).
func classify(providerRef, raw string) (kind, key, ruleID string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("%w: empty identity", ErrInvalid)
	}
	if up := strings.ToUpper(raw); cvePattern.MatchString(up) {
		return IdentityCVE, "cve:" + up, "", nil
	}
	if lo := strings.ToLower(raw); ghsaPattern.MatchString(lo) {
		return IdentityGHSA, "ghsa:" + lo, "", nil
	}
	if strings.TrimSpace(providerRef) == "" {
		return "", "", "", fmt.Errorf("%w: rule identity needs a provider", ErrInvalid)
	}
	// Rule ids are provider-scoped because they are not portable between
	// providers.
	return IdentityRule, "rule:" + providerRef + ":" + raw, raw, nil
}

// CanonicalizeIdentity resolves the canonical problem identity. A CVE wins
// over a GHSA, which wins over a provider-scoped rule id; every other
// identity becomes an alias.
func CanonicalizeIdentity(providerRef, identity string, aliases []string) (CanonicalIdentity, error) {
	type ident struct{ kind, key, rule string }
	all := make([]ident, 0, len(aliases)+1)
	for i, raw := range append([]string{identity}, aliases...) {
		if i > 0 && strings.TrimSpace(raw) == "" {
			continue
		}
		k, key, rule, err := classify(providerRef, raw)
		if err != nil {
			return CanonicalIdentity{}, err
		}
		all = append(all, ident{k, key, rule})
	}
	seen := map[string]bool{}
	keys := make([]string, 0, len(all))
	for _, a := range all {
		if !seen[a.key] {
			seen[a.key] = true
			keys = append(keys, a.key)
		}
	}
	sort.Strings(keys)

	best := all[0]
	rank := func(kind string) int {
		switch kind {
		case IdentityCVE:
			return 3
		case IdentityGHSA:
			return 2
		}
		return 1
	}
	for _, a := range all[1:] {
		if rank(a.kind) > rank(best.kind) || (rank(a.kind) == rank(best.kind) && rank(a.kind) > 1 && a.key < best.key) {
			best = a
		}
	}
	return CanonicalIdentity{Kind: best.kind, Key: best.key, Keys: keys, RuleID: best.rule}, nil
}

// NormalizeSubject lowercases and trims a subject into its canonical form.
// ruleID is applied only to rule identities.
func NormalizeSubject(s Subject, ruleID string) (Subject, error) {
	out := Subject{
		Repository:     normalizeRepository(s.Repository),
		Resource:       strings.ToLower(strings.TrimSpace(s.Resource)),
		PackagePURL:    normalizePURL(s.PackagePURL),
		Path:           normalizePath(s.Path),
		Location:       strings.TrimSpace(s.Location),
		ArtifactDigest: strings.ToLower(strings.TrimSpace(s.ArtifactDigest)),
		Service:        strings.ToLower(strings.TrimSpace(s.Service)),
		RuleID:         ruleID,
	}
	if out.ArtifactDigest != "" && !digestPattern.MatchString(out.ArtifactDigest) {
		return Subject{}, fmt.Errorf("%w: artifact_digest must look like sha256:<hex>", ErrInvalid)
	}
	for _, f := range []string{out.Repository, out.Resource, out.PackagePURL, out.Path, out.Location, out.Service, out.RuleID} {
		if len(f) > 1024 {
			return Subject{}, fmt.Errorf("%w: subject field too long", ErrInvalid)
		}
	}
	return out, nil
}

// checkSubjectStrength refuses a subject that names a problem and a
// repository but no package, path, location or artifact identity.
func checkSubjectStrength(s Subject) error {
	if (s.Repository == "" && s.Resource == "") ||
		(s.PackagePURL == "" && s.Path == "" && s.Location == "" && s.ArtifactDigest == "") {
		return ErrSubjectTooWeak
	}
	return nil
}

// Fingerprint is the SHA-256 over the canonical (sorted-key) JSON of the
// normalized subject. The revision is deliberately not part of it: it changes
// across fixes. The artifact digest is, so a source state and a deployed
// artifact state stay distinct occurrences.
func Fingerprint(s Subject) string {
	m := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("repository", s.Repository)
	set("resource", s.Resource)
	set("package_purl", s.PackagePURL)
	set("path", s.Path)
	set("location", s.Location)
	set("artifact_digest", s.ArtifactDigest)
	set("service", s.Service)
	set("rule_id", s.RuleID)
	b, _ := json.Marshal(m) // map[string]string: keys sorted, cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeRepository(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	for _, p := range []string{"https://", "http://", "ssh://", "git@"} {
		r = strings.TrimPrefix(r, p)
	}
	r = strings.TrimPrefix(r, "github.com:")
	r = strings.TrimSuffix(strings.TrimSuffix(r, "/"), ".git")
	return strings.TrimPrefix(r, "github.com/")
}

func normalizePath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return ""
	}
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")
	if p == "." {
		return ""
	}
	return p
}

// normalizePURL lowercases the scheme and type, drops the subpath and sorts
// the qualifiers so equivalent purls from different providers compare equal.
func normalizePURL(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.Index(p, "#"); i >= 0 {
		p = p[:i]
	}
	base, qual, hasQual := strings.Cut(p, "?")
	if strings.HasPrefix(strings.ToLower(base), "pkg:") {
		if i := strings.Index(base, "/"); i > 0 {
			base = strings.ToLower(base[:i]) + base[i:]
		}
	}
	if !hasQual || qual == "" {
		return base
	}
	parts := strings.Split(qual, "&")
	sort.Strings(parts)
	return base + "?" + strings.Join(parts, "&")
}
