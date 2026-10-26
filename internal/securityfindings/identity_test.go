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
	"errors"
	"reflect"
	"testing"
)

func TestCanonicalizeIdentity(t *testing.T) {
	cases := []struct {
		name     string
		identity string
		aliases  []string
		kind     string
		key      string
		keys     []string
	}{
		{"cve upper-cased", "cve-2024-1234", nil, IdentityCVE, "cve:CVE-2024-1234", []string{"cve:CVE-2024-1234"}},
		{"ghsa lower-cased", "GHSA-ABCD-1234-WXYZ", nil, IdentityGHSA, "ghsa:ghsa-abcd-1234-wxyz", []string{"ghsa:ghsa-abcd-1234-wxyz"}},
		{"cve wins over ghsa", "GHSA-abcd-1234-wxyz", []string{"CVE-2024-1234"}, IdentityCVE, "cve:CVE-2024-1234",
			[]string{"cve:CVE-2024-1234", "ghsa:ghsa-abcd-1234-wxyz"}},
		{"rule is provider scoped", "go/sql-injection", nil, IdentityRule, "rule:codeql:go/sql-injection", []string{"rule:codeql:go/sql-injection"}},
		{"cve alias outranks a rule", "go/sql-injection", []string{"CVE-2024-12345"}, IdentityCVE, "cve:CVE-2024-12345",
			[]string{"cve:CVE-2024-12345", "rule:codeql:go/sql-injection"}},
	}
	for _, c := range cases {
		got, err := CanonicalizeIdentity("codeql", c.identity, c.aliases)
		if err != nil || got.Kind != c.kind || got.Key != c.key || !reflect.DeepEqual(got.Keys, c.keys) {
			t.Errorf("%s: got %+v err %v", c.name, got, err)
		}
	}
	if _, err := CanonicalizeIdentity("codeql", " ", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty identity: %v", err)
	}
	// The same rule id from two providers is two identities.
	a, _ := CanonicalizeIdentity("codeql", "r1", nil)
	b, _ := CanonicalizeIdentity("semgrep", "r1", nil)
	if a.Key == b.Key {
		t.Errorf("rule identities must be provider scoped")
	}
}

func TestSubjectFingerprint(t *testing.T) {
	norm := func(s Subject) Subject {
		out, err := NormalizeSubject(s, "")
		if err != nil {
			t.Fatalf("NormalizeSubject(%+v): %v", s, err)
		}
		return out
	}
	base := Subject{Repository: "MCTLHQ/mctl-api", PackagePURL: "pkg:golang/example.com/x@1.2.3?b=2&a=1"}
	same := Subject{Repository: "https://github.com/mctlhq/mctl-api.git", PackagePURL: "PKG:golang/example.com/x@1.2.3?a=1&b=2#sub"}
	if Fingerprint(norm(base)) != Fingerprint(norm(same)) {
		t.Errorf("equivalent subjects from different providers must share a fingerprint")
	}
	differ := []Subject{
		{Repository: "mctlhq/other", PackagePURL: base.PackagePURL},
		{Repository: base.Repository, PackagePURL: base.PackagePURL, ArtifactDigest: "sha256:" + hex64('a')},
		{Repository: base.Repository, PackagePURL: base.PackagePURL, ArtifactDigest: "sha256:" + hex64('b')},
		{Repository: base.Repository, Path: "a.go", Location: "1:2"},
		{Repository: base.Repository, Path: "a.go", Location: "3:4"},
	}
	seen := map[string]int{Fingerprint(norm(base)): -1}
	for i, d := range differ {
		fp := Fingerprint(norm(d))
		if j, dup := seen[fp]; dup {
			t.Errorf("subject %d collides with %d", i, j)
		}
		seen[fp] = i
	}
	if _, err := NormalizeSubject(Subject{Repository: "r", ArtifactDigest: "latest"}, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("malformed artifact digest: %v", err)
	}
	// The rule id is part of a rule identity's subject.
	r1, _ := NormalizeSubject(Subject{Repository: "r", Path: "a.go"}, "x")
	r2, _ := NormalizeSubject(Subject{Repository: "r", Path: "a.go"}, "y")
	if Fingerprint(r1) == Fingerprint(r2) {
		t.Errorf("rule id must change the fingerprint")
	}
}

func TestSubjectTooWeak(t *testing.T) {
	weak := []Subject{
		{},
		{Repository: "mctlhq/mctl-api"},
		{PackagePURL: "pkg:golang/x@1"},
		{Service: "api", Repository: "mctlhq/mctl-api"},
	}
	for _, w := range weak {
		n, _ := NormalizeSubject(w, "")
		if err := checkSubjectStrength(n); !errors.Is(err, ErrSubjectTooWeak) {
			t.Errorf("%+v should be too weak", w)
		}
	}
	for _, ok := range []Subject{
		{Repository: "r", PackagePURL: "pkg:golang/x@1"},
		{Repository: "r", Path: "a.go"},
		{Resource: "registry/img", ArtifactDigest: "sha256:" + hex64('c')},
		{Repository: "r", Location: "func Foo"},
	} {
		n, _ := NormalizeSubject(ok, "")
		if err := checkSubjectStrength(n); err != nil {
			t.Errorf("%+v should be strong enough: %v", ok, err)
		}
	}
}

func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
