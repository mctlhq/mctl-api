// Copyright 2026 MCTL Authors
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

package glovojoin

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

// A digest recorded next to the code is the frozen one: a change of the
// contract document has to change this file in the same commit.
func TestVersionDigestsMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/version-digests.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[contract.Version] != contract.Digest {
		t.Fatalf("version-digests.json = %v, contract is %s %s", m, contract.Version, contract.Digest)
	}
}

// T7a/T7b: the join package never speaks the glovo-read wire (that is the
// read bridge's) and never handles a grr_ read id.
func TestJoinPackageDoesNotUseTheReadWireOrReadIDs(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, bad := range []string{"glovo-read/v1alpha1", "grr_"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s mentions %q", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// T14: the join never turns the v1alpha2 wire on. The only non-test caller of
// EnableWireVersions is the runtime store constructor, and the plain NewStore
// leaves the flag off.
func TestWireVersionsAreEnabledOnlyByTheRuntimeStore(t *testing.T) {
	var callers []string
	root := filepath.Join("..", "..")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if strings.Contains(t, ".EnableWireVersions(") && !strings.HasPrefix(t, "//") {
				callers = append(callers, filepath.ToSlash(p))
			}
		}
		return nil
	})
	if len(callers) != 1 || !strings.HasSuffix(callers[0], "internal/bridge/runtime.go") {
		t.Fatalf("EnableWireVersions callers = %v, want only internal/bridge/runtime.go", callers)
	}
	s := newStack(t)
	st, err := bridge.NewStore(context.Background(), s.url(s.mig))
	if err != nil {
		t.Fatalf("bridge.NewStore: %v", err)
	}
	defer st.Close()
	if st.WireVersionsEnabled() {
		t.Fatal("NewStore turned the wire versions on")
	}
}
