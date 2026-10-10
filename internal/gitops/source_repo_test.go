// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ComponentSourceRepo (mctl-api#530): the record a CI token is checked
// against, so absence and unreadability must stay distinct.
func TestComponentSourceRepo(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	cache := filepath.Join(root, "cache")
	runGit(t, root, "init", "--bare", remote)
	runGit(t, root, "clone", remote, work)
	runGit(t, work, "checkout", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test User")
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(work, "platform-gitops", "services", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("labs/tg/catalog-info.yaml", "metadata:\n  annotations:\n    github.com/source-repo: mctlhq/mctl-telegram\n")
	write("labs/noannot/catalog-info.yaml", "metadata:\n  annotations:\n    argocd/app-name: labs-noannot\n")
	write("labs/nofile/values.yaml", "image: {tag: '1'}\n")
	write("labs/broken/catalog-info.yaml", "metadata: [\n")
	write("labs/numeric/catalog-info.yaml", "metadata:\n  annotations:\n    github.com/source-repo: {a: 1}\n")
	commitAll(t, work, "services")
	runGit(t, work, "push", "origin", "main")

	unsynced := &Reader{localPath: filepath.Join(root, "never")}
	if _, err := unsynced.ComponentSourceRepo("labs", "tg"); err == nil || errors.Is(err, ErrSourceRepoNotRegistered) {
		t.Fatalf("an unsynced checkout answered %v; it must be an error, not 'not registered'", err)
	}

	r := &Reader{repoURL: remote, branch: "main", localPath: cache}
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}
	if got, err := r.ComponentSourceRepo("labs", "tg"); err != nil || got != "mctlhq/mctl-telegram" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, c := range [][2]string{{"labs", "noannot"}, {"labs", "nofile"}, {"labs", "missing"}, {"nosuchteam", "tg"}} {
		if _, err := r.ComponentSourceRepo(c[0], c[1]); !errors.Is(err, ErrSourceRepoNotRegistered) {
			t.Errorf("%s/%s: got %v, want ErrSourceRepoNotRegistered", c[0], c[1], err)
		}
	}
	for _, c := range [][2]string{{"labs", "broken"}, {"labs", "numeric"}, {"labs", "../labs"}, {"..", "tg"}, {"labs", ""}} {
		if _, err := r.ComponentSourceRepo(c[0], c[1]); err == nil || errors.Is(err, ErrSourceRepoNotRegistered) {
			t.Errorf("%s/%s: got %v, want a read error", c[0], c[1], err)
		}
	}

	// A symlinked component directory or file is refused, not followed.
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "catalog-info.yaml"), []byte("metadata:\n  annotations:\n    github.com/source-repo: evil/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := filepath.Join(cache, "platform-gitops", "services", "labs")
	if err := os.Symlink(outside, filepath.Join(svc, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(svc, "linkfile"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "catalog-info.yaml"), filepath.Join(svc, "linkfile", "catalog-info.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, comp := range []string{"linkdir", "linkfile"} {
		if got, err := r.ComponentSourceRepo("labs", comp); err == nil || errors.Is(err, ErrSourceRepoNotRegistered) {
			t.Errorf("%s: got %q, %v; a symlink must be a read error", comp, got, err)
		}
	}
}
