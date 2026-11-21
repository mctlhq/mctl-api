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

package grant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const grantImportPath = "github.com/mctlhq/mctl-api/internal/glovo/grant"

// allowedImporters are the production packages that may import this one.
// Today there is none: the human decision path and the point of effect are
// the next slices, and each adds its own package here in the PR that wires
// it, where a reviewer sees it. An MCP tool package must never be listed.
var allowedImporters = map[string]bool{}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir = parent
			continue
		}
		t.Fatal("go.mod not found")
	}
}

// TestOnlyAllowedPackagesImportGrant keeps the mint and consume surface away
// from every MCP tool, agent path and route that nobody reviewed for it.
func TestOnlyAllowedPackagesImportGrant(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var seen int
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "vendor" || n == ".worktrees" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		seen++
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		for _, im := range f.Imports {
			if strings.Trim(im.Path.Value, "`\"") == grantImportPath && rel != "internal/glovo/grant" && !allowedImporters[rel] {
				t.Errorf("%s imports the grant package, which no reviewed path is allowed to yet", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 100 {
		t.Fatalf("the walk saw only %d files: the scan is not looking at the repository", seen)
	}
}
