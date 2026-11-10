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

//go:build !glovojoin_fixture

package control

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// T29: the fixture seam cannot reach a release build. The gate and the dispatch
// TTL are constants of the build; the only way to open the first or move the
// second is the glovojoin_fixture tag, which nothing that ships passes.

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
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func goRun(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...) //nolint:gosec // fixed arguments of a test
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestReleaseBuildIsClosedAndFixed(t *testing.T) {
	if glovo.ControlDefault.Open {
		t.Fatal("the control gate is open in a release build")
	}
	if glovo.Default.Open {
		t.Fatal("the Glovo gate is open in a release build")
	}
	const ttl time.Duration = DispatchCommandTTL // a constant: a variable would not compile here
	if ttl != 900*time.Second {
		t.Fatalf("the dispatch TTL is %s", ttl)
	}
}

func TestFixtureFilesOnlyUnderTheTag(t *testing.T) {
	list := func(pkg string, tags ...string) string {
		args := []string{"list"}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		return goRun(t, append(args, "-f", "{{join .GoFiles \" \"}}", pkg)...)
	}
	for _, c := range []struct{ pkg, release, fixture string }{
		{"./internal/glovo", "gate_release.go", "gate_fixture.go"},
		{"./internal/glovo/control", "ttl_release.go", "ttl_fixture.go"},
	} {
		plain := " " + strings.TrimSpace(list(c.pkg)) + " "
		tagged := " " + strings.TrimSpace(list(c.pkg, "glovojoin_fixture")) + " "
		if !strings.Contains(plain, " "+c.release+" ") || strings.Contains(plain, " "+c.fixture+" ") {
			t.Errorf("%s without the tag: %s", c.pkg, plain)
		}
		if strings.Contains(tagged, " "+c.release+" ") || !strings.Contains(tagged, " "+c.fixture+" ") {
			t.Errorf("%s with the tag: %s", c.pkg, tagged)
		}
	}
}

func TestNothingThatShipsPassesTheTag(t *testing.T) {
	root := repoRoot(t)
	files := []string{"Dockerfile", "Makefile"}
	for _, glob := range []string{".github/workflows/*", "helm/*", "helm/*/*", "helm/*/templates/*", "scripts/*"} {
		m, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			rel, _ := filepath.Rel(root, f)
			files = append(files, rel)
		}
	}
	scanned := 0
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, f)) //nolint:gosec // paths under the repository root
		if err != nil {
			continue // a directory or a file that is not there
		}
		scanned++
		if strings.Contains(string(b), "glovojoin_fixture") {
			t.Errorf("%s mentions the fixture tag", f)
		}
	}
	if scanned < 5 {
		t.Fatalf("only %d build files scanned: the scan is not looking where the build is", scanned)
	}
	docker, err := os.ReadFile(filepath.Join(root, "Dockerfile")) //nolint:gosec // fixed path
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(docker), "-tags") {
		t.Error("the Dockerfile builds with -tags: the build must be the plain one")
	}
}

// The fixture half runs under the tag, in a child go test, so that the one
// default `go test ./...` also proves the tagged build compiles and behaves.
func TestFixtureBuildOpensTheSeam(t *testing.T) {
	out := goRun(t, "test", "-tags", "glovojoin_fixture", "-count=1", "-run", "^TestFixtureSeam$", "-v", "./internal/glovo/control/")
	if !strings.Contains(out, "--- PASS: TestFixtureSeam") {
		t.Fatalf("the tagged test did not run:\n%s", out)
	}
}
