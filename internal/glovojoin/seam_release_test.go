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

package glovojoin

import (
	"os/exec"
	"strings"
	"testing"
)

// T29 (join half): the fixture files are in the package only under the tag.
func TestFixtureFilesOnlyUnderTheTag(t *testing.T) {
	list := func(tags ...string) string {
		args := []string{"list"}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		out, err := exec.Command("go", append(args, "-f", `{{join .GoFiles " "}}`, ".")...).CombinedOutput() //nolint:gosec // fixed arguments of a test
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		return " " + strings.TrimSpace(string(out)) + " "
	}
	plain, tagged := list(), list("glovojoin_fixture")
	for _, c := range [][2]string{{"ttl_release.go", "ttl_fixture.go"}} {
		if !strings.Contains(plain, " "+c[0]+" ") || strings.Contains(plain, " "+c[1]+" ") {
			t.Errorf("without the tag: %s", plain)
		}
		if strings.Contains(tagged, " "+c[0]+" ") || !strings.Contains(tagged, " "+c[1]+" ") {
			t.Errorf("with the tag: %s", tagged)
		}
	}
	if strings.Contains(plain, " bridge_fixture.go ") || !strings.Contains(tagged, " bridge_fixture.go ") {
		t.Errorf("bridge_fixture.go must be in the tagged build only:\nplain: %s\ntagged: %s", plain, tagged)
	}
}
