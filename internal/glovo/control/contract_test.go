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

package control

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

//go:embed contract
var contractFS embed.FS

// Every artifact matches SHA256SUMS, none is missing, none is extra, and each
// refusal code of the closed set has a dispatch case. The consumer (#990)
// pins the same sums.
func TestContractArtifactsMatchSums(t *testing.T) {
	sums, err := contractFS.ReadFile("contract/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("bad SHA256SUMS line %q", line)
		}
		listed[f[1]] = f[0]
	}
	entries, err := contractFS.ReadDir("contract")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if e.Name() == "SHA256SUMS" {
			continue
		}
		seen++
		data, err := contractFS.ReadFile("contract/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		if listed[e.Name()] != hex.EncodeToString(h[:]) {
			t.Errorf("%s does not match SHA256SUMS", e.Name())
		}
		if !json.Valid(data) {
			t.Errorf("%s is not JSON", e.Name())
		}
	}
	if seen != len(listed) {
		t.Errorf("%d artifacts, %d sums", seen, len(listed))
	}
	for _, c := range RefusalCodes {
		if _, ok := listed["dispatch_refused_"+string(c)+".json"]; !ok {
			t.Errorf("no dispatch case for refusal %s", c)
		}
	}
}
