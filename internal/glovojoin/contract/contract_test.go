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

package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // fixed test paths inside the repository
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// A byte change to the document without a new Digest constant fails here.
func TestContractDigestIsPinned(t *testing.T) {
	if got := ComputedDigest(); got != Digest {
		t.Fatalf("embedded contract digest %s != pinned %s: bump Version and Digest together", got, Digest)
	}
}

func TestContractVersionMatchesDocument(t *testing.T) {
	d := MustLoad()
	if d.Version != Version || d.BasePath != BasePath {
		t.Fatalf("document version/base %q %q != %q %q", d.Version, d.BasePath, Version, BasePath)
	}
	if len(d.Routes) != 9 {
		t.Fatalf("routes = %d, want 9", len(d.Routes))
	}
}

// The frozen upstream inputs are byte-pinned; they must be changed upstream.
func TestVendoredInputsArePinned(t *testing.T) {
	pins := map[string]string{
		"testdata/glovo-mcp-tools.json":    "sha256:b7df86b017442a890a3f409a0e4fe610b29b8ea94fbdc7c4d1ee57f398dab50c",
		"testdata/facade/wire.golden.json": "sha256:5acdde3ae3fd92bf81b7f91d8f52b4767627de3f1c080058dda6dea2db295f0a",
	}
	for p, want := range pins {
		if got := fileSHA(t, p); got != want {
			t.Errorf("%s digest %s != %s", p, got, want)
		}
	}
}

// The bridge schemas the contract depends on must equal the in-repo files.
func TestDependencyDigestsMatchBridgeSchemas(t *testing.T) {
	d := MustLoad()
	root := filepath.Join("..", "..", "bridge", "schema")
	for name, want := range d.Dependencies.BridgeV1alpha1 {
		if got := fileSHA(t, filepath.Join(root, name)); got != want {
			t.Errorf("%s digest %s != contract %s", name, got, want)
		}
	}
	got := fileSHA(t, filepath.Join(root, "v1alpha2", "command-place-order-fake.schema.json"))
	if got != d.Dependencies.PlaceOrderFakeSchema {
		t.Errorf("place-order-fake digest %s != contract %s", got, d.Dependencies.PlaceOrderFakeSchema)
	}
}

// Every route that names a tool has a 200 schema equal to the pinned tool
// output schema, except that the order route drops handoff_url (the facade
// never returns a handoff).
func TestRouteResponsesEqualPinnedToolOutputSchemas(t *testing.T) {
	b, err := os.ReadFile("testdata/glovo-mcp-tools.json")
	if err != nil {
		t.Fatal(err)
	}
	var tools struct {
		Tools []struct {
			Name         string         `json:"name"`
			OutputSchema map[string]any `json:"output_schema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &tools); err != nil {
		t.Fatal(err)
	}
	by := map[string]map[string]any{}
	for _, tl := range tools.Tools {
		by[tl.Name] = tl.OutputSchema
	}
	for _, r := range MustLoad().Routes {
		if r.Tool == nil {
			continue
		}
		want, ok := by[*r.Tool]
		if !ok {
			t.Errorf("route %s: tool %s not in pinned schema", r.ID, *r.Tool)
			continue
		}
		var got map[string]any
		if err := json.Unmarshal(r.Response, &got); err != nil {
			t.Fatal(err)
		}
		if r.ID == "order" {
			props, _ := want["properties"].(map[string]any)
			cp := map[string]any{}
			for k, v := range want {
				cp[k] = v
			}
			np := map[string]any{}
			for k, v := range props {
				if k != "handoff_url" {
					np[k] = v
				}
			}
			cp["properties"] = np
			want = cp
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(want)
		if !bytes.Equal(gb, wb) {
			t.Errorf("route %s response schema differs from tool %s output schema", r.ID, *r.Tool)
		}
	}
}

func TestWireForIsClosedAndFailsClosed(t *testing.T) {
	d := MustLoad()
	for _, c := range d.Errors.Codes {
		if s, w := d.WireFor(c.Code); s != c.Status || w != c.Wire {
			t.Errorf("%s -> %d %s, want %d %s", c.Code, s, w, c.Status, c.Wire)
		}
	}
	if s, w := d.WireFor("no_such_code"); s != 503 || w != "dependency_unavailable" {
		t.Errorf("unknown code -> %d %s", s, w)
	}
}
