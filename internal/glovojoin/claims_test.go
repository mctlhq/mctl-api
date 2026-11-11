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
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// bannedClaim matches prose that says the account is connected, the basket
// moved, or the order was placed. The facade only prepares an order for the
// owner's decision (owner constraint 10.11): none of those is ever true at
// this layer, so none may be said. State and outcome values such as "placed"
// are contract data, not prose, and are not matched on their own.
var bannedClaim = regexp.MustCompile(`(?i)(account\W+(is\W+|was\W+|has\W+been\W+)?connected|(is|are|was|have|has)\W+(now\W+|been\W+)?connected|connected\W+(your|the)\W+account|` +
	`basket\W+(is\W+|was\W+|has\W+been\W+)?(transferred|sent|moved|copied|added)|(transferred|sent|moved|copied|added)\W+(your|the)\W+basket|` +
	`order\W+(is\W+|was\W+|has\W+been\W+)?(placed|confirmed|submitted|completed)|(placed|confirmed|submitted)\W+(your|the)\W+order|` +
	`successfully\W+(connected|placed|ordered))`)

func jsonStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			jsonStrings(e, out)
		}
	case map[string]any:
		for _, e := range x {
			jsonStrings(e, out)
		}
	}
}

func TestBannedClaimPatternMatchesWhatItShould(t *testing.T) {
	for _, s := range []string{"Your account is connected", "The basket was transferred", "Order placed", "your order has been placed",
		"We connected your account", "successfully ordered", "the order is confirmed"} {
		if !bannedClaim.MatchString(s) {
			t.Errorf("%q is not matched", s)
		}
	}
	for _, s := range []string{"awaiting_approval", "OUTCOME_UNKNOWN", "connection_state", "OUTCOME_OBSERVED_PLACED", "the owner decides", "not_ready"} {
		if bannedClaim.MatchString(s) {
			t.Errorf("%q is matched", s)
		}
	}
}

// Every string a user could be shown through the facade: the body of every
// error the writer can produce, and every golden of every route.
func TestFacadeNeverClaimsConnectionTransferOrPlacement(t *testing.T) {
	rt := &Routes{}
	rt.init()
	var all []string
	for _, c := range rt.doc.Errors.Codes {
		rec := httptest.NewRecorder()
		rt.refuse(rec, "x", &Refusal{Err: glovo.Refuse(glovo.Code(c.Code)), Reason: "r"})
		var v any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("%s: %v", c.Code, err)
		}
		jsonStrings(v, &all)
	}
	files, err := filepath.Glob(filepath.Join("testdata", "v1alpha1", "*", "*.json"))
	if err != nil || len(files) < 8 {
		t.Fatalf("goldens: %d files, %v", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // testdata path from Glob
		if err != nil {
			t.Fatal(err)
		}
		_, body, _ := strings.Cut(string(raw), "\n")
		var v any
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		jsonStrings(v, &all)
	}
	if len(all) < 40 {
		t.Fatalf("only %d strings scanned", len(all))
	}
	for _, s := range all {
		if bannedClaim.MatchString(s) {
			t.Errorf("a user-facing string claims connection, transfer or placement: %q", s)
		}
	}
}

// No full URL, token or session parameter reaches an application log: the join
// slice writes no application log at all (it counts refusals in metrics with
// fixed labels). If a log call appears, this fails and the redaction rule of
// 10.11 becomes owed.
func TestJoinSliceWritesNoApplicationLog(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob(filepath.Join("..", "api", "glovo_join*.go"))
	more2, _ := filepath.Glob(filepath.Join("..", "..", "cmd", "api", "glovo_join.go"))
	files = append(append(files, more...), more2...)
	logCall := regexp.MustCompile(`\b(slog\.(Debug|Info|Warn|Error|Log)|log\.(Print|Fatal|Panic)\w*|fmt\.Print\w*)\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // package source
		if err != nil {
			t.Fatal(err)
		}
		if loc := logCall.FindIndex(src); loc != nil {
			t.Errorf("%s writes to a log: %s", f, src[loc[0]:loc[1]])
		}
	}
}
