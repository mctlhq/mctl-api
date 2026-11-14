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

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
)

// trailingBodies are one valid object followed by something that is not
// whitespace. dec.More() is false before a stray '}' or ']', which is how
// the first two used to get through.
var trailingBodies = []string{`{"a":1}}`, `{"a":1}]`, `{"a":1} {"b":2}`, `{"a":1} 1`}

func TestJSONHasTrailingData(t *testing.T) {
	for _, body := range append(trailingBodies, `{"a":1}x`) {
		dec := json.NewDecoder(strings.NewReader(body))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%s: decode: %v", body, err)
		}
		if !jsonHasTrailingData(dec) {
			t.Errorf("%s: trailing data not detected", body)
		}
	}
	for _, body := range []string{`{"a":1}`, "{\"a\":1}  \n\t"} {
		dec := json.NewDecoder(strings.NewReader(body))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%q: decode: %v", body, err)
		}
		if jsonHasTrailingData(dec) {
			t.Errorf("%q: clean body reported as trailing data", body)
		}
	}
}

func TestDecodeReviewBodyRefusesTrailingData(t *testing.T) {
	for _, body := range trailingBodies {
		var dst struct {
			A int `json:"a"`
		}
		w := httptest.NewRecorder()
		if code := decodeReviewBody(w, []byte(body), &dst); code != reviewreceipts.CodeMalformed {
			t.Errorf("%s: code %q, want %q", body, code, reviewreceipts.CodeMalformed)
		}
	}
}

func TestDecodeDecisionBodyRefusesTrailingData(t *testing.T) {
	for _, body := range trailingBodies {
		var dst struct {
			A int `json:"a"`
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if decodeDecisionBody(w, r, &dst) {
			t.Errorf("%s: accepted", body)
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, w.Code)
		}
	}
}
