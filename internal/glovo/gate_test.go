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

package glovo

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestGateClosed(t *testing.T) {
	for _, u := range []*auth.User{nil, {ID: "a"}} {
		if e := Default.Authorize(u); e == nil || e.Code != CodeNotReady {
			t.Fatalf("got %v", e)
		}
	}
}

func TestGateOpenDenies(t *testing.T) {
	g := Gate{Open: true}
	for _, u := range []*auth.User{nil, {ID: "a"}, auth.NewGitHubUser("alice", nil)} {
		if e := g.Authorize(u); e == nil || e.Code != CodeNotAuthorized {
			t.Fatalf("got %v", e)
		}
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, &Error{Code: CodeNotReady, Description: "d"})
	if w.Code != 503 || w.Body.String() != "{\"error\":\"not_ready\",\"error_description\":\"d\"}\n" {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	WriteError(w, &Error{Code: CodeNotAuthorized, Description: "d"})
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	if !errors.Is(&Error{Code: CodeNotReady}, &Error{Code: CodeNotReady}) {
		t.Fatal("errors.Is")
	}
}
