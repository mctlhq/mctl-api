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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestGateClosed(t *testing.T) {
	for _, u := range []*auth.User{nil, {ID: "a"}} {
		if !errors.Is(Default.Authorize(u), &Error{Code: CodeNotReady}) {
			t.Fatalf("got %v", Default.Authorize(u))
		}
	}
}

func TestGateOpenDenies(t *testing.T) {
	g := Gate{Open: true}
	for _, u := range []*auth.User{nil, {ID: "a"}, auth.NewGitHubUser("alice", nil)} {
		if !errors.Is(g.Authorize(u), &Error{Code: CodeNotAuthorized}) {
			t.Fatalf("got %v", g.Authorize(u))
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

// glovoUser verifies a forged Glovo-audience token with a principal, the only
// way outside package auth to obtain such a caller.
func glovoUser(t *testing.T, pid string) *auth.User {
	t.Helper()
	const base = "https://api.example"
	secret := []byte("test-secret")
	o := auth.NewOAuthServer(base, "c", "s", secret, nil, auth.NewGitHubValidator(nil))
	o.GlovoResource = auth.GlovoResourceIntended
	o.PrincipalMode = true
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(map[string]any{"iss": base, "sub": "dan", "aud": auth.GlovoResourceIntended, "pid": pid,
		"groups": []string{}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(in))
	u, err := o.ValidateJWT(in + "." + enc.EncodeToString(mac.Sum(nil)))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestGateOpenAuthorizesGlovoPrincipal(t *testing.T) {
	u := glovoUser(t, "prn_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if !u.IsGlovoAudience() {
		t.Fatal("not a glovo-audience user")
	}
	if err := (Gate{Open: true}).Authorize(u); err != nil {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(Default.Authorize(u), &Error{Code: CodeNotReady}) {
		t.Fatal("closed gate must refuse")
	}
}
