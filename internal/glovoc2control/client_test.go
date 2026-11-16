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

package glovoc2control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeToken(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c, err := New(s.URL, writeToken(t, "tok-secret\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSetKilledSendsAuthenticatedPutAndConfirms(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer tok-secret" {
			t.Errorf("bad request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"killed":true}`))
	})
	st, err := c.SetKilled(context.Background(), true)
	if err != nil || !st.Killed {
		t.Fatalf("st=%+v err=%v", st, err)
	}
}

func TestSetKilledFailuresAreUnknown(t *testing.T) {
	bodies := map[string]func(http.ResponseWriter, *http.Request){
		"500": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"401 ok-looking body": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"killed":true}`))
		},
		"202 ok-looking body": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"killed":true}`))
		},
		"204":       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) },
		"empty":     func(w http.ResponseWriter, _ *http.Request) {},
		"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{`)) },
		"missing":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) },
		"mismatch":  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"killed":false}`)) },
		"oversize": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"killed":true,"x":"` + strings.Repeat("a", 5000) + `"}`))
		},
	}
	for name, h := range bodies {
		c := newTestClient(t, h)
		_, err := c.SetKilled(context.Background(), true)
		if !errors.Is(err, ErrUnknown) {
			t.Fatalf("%s: err=%v", name, err)
		}
		if strings.Contains(err.Error(), "tok-secret") {
			t.Fatalf("%s: token leaked in error", name)
		}
	}
	// Transport failure.
	c, _ := New("http://127.0.0.1:1", writeToken(t, "tok-secret"), nil)
	_, err := c.SetKilled(context.Background(), true)
	if !errors.Is(err, ErrUnknown) || !strings.Contains(err.Error(), "(connect)") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("transport: %v", err)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	for _, tc := range [][2]string{{"", "/t"}, {"ftp://x", "/t"}, {"http://u:p@x", "/t"}, {"http://x", ""}, {"http://x", "relative"}} {
		if _, err := New(tc[0], tc[1], nil); err == nil {
			t.Fatalf("accepted %q", tc)
		}
	}
}

func TestSetKilledNeverFollowsRedirects(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = w.Write([]byte(`{"killed":true}`))
	}))
	defer other.Close()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	if _, err := c.SetKilled(context.Background(), true); !errors.Is(err, ErrUnknown) {
		t.Fatalf("err=%v", err)
	}
	if hit {
		t.Fatal("redirect target was contacted (bearer token would leak)")
	}
}

func TestSetKilledRereadsTokenPerCall(t *testing.T) {
	var seen []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"killed":true}`))
	}))
	defer s.Close()
	p := writeToken(t, "first")
	c, err := New(s.URL, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"first", "second"} {
		if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SetKilled(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0] != "Bearer first" || seen[1] != "Bearer second" {
		t.Fatalf("token not re-read per call: %v", seen)
	}
}

func TestSetKilledBadTokenFileNeverSendsRequest(t *testing.T) {
	for name, content := range map[string]*string{"missing": nil, "empty": ptr(""), "blank": ptr(" \n"), "inner space": ptr("a b"), "oversize": ptr(strings.Repeat("a", 17000))} {
		hit := false
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hit = true
			_, _ = w.Write([]byte(`{"killed":true}`))
		}))
		p := filepath.Join(t.TempDir(), "absent")
		if content != nil {
			p = writeToken(t, *content)
		}
		c, err := New(s.URL, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.SetKilled(context.Background(), true)
		s.Close()
		if !errors.Is(err, ErrUnknown) || hit {
			t.Fatalf("%s: err=%v requestSent=%v", name, err, hit)
		}
	}
}

func ptr(s string) *string { return &s }
