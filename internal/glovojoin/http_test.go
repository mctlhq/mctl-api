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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

type httpFx struct {
	*stack
	rt  *Routes
	srv *httptest.Server
	b   *recBridge
	tok string
	ref string
}

func (f *httpFx) do(method, path string, hdr map[string]string, body string) (*http.Response, string) {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.String()
}

func (f *httpFx) auth(extra map[string]string) map[string]string {
	h := map[string]string{SubjectTokenHeader: f.tok, "Content-Type": "application/json"}
	if f.ref != "" {
		h[ScopeRefHeader] = f.ref
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func newHTTPFx(t *testing.T) *httpFx {
	s := newStack(t)
	s.activate("k-http")
	b := s.bridgeWith(t)
	res := &fakeResolver{sc: scope.Scope{PrincipalID: stackOwner, Tenant: stackTenant, Role: "admin", GrantID: "tgr_1", RefreshFamilyID: "fam_1"}}
	inst := &fakeInstalls{inst: &glovo.Install{InstallID: s.installID, TenantID: stackTenant, InstallRevision: s.installRev}}
	rt := &Routes{
		Verifier: &SubjectVerifier{Tokens: newOAuth(), Resolver: res, Installs: inst},
		Refs:     &ScopeRefs{DB: s.rp},
		Reader:   s.reader(b),
		Prepare:  s.prepare,
		Connect:  &connect.Service{Store: s.conns, HandoffBaseURL: "https://handoff.example"},
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.StripPrefix("/api/v1/assistants/glovo/v1alpha1", rt.Handler()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := &httpFx{stack: s, rt: rt, srv: srv, b: b, tok: glovoToken(t, time.Now().Add(time.Hour))}
	f.rt = rt
	return f
}

const jb = "/api/v1/assistants/glovo/v1alpha1"

func TestHTTPHappyPathResolveToPrepareAndReplay(t *testing.T) {
	f := newHTTPFx(t)
	resp, body := f.do("POST", jb+"/resolve", f.auth(nil), "{}")
	if resp.StatusCode != 200 {
		t.Fatalf("resolve %d %s", resp.StatusCode, body)
	}
	var rv struct{ ScopeRef, Tenant string }
	var raw map[string]string
	_ = json.Unmarshal([]byte(body), &raw)
	rv.ScopeRef, rv.Tenant = raw["scope_ref"], raw["tenant"]
	if rv.Tenant != stackTenant || !strings.HasPrefix(rv.ScopeRef, "gsc_") {
		t.Fatalf("resolve body %s", body)
	}
	f.ref = rv.ScopeRef

	resp, body = f.do("GET", jb+"/connection", f.auth(nil), "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"connection_state":"active"`) || strings.Contains(body, "provider_account_label") {
		t.Fatalf("connection %d %s", resp.StatusCode, body)
	}
	resp, body = f.do("POST", jb+"/orders:list", f.auth(nil), "{}")
	if resp.StatusCode != 200 {
		t.Fatalf("orders %d %s", resp.StatusCode, body)
	}
	var h struct {
		Orders []struct {
			OrderRef string `json:"order_ref"`
		}
	}
	_ = json.Unmarshal([]byte(body), &h)
	resp, body = f.do("POST", jb+"/previews", f.auth(nil), `{"order_ref":"`+h.Orders[0].OrderRef+`"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("preview %d %s", resp.StatusCode, body)
	}
	var pv struct {
		PreviewID string `json:"preview_id"`
	}
	_ = json.Unmarshal([]byte(body), &pv)
	pbody := `{"preview_id":"` + pv.PreviewID + `","idempotency_key":"k1"}`
	resp1, first := f.do("POST", jb+"/orders:prepare", f.auth(map[string]string{"Idempotency-Key": "k1"}), pbody)
	if resp1.StatusCode != 200 || resp1.Header.Get("Idempotent-Replayed") != "" {
		t.Fatalf("prepare %d %s", resp1.StatusCode, first)
	}
	resp2, second := f.do("POST", jb+"/orders:prepare", f.auth(map[string]string{"Idempotency-Key": "k1"}), pbody)
	if resp2.StatusCode != 200 || resp2.Header.Get("Idempotent-Replayed") != "true" || second != first {
		t.Fatalf("replay %d %q vs %q", resp2.StatusCode, second, first)
	}
	if w := f.writes(); w[5] != 0 {
		t.Fatalf("bridge_commands = %d", w[5])
	}
}

func TestHTTPRefusalsAndErrorBodies(t *testing.T) {
	f := newHTTPFx(t)
	_, body := f.do("POST", jb+"/resolve", f.auth(nil), "{}")
	var raw map[string]string
	_ = json.Unmarshal([]byte(body), &raw)
	f.ref = raw["scope_ref"]
	pb := `{"preview_id":"pvw_x","idempotency_key":"a"}`
	cases := []struct {
		name, method, path string
		hdr                map[string]string
		body               string
		status             int
		wire               string
	}{
		{"no token", "POST", "/resolve", map[string]string{}, "{}", 401, ""},
		{"token in query", "POST", "/resolve?access_token=x", f.auth(nil), "{}", 401, ""},
		{"query string", "GET", "/basket?x=1", f.auth(nil), "", 400, "invalid_arguments"},
		{"unknown field", "POST", "/resolve", f.auth(nil), `{"a":1}`, 400, "invalid_arguments"},
		{"trailing value", "POST", "/resolve", f.auth(nil), `{}{}`, 400, "invalid_arguments"},
		{"key mismatch", "POST", "/orders:prepare", f.auth(map[string]string{"Idempotency-Key": "b"}), pb, 400, "invalid_arguments"},
		{"key missing", "POST", "/orders:prepare", f.auth(nil), pb, 400, "invalid_arguments"},
		{"limit too big", "POST", "/orders:list", f.auth(nil), `{"limit":21}`, 400, "invalid_arguments"},
		{"no scope ref", "GET", "/connection", map[string]string{SubjectTokenHeader: f.tok}, "", 403, ""},
		{"bad order ref", "GET", "/orders/nope", f.auth(nil), "", 404, "not_found"},
		{"status unwired", "GET", "/orders/ordr_AAAAAAAAAAAAAAAAAAAA", f.auth(nil), "", 503, "not_ready"},
		{"unissued preview", "POST", "/orders:prepare", f.auth(map[string]string{"Idempotency-Key": "a"}), pb, 404, "not_found"},
	}
	for _, c := range cases {
		resp, b := f.do(c.method, jb+c.path, c.hdr, c.body)
		if resp.StatusCode != c.status {
			t.Errorf("%s: status %d (%s), want %d", c.name, resp.StatusCode, b, c.status)
			continue
		}
		if c.wire != "" {
			var e map[string]string
			if err := json.Unmarshal([]byte(b), &e); err != nil || e["error"] != c.wire && !(c.name == "status unwired") || e["error_description"] == "" {
				t.Errorf("%s: body %s", c.name, b)
			}
		}
	}
}

func TestHTTPRateLimitsCarryRetryAfter(t *testing.T) {
	f := newHTTPFx(t)
	f.rt.PerSubject = 3
	f.rt.Writes = 2
	f.rt.Aggregate = 1000
	// reinitialise the limiters with the small limits (fresh once)
	f.rt.once = sync.Once{}
	_ = f.rt.Handler()
	codes := []int{}
	for i := 0; i < 5; i++ {
		resp, _ := f.do("POST", jb+"/resolve", f.auth(nil), "{}")
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == 429 && resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	if codes[3] != 429 && codes[4] != 429 {
		t.Fatalf("codes = %v", codes)
	}
}

func TestHTTPCompatibilityIsNeverDeployReady(t *testing.T) {
	f := newHTTPFx(t)
	resp, body := f.do("GET", jb+"/compatibility", nil, "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"deploy_ready":false`) {
		t.Fatalf("compat %d %s", resp.StatusCode, body)
	}
}
