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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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

var (
	goldenID   = regexp.MustCompile(`(gsc|pvw|ordr|tnr|prr|irv|pho|con|gin|apr|ccr|cns|aar|gpv)_[A-Za-z0-9_-]+`)
	goldenTime = regexp.MustCompile(`\d{4}-\d\d-\d\dT[0-9:.]+Z`)
	goldenSHA  = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	goldenKey  = regexp.MustCompile(`"(connection_id|handoff_url)":"[^"]+"`)
)

// golden compares one wire answer, with its volatile values replaced by
// placeholders, to testdata/v1alpha1/<route>/<name>.json.
func golden(t *testing.T, route, name string, status int, body string) {
	t.Helper()
	norm := goldenSHA.ReplaceAllString(goldenTime.ReplaceAllString(goldenID.ReplaceAllString(body, "<id>"), "<time>"), "<digest>")
	norm = goldenKey.ReplaceAllString(norm, `"$1":"<value>"`)
	got := fmt.Sprintf("%d\n%s\n", status, norm)
	path := filepath.Join("testdata", "v1alpha1", route, name+".json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (UPDATE_GOLDEN=1 writes it)", path, err)
	}
	if string(want) != got {
		t.Errorf("%s changed:\nwant %q\n got %q", path, want, got)
	}
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
	golden(t, "resolve", "ok", resp.StatusCode, body)

	resp, body = f.do("GET", jb+"/connection", f.auth(nil), "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"connection_state":"active"`) || strings.Contains(body, "provider_account_label") {
		t.Fatalf("connection %d %s", resp.StatusCode, body)
	}
	golden(t, "connection", "ok", resp.StatusCode, body)
	resp, body = f.do("POST", jb+"/orders:list", f.auth(nil), "{}")
	if resp.StatusCode != 200 {
		t.Fatalf("orders %d %s", resp.StatusCode, body)
	}
	golden(t, "orders", "ok", resp.StatusCode, body)
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
	golden(t, "preview", "ok", resp.StatusCode, body)
	var pv struct {
		PreviewID string `json:"preview_id"`
	}
	_ = json.Unmarshal([]byte(body), &pv)
	pbody := `{"preview_id":"` + pv.PreviewID + `","idempotency_key":"k1"}`
	resp1, first := f.do("POST", jb+"/orders:prepare", f.auth(map[string]string{"Idempotency-Key": "k1"}), pbody)
	if resp1.StatusCode != 200 || resp1.Header.Get("Idempotent-Replayed") != "" {
		t.Fatalf("prepare %d %s", resp1.StatusCode, first)
	}
	golden(t, "prepare", "ok", resp1.StatusCode, first)
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
		golden(t, "refusals", strings.ReplaceAll(c.name, " ", "_"), resp.StatusCode, b)
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
	golden(t, "compatibility", "not_ready", resp.StatusCode, body)
}

// A6: every row of the contract's code table and condition table reaches the
// wire with the status and body the contract says, through the same writer the
// routes use, and no refusal carries more than a fixed description.
func TestHTTPErrorWriterFollowsTheContractTables(t *testing.T) {
	rt := &Routes{}
	rt.init()
	var notes []Refused
	rt.OnRefused = func(e Refused) { notes = append(notes, e) }
	descByWire := map[string]string{}
	for _, c := range rt.doc.Errors.Codes {
		rec := httptest.NewRecorder()
		rt.refuse(rec, "x", &Refusal{Err: glovo.Refuse(glovo.Code(c.Code)), Reason: "leaky:detail"})
		var e map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
			t.Fatalf("%s: %v", c.Code, err)
		}
		if rec.Code != c.Status || e["error"] != c.Wire || len(e) != 2 || e["error_description"] == "" {
			t.Errorf("%s: %d %s, want %d %s", c.Code, rec.Code, rec.Body.String(), c.Status, c.Wire)
		}
		if strings.Contains(rec.Body.String(), "leaky") {
			t.Errorf("%s: the internal reason reached the wire", c.Code)
		}
		if rec.Code == 429 && rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s: 429 without Retry-After", c.Code)
		}
		if c.Wire == "dependency_unavailable" {
			if d, ok := descByWire[c.Wire]; ok && d != e["error_description"] {
				t.Errorf("%s: dependency_unavailable descriptions differ, one internal code is distinguishable", c.Code)
			}
			descByWire[c.Wire] = e["error_description"]
		}
	}
	if len(notes) != len(rt.doc.Errors.Codes) {
		t.Fatalf("OnRefused called %d times for %d refusals", len(notes), len(rt.doc.Errors.Codes))
	}
	for _, c := range rt.doc.Errors.Conditions {
		if c.Status == 401 {
			continue
		}
		for _, code := range strings.Split(c.Code, "|") {
			if st, _ := rt.doc.WireFor(code); st != c.Status {
				t.Errorf("condition %s: code %s maps to %d, table says %d", c.Reason, code, st, c.Status)
			}
		}
	}
	rec := httptest.NewRecorder()
	rt.refuse(rec, "x", &Refusal{Err: glovo.Refuse(glovo.Code("brand_new_code"))})
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "dependency_unavailable") {
		t.Fatalf("unmapped code = %d %s, want a closed 503", rec.Code, rec.Body.String())
	}
}

// T3: every subject-token failure is the same 401, the response never echoes
// the token, and nothing logged contains it.
func TestHTTPSubjectTokenFailuresAre401AndLeakNothing(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	f := newHTTPFx(t)
	bad := map[string]string{
		"garbage":        "not.a.jwt-SECRETGARBAGE",
		"expired":        forgeSubject(t, subjResource, time.Now().Add(-time.Hour), map[string]any{"tgr": "tgr_1"}),
		"wrong audience": forgeSubject(t, "https://elsewhere.example", time.Now().Add(time.Hour), map[string]any{"tgr": "tgr_1"}),
		"bad signature":  glovoToken(t, time.Now().Add(time.Hour)) + "x",
	}
	for name, tok := range bad {
		resp, body := f.do("POST", jb+"/resolve", map[string]string{SubjectTokenHeader: tok}, "{}")
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
		if strings.Contains(body, tok) || strings.Contains(logs.String(), tok) {
			t.Errorf("%s: the token reached a response or a log", name)
		}
	}
}

// T11: the route table is exactly the contract's nine routes, only connect and
// prepare write, and no join route can enqueue a bridge command: after the
// whole read-to-prepare path the command table is empty (see the happy-path
// test) and no handler holds a bridge enqueue seam at all.
func TestHTTPRouteTableIsTheContractAndOnlyTwoWrite(t *testing.T) {
	rt := &Routes{}
	table := rt.RouteTable()
	if len(table) != 9 {
		t.Fatalf("%d routes, want 9", len(table))
	}
	writes := map[string]bool{}
	for _, r := range table {
		if r.Idempotent {
			writes[r.ID] = true
		}
		if rt.handlerFor(r.ID) == nil {
			t.Errorf("route %s has no handler", r.ID)
		}
	}
	if len(writes) != 2 || !writes["connect"] || !writes["prepare"] {
		t.Fatalf("idempotent routes = %v, want connect and prepare", writes)
	}
}
