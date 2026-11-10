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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/control"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	ctlOrder    = "ordr_ABCDEFGHIJKLMNOP0123"
	ctlApproval = "aar_ABCDEFGHIJKLMNOP0123"
	ctlCommand  = "cmd_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ctlFP       = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

// fakeControl is the service behind the routes: it records every call and
// answers what the test configured.
type fakeControl struct {
	mu       sync.Mutex
	ready    error
	tenantOf func(ref string) string
	dispatch func() (*control.Result, error)
	cancel   func() (*control.Result, error)
	readCmd  func() (*control.CommandView, error)
	readAAR  func() (*workitems.GlovoApprovalStatus, error)
	calls    []string
	tenants  [][]string
}

func (f *fakeControl) rec(name string, tenants []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	f.tenants = append(f.tenants, append([]string(nil), tenants...))
}

func (f *fakeControl) Ready(context.Context) error { return f.ready }

func (f *fakeControl) TenantFor(_ context.Context, tenants []string, ref string) string {
	f.rec("tenant_for", tenants)
	if f.tenantOf != nil {
		return f.tenantOf(ref)
	}
	return "acme"
}

func (f *fakeControl) Dispatch(_ context.Context, tenants []string, _, _, _ string) (*control.Result, error) {
	f.rec("dispatch", tenants)
	return f.dispatch()
}

func (f *fakeControl) Cancel(_ context.Context, tenants []string, _ string) (*control.Result, error) {
	f.rec("cancel", tenants)
	return f.cancel()
}

func (f *fakeControl) ReadCommand(_ context.Context, tenants []string, _ string) (*control.CommandView, error) {
	f.rec("read_command", tenants)
	return f.readCmd()
}

func (f *fakeControl) ReadApproval(_ context.Context, tenants []string, _ string) (*workitems.GlovoApprovalStatus, error) {
	f.rec("read_approval", tenants)
	return f.readAAR()
}

func (f *fakeControl) served() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c != "tenant_for" {
			out = append(out, c)
		}
	}
	return out
}

type ctlRig struct {
	t      *testing.T
	h      http.Handler
	svc    *fakeControl
	log    *audit.Logger
	routes *GlovoControlRoutes
}

// newCtlRig builds the real router with the control routes mounted; the test
// names the caller with the X-Test-Caller header (the verifier of the real
// principal does not exist yet).
func newCtlRig(t *testing.T, mod func(*GlovoControlRoutes)) *ctlRig {
	t.Helper()
	svc := &fakeControl{
		dispatch: func() (*control.Result, error) {
			return &control.Result{OrderRef: ctlOrder, CommandID: ctlCommand, OrderState: "dispatched", EffectState: "none"}, nil
		},
		cancel: func() (*control.Result, error) {
			return &control.Result{OrderRef: ctlOrder, OrderState: "cancelled", EffectState: "none"}, nil
		},
		readCmd: func() (*control.CommandView, error) {
			return &control.CommandView{CommandID: ctlCommand, OrderRef: ctlOrder, Status: "pending", EffectState: "none"}, nil
		},
		readAAR: func() (*workitems.GlovoApprovalStatus, error) {
			return &workitems.GlovoApprovalStatus{ApprovalRef: ctlApproval, State: "approved", OrderRef: ctlOrder,
				ExpiresAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}, nil
		},
	}
	routes := &GlovoControlRoutes{Open: true, Enabled: true, Tenants: []string{"acme"}, Dispatcher: svc}
	if mod != nil {
		mod(routes)
	}
	log := audit.NewLogger()
	inject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var u *auth.User
			switch r.Header.Get("X-Test-Caller") {
			case "worker":
				u = auth.NewGlovoControlWorkerUser()
			case "admin":
				u = auth.NewGitHubUser("root", []string{"admins"})
			case "user":
				u = auth.NewGitHubUser("alice", []string{"acme"})
			case "service":
				u = auth.NewServiceUser()
			case "glovo_worker":
				u = auth.NewGlovoWorkerUser()
			case "bridge":
				u = auth.NewBridgeProviderUser("fake")
			}
			if u != nil {
				r = r.WithContext(auth.WithUser(r.Context(), u))
			}
			next.ServeHTTP(w, r)
		})
	}
	return &ctlRig{t: t, h: NewRouter(Options{AuthMiddleware: inject, AuditLog: log, GlovoControl: routes}), svc: svc, log: log, routes: routes}
}

type ctlResp struct {
	code   int
	body   string
	header http.Header
}

func (g *ctlRig) do(caller, method, path, body string) ctlResp {
	g.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if caller != "" {
		req.Header.Set("X-Test-Caller", caller)
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	return ctlResp{code: rec.Code, body: rec.Body.String(), header: rec.Header()}
}

func (r ctlResp) errCode() string {
	var m map[string]string
	_ = json.Unmarshal([]byte(r.body), &m)
	return m["error"]
}

var (
	dispatchPath = "/api/v1/internal/glovo/orders/" + ctlOrder + "/dispatch"
	cancelPath   = "/api/v1/internal/glovo/orders/" + ctlOrder + "/cancel"
	commandPath  = "/api/v1/internal/glovo/commands/" + ctlCommand
	approvalPath = "/api/v1/internal/glovo/approvals/" + ctlApproval
	dispatchBody = `{"approval_ref":"` + ctlApproval + `","fingerprint":"` + ctlFP + `"}`
)

func TestControlActorIsThePrincipal(t *testing.T) {
	if control.ActorID != auth.GlovoControlWorkerUserID {
		t.Fatalf("control.ActorID %q is not the principal %q: the order events would carry another identity", control.ActorID, auth.GlovoControlWorkerUserID)
	}
}

// Dark: with the gate closed, the flag off or no configuration at all, the
// routes do not exist, for every caller.
func TestControlRoutesAreDark(t *testing.T) {
	for name, mod := range map[string]func(*GlovoControlRoutes){
		"gate closed": func(g *GlovoControlRoutes) { g.Open = false },
		"flag off":    func(g *GlovoControlRoutes) { g.Enabled = false },
		"both off":    func(g *GlovoControlRoutes) { g.Open, g.Enabled = false, false },
	} {
		t.Run(name, func(t *testing.T) {
			g := newCtlRig(t, mod)
			for _, caller := range []string{"worker", "admin", ""} {
				for _, c := range []struct{ method, path, body string }{
					{http.MethodPost, dispatchPath, dispatchBody}, {http.MethodPost, cancelPath, "{}"},
					{http.MethodGet, commandPath, ""}, {http.MethodGet, approvalPath, ""},
				} {
					got := g.do(caller, c.method, c.path, c.body)
					if got.code == http.StatusOK || got.code == http.StatusServiceUnavailable {
						t.Errorf("%s %s as %q: %d %s", c.method, c.path, caller, got.code, got.body)
					}
					if caller == "worker" && got.code != http.StatusNotFound {
						t.Errorf("worker %s %s: %d, want 404", c.method, c.path, got.code)
					}
				}
			}
			if len(g.svc.served()) != 0 {
				t.Fatalf("an unmounted route called the service: %v", g.svc.served())
			}
		})
	}
	// No configuration at all.
	h := NewRouter(Options{AuthMiddleware: func(next http.Handler) http.Handler { return next }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, commandPath, nil))
	if rec.Code == http.StatusOK || rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("an unconfigured router: %d", rec.Code)
	}
}

// Mounted but not ready: 503 not_ready before the body is read and before the
// service is asked anything else.
func TestControlRoutesAnswerNotReady(t *testing.T) {
	for name, mod := range map[string]func(*GlovoControlRoutes){
		"nil service":       func(g *GlovoControlRoutes) { g.Dispatcher = nil },
		"typed nil":         func(g *GlovoControlRoutes) { g.Dispatcher = (*control.Dispatcher)(nil) },
		"service not ready": func(g *GlovoControlRoutes) { g.Dispatcher.(*fakeControl).ready = errors.New("proof failed") },
	} {
		t.Run(name, func(t *testing.T) {
			g := newCtlRig(t, mod)
			for _, c := range []struct{ method, path, body string }{
				{http.MethodPost, dispatchPath, dispatchBody}, {http.MethodPost, cancelPath, "{}"},
				{http.MethodGet, commandPath, ""}, {http.MethodGet, approvalPath, ""},
			} {
				got := g.do("worker", c.method, c.path, c.body)
				if got.code != http.StatusServiceUnavailable || got.errCode() != "not_ready" {
					t.Errorf("%s %s: %d %s", c.method, c.path, got.code, got.body)
				}
			}
			if len(g.svc.served()) != 0 {
				t.Fatalf("the service was called while not ready: %v", g.svc.served())
			}
		})
	}
}

// Only the control worker reaches the routes; the worker reaches nothing else.
func TestControlPrincipalAndGate(t *testing.T) {
	g := newCtlRig(t, nil)
	routes := []struct{ method, path, body string }{
		{http.MethodPost, dispatchPath, dispatchBody}, {http.MethodPost, cancelPath, "{}"},
		{http.MethodGet, commandPath, ""}, {http.MethodGet, approvalPath, ""},
	}
	for _, caller := range []string{"", "user", "admin", "service", "glovo_worker", "bridge"} {
		for _, c := range routes {
			got := g.do(caller, c.method, c.path, c.body)
			if got.code == http.StatusOK || got.code == http.StatusNotFound && caller == "" {
				t.Errorf("%q %s %s: %d %s", caller, c.method, c.path, got.code, got.body)
			}
			if got.code != http.StatusForbidden && got.code != http.StatusUnauthorized {
				t.Errorf("%q %s %s: %d, want 401 or 403", caller, c.method, c.path, got.code)
			}
		}
	}
	if len(g.svc.served()) != 0 {
		t.Fatalf("a caller that is not the control worker reached the service: %v", g.svc.served())
	}
	// The worker, on anything else, is refused before the handler.
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/tenants", ""},
		{http.MethodGet, "/api/v1/services", ""},
		{http.MethodPost, "/api/v1/internal/glovo/orders/" + ctlOrder + "/other", "{}"},
		{http.MethodGet, dispatchPath, ""},
		{http.MethodPut, cancelPath, "{}"},
		{http.MethodPost, commandPath, "{}"},
		{http.MethodDelete, approvalPath, ""},
		{http.MethodGet, "/api/v1/internal/glovo/orders/" + ctlOrder, ""},
		{http.MethodPost, "/api/v1/internal/glovo/orders/" + ctlOrder + "/dispatch/x", "{}"},
		{http.MethodGet, "/api/v1/bridge/commands/" + ctlCommand, ""},
		{http.MethodPost, "/api/v1/bridge/commands/claim", "{}"},
		{http.MethodPost, "/api/v1/glovo/pilot/acme/principals/prn_x", "{}"},
	} {
		got := g.do("worker", c.method, c.path, c.body)
		if got.code != http.StatusForbidden || got.errCode() != "not_authorized" {
			t.Errorf("worker %s %s: %d %s, want 403 not_authorized", c.method, c.path, got.code, got.body)
		}
	}
	if len(g.svc.served()) != 0 {
		t.Fatalf("the service was called: %v", g.svc.served())
	}
}

func TestControlDispatchSuccessAndReplay(t *testing.T) {
	g := newCtlRig(t, nil)
	got := g.do("worker", http.MethodPost, dispatchPath, dispatchBody)
	if got.code != http.StatusOK || got.header.Get("Idempotent-Replayed") != "" {
		t.Fatalf("%d %v %s", got.code, got.header, got.body)
	}
	if got.body != `{"command_id":"`+ctlCommand+`","effect_state":"none","order_state":"dispatched"}`+"\n" {
		t.Fatalf("body %q", got.body)
	}
	g.svc.dispatch = func() (*control.Result, error) {
		return &control.Result{CommandID: ctlCommand, OrderState: "dispatched", EffectState: "none", Replayed: true}, nil
	}
	got = g.do("worker", http.MethodPost, dispatchPath, dispatchBody)
	if got.code != http.StatusOK || got.header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %v", got.code, got.header)
	}
}

func TestControlCancelAndReads(t *testing.T) {
	g := newCtlRig(t, nil)
	got := g.do("worker", http.MethodPost, cancelPath, "")
	if got.code != http.StatusOK || got.body != `{"effect_state":"none","order_state":"cancelled"}`+"\n" {
		t.Fatalf("cancel with no body: %d %s", got.code, got.body)
	}
	got = g.do("worker", http.MethodPost, cancelPath, "{}")
	if got.code != http.StatusOK {
		t.Fatalf("cancel with {}: %d %s", got.code, got.body)
	}
	g.svc.cancel = func() (*control.Result, error) {
		return &control.Result{CommandID: ctlCommand, OrderState: "unknown", EffectState: "permitted"}, nil
	}
	got = g.do("worker", http.MethodPost, cancelPath, "{}")
	if got.body != `{"command_id":"`+ctlCommand+`","effect_state":"permitted","order_state":"unknown"}`+"\n" {
		t.Fatalf("cancel body %q", got.body)
	}
	got = g.do("worker", http.MethodGet, commandPath, "")
	if got.code != http.StatusOK || got.body != `{"command_id":"`+ctlCommand+`","effect_state":"none","order_ref":"`+ctlOrder+`","status":"pending"}`+"\n" {
		t.Fatalf("pending command: %d %s", got.code, got.body)
	}
	g.svc.readCmd = func() (*control.CommandView, error) {
		return &control.CommandView{CommandID: ctlCommand, OrderRef: ctlOrder, Status: "completed", EffectState: "succeeded",
			Outcome: "succeeded", ProviderEffect: "applied", ErrorCode: "none", ResultDigest: "sha256:aa"}, nil
	}
	got = g.do("worker", http.MethodGet, commandPath, "")
	var m map[string]string
	if err := json.Unmarshal([]byte(got.body), &m); err != nil || len(m) != 8 || m["outcome"] != "succeeded" || m["provider_effect"] != "applied" ||
		m["error_code"] != "none" || m["result_digest"] != "sha256:aa" {
		t.Fatalf("completed command: %s %v", got.body, err)
	}
	got = g.do("worker", http.MethodGet, approvalPath, "")
	if got.code != http.StatusOK || got.body != `{"approval_ref":"`+ctlApproval+`","expires_at":"2026-11-10T12:00:00Z","order_ref":"`+ctlOrder+`","state":"approved"}`+"\n" {
		t.Fatalf("approval: %d %s", got.code, got.body)
	}
}

// The body carries two refs and nothing else: anything unknown, repeated,
// oversized, malformed or missing is invalid_request and reaches no service.
func TestControlBodyHygiene(t *testing.T) {
	g := newCtlRig(t, nil)
	big := `{"approval_ref":"` + ctlApproval + `","fingerprint":"` + ctlFP + `","x":"` + strings.Repeat("a", 2000) + `"}`
	for name, body := range map[string]string{
		"unknown field":   `{"approval_ref":"` + ctlApproval + `","fingerprint":"` + ctlFP + `","tenant":"other"}`,
		"duplicate key":   `{"approval_ref":"` + ctlApproval + `","approval_ref":"` + ctlApproval + `","fingerprint":"` + ctlFP + `"}`,
		"oversized":       big,
		"not json":        `approval_ref=` + ctlApproval,
		"array":           `[]`,
		"empty":           ``,
		"missing ref":     `{"fingerprint":"` + ctlFP + `"}`,
		"missing fp":      `{"approval_ref":"` + ctlApproval + `"}`,
		"bad ref":         `{"approval_ref":"aar_x","fingerprint":"` + ctlFP + `"}`,
		"bad fingerprint": `{"approval_ref":"` + ctlApproval + `","fingerprint":"sha256:zz"}`,
		"trailing data":   dispatchBody + `{}`,
		"payload field":   `{"approval_ref":"` + ctlApproval + `","fingerprint":"` + ctlFP + `","payload":{"lines":[]}}`,
	} {
		got := g.do("worker", http.MethodPost, dispatchPath, body)
		if got.code != http.StatusBadRequest || got.errCode() != "invalid_request" {
			t.Errorf("dispatch %s: %d %s", name, got.code, got.body)
		}
	}
	for name, body := range map[string]string{"unknown": `{"force":true}`, "duplicate": `{"a":1,"a":2}`, "array": `[]`, "oversized": big} {
		got := g.do("worker", http.MethodPost, cancelPath, body)
		if got.code != http.StatusBadRequest || got.errCode() != "invalid_request" {
			t.Errorf("cancel %s: %d %s", name, got.code, got.body)
		}
	}
	for _, p := range []string{
		"/api/v1/internal/glovo/orders/ordr_x/dispatch", "/api/v1/internal/glovo/orders/aar_ABCDEFGHIJKLMNOP0123/dispatch",
		"/api/v1/internal/glovo/orders/ORDR_ABCDEFGHIJKLMNOP0123/dispatch", "/api/v1/internal/glovo/orders/ordr_ABCDEFGHIJKLMNOP0123%0A/dispatch",
	} {
		got := g.do("worker", http.MethodPost, p, dispatchBody)
		if got.code != http.StatusBadRequest && got.code != http.StatusNotFound && got.code != http.StatusForbidden {
			t.Errorf("%s: %d %s", p, got.code, got.body)
		}
	}
	for _, p := range []string{"/api/v1/internal/glovo/commands/cmd_short", "/api/v1/internal/glovo/commands/" + ctlOrder, "/api/v1/internal/glovo/approvals/aar_x"} {
		got := g.do("worker", http.MethodGet, p, "")
		if got.code != http.StatusBadRequest || got.errCode() != "invalid_request" {
			t.Errorf("%s: %d %s", p, got.code, got.body)
		}
	}
	if s := g.svc.served(); len(s) != 0 {
		t.Fatalf("a malformed request reached the service: %v", s)
	}
}

// The tenants the service sees are the server-side bound, whatever the
// request says.
func TestControlTenantBoundIsServerSide(t *testing.T) {
	g := newCtlRig(t, func(r *GlovoControlRoutes) { r.Tenants = []string{"acme", "globex"} })
	req := httptest.NewRequest(http.MethodPost, dispatchPath+"?tenant=other&tenants=evil", strings.NewReader(dispatchBody))
	req.Header.Set("X-Test-Caller", "worker")
	req.Header.Set("X-Tenant", "other")
	req.Header.Set("X-Mctl-Tenant", "other")
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	g.svc.mu.Lock()
	defer g.svc.mu.Unlock()
	if len(g.svc.tenants) == 0 {
		t.Fatal("the service was not called")
	}
	for i, ts := range g.svc.tenants {
		if len(ts) != 2 || ts[0] != "acme" || ts[1] != "globex" {
			t.Errorf("call %d (%s) saw tenants %v", i, g.svc.calls[i], ts)
		}
	}
}

// Every refusal is a closed code with the fixed description; the internal
// reason reaches the audit row and nothing else.
func TestControlRefusalsAreClosedAndAudited(t *testing.T) {
	const secret = "SECRET-INTERNAL-REASON-do-not-leak"
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{glovo.Refuse(glovo.CodeApprovalExpired), 409, "approval_expired"},
		{glovo.Refuse(glovo.CodeBasketChanged), 409, "basket_changed"},
		{glovo.ErrNotFound, 404, "not_found"},
		{glovo.Refuse(glovo.CodeTenantBusy), 409, "tenant_busy"},
		{errors.New(secret), 503, "unavailable"},
		{glovo.Refuse(glovo.CodeApprovalInvalid), 409, "approval_invalid"},
		{glovo.Refuse(glovo.CodeInvalidTransition), 409, "invalid_transition"},
		{glovo.Refuse(glovo.CodeNoConnection), 404, "no_connection"},
		{glovo.Refuse(glovo.CodeFingerprintChanged), 503, "unavailable"}, // outside the control set
	}
	for _, c := range cases {
		g := newCtlRig(t, nil)
		g.svc.dispatch = func() (*control.Result, error) {
			return nil, &leaky{err: c.err, reason: secret}
		}
		got := g.do("worker", http.MethodPost, dispatchPath, dispatchBody)
		if got.errCode() != c.code {
			t.Errorf("%v: %s, want %s (%d)", c.err, got.body, c.code, got.code)
		}
		if want := glovo.Status(glovo.Code(c.code)); got.code != want {
			t.Errorf("%s: status %d, want %d", c.code, got.code, want)
		}
		if strings.Contains(got.body, secret) {
			t.Errorf("%s: the internal reason reached the response: %s", c.code, got.body)
		}
		rows := g.log.List(10)
		if len(rows) != 1 || rows[0].Operation != "glovo.control.dispatch" || rows[0].Status != "refused" || rows[0].RefusalCode != c.code ||
			rows[0].UserID != control.ActorID || rows[0].RiskLevel != "high" {
			t.Errorf("%s: audit %+v", c.code, rows)
			continue
		}
		if p := rows[0].Parameters; p["order_ref"] != ctlOrder || p["approval_ref"] != ctlApproval || p["route"] != "dispatch" || len(p) != 3 {
			t.Errorf("%s: audit parameters %v", c.code, p)
		}
		if len(rows[0].Message) > 200 {
			t.Errorf("audit message is %d bytes", len(rows[0].Message))
		}
	}
}

type leaky struct {
	err    error
	reason string
}

func (l *leaky) Error() string { return l.err.Error() + ": " + l.reason }
func (l *leaky) Unwrap() error { return l.err }

func TestControlAuditOfSuccessCarriesIDsOnly(t *testing.T) {
	g := newCtlRig(t, nil)
	if got := g.do("worker", http.MethodPost, dispatchPath, dispatchBody); got.code != 200 {
		t.Fatal(got.body)
	}
	if got := g.do("worker", http.MethodPost, cancelPath, "{}"); got.code != 200 {
		t.Fatal(got.body)
	}
	if got := g.do("worker", http.MethodGet, commandPath, ""); got.code != 200 {
		t.Fatal(got.body)
	}
	if got := g.do("worker", http.MethodGet, approvalPath, ""); got.code != 200 {
		t.Fatal(got.body)
	}
	rows := g.log.List(10)
	if len(rows) != 4 {
		t.Fatalf("%d audit rows", len(rows))
	}
	for _, r := range rows {
		if r.Status != "succeeded" || r.UserID != control.ActorID || !strings.HasPrefix(r.Operation, "glovo.control.") || r.RefusalCode != "" {
			t.Errorf("row %+v", r)
		}
		for k, v := range r.Parameters {
			switch k {
			case "route", "order_ref", "command_id", "approval_ref", "replayed", "order_state":
			default:
				t.Errorf("%s: unexpected audit parameter %s=%s", r.Operation, k, v)
			}
			if strings.Contains(v, "sha256:") || strings.Contains(v, "{") {
				t.Errorf("%s: audit parameter %s carries content: %s", r.Operation, k, v)
			}
		}
	}
}

// One budget per (principal, tenant): the fourth call in the minute is 429, a
// second tenant has its own budget, and an unresolved tenant shares one.
func TestControlRateLimit(t *testing.T) {
	g := newCtlRig(t, func(r *GlovoControlRoutes) { r.PerMinute = 3 })
	g.svc.tenantOf = func(ref string) string {
		if ref == "ordr_ZZZZZZZZZZZZZZZZ0123" {
			return "globex"
		}
		return "acme"
	}
	for i := 0; i < 3; i++ {
		if got := g.do("worker", http.MethodPost, cancelPath, "{}"); got.code != 200 {
			t.Fatalf("call %d: %d %s", i, got.code, got.body)
		}
	}
	got := g.do("worker", http.MethodPost, cancelPath, "{}")
	if got.code != http.StatusTooManyRequests || got.errCode() != "rate_limited" {
		t.Fatalf("fourth call: %d %s", got.code, got.body)
	}
	if n := len(g.svc.served()); n != 3 {
		t.Fatalf("%d calls reached the service", n)
	}
	other := g.do("worker", http.MethodPost, "/api/v1/internal/glovo/orders/ordr_ZZZZZZZZZZZZZZZZ0123/cancel", "{}")
	if other.code != 200 {
		t.Fatalf("another tenant shares the budget: %d %s", other.code, other.body)
	}
	rows := g.log.List(20)
	if rows[0].Status != "succeeded" {
		t.Fatalf("latest audit %+v", rows[0])
	}
	var limited bool
	for _, r := range rows {
		if r.RefusalCode == "rate_limited" {
			limited = true
		}
	}
	if !limited {
		t.Fatal("the rate-limited call was not audited")
	}
}
