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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore/refreshstoretest"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

// The end-to-end harness of the synthetic Glovo connection routes
// (mctl-api#961). It builds the real NewRouter, the real auth middleware for
// the Glovo-audience tokens (minted through the real consent and token
// endpoints with a selected team), the real worker credential and the real
// glovo.Store on a per-test Postgres database with its own migration and
// runtime roles. Only the two human admin/owner callers of the tenant routes
// are injected by a bearer prefix, because their authentication is not what
// this slice adds.

const (
	e2ePassword  = "pw-glovo-e2e-test" //nolint:gosec // throwaway password of roles in a per-test scratch database
	e2eWorkerTok = "glovo-worker-test-token-0123456789abcdef"
	e2eServiceTk = "service-test-token-0123456789abcdef0123"
	e2eHandoff   = "https://handoff.example.test/h"
)

func e2ePRN(c byte) string { return "prn_01J" + strings.Repeat(string(c), 23) }

var (
	prnA1    = e2ePRN('A') // alpha, allowlisted
	prnA2    = e2ePRN('B') // alpha, allowlisted
	prnB1    = e2ePRN('C') // beta, allowlisted
	prnU3    = e2ePRN('D') // alpha and labs, allowlisted, no selection
	prnOwner = e2ePRN('E') // owner of alpha (not on the allowlist)
	prnRoot  = e2ePRN('F') // platform admin, not a tenant owner
	prnOwAdm = e2ePRN('G') // owner of alpha and platform admin
)

// e2eMembers is the principal-keyed membership reader.
type e2eMembers struct {
	mu    sync.Mutex
	roles map[string]map[string]string
	err   error
}

func (m *e2eMembers) set(tenant, prn, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.roles[tenant] == nil {
		m.roles[tenant] = map[string]string{}
	}
	if role == "" {
		delete(m.roles[tenant], prn)
		return
	}
	m.roles[tenant][prn] = role
}

func (m *e2eMembers) TryNamespacesForPrincipal(prn string) (gitops.PrincipalMembership, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return gitops.PrincipalMembership{}, false, m.err
	}
	var ns []string
	for tenant, by := range m.roles {
		if _, ok := by[prn]; ok {
			ns = append(ns, tenant)
		}
	}
	return gitops.PrincipalMembership{Namespaces: ns}, true, nil
}

func (m *e2eMembers) MemberRolesForPrincipal(tenant, prn string) ([][]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	if r, ok := m.roles[tenant][prn]; ok {
		return [][]string{{r}}, nil
	}
	return nil, nil
}

// e2ePrincipals is the principal store the auth middleware checks a token's
// principal against: every principal is active unless listed.
type e2ePrincipals struct {
	mu       sync.Mutex
	disabled map[string]bool
}

func (*e2ePrincipals) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return "", nil
}

func (p *e2ePrincipals) CheckPrincipal(_ context.Context, prn string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled[prn] {
		return auth.ErrPrincipalDisabled
	}
	return nil
}

func (p *e2ePrincipals) CheckHumanPrincipal(ctx context.Context, prn string) error {
	return p.CheckPrincipal(ctx, prn)
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type e2eEnv struct {
	t       *testing.T
	router  http.Handler
	oauth   *auth.OAuthServer
	consent *Handlers
	store   *glovo.Store
	pool    *pgxpool.Pool
	routes  *GlovoRoutes
	members *e2eMembers
	logs    *safeBuf
	secret  []byte

	dbName, mig, rt string
	baseURL         string
	migURL, rtURL   string
	users           map[string]*auth.User
	minted          []string // every access token minted, for the no-leak scan
	keys            []string // every Idempotency-Key sent
	refs            []string // every handoff reference issued
	respMu          sync.Mutex
	responses       [][]byte // every response body except the handoff response
}

type e2eOpts struct {
	disabled     bool
	noWorker     bool
	noPurger     bool
	storeOptions []glovo.Option
	// configure, when set, adjusts the router options before NewRouter.
	configure func(e *e2eEnv, o *Options)
}

func e2eAdminURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo end-to-end tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	return u
}

func e2eURLFor(t *testing.T, base, user, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, e2ePassword)
	u.Path = "/" + db
	return u.String()
}

func e2eRand(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newE2E(t *testing.T, o e2eOpts) *e2eEnv {
	t.Helper()
	base := e2eAdminURL(t)
	ctx := context.Background()
	sfx := e2eRand(6)
	e := &e2eEnv{t: t, baseURL: base, dbName: "g961db_" + sfx, mig: "g961mig_" + sfx, rt: "g961rt_" + sfx,
		secret: []byte("e2e-jwt-secret-0123456789abcdef"), users: map[string]*auth.User{}, logs: &safeBuf{}}
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, e.mig, e2ePassword),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, e.rt, e2ePassword),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.dbName, e.mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.dbName),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.dbName, e.rt),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	_ = admin.Close(ctx)
	e.migURL, e.rtURL = e2eURLFor(t, base, e.mig, e.dbName), e2eURLFor(t, base, e.rt, e.dbName)
	t.Cleanup(func() {
		if e.pool != nil {
			e.pool.Close()
		}
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.dbName))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, e.rt))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, e.mig))
	})
	if err := glovo.ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	e.pool, err = pgxpool.New(ctx, e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	opts := []glovo.Option{glovo.WithExplicitURL(true),
		glovo.WithRevocationHook(func(context.Context, pgx.Tx, []string, string) error { return nil }),
		glovo.WithLockTimeout(3 * time.Second)}
	if !o.noPurger {
		opts = append(opts, glovo.WithEndPurger(glovo.PurgeHandoffRefs))
	}
	opts = append(opts, glovo.WithEndPurgerRequired(true))
	opts = append(opts, o.storeOptions...)
	e.store, err = glovo.NewStore(ctx, e.pool, e.rt, e.mig, opts...)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	e.members = &e2eMembers{roles: map[string]map[string]string{}}
	for _, m := range []struct{ tenant, prn, role string }{
		{"alpha", prnA1, "developer"}, {"alpha", prnA2, "developer"}, {"alpha", prnU3, "developer"},
		{"beta", prnB1, "developer"}, {"labs", prnU3, "developer"},
		{"alpha", prnOwner, "owner"}, {"alpha", prnOwAdm, "owner"}, {"sys", prnA1, "developer"},
	} {
		e.members.set(m.tenant, m.prn, m.role)
	}

	// The OAuth server: Glovo resource, principal mode, the in-memory
	// transactional grant and refresh stores of the consent tests. Consent
	// lists teams through an eligibility without the non-selectable set, so a
	// token can name "sys"; the resolver's own eligibility refuses it.
	srv := auth.NewOAuthServer("https://api.mctl.ai", "gh", "sec", e.secret, []string{glovoCB}, nil)
	srv.GlovoResource, srv.PrincipalMode, srv.GlovoEnabled = glovoRes, true, !o.disabled
	srv.SupportResource = "https://support.mctl.ai/mcp"
	grants := refreshstoretest.NewTxGrants()
	srv.RefreshStore, srv.TeamGrants = refreshstoretest.NewBound(grants), grants
	srv.TeamEligibility = &scope.Eligibility{Membership: e.members, Allowlist: e.store, NonSelectable: map[string]bool{}}
	e.oauth = srv
	e.consent = &Handlers{opts: Options{OAuthServer: srv, AuditLog: audit.NewLogger()}}

	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", e2eServiceTk)
	if !o.noWorker {
		f := filepath.Join(t.TempDir(), "worker-token")
		if err := os.WriteFile(f, []byte(e2eWorkerTok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", f)
	} else {
		t.Setenv("MCTL_GLOVO_WORKER_TOKEN_FILE", "")
	}
	elig := &scope.Eligibility{Membership: e.members, Allowlist: e.store, NonSelectable: map[string]bool{"sys": true}}
	e.routes = &GlovoRoutes{
		Enabled: !o.disabled, ResourceConfigured: true, WorkerConfigured: auth.GlovoWorkerConfigured(),
		Store:    e.store,
		Resolver: &scope.Resolver{Grants: grants, Elig: elig, Resource: glovoRes, Ready: srv.GlovoReady},
		Connect:  &connect.Service{Store: e.store, HandoffBaseURL: e2eHandoff},
	}

	// Injected callers: tenant routes only.
	for tok, u := range map[string]struct {
		login, prn string
		groups     []string
	}{
		"owner":      {"alpha-owner", prnOwner, []string{"alpha"}},
		"root":       {"root-admin", prnRoot, []string{"admins"}},
		"owner-root": {"owner-admin", prnOwAdm, []string{"admins", "alpha"}},
	} {
		usr := auth.NewGitHubUser(u.login, u.groups)
		pr := &relayPrincipals{byLogin: map[string]string{u.login: u.prn}}
		if err := auth.AttachPrincipal(ctx, pr, usr); err != nil {
			t.Fatal(err)
		}
		e.users["tu:"+tok] = usr
	}
	e.users["tu:bridge"] = auth.NewBridgeProviderUser("e2e-bridge")
	real := auth.Middleware(nil, nil, nil, srv, auth.WithPrincipalResolver(&e2ePrincipals{disabled: map[string]bool{}}))
	mw := func(next http.Handler) http.Handler {
		realNext := real(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); strings.HasPrefix(tok, "tu:") {
				u, ok := e.users[tok]
				if !ok {
					http.Error(w, "unknown test user", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
				return
			}
			realNext.ServeHTTP(w, r)
		})
	}
	ro := Options{
		AuthMiddleware: mw, OAuthServer: srv, TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: e.members,
		GitReader: newAllowGit("alpha", "beta", "labs", "sys"), GlovoAllowlist: e.store, Glovo: e.routes,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	}
	if o.configure != nil {
		o.configure(e, &ro)
	}
	e.router = NewRouter(ro)

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return e
}

// call performs one request on the real router and returns the status and body.
func (e *e2eEnv) call(method, path, bearer string, body any, hdr ...string) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:4242" // loopback skips the per-user limiter
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if !strings.HasSuffix(path, "/handoff") {
		e.respMu.Lock()
		e.responses = append(e.responses, append([]byte(nil), rec.Body.Bytes()...))
		e.respMu.Unlock()
	}
	return rec.Code, rec.Body.Bytes()
}

func (e *e2eEnv) callJSON(method, path, bearer string, body any, hdr ...string) (int, map[string]any) {
	e.t.Helper()
	code, raw := e.call(method, path, bearer, body, hdr...)
	var m map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			e.t.Fatalf("%s %s: not JSON (%d): %s", method, path, code, raw)
		}
	}
	return code, m
}

// mint runs the real consent and token endpoints for prn with the selected
// team and returns the Glovo-audience access token.
func (e *e2eEnv) mint(prn, tenant string) string {
	e.t.Helper()
	ce := &glovoConsentEnv{h: e.consent, o: e.oauth, log: audit.NewLogger()}
	c := glovoCompletion("client-" + prn[len(prn)-4:])
	c.PrincipalID = prn
	rec, token, cookie := ce.startConsent(e.t, c)
	if rec.Code != http.StatusOK || token == "" || cookie == nil {
		e.t.Fatalf("consent page for %s: %d %s", prn, rec.Code, rec.Body.String())
	}
	p := locationParams(e.t, ce.decide(token, "approve", cookie, tenant))
	code := p.Get("code")
	if code == "" {
		e.t.Fatalf("no code for %s on %s: %v", prn, tenant, p)
	}
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {glovoVerifier},
		"client_id": {c.ClientID}, "redirect_uri": {glovoCB}, "resource": {glovoRes}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	trec := httptest.NewRecorder()
	e.consent.handleOAuthToken(trec, req)
	var tok map[string]any
	_ = json.Unmarshal(trec.Body.Bytes(), &tok)
	access, _ := tok["access_token"].(string)
	if trec.Code != http.StatusOK || access == "" {
		e.t.Fatalf("token exchange for %s: %d %s", prn, trec.Code, trec.Body.String())
	}
	e.minted = append(e.minted, access)
	return access
}

// forge signs an access token with the given claims, the way the verifier
// expects, for tokens the consent flow refuses to issue.
func (e *e2eEnv) forge(aud any, pid, tgr, stn string) string {
	e.t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims := map[string]any{"iss": "https://api.mctl.ai", "sub": "forged", "aud": aud, "groups": []string{},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "pid": pid}
	if tgr != "" {
		claims["tgr"] = tgr
	}
	if stn != "" {
		claims["stn"] = stn
	}
	body, _ := json.Marshal(claims)
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, e.secret)
	mac.Write([]byte(in))
	tok := in + "." + enc.EncodeToString(mac.Sum(nil))
	e.minted = append(e.minted, tok)
	return tok
}

// allow adds the principal to the pilot allowlist through #960's admin route.
func (e *e2eEnv) allow(tenant, prn string) {
	e.t.Helper()
	if code, _ := e.call(http.MethodPut, "/api/v1/glovo/pilot/"+tenant+"/principals/"+prn, "tu:root", nil); code != http.StatusNoContent {
		e.t.Fatalf("allowlist add %s %s: %d", tenant, prn, code)
	}
}

func (e *e2eEnv) unallow(tenant, prn string) {
	e.t.Helper()
	if code, _ := e.call(http.MethodDelete, "/api/v1/glovo/pilot/"+tenant+"/principals/"+prn, "tu:root", nil); code != http.StatusNoContent {
		e.t.Fatalf("allowlist remove %s %s: %d", tenant, prn, code)
	}
}

// installTenant installs the tenant as its owner and returns the revision.
func (e *e2eEnv) installTenant(tenant string) int64 {
	e.t.Helper()
	code, m := e.callJSON(http.MethodPut, "/api/v1/glovo/tenants/"+tenant+"/installation", "tu:owner", nil)
	if code != http.StatusCreated && code != http.StatusOK {
		e.t.Fatalf("install %s: %d %v", tenant, code, m)
	}
	return int64(m["install_revision"].(float64))
}

// admin opens a connection as the migration role (the owner), for the tests
// that move a clock or seed rows the runtime role cannot touch.
func (e *e2eEnv) adminExec(sql string, args ...any) {
	e.t.Helper()
	c, err := pgx.Connect(context.Background(), e.migURL)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *e2eEnv) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func e2eBody(schema string) map[string]any { return map[string]any{"schema": schema} }

const (
	facade = "/api/v1/glovo/facade"
	worker = "/api/v1/glovo/worker"
)

func (e *e2eEnv) key() string {
	k := "idem-" + e2eRand(8)
	e.keys = append(e.keys, k)
	return k
}

// connect creates a connection for the token's owner and returns its id.
func (e *e2eEnv) connectAs(tok string) string {
	e.t.Helper()
	code, m := e.callJSON(http.MethodPost, facade+"/connections", tok, e2eBody("glovo-connection/v1alpha1.ConnectRequest"), "Idempotency-Key", e.key())
	if code != http.StatusCreated {
		e.t.Fatalf("connect: %d %v", code, m)
	}
	return m["connection_id"].(string)
}

// handoffAs issues a handoff reference.
func (e *e2eEnv) handoffAs(tok, id string) string {
	e.t.Helper()
	code, m := e.callJSON(http.MethodPost, facade+"/connections/"+id+"/handoff", tok, e2eBody("glovo-connection/v1alpha1.ActionRequest"))
	if code != http.StatusOK {
		e.t.Fatalf("handoff: %d %v", code, m)
	}
	ref := m["handoff_ref"].(string)
	e.refs = append(e.refs, ref)
	return ref
}

func (e *e2eEnv) activate(id string, rev int64, ref string) (int, map[string]any) {
	return e.callJSON(http.MethodPost, worker+"/connections/"+id+"/activate", e2eWorkerTok,
		map[string]any{"schema": "glovo-connection/v1alpha1.WorkerActivateRequest", "install_revision": rev, "handoff_ref": ref})
}

func (e *e2eEnv) check(id string, rev int64) (int, map[string]any) {
	return e.callJSON(http.MethodPost, worker+"/check", e2eWorkerTok,
		map[string]any{"schema": "glovo-connection/v1alpha1.WorkerCheckRequest", "connection_id": id, "install_revision": rev})
}

func (e *e2eEnv) expire(id string) (int, map[string]any) {
	return e.callJSON(http.MethodPost, worker+"/connections/"+id+"/expire", e2eWorkerTok, e2eBody("glovo-connection/v1alpha1.ActionRequest"))
}

// activeConnection takes a fresh connection of tok's owner to active.
func (e *e2eEnv) activeConnection(tok string, rev int64) string {
	e.t.Helper()
	id := e.connectAs(tok)
	ref := e.handoffAs(tok, id)
	if code, m := e.activate(id, rev, ref); code != http.StatusOK {
		e.t.Fatalf("activate: %d %v", code, m)
	}
	return id
}

func errCode(m map[string]any) string {
	s, _ := m["error"].(string)
	return s
}
