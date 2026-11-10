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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The OAuth MCP-client harness of the Glovo basket MCP (mctl-api#1006): the
// real router with the basket host mounted, the real auth middleware with
// EdDSA-signed access tokens minted through the real consent and token
// endpoints, scope.Resolve on the real grant store, the real mcp-go
// Streamable HTTP client over httptest, the Postgres basket and approval
// ledgers under split roles, and the human decision through the real
// POST /api/v1/action-approvals/{id}/decision handler.

const basketHost = "glovo.mctl.ai"

type basketEnv struct {
	*e2eEnv
	srv  *httptest.Server
	priv ed25519.PrivateKey
}

func newBasketEnv(t *testing.T) *basketEnv {
	t.Helper()
	be := &basketEnv{}
	e := newE2E(t, e2eOpts{configure: func(e *e2eEnv, o *Options) {
		ctx := context.Background()
		wi := "g1006wi_" + e2eRand(6)
		admin, err := pgx.Connect(ctx, e.baseURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{
			fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, wi, e2ePassword),
			fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.dbName, wi),
		} {
			if _, err := admin.Exec(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		_ = admin.Close(ctx)
		t.Cleanup(func() {
			c, err := pgx.Connect(context.Background(), e.baseURL)
			if err != nil {
				return
			}
			defer func() { _ = c.Close(context.Background()) }()
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.dbName))
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, wi))
		})
		if err := workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, workitems.WithWorkItemsRole(wi)); err != nil {
			t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
		}
		if err := glovobasket.ApplySchema(ctx, e.migURL, e.rt); err != nil {
			t.Fatalf("glovobasket.ApplySchema: %v", err)
		}
		if err := glovobasket.VerifySchema(ctx, e.pool); err != nil {
			t.Fatalf("VerifySchema: %v", err)
		}
		// The Glovo store's own readiness still holds with the basket tables:
		// their grants are registered.
		if err := e.store.Ready(ctx); err != nil {
			t.Fatalf("glovo.Store.Ready with the basket tables: %v", err)
		}
		wis, err := workitems.NewStore(ctx, e2eURLFor(t, e.baseURL, wi, e.dbName))
		if err != nil {
			t.Fatalf("workitems.NewStore: %v", err)
		}
		t.Cleanup(wis.Close)
		store := &glovobasket.PGStore{Pool: e.pool}
		mcpH, err := glovobasket.NewHandler(glovobasket.Config{Store: store, Resolver: e.routes.Resolver})
		if err != nil {
			t.Fatal(err)
		}
		o.WorkItems = wis
		o.GlovoBasket = &GlovoBasketRoutes{Host: basketHost, Resource: glovoRes, MCP: mcpH, Payloads: store,
			Decisions: &workitems.GlovoBasketDecisions{Reader: e.pool, Begin: e.pool.Begin,
				ReadyFn: func(ctx context.Context) error { return glovobasket.VerifySchema(ctx, e.pool) }}}
		o.ApprovalBindingMode = ApprovalBindingEnforce
	}})
	be.e2eEnv = e

	// EdDSA access tokens; HS256 is no longer accepted.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	keys, _ := json.Marshal(map[string]any{"active": "k1", "keys": []map[string]string{{
		"kid": "k1", "alg": "EdDSA", "private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}}})
	if err := e.oauth.ConfigureSigning(auth.JWTSigningConfig{Alg: "EdDSA", KeysJSON: string(keys), AcceptHS256: false, RequireAud: true}); err != nil {
		t.Fatal(err)
	}
	be.priv = priv

	// The human owners of the decision route (their own login is not what
	// this slice adds).
	for tok, u := range map[string]struct{ login, prn string }{"a1": {"alpha-a1", prnA1}, "a2": {"alpha-a2", prnA2}} {
		usr := auth.NewGitHubUser(u.login, []string{"alpha"})
		if err := auth.AttachPrincipal(context.Background(), &relayPrincipals{byLogin: map[string]string{u.login: u.prn}}, usr); err != nil {
			t.Fatal(err)
		}
		e.users["tu:"+tok] = usr
	}
	for _, p := range []struct{ tenant, prn string }{{"alpha", prnA1}, {"alpha", prnA2}, {"beta", prnB1}} {
		e.allow(p.tenant, p.prn)
	}
	// The listener is loopback here and a pod address in production; mcp-go's
	// DNS-rebinding guard keys on the local address, so the test presents the
	// production one. The guard itself stays on.
	podAddr := &net.TCPAddr{IP: net.ParseIP("10.42.0.7"), Port: 8080}
	be.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.router.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, podAddr)))
	}))
	t.Cleanup(be.srv.Close)
	return be
}

// hostRT sends every request to the test server with Host set to the basket
// host, as a client reaching https://glovo.mctl.ai would.
type hostRT struct{ host string }

func (h hostRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = h.host
	return http.DefaultTransport.RoundTrip(r)
}

func (b *basketEnv) httpClient() *http.Client { return &http.Client{Transport: hostRT{basketHost}} }

func (b *basketEnv) raw(method, path, bearer, body string) (int, http.Header, []byte) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.srv.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := b.httpClient().Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

// mcpClient is the real mcp-go Streamable HTTP client with the bearer.
func (b *basketEnv) mcpClient(tok string) *client.Client {
	b.t.Helper()
	c, err := client.NewStreamableHttpClient(b.srv.URL+"/mcp",
		transport.WithHTTPBasicClient(b.httpClient()),
		transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + tok}))
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(context.Background()); err != nil {
		b.t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "basket-harness", Version: "1"}
	if _, err := c.Initialize(context.Background(), init); err != nil {
		b.t.Fatalf("initialize: %v", err)
	}
	return c
}

func callTool(t *testing.T, c *client.Client, tool string, args map[string]any) (map[string]any, string) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name, req.Params.Arguments = tool, args
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].(mcp.TextContent).Text), &m); err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		return nil, m["error"].(string)
	}
	return m, ""
}

func mustTool(t *testing.T, c *client.Client, tool string, args map[string]any) map[string]any {
	t.Helper()
	m, code := callTool(t, c, tool, args)
	if code != "" {
		t.Fatalf("%s: %s", tool, code)
	}
	return m
}

func basketRev(m map[string]any) (string, float64) {
	b := m["basket"].(map[string]any)
	return b["basket_id"].(string), b["current"].(map[string]any)["revision"].(float64)
}

// resign re-signs tok's claims, changed by mut, with the real signing key.
func (b *basketEnv) resign(tok string, mut func(map[string]any)) string {
	b.t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		b.t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		b.t.Fatal(err)
	}
	mut(claims)
	body, _ := json.Marshal(claims)
	in := parts[0] + "." + base64.RawURLEncoding.EncodeToString(body)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(b.priv, []byte(in)))
}

// decide is the human owner's decision, the way the decision surface sends
// it: the binding read from the payload route.
func (b *basketEnv) decide(human, ref, decision string, mutBinding func(map[string]any)) (int, map[string]any) {
	b.t.Helper()
	code, p := b.callJSON(http.MethodGet, "/api/v1/action-approvals/"+ref+"/glovo-basket", human, nil)
	if code != http.StatusOK {
		return code, p
	}
	bind := p["decision_binding"].(map[string]any)
	if mutBinding != nil {
		mutBinding(bind)
	}
	body := map[string]any{"decision": decision}
	if decision == workitems.DecisionApprove {
		body["binding"] = bind
	}
	return b.callJSON(http.MethodPost, "/api/v1/action-approvals/"+ref+"/decision", human, body)
}

func TestGlovoBasketMCPOAuthHarness(t *testing.T) {
	b := newBasketEnv(t)

	// Discovery: the basket host's 401 points at its own metadata, which
	// names the Glovo resource and the API as the authorization server.
	code, hdr, _ := b.raw(http.MethodPost, "/mcp", "", `{}`)
	if code != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), `resource_metadata="https://glovo.mctl.ai/.well-known/oauth-protected-resource"`) {
		t.Fatalf("unauthenticated /mcp: %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	code, _, raw := b.raw(http.MethodGet, "/.well-known/oauth-protected-resource", "", "")
	var prm ProtectedResourceMeta
	if code != http.StatusOK || json.Unmarshal(raw, &prm) != nil || prm.Resource != glovoRes ||
		len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != "https://api.mctl.ai" {
		t.Fatalf("protected resource metadata: %d %s", code, raw)
	}
	// Nothing else lives on the basket host.
	if code, _, _ := b.raw(http.MethodGet, "/api/v1/action-approvals", "tu:a1", ""); code != http.StatusNotFound {
		t.Fatalf("API route on the basket host: %d", code)
	}

	// Token: the real consent and token endpoints, EdDSA-signed.
	tok := b.mint(prnA1, "alpha")
	if hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0]); !strings.Contains(string(hdr), `"EdDSA"`) {
		t.Fatalf("token header: %s", hdr)
	}
	c := b.mcpClient(tok)
	tools, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil || len(tools.Tools) != 6 {
		t.Fatalf("tools: %v %v", tools, err)
	}

	created := mustTool(t, c, glovobasket.ToolCreateBasket, map[string]any{"client_key": "harness-1"})
	id, _ := basketRev(created)
	m := mustTool(t, c, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1,
		"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-EGGS-12", "quantity": 1}}})
	if _, rev := basketRev(m); rev != 2 {
		t.Fatalf("update: %v", m)
	}
	ap := mustTool(t, c, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})
	ref := ap["approval_ref"].(string)
	if ap["state"] != "pending" {
		t.Fatalf("request: %v", ap)
	}

	// Another owner in the same team, and a member of another team, see
	// nothing: the basket and the approval are not_found, as a missing one.
	for name, other := range map[string]string{"same team": b.mint(prnA2, "alpha"), "other team": b.mint(prnB1, "beta")} {
		oc := b.mcpClient(other)
		if _, code := callTool(t, oc, glovobasket.ToolGetBasket, map[string]any{"basket_id": id}); code != "not_found" {
			t.Errorf("%s get: %s", name, code)
		}
		if _, code := callTool(t, oc, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref}); code != "not_found" {
			t.Errorf("%s status: %s", name, code)
		}
	}

	// The payload read and the decision are the owner's alone. Another
	// member of the team, even the team's owner, is refused.
	if code, _ := b.callJSON(http.MethodGet, "/api/v1/action-approvals/"+ref+"/glovo-basket", "tu:a2", nil); code != http.StatusNotFound {
		t.Fatalf("payload read by another member: %d", code)
	}
	// The bound owner reads it only while a member, like the decision.
	b.members.set("alpha", prnA1, "")
	if code, _ := b.callJSON(http.MethodGet, "/api/v1/action-approvals/"+ref+"/glovo-basket", "tu:a1", nil); code != http.StatusNotFound {
		t.Fatalf("payload read by the owner after leaving the team: %d", code)
	}
	b.members.set("alpha", prnA1, "developer")
	for _, other := range []string{"tu:a2", "tu:owner", "tu:root"} {
		if code, m := b.callJSON(http.MethodPost, "/api/v1/action-approvals/"+ref+"/decision", other,
			map[string]any{"decision": "deny"}); code != http.StatusForbidden {
			t.Fatalf("decision by %s: %d %v", other, code, m)
		}
	}
	// The MCP's own token cannot reach the decision route.
	if code, _ := b.callJSON(http.MethodPost, "/api/v1/action-approvals/"+ref+"/decision", tok, map[string]any{"decision": "approve"}); code != http.StatusUnauthorized {
		t.Fatalf("decision with the glovo-audience token: %d", code)
	}
	// A binding that names other content is refused.
	if code, m := b.decide("tu:a1", ref, workitems.DecisionApprove, func(bind map[string]any) {
		bind["content_digest"] = "sha256:" + strings.Repeat("0", 64)
	}); code == http.StatusOK {
		t.Fatalf("approve with a forged content digest: %v", m)
	}

	// The payload shows the frozen revision.
	code, p := b.callJSON(http.MethodGet, "/api/v1/action-approvals/"+ref+"/glovo-basket", "tu:a1", nil)
	bk, _ := p["basket"].(map[string]any)
	if code != http.StatusOK || bk["revision"].(float64) != 2 || bk["basket_fingerprint"] != ap["basket_fingerprint"] ||
		len(bk["lines"].([]any)) != 1 || bk["totals"].(map[string]any)["total_minor"].(float64) != 389+199+50 {
		t.Fatalf("payload: %d %v", code, p)
	}
	if _, leaked := bk["owner"]; leaked {
		t.Fatal("payload carries the owner")
	}

	// An update after the request is a new revision.
	m = mustTool(t, c, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2,
		"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-WATER-6", "quantity": 1}}})
	if _, rev := basketRev(m); rev != 3 {
		t.Fatalf("update after request: %v", m)
	}

	// The human owner approves revision 2 through the real decision route.
	if code, m := b.decide("tu:a1", ref, workitems.DecisionApprove, nil); code != http.StatusOK {
		t.Fatalf("owner approve: %d %v", code, m)
	}
	// A replayed decision changes nothing.
	if code, _ := b.decide("tu:a1", ref, workitems.DecisionDeny, nil); code == http.StatusOK {
		t.Fatal("a second decision was accepted")
	}
	st := mustTool(t, c, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref})
	if st["state"] != "approved" || st["revision"].(float64) != 2 || st["current_revision"].(float64) != 3 ||
		st["authorizes_current_revision"] != false {
		t.Fatalf("old approval vs new revision: %v", st)
	}
	// Revision 3 needs, and gets, its own approval; denying it is rejected.
	ap3 := mustTool(t, c, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 3})
	if ap3["approval_ref"] == ref {
		t.Fatal("revision 3 reused the approval of revision 2")
	}
	if code, m := b.decide("tu:a1", ap3["approval_ref"].(string), workitems.DecisionDeny, nil); code != http.StatusOK {
		t.Fatalf("owner deny: %d %v", code, m)
	}
	if st := mustTool(t, c, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ap3["approval_ref"]}); st["state"] != "rejected" {
		t.Fatalf("denied status: %v", st)
	}

	// The audit names the basket revision, never a token or a basket body.
	logs := b.logs.String()
	for _, tk := range b.minted {
		if strings.Contains(logs, tk) {
			t.Fatal("a token reached the logs")
		}
	}
}

func TestGlovoBasketMCPRefusals(t *testing.T) {
	b := newBasketEnv(t)
	tok := b.mint(prnA1, "alpha")
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	if code, _, raw := b.raw(http.MethodPost, "/mcp", tok, init); code != http.StatusOK {
		t.Fatalf("baseline: %d %s", code, raw)
	}
	cases := map[string]string{
		// A real token of the API audience.
		"wrong audience": func() string {
			s, err := b.oauth.IssueJWT("alpha-a1", prnA1, []string{"alpha"})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}(),
		// HS256 with the old shared secret.
		"forged hs256": b.forge(glovoRes, prnA1, "tgr_x", "alpha"),
		"expired": b.resign(tok, func(c map[string]any) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
			c["iat"] = time.Now().Add(-time.Hour).Unix()
		}),
		"two audiences": b.resign(tok, func(c map[string]any) { c["aud"] = []string{glovoRes, "https://api.mctl.ai"} }),
		"garbage":       "not-a-token",
	}
	for name, bad := range cases {
		if code, _, raw := b.raw(http.MethodPost, "/mcp", bad, init); code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	// A validly signed token whose team claim was changed is refused by the
	// grant check, before any tool runs.
	if code, _, raw := b.raw(http.MethodPost, "/mcp", b.resign(tok, func(c map[string]any) { c["stn"] = "beta" }), list); code == http.StatusOK {
		t.Errorf("tampered team: %d %s", code, raw)
	}
	// The platform MCP on the main host still refuses the Glovo token.
	if code, _ := b.call(http.MethodPost, "/mcp", tok, init); code != http.StatusUnauthorized {
		t.Errorf("platform /mcp with a glovo token: %d", code)
	}
	// Payload limit.
	if code, _, _ := b.raw(http.MethodPost, "/mcp", tok, `{"pad":"`+strings.Repeat("x", glovobasket.MaxRequestBytes)+`"}`); code != http.StatusBadRequest {
		t.Errorf("oversize body: %d", code)
	}
	// Removed from the allowlist, then from the team: refused on the next
	// request with the same token.
	b.unallow("alpha", prnA1)
	if code, _, raw := b.raw(http.MethodPost, "/mcp", tok, list); code == http.StatusOK {
		t.Errorf("off the allowlist: %d %s", code, raw)
	}
	b.allow("alpha", prnA1)
	b.members.set("alpha", prnA1, "")
	if code, _, raw := b.raw(http.MethodPost, "/mcp", tok, list); code == http.StatusOK {
		t.Errorf("not a member: %d %s", code, raw)
	}
	b.members.set("alpha", prnA1, "developer")
	if code, _, raw := b.raw(http.MethodPost, "/mcp", tok, list); code != http.StatusOK {
		t.Errorf("member again: %d %s", code, raw)
	}
}
