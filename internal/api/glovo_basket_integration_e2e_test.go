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
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The integration of the basket MCP and its approval page (mctl-api#1006):
// two mctl-api replicas (two routers, two Handlers, two MCP handlers, two
// page deciders) on one database, the real mcp-go client over real HTTP with
// tokens from the real consent and token endpoints, the page backed by the
// basket store through NewGlovoBasketApprovalView, decisions through the
// basket ledger the decision route resolves (glovoDecisionsFor), and the
// owner's sign-in on a fake ZITADEL.

const integPageBase = "https://api.example"

type integEnv struct {
	*mcpBasketEnv
	b   *mcpBasketEnv // replica B: its own router and server, the same database
	idp *fakeIdP
}

func newIntegEnv(t *testing.T) *integEnv {
	t.Helper()
	x := &integEnv{}
	var saved Options
	x.mcpBasketEnv = newMCPBasketEnv(t, func(e *e2eEnv, o *Options, store *glovobasket.PGStore) {
		x.idp = newFakeIdP(t)
		x.idp.clientID, x.idp.clientSecret = "basket-client", "basket-secret"
		flow, err := flowstore.NewPostgresStore(context.Background(), e.migURL)
		if err != nil {
			t.Fatalf("flow store: %v", err)
		}
		page := &GlovoBasketApprovalPageOptions{
			ProviderName: "zitadel", Issuer: x.idp.srv.URL, ClientID: "basket-client", ClientSecret: "basket-secret",
			BaseURL: integPageBase,
			Principals: &fakeSignInPrincipals{ids: map[string]string{
				"z-a1": prnA1, "z-a2": prnA2, "z-b1": prnB1, "z-root": prnRoot,
			}},
			Authz: &auth.PrincipalAuthz{Admins: map[string]bool{prnRoot: true}, Members: noTenants{}},
			View:  NewGlovoBasketApprovalView(store),
			Flow:  flow,
		}
		o.GlovoBasketApproval = page
		o.GlovoBasket.MCP = integMCP(t, store, e, page.BaseURL)
		saved = *o
	})

	// Replica B: nothing in memory shared with A but the test's fakes.
	ob := saved
	routes := *saved.GlovoBasket
	routes.MCP = integMCP(t, &glovobasket.PGStore{Pool: x.pool}, x.e2eEnv, saved.GlovoBasketApproval.BaseURL)
	ob.GlovoBasket = &routes
	page := *saved.GlovoBasketApproval
	ob.GlovoBasketApproval = &page
	routerB := NewRouter(ob)
	podAddr := &net.TCPAddr{IP: net.ParseIP("10.42.0.8"), Port: 8080}
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerB.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, podAddr)))
	}))
	t.Cleanup(srvB.Close)
	x.b = &mcpBasketEnv{e2eEnv: x.e2eEnv, srv: srvB, priv: x.priv}
	return x
}

func integMCP(t *testing.T, store *glovobasket.PGStore, e *e2eEnv, base string) http.Handler {
	t.Helper()
	h, err := glovobasket.NewHandler(glovobasket.Config{Store: store, Resolver: e.routes.Resolver, ApprovalPageBaseURL: base})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// browse is one browser request to a replica's API host, redirects not
// followed. The __Host- cookie is Secure, so it is carried by hand over the
// test's plain HTTP.
func (x *integEnv) browse(srv *httptest.Server, method, path string, ck *http.Cookie, form url.Values) (int, http.Header, string) {
	x.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if ck != nil {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

// signIn opens the approval link on open, starts the sign-in there, plays
// ZITADEL for subject and comes back on back. It returns the browser cookie,
// the callback's status and body, and the decide form it offered.
func (x *integEnv) signIn(open, back *httptest.Server, approvalURL, subject string) (*http.Cookie, int, string, url.Values) {
	x.t.Helper()
	u, err := url.Parse(approvalURL)
	if err != nil || u.Scheme+"://"+u.Host != integPageBase || !strings.HasPrefix(u.Path, basketPagePrefix) {
		x.t.Fatalf("approval_url %q", approvalURL)
	}
	ref := strings.TrimPrefix(u.Path, basketPagePrefix)
	code, _, body := x.browse(open, http.MethodGet, u.Path, nil, nil)
	if code != http.StatusOK || !strings.Contains(body, `action="`+basketStartPath+`"`) {
		x.t.Fatalf("link page: %d %s", code, body)
	}
	code, hdr, body := x.browse(open, http.MethodPost, basketStartPath, nil, url.Values{"approval_ref": {ref}})
	if code != http.StatusSeeOther {
		x.t.Fatalf("start: %d %s", code, body)
	}
	var ck *http.Cookie
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		if c.Name == basketCookieName {
			ck = c
		}
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	q := loc.Query()
	if ck == nil || !strings.HasPrefix(loc.String(), x.idp.srv.URL+"/authorize") ||
		q.Get("redirect_uri") != integPageBase+basketCallbackPath {
		x.t.Fatalf("start redirect %s cookie %v", loc, ck)
	}
	x.idp.mu.Lock()
	x.idp.challenge, x.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	x.idp.extra = map[string]any{"sub": subject}
	x.idp.mu.Unlock()
	code, _, body = x.browse(back, http.MethodGet, basketCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return ck, code, body, form
}

func (x *integEnv) confirm(srv *httptest.Server, ck *http.Cookie, form url.Values, decision string) (int, string) {
	x.t.Helper()
	code, _, body := x.browse(srv, http.MethodPost, basketConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision}})
	return code, body
}

// expire plays the clock: it moves an approval's expiry into the past as the
// superuser, with the guard triggers off for that one session, because no
// role of the application may change expires_at (the guard refuses it).
func (x *integEnv) expire(t *testing.T, ref string) {
	t.Helper()
	cfg, err := pgx.ParseConfig(x.baseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = x.dbName
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	for _, q := range []string{`SET session_replication_role = replica`,
		`UPDATE action_approval_requests SET expires_at = now() - interval '1 second' WHERE id='` + ref + `'`} {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func (x *integEnv) ledgerState(ref string) string {
	x.t.Helper()
	var s string
	cfg, _ := pgx.ParseConfig(x.baseURL)
	cfg.Database = x.dbName
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		x.t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	if err := c.QueryRow(context.Background(), `SELECT state FROM action_approval_requests WHERE id=$1`, ref).Scan(&s); err != nil {
		x.t.Fatal(err)
	}
	return s
}

func TestGlovoBasketIntegration_TwoReplicasMCPToPageToStatus(t *testing.T) {
	x := newIntegEnv(t)
	a, b := x.mcpBasketEnv, x.b

	// Discovery on replica B: the basket host's 401 names its metadata,
	// which names the API as the authorization server.
	code, hdr, _ := b.raw(http.MethodPost, "/mcp", "", `{}`)
	if code != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), "oauth-protected-resource") {
		t.Fatalf("unauthenticated /mcp on B: %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	code, _, raw := b.raw(http.MethodGet, "/.well-known/oauth-protected-resource", "", "")
	var prm ProtectedResourceMeta
	if code != http.StatusOK || json.Unmarshal(raw, &prm) != nil || prm.Resource != glovoRes {
		t.Fatalf("protected resource metadata on B: %d %s", code, raw)
	}

	// Authorization and token: the repo's own consent and token endpoints.
	tok := x.mint(prnA1, "alpha")
	ca, cb := a.mcpClient(tok), b.mcpClient(tok)
	for name, c := range map[string]interface {
		ListTools(context.Context, mcp.ListToolsRequest) (*mcp.ListToolsResult, error)
	}{"A": ca, "B": cb} {
		tools, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
		if err != nil || len(tools.Tools) != 6 {
			t.Fatalf("tools on %s: %v %v", name, tools, err)
		}
	}

	// Create on A, update on B, request the approval on A.
	id, _ := basketRev(mustTool(t, ca, glovobasket.ToolCreateBasket, map[string]any{"client_key": "integ-1"}))
	m := mustTool(t, cb, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1,
		"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-EGGS-12", "quantity": 2}}})
	if _, rev := basketRev(m); rev != 2 {
		t.Fatalf("update on B: %v", m)
	}
	ap := mustTool(t, ca, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})
	ref, link := ap["approval_ref"].(string), ap["approval_url"].(string)
	if ap["state"] != "pending" || link != integPageBase+basketPagePrefix+ref {
		t.Fatalf("request approval: %v", ap)
	}

	// The owner opens the link on A, ZITADEL sends them back to B, and B
	// shows the frozen revision from the basket store.
	ck, code, body, form := x.signIn(a.srv, b.srv, link, "z-a1")
	if code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("owner callback on B: %d %s", code, body)
	}
	for _, want := range []string{"Basket: " + id + ", revision 2", "Basket fingerprint: " + ap["basket_fingerprint"].(string), "(pending)"} {
		if !strings.Contains(body, html.EscapeString(want)) {
			t.Fatalf("page does not show %q: %s", want, body)
		}
	}
	// Approved on A; the same form again, on either replica, decides nothing.
	if code, body := x.confirm(a.srv, ck, form, "approve"); code != http.StatusOK || !strings.Contains(body, "Basket approved") {
		t.Fatalf("confirm on A: %d %s", code, body)
	}
	for name, srv := range map[string]*httptest.Server{"A": a.srv, "B": b.srv} {
		if code, _ := x.confirm(srv, ck, form, "reject"); code != http.StatusBadRequest {
			t.Errorf("replayed confirm on %s: %d", name, code)
		}
	}
	if s := x.ledgerState(ref); s != workitems.ApprovalApproved {
		t.Fatalf("ledger after the page: %s", s)
	}

	// The agent reads the decision through the MCP, on B.
	st := mustTool(t, cb, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref})
	if st["state"] != "approved" || st["revision"].(float64) != 2 || st["authorizes_current_revision"] != true {
		t.Fatalf("status after approval: %v", st)
	}

	// An update after the approval is revision 3, which the approval does
	// not cover; revision 3 needs its own, pending approval.
	m = mustTool(t, ca, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2,
		"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-WATER-6", "quantity": 1}}})
	if _, rev := basketRev(m); rev != 3 {
		t.Fatalf("update after approval: %v", m)
	}
	st = mustTool(t, cb, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref})
	if st["state"] != "approved" || st["current_revision"].(float64) != 3 || st["authorizes_current_revision"] != false {
		t.Fatalf("old approval vs revision 3: %v", st)
	}
	ap3 := mustTool(t, cb, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 3})
	if ap3["approval_ref"] == ref || ap3["state"] != "pending" {
		t.Fatalf("revision 3 approval: %v", ap3)
	}
	st = mustTool(t, ca, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ap3["approval_ref"]})
	if st["state"] != "pending" || st["revision"].(float64) != 3 || st["authorizes_current_revision"] != false {
		t.Fatalf("status of revision 3: %v", st)
	}
	// The approved revision 2 cannot be decided again on the page.
	if _, code, _, form := x.signIn(b.srv, a.srv, link, "z-a1"); code == http.StatusOK && form.Get("csrf") != "" {
		t.Fatal("the page offered a decision on an approved, superseded revision")
	}

	logs := x.logs.String()
	for _, tk := range x.minted {
		if strings.Contains(logs, tk) {
			t.Fatal("a token reached the logs")
		}
	}
}

func TestGlovoBasketIntegration_Refusals(t *testing.T) {
	x := newIntegEnv(t)
	a, b := x.mcpBasketEnv, x.b
	tok := x.mint(prnA1, "alpha")
	ca, cb := a.mcpClient(tok), b.mcpClient(tok)

	newApproval := func(key string) (string, string, string) {
		t.Helper()
		id, _ := basketRev(mustTool(t, ca, glovobasket.ToolCreateBasket, map[string]any{"client_key": key}))
		mustTool(t, ca, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1,
			"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-EGGS-12", "quantity": 1}}})
		ap := mustTool(t, cb, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})
		return id, ap["approval_ref"].(string), ap["approval_url"].(string)
	}

	t.Run("wrong audience", func(t *testing.T) {
		// An API-audience token at the basket MCP.
		api, err := x.oauth.IssueJWT("alpha-a1", prnA1, []string{"alpha"})
		if err != nil {
			t.Fatal(err)
		}
		if code, _, raw := b.raw(http.MethodPost, "/mcp", api, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); code != http.StatusUnauthorized {
			t.Errorf("API-audience token on B's MCP: %d %s", code, raw)
		}
		// The basket token at the decision route.
		_, ref, link := newApproval("aud")
		if code, _ := x.callJSON(http.MethodPost, "/api/v1/action-approvals/"+ref+"/decision", tok, map[string]any{"decision": "approve"}); code != http.StatusUnauthorized {
			t.Errorf("basket token on the decision route: %d", code)
		}
		// A ZITADEL ID token for another client at the page.
		x.idp.mu.Lock()
		x.idp.audOverride = "another-client"
		x.idp.mu.Unlock()
		_, code, body, form := x.signIn(a.srv, b.srv, link, "z-a1")
		x.idp.mu.Lock()
		x.idp.audOverride = ""
		x.idp.mu.Unlock()
		if code == http.StatusOK || form.Get("csrf") != "" {
			t.Errorf("ID token of another audience: %d %s", code, body)
		}
		if s := x.ledgerState(ref); s != workitems.ApprovalPending {
			t.Errorf("state: %s", s)
		}
	})

	t.Run("non-owners see one uniform not found", func(t *testing.T) {
		id, ref, link := newApproval("others")
		for name, sub := range map[string]string{"other owner, same team": "z-a2", "other team": "z-b1", "admin, not the owner": "z-root"} {
			_, code, body, form := x.signIn(a.srv, b.srv, link, sub)
			if code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(body, id) {
				t.Errorf("%s on the page: %d %s", name, code, body)
			}
		}
		for name, other := range map[string]string{"same team": x.mint(prnA2, "alpha"), "other team": x.mint(prnB1, "beta")} {
			if _, code := callTool(t, b.mcpClient(other), glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref}); code != "not_found" {
				t.Errorf("%s status: %s", name, code)
			}
		}
		for _, other := range []string{"tu:a2", "tu:owner", "tu:root"} {
			if code, _ := x.callJSON(http.MethodPost, "/api/v1/action-approvals/"+ref+"/decision", other, map[string]any{"decision": "deny"}); code != http.StatusForbidden {
				t.Errorf("decision route by %s: %d", other, code)
			}
		}
		if s := x.ledgerState(ref); s != workitems.ApprovalPending {
			t.Errorf("state: %s", s)
		}
	})

	t.Run("replay", func(t *testing.T) {
		_, ref, link := newApproval("replay")
		ck, code, _, form := x.signIn(b.srv, a.srv, link, "z-a1")
		if code != http.StatusOK {
			t.Fatalf("callback: %d", code)
		}
		if code, _ := x.confirm(b.srv, ck, form, "reject"); code != http.StatusOK {
			t.Fatalf("reject: %d", code)
		}
		if code, _ := x.confirm(a.srv, ck, form, "approve"); code != http.StatusBadRequest {
			t.Errorf("replayed confirm: %d", code)
		}
		if st := mustTool(t, ca, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref}); st["state"] != "rejected" {
			t.Errorf("status after reject and replay: %v", st)
		}
	})

	t.Run("superseded", func(t *testing.T) {
		id, ref, link := newApproval("stale")
		ck, code, _, form := x.signIn(a.srv, b.srv, link, "z-a1")
		if code != http.StatusOK || form.Get("csrf") == "" {
			t.Fatalf("callback: %d", code)
		}
		// The agent changes the basket while the owner looks at revision 2.
		mustTool(t, cb, glovobasket.ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2,
			"ops": []any{map[string]any{"op": "add", "item_code": "FAKE-WATER-6", "quantity": 1}}})
		if code, body := x.confirm(b.srv, ck, form, "approve"); code != http.StatusConflict {
			t.Errorf("confirm of a superseded revision: %d %s", code, body)
		}
		if _, code, _, form := x.signIn(a.srv, b.srv, link, "z-a1"); code != http.StatusConflict || form.Get("csrf") != "" {
			t.Errorf("a new sign-in on a superseded revision: %d", code)
		}
		// A stale request for revision 2 is refused too.
		if _, c := callTool(t, ca, glovobasket.ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2}); c != "stale_version" {
			t.Errorf("stale request: %s", c)
		}
		if s := x.ledgerState(ref); s != workitems.ApprovalPending {
			t.Errorf("state: %s", s)
		}
	})

	t.Run("expired", func(t *testing.T) {
		_, ref, link := newApproval("expired")
		ck, code, _, form := x.signIn(a.srv, b.srv, link, "z-a1")
		if code != http.StatusOK || form.Get("csrf") == "" {
			t.Fatalf("callback: %d", code)
		}
		x.expire(t, ref)
		if code, body := x.confirm(a.srv, ck, form, "approve"); code != http.StatusConflict {
			t.Errorf("confirm after expiry: %d %s", code, body)
		}
		if _, code, body, form := x.signIn(b.srv, a.srv, link, "z-a1"); form.Get("csrf") != "" || !strings.Contains(body, "expired") {
			t.Errorf("a new sign-in after expiry: %d %s", code, body)
		}
		if st := mustTool(t, cb, glovobasket.ToolApprovalStatus, map[string]any{"approval_ref": ref}); st["state"] != "expired" {
			t.Errorf("status after expiry: %v", st)
		}
		if s := x.ledgerState(ref); s == workitems.ApprovalApproved {
			t.Errorf("an expired approval was approved")
		}
	})
}
