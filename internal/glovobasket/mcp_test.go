package glovobasket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	prnOwner = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	prnOther = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
)

type unit struct {
	t     *testing.T
	store *memStore
	c     *client.Client
}

func newUnit(t *testing.T, cfg Config) *unit {
	t.Helper()
	st := newMemStore()
	if cfg.Store == nil {
		cfg.Store = st
	}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := newMCPServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.NewInProcessClient(srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(context.Background(), init); err != nil {
		t.Fatal(err)
	}
	return &unit{t: t, store: st, c: c}
}

func as(prn, tenant string) context.Context {
	return context.WithValue(context.Background(), scopeKey{}, scope.Scope{PrincipalID: prn, Tenant: tenant, GrantID: "tgr_x"})
}

// call runs a tool and returns its structured result or its error code.
func (u *unit) call(ctx context.Context, tool string, args map[string]any) (map[string]any, string) {
	u.t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name, req.Params.Arguments = tool, args
	res, err := u.c.CallTool(ctx, req)
	if err != nil {
		u.t.Fatalf("%s: %v", tool, err)
	}
	text := res.Content[0].(mcp.TextContent).Text
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		u.t.Fatalf("%s: not JSON: %s", tool, text)
	}
	if res.IsError {
		return nil, m["error"].(string)
	}
	return m, ""
}

func (u *unit) must(ctx context.Context, tool string, args map[string]any) map[string]any {
	u.t.Helper()
	m, code := u.call(ctx, tool, args)
	if code != "" {
		u.t.Fatalf("%s: %s", tool, code)
	}
	return m
}

func basketOf(m map[string]any) (id string, rev int64, fp string, total float64) {
	b := m["basket"].(map[string]any)
	cur := b["current"].(map[string]any)
	fp, _ = cur["basket_fingerprint"].(string)
	return b["basket_id"].(string), int64(cur["revision"].(float64)), fp, cur["totals"].(map[string]any)["total_minor"].(float64)
}

func TestToolsAreExactlySixAndNoneApproves(t *testing.T) {
	u := newUnit(t, Config{})
	res, err := u.c.ListTools(as(prnOwner, "alpha"), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
		if strings.Contains(tl.Name, "approve") || strings.Contains(tl.Name, "decide") || strings.Contains(tl.Name, "order") {
			t.Errorf("tool %s may not exist", tl.Name)
		}
	}
	sort.Strings(names)
	want := []string{ToolApprovalStatus, ToolCreateBasket, ToolGetBasket, ToolListProducts, ToolRequestApproval, ToolUpdateBasket}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("tools = %v", names)
	}
}

func TestBasketFlowAndRevisions(t *testing.T) {
	u := newUnit(t, Config{})
	ctx := as(prnOwner, "alpha")
	p := u.must(ctx, ToolListProducts, nil)
	if len(p["products"].([]any)) != len(catalog) || p["store_ref"] != StoreRef {
		t.Fatalf("catalog: %v", p)
	}
	m := u.must(ctx, ToolCreateBasket, map[string]any{"client_key": "k1"})
	id, rev, fp, _ := basketOf(m)
	if rev != 1 || fp != "" || m["created"] != true {
		t.Fatalf("created: %v", m)
	}
	// Idempotent by client key.
	again := u.must(ctx, ToolCreateBasket, map[string]any{"client_key": "k1"})
	if id2, _, _, _ := basketOf(again); id2 != id || again["created"] != false {
		t.Fatalf("idempotent create: %v", again)
	}
	// An empty basket has nothing to approve.
	if _, code := u.call(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 1}); code != string(glovo.CodeInvalidRequest) {
		t.Fatalf("approval of an empty basket: %s", code)
	}
	m = u.must(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1, "ops": []any{
		map[string]any{"op": "add", "item_code": "FAKE-MILK-1L", "quantity": 2},
		map[string]any{"op": "add", "item_code": "FAKE-BREAD", "quantity": 1},
	}})
	_, rev, fp1, total := basketOf(m)
	// 2*129 + 320 + 199 + 50, priced by the server.
	if rev != 2 || !strings.HasPrefix(fp1, "sha256:") || total != 2*129+320+199+50 {
		t.Fatalf("update: rev=%d fp=%q total=%v", rev, fp1, total)
	}
	ap := u.must(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})
	ref := ap["approval_ref"].(string)
	if ap["state"] != "pending" || ap["basket_fingerprint"] != fp1 || ap["revision"].(float64) != 2 {
		t.Fatalf("request: %v", ap)
	}
	if _, ok := ap["approval_url"]; ok {
		t.Fatalf("approval_url without a configured page: %v", ap)
	}
	// Asking again for the same revision is the same approval.
	if again := u.must(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2}); again["approval_ref"] != ref {
		t.Fatalf("second request: %v", again)
	}
	// An update after the request is a new revision ...
	m = u.must(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2, "ops": []any{
		map[string]any{"op": "set", "item_code": "FAKE-MILK-1L", "quantity": 5}}})
	if _, rev, fp3, _ := basketOf(m); rev != 3 || fp3 == fp1 {
		t.Fatalf("update after request: rev=%d", rev)
	}
	// ... and the old approval, once approved, does not cover it.
	if err := u.store.decide(ref, workitems.GlovoBasketStateApproved); err != nil {
		t.Fatal(err)
	}
	st := u.must(ctx, ToolApprovalStatus, map[string]any{"approval_ref": ref})
	if st["state"] != "approved" || st["authorizes_current_revision"] != false || st["current_revision"].(float64) != 3 {
		t.Fatalf("old approval vs new revision: %v", st)
	}
	// The new revision gets its own approval.
	ap3 := u.must(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 3})
	if ap3["approval_ref"] == ref {
		t.Fatal("a new revision reused the old approval")
	}
	// A stale writer is refused, never merged.
	if _, code := u.call(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2, "ops": []any{
		map[string]any{"op": "remove", "item_code": "FAKE-BREAD"}}}); code != string(glovo.CodeStaleVersion) {
		t.Fatalf("stale update: %s", code)
	}
	if _, code := u.call(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2}); code != string(glovo.CodeStaleVersion) {
		t.Fatalf("stale request: %s", code)
	}
}

// Another owner in the same team, and the same principal in another team,
// see the basket and the approval exactly as a missing one.
func TestOwnerScopeHasNoOracle(t *testing.T) {
	u := newUnit(t, Config{})
	own := as(prnOwner, "alpha")
	id, _, _, _ := basketOf(u.must(own, ToolCreateBasket, map[string]any{"client_key": "k"}))
	u.must(own, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1, "ops": []any{
		map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": 3}}})
	ref := u.must(own, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})["approval_ref"].(string)
	missing := "gbk_" + strings.Repeat("Z", 26)
	for name, ctx := range map[string]context.Context{"other owner": as(prnOther, "alpha"), "other team": as(prnOwner, "beta")} {
		for _, c := range []struct {
			tool string
			args map[string]any
		}{
			{ToolGetBasket, map[string]any{"basket_id": id}},
			{ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 2, "ops": []any{map[string]any{"op": "remove", "item_code": "FAKE-APPLE"}}}},
			{ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2}},
			{ToolApprovalStatus, map[string]any{"approval_ref": ref}},
		} {
			if _, code := u.call(ctx, c.tool, c.args); code != string(glovo.CodeNotFound) {
				t.Errorf("%s %s: %s, want not_found", name, c.tool, code)
			}
		}
		if _, code := u.call(ctx, ToolGetBasket, map[string]any{"basket_id": missing}); code != string(glovo.CodeNotFound) {
			t.Errorf("%s missing basket: %s", name, code)
		}
	}
	// A failed read is unavailable, never not_found.
	u.store.failReads = errors.New("connection reset")
	if _, code := u.call(own, ToolGetBasket, map[string]any{"basket_id": id}); code != string(glovo.CodeUnavailable) {
		t.Fatalf("failed read: %s, want unavailable", code)
	}
	if _, code := u.call(own, ToolApprovalStatus, map[string]any{"approval_ref": ref}); code != string(glovo.CodeUnavailable) {
		t.Fatalf("failed status read: %s, want unavailable", code)
	}
}

// The client sends no prices and nothing outside the schema; quantities and
// sizes are bounded.
func TestUpdateRefusesPricesAndOutOfBoundsInput(t *testing.T) {
	u := newUnit(t, Config{})
	ctx := as(prnOwner, "alpha")
	id, _, _, _ := basketOf(u.must(ctx, ToolCreateBasket, map[string]any{"client_key": "k"}))
	for name, ops := range map[string][]any{
		"client price":     {map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": 1, "unit_price_minor": 1}},
		"unknown item":     {map[string]any{"op": "add", "item_code": "FAKE-CAVIAR", "quantity": 1}},
		"zero add":         {map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": 0}},
		"over max":         {map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": MaxQuantity + 1}},
		"accumulated over": {map[string]any{"op": "set", "item_code": "FAKE-APPLE", "quantity": 60}, map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": 60}},
		"negative set":     {map[string]any{"op": "set", "item_code": "FAKE-APPLE", "quantity": -1}},
		"bad op":           {map[string]any{"op": "price", "item_code": "FAKE-APPLE", "quantity": 1}},
		"no ops":           {},
	} {
		if _, code := u.call(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1, "ops": ops}); code != string(glovo.CodeInvalidRequest) {
			t.Errorf("%s: %s, want invalid_request", name, code)
		}
	}
	tooMany := make([]any, MaxOpsPerUpdate+1)
	for i := range tooMany {
		tooMany[i] = map[string]any{"op": "add", "item_code": "FAKE-APPLE", "quantity": 1}
	}
	if _, code := u.call(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1, "ops": tooMany}); code != string(glovo.CodeInvalidRequest) {
		t.Errorf("too many ops: %s", code)
	}
	if _, code := u.call(ctx, ToolCreateBasket, map[string]any{"client_key": strings.Repeat("k", MaxClientKeyLen+1)}); code != string(glovo.CodeInvalidRequest) {
		t.Errorf("long client key: %s", code)
	}
	if _, code := u.call(ctx, ToolCreateBasket, map[string]any{"client_key": "k", "total_minor": 1}); code != string(glovo.CodeInvalidRequest) {
		t.Errorf("unknown create field: %s", code)
	}
}

func TestQuotas(t *testing.T) {
	u := newUnit(t, Config{CallsPerMinute: 3, MaxBaskets: 1})
	ctx := as(prnOwner, "alpha")
	u.must(ctx, ToolCreateBasket, map[string]any{"client_key": "a"})
	if _, code := u.call(ctx, ToolCreateBasket, map[string]any{"client_key": "b"}); code != string(glovo.CodeRateLimited) {
		t.Fatalf("basket quota: %s", code)
	}
	u.must(ctx, ToolListProducts, nil)
	if _, code := u.call(ctx, ToolListProducts, nil); code != string(glovo.CodeRateLimited) {
		t.Fatalf("call quota: %s", code)
	}
	// The quota is per principal.
	u.must(as(prnOther, "alpha"), ToolListProducts, nil)
}

func TestNoScopeIsNotAuthorized(t *testing.T) {
	u := newUnit(t, Config{})
	if _, code := u.call(context.Background(), ToolListProducts, nil); code != string(glovo.CodeNotAuthorized) {
		t.Fatalf("no scope: %s", code)
	}
}

// A stored revision that no longer reproduces its fingerprint is refused
// before anything is approved.
func TestVerifyFrozenRefusesATamperedRevision(t *testing.T) {
	r, err := price(2, map[string]int64{"FAKE-APPLE": 2}, timeZero)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFrozen(r); err != nil {
		t.Fatalf("intact revision: %v", err)
	}
	for name, mut := range map[string]func(*Revision){
		"canonical": func(r *Revision) {
			r.Canonical = []byte(strings.Replace(string(r.Canonical), `"quantity":2`, `"quantity":3`, 1))
		},
		"fingerprint": func(r *Revision) { r.Fingerprint = "sha256:" + strings.Repeat("0", 64) },
		"lines": func(r *Revision) {
			r.Lines = append([]Line(nil), Line{ItemCode: "FAKE-APPLE", Quantity: 9, UnitPriceMinor: 45})
		},
	} {
		c := r
		c.Canonical = append([]byte(nil), r.Canonical...)
		mut(&c)
		if err := verifyFrozen(c); !errors.Is(err, glovo.Refuse(glovo.CodeFingerprintChanged)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An oversize request body is refused before anything reads it.
func TestHandlerRefusesOversizeBodies(t *testing.T) {
	h, err := NewHandler(Config{Store: newMemStore(), Resolver: &scope.Resolver{}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat(" ", MaxRequestBytes+1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("oversize: %d %s", rec.Code, rec.Body)
	}
	// Without a resolved scope nothing runs.
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	if _, err := NewHandler(Config{Store: newMemStore()}); err == nil {
		t.Fatal("a handler without a resolver was built")
	}
}

var timeZero = mustTime("2026-11-10T00:00:00Z")

func TestRequestApprovalReturnsThePageURL(t *testing.T) {
	u := newUnit(t, Config{ApprovalPageBaseURL: "https://api.example/"})
	ctx := as(prnOwner, "alpha")
	id, _, _, _ := basketOf(u.must(ctx, ToolCreateBasket, map[string]any{"client_key": "k1"}))
	u.must(ctx, ToolUpdateBasket, map[string]any{"basket_id": id, "expected_revision": 1, "ops": []any{
		map[string]any{"op": "add", "item_code": "FAKE-RICE-1KG", "quantity": 1},
	}})
	for i := 0; i < 2; i++ { // the first request and the idempotent repeat
		ap := u.must(ctx, ToolRequestApproval, map[string]any{"basket_id": id, "expected_revision": 2})
		ref, _ := ap["approval_ref"].(string)
		if ref == "" || ap["approval_url"] != "https://api.example/glovo/basket/approvals/"+ref {
			t.Fatalf("request %d: %v", i, ap)
		}
	}
	for _, bad := range []string{"http://api.example", "https://api.example/x", "https://api.example?a=1", "https://u@api.example",
		"api.example", "https://"} {
		if _, err := newMCPServer(Config{Store: newMemStore(), ApprovalPageBaseURL: bad}); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
