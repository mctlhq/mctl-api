package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// workItemsEnv is one test's handler over a real Postgres store. Rows are
// scoped to the test's own tenant and deleted by tenant, never unscoped: the
// store package's tests share the database.
type workItemsEnv struct {
	t       *testing.T
	h       *Handlers
	router  chi.Router
	tenant  string
	audit   *audit.Logger
	connStr string
}

func newWorkItemsEnv(t *testing.T) *workItemsEnv {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed work-items handler test")
	}
	ctx := context.Background()
	store, err := workitems.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tenant := fmt.Sprintf("wi-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		pool, err := pgxpool.New(ctx, connStr)
		if err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM work_items WHERE tenant LIKE $1`, tenant+"%")
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE execution_id LIKE $1`, tenant+"%")
			pool.Close()
		}
		store.Close()
	})
	env := &workItemsEnv{t: t, tenant: tenant, audit: audit.NewLogger(), connStr: connStr}
	env.h = &Handlers{opts: Options{WorkItems: store, AuditLog: env.audit}}
	env.router = workItemsRouter(env.h)
	return env
}

func workItemsRouter(h *Handlers) chi.Router {
	r := chi.NewRouter()
	r.Post("/api/v1/work-items", h.CreateWorkItem)
	r.Get("/api/v1/work-items", h.ListWorkItems)
	r.Get("/api/v1/work-items/{id}", h.GetWorkItem)
	r.Patch("/api/v1/work-items/{id}", h.TransitionWorkItem)
	r.Post("/api/v1/work-items/{id}/intents", h.AppendWorkItemIntent)
	r.Get("/api/v1/work-items/{id}/executions", h.ListWorkItemExecutions)
	r.Post("/api/v1/work-items/{id}/executions", h.AttachWorkItemExecution)
	r.Post("/api/v1/work-items/{id}/resume", h.ResumeWorkItem)
	r.Post("/api/v1/work-items/{id}/surface-refs", h.LinkWorkItemSurface)
	r.Get("/api/v1/work-items/{id}/events", h.ListWorkItemEvents)
	r.Post("/api/v1/work-items/{id}/executions/{execution_id}/snapshot", h.SealWorkItemSnapshot)
	r.Get("/api/v1/work-items/{id}/executions/{execution_id}/snapshot", h.GetWorkItemExecutionSnapshot)
	r.Get("/api/v1/work-items/{id}/snapshots", h.ListWorkItemSnapshots)
	r.Get("/api/v1/work-items/{id}/snapshots/{snapshot_id}", h.GetWorkItemSnapshot)
	r.Post("/api/v1/action-approvals", h.CreateActionApproval)
	r.Get("/api/v1/action-approvals", h.ListActionApprovals)
	r.Get("/api/v1/action-approvals/{id}", h.GetActionApproval)
	r.Post("/api/v1/action-approvals/{id}/decision", h.DecideActionApproval)
	r.Post("/api/v1/action-approvals/{id}/consume", h.ConsumeActionApproval)
	r.Post("/api/v1/work-items/{id}/execution-requests", h.CreateExecutionRequest)
	r.Get("/api/v1/work-items/{id}/execution-requests", h.ListExecutionRequests)
	r.Get("/api/v1/work-items/{id}/execution-requests/{request_id}", h.GetExecutionRequest)
	r.Post("/api/v1/execution-requests/claim", h.ClaimExecutionRequest)
	r.Post("/api/v1/execution-requests/{request_id}/fulfil", h.FulfilExecutionRequest)
	r.Post("/api/v1/execution-requests/{request_id}/reject", h.RejectExecutionRequest)
	return r
}

type wiResponse struct {
	code int
	body map[string]any
	raw  string
}

func (e *workItemsEnv) do(user *auth.User, method, path string, body any, headers ...string) wiResponse {
	e.t.Helper()
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if user != nil {
		req = req.WithContext(auth.WithUser(req.Context(), user))
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	out := wiResponse{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func (e *workItemsEnv) user(login string) *auth.User {
	return auth.NewGitHubUser(login, []string{e.tenant})
}

func (e *workItemsEnv) open(user *auth.User, extra map[string]any) map[string]any {
	e.t.Helper()
	body := map[string]any{"tenant": e.tenant, "title": "ship it"}
	for k, v := range extra {
		body[k] = v
	}
	res := e.do(user, "POST", "/api/v1/work-items", body)
	if res.code != http.StatusCreated {
		e.t.Fatalf("create = %d %s", res.code, res.raw)
	}
	return res.body["work_item"].(map[string]any)
}

func code(res wiResponse) string {
	c, _ := res.body["code"].(string)
	return c
}

func TestWorkItems_UnconfiguredStoreAnswers503(t *testing.T) {
	h := &Handlers{}
	r := workItemsRouter(h)
	for _, rt := range [][2]string{{"GET", "/api/v1/work-items"}, {"POST", "/api/v1/work-items"}, {"GET", "/api/v1/work-items/wi_x"}, {"POST", "/api/v1/work-items/wi_x/resume"},
		{"POST", "/api/v1/work-items/wi_x/execution-requests"}, {"GET", "/api/v1/work-items/wi_x/execution-requests"},
		{"POST", "/api/v1/execution-requests/claim"}, {"POST", "/api/v1/execution-requests/xr_x/fulfil"}} {
		req := httptest.NewRequest(rt[0], rt[1], strings.NewReader("{}"))
		req = req.WithContext(auth.WithUser(req.Context(), auth.NewGitHubUser("alice", []string{"acme"})))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", rt[0], rt[1], rec.Code)
		}
	}
}

func TestWorkItems_OpenReadAndPersist(t *testing.T) {
	e := newWorkItemsEnv(t)
	if res := e.do(nil, "GET", "/api/v1/work-items", nil); res.code != http.StatusUnauthorized {
		t.Fatalf("anonymous list = %d", res.code)
	}
	alice := e.user("alice")
	item := e.open(alice, map[string]any{"origin_surface": "telegram"})
	id := item["id"].(string)
	if item["owner_principal"] != "github:alice" || item["created_by"] != "github:alice" || item["state"] != "active" || item["schema_version"] != "workitem/v1" {
		t.Fatalf("created %v", item)
	}

	// Read back through a second store: the item is durable, not cached.
	store2, err := workitems.NewStore(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	e2 := &workItemsEnv{t: t, h: &Handlers{opts: Options{WorkItems: store2}}}
	e2.router = workItemsRouter(e2.h)
	res := e2.do(alice, "GET", "/api/v1/work-items/"+id, nil)
	if res.code != http.StatusOK || res.body["schema_version"] != "workitem/v1" || res.body["state_version"] != float64(1) || res.body["latest_execution"] != nil {
		t.Fatalf("get = %d %s", res.code, res.raw)
	}
	if res := e.do(alice, "GET", "/api/v1/work-items/wi_missing", nil); res.code != http.StatusNotFound || code(res) != "work_item_not_found" {
		t.Fatalf("missing = %d %s", res.code, res.raw)
	}
	list := e.do(alice, "GET", "/api/v1/work-items?tenant="+e.tenant, nil)
	if items, _ := list.body["items"].([]any); list.code != http.StatusOK || len(items) != 1 {
		t.Fatalf("list = %d %s", list.code, list.raw)
	}
}

func TestWorkItems_IdempotentOpen(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	body := map[string]any{"tenant": e.tenant, "title": "once"}
	first := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k-1")
	again := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k-1")
	if first.code != http.StatusCreated || again.code != http.StatusOK {
		t.Fatalf("codes = %d, %d", first.code, again.code)
	}
	if first.body["work_item"].(map[string]any)["id"] != again.body["work_item"].(map[string]any)["id"] {
		t.Fatal("replay opened a second item")
	}
	body["title"] = "something else"
	if res := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k-1"); res.code != http.StatusConflict || code(res) != "idempotency_key_reused" {
		t.Fatalf("reused key = %d %s", res.code, res.raw)
	}
	body["idempotency_key"] = "k-2"
	if res := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k-3"); res.code != http.StatusBadRequest {
		t.Fatalf("header/body key mismatch = %d %s", res.code, res.raw)
	}
}

func TestWorkItems_ForgedActorIsRejectedEverywhere(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	item := e.open(alice, nil)
	id := item["id"].(string)
	cases := []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "x", "actor": "tg:123"}},
		{"POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "x", "owner_principal": "github:bob"}},
		{"POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "x", "created_by": "github:bob"}},
		{"PATCH", "/api/v1/work-items/" + id, map[string]any{"action": "archive", "expected_state_version": 1, "actor": "tg:123"}},
		{"POST", "/api/v1/work-items/" + id + "/intents", map[string]any{"text": "hi", "on_behalf_of": "tg:123"}},
		{"POST", "/api/v1/work-items/" + id + "/resume", map[string]any{"expected_state_version": 1, "engine": "argo", "engine_ref": "x", "actor_principal": "tg:123"}},
		{"POST", "/api/v1/work-items/" + id + "/executions", map[string]any{"engine": "argo", "engine_ref": "x", "subject": "tg:123"}},
	}
	for _, c := range cases {
		res := e.do(alice, c.method, c.path, c.body)
		if res.code != http.StatusBadRequest || code(res) != "actor_not_accepted" {
			t.Errorf("%s %s %v = %d %s", c.method, c.path, c.body, res.code, res.raw)
		}
	}
	// Nothing happened: still one item, still at version 1, one event.
	got := e.do(alice, "GET", "/api/v1/work-items/"+id, nil)
	if got.body["state_version"] != float64(1) {
		t.Fatalf("forged requests changed the item: %s", got.raw)
	}
	list := e.do(alice, "GET", "/api/v1/work-items?tenant="+e.tenant, nil)
	if items, _ := list.body["items"].([]any); len(items) != 1 {
		t.Fatalf("forged create opened an item: %s", list.raw)
	}
}

func TestWorkItems_SurfaceActorIsCorrelationNeverIdentity(t *testing.T) {
	e := newWorkItemsEnv(t)
	svc := auth.NewServiceUser()
	item := e.open(e.user("alice"), nil)
	id := item["id"].(string)
	res := e.do(svc, "POST", "/api/v1/work-items/"+id+"/surface-refs",
		map[string]any{"surface": "telegram", "external_id": "chat-9", "actor_external_id": "tg:123"})
	if res.code != http.StatusCreated {
		t.Fatalf("link = %d %s", res.code, res.raw)
	}
	// The service acted as itself, and the Telegram id is only stored.
	res = e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "dev-loop-1", "phase": "Running"})
	if res.code != http.StatusCreated {
		t.Fatalf("attach = %d %s", res.code, res.raw)
	}
	events := e.do(svc, "GET", "/api/v1/work-items/"+id+"/events", nil)
	list, _ := events.body["events"].([]any)
	if len(list) != 3 {
		t.Fatalf("events = %s", events.raw)
	}
	for _, raw := range list[1:] {
		ev := raw.(map[string]any)
		if ev["actor_principal"] != "service:"+auth.ServiceUserID {
			t.Errorf("event %v: actor = %v, want the service principal", ev["kind"], ev["actor_principal"])
		}
	}
	if strings.Contains(events.raw, "tg:123") || strings.Contains(events.raw, "chat-9") {
		t.Fatalf("history copies surface ids: %s", events.raw)
	}
	if list[0].(map[string]any)["actor_principal"] != "github:alice" {
		t.Fatalf("subject not preserved: %v", list[0])
	}
}

func TestWorkItems_VisibilityAnswers404AndTenantAccess403(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, bob := e.user("alice"), e.user("bob")
	mallory := auth.NewGitHubUser("mallory", []string{"elsewhere"})
	shared := e.open(alice, nil)["id"].(string)
	private := e.open(alice, map[string]any{"visibility": "private"})["id"].(string)

	if res := e.do(mallory, "GET", "/api/v1/work-items/"+shared, nil); res.code != http.StatusNotFound {
		t.Errorf("other tenant read = %d", res.code)
	}
	if res := e.do(mallory, "PATCH", "/api/v1/work-items/"+shared, map[string]any{"action": "archive", "expected_state_version": 1}); res.code != http.StatusNotFound {
		t.Errorf("other tenant write = %d", res.code)
	}
	if res := e.do(bob, "GET", "/api/v1/work-items/"+private, nil); res.code != http.StatusNotFound {
		t.Errorf("private read by another member = %d", res.code)
	}
	if res := e.do(bob, "GET", "/api/v1/work-items/"+shared, nil); res.code != http.StatusOK {
		t.Errorf("tenant item read by a member = %d", res.code)
	}
	list := e.do(bob, "GET", "/api/v1/work-items?tenant="+e.tenant, nil)
	if items, _ := list.body["items"].([]any); len(items) != 1 {
		t.Errorf("bob lists %s", list.raw)
	}
	if res := e.do(mallory, "POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "x"}); res.code != http.StatusForbidden || code(res) != "tenant_forbidden" {
		t.Errorf("create in foreign tenant = %d %s", res.code, res.raw)
	}
	if res := e.do(mallory, "GET", "/api/v1/work-items?tenant="+e.tenant, nil); res.code != http.StatusForbidden {
		t.Errorf("list foreign tenant = %d", res.code)
	}
	// A guessable external_key never reveals someone's private item.
	e.open(alice, map[string]any{"visibility": "private", "external_key": "https://github.com/o/r/issues/1"})
	for _, vis := range []string{"private", "tenant"} {
		res := e.do(bob, "POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "x", "visibility": vis, "external_key": "https://github.com/o/r/issues/1"})
		if res.code != http.StatusConflict || code(res) != "external_key_in_use" || strings.Contains(res.raw, "wi_") {
			t.Errorf("external_key onto a private item (%s) = %d %s", vis, res.code, res.raw)
		}
	}
	admin := auth.NewGitHubUser("root", []string{"admins"})
	if res := e.do(admin, "GET", "/api/v1/work-items/"+private, nil); res.code != http.StatusOK {
		t.Errorf("admin read private = %d", res.code)
	}
}

func TestWorkItems_StaleVersionIs409WithCurrentState(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	id := e.open(alice, nil)["id"].(string)
	if res := e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "wait", "waiting_reason": "input", "expected_state_version": 1}); res.code != http.StatusOK {
		t.Fatalf("wait = %d %s", res.code, res.raw)
	}
	res := e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "complete", "expected_state_version": 1})
	details, _ := res.body["details"].(map[string]any)
	if res.code != http.StatusConflict || code(res) != "state_version_conflict" || details["state"] != "waiting" || details["state_version"] != float64(2) {
		t.Fatalf("stale = %d %s", res.code, res.raw)
	}
	if res := e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "resume", "expected_state_version": 2}); res.code != http.StatusBadRequest {
		t.Fatalf("resume through PATCH = %d %s", res.code, res.raw)
	}
	if res := e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "complete", "expected_state_version": 2}); res.code != http.StatusOK {
		t.Fatalf("complete = %d %s", res.code, res.raw)
	}
	res = e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "archive", "expected_state_version": 3})
	if res.code != http.StatusConflict || code(res) != "invalid_transition" {
		t.Fatalf("out of terminal = %d %s", res.code, res.raw)
	}
}

func TestWorkItems_ResumeStartsTheNextExecution(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, svc := e.user("alice"), auth.NewServiceUser()
	id := e.open(alice, nil)["id"].(string)
	first := e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "run-1", "phase": "Running"})
	if first.code != http.StatusCreated {
		t.Fatalf("attach = %d %s", first.code, first.raw)
	}
	e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "wait", "waiting_reason": "input", "expected_state_version": 1})
	resume := map[string]any{"expected_state_version": 2, "engine": "temporal", "engine_ref": "run-2"}
	if res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/resume", resume, "Idempotency-Key", "r-1"); res.code != http.StatusConflict || code(res) != "execution_active" {
		t.Fatalf("resume over a running execution = %d %s", res.code, res.raw)
	}
	e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "run-1", "phase": "Failed"})
	res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/resume", resume, "Idempotency-Key", "r-1")
	if res.code != http.StatusCreated {
		t.Fatalf("resume = %d %s", res.code, res.raw)
	}
	exec := res.body["execution"].(map[string]any)
	firstID := first.body["execution"].(map[string]any)["id"]
	if res.body["work_item"].(map[string]any)["state"] != "active" || exec["attempt"] != float64(2) || exec["resumed_from_execution_id"] != firstID {
		t.Fatalf("resumed = %s", res.raw)
	}
	again := e.do(alice, "POST", "/api/v1/work-items/"+id+"/resume", resume, "Idempotency-Key", "r-1")
	if again.code != http.StatusOK || again.body["execution"].(map[string]any)["id"] != exec["id"] {
		t.Fatalf("replayed resume = %d %s", again.code, again.raw)
	}
	view := e.do(alice, "GET", "/api/v1/work-items/"+id, nil)
	if view.body["latest_execution"].(map[string]any)["id"] != exec["id"] {
		t.Fatalf("latest execution = %s", view.raw)
	}
}

func TestWorkItems_NoTranscriptInHistoryOrAudit(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	id := e.open(alice, nil)["id"].(string)
	const text = "please retry the deploy of the billing service"
	if res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": text}); res.code != http.StatusCreated {
		t.Fatalf("intent = %d %s", res.code, res.raw)
	}
	if res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": strings.Repeat("x", workitems.MaxIntentBytes+1)}); res.code != http.StatusBadRequest {
		t.Fatalf("oversized intent = %d", res.code)
	}
	if res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": "token ghp_" + strings.Repeat("a", 36)}); res.code != http.StatusBadRequest || code(res) != "secret_in_text" {
		t.Fatalf("secret intent = %d %s", res.code, res.raw)
	}
	events := e.do(alice, "GET", "/api/v1/work-items/"+id+"/events", nil)
	if strings.Contains(events.raw, "billing") {
		t.Fatalf("history carries intent text: %s", events.raw)
	}
	for _, entry := range e.audit.List(100) {
		raw, _ := json.Marshal(entry)
		if strings.Contains(string(raw), "billing") {
			t.Fatalf("audit carries intent text: %s", raw)
		}
		if entry.Parameters["actor"] != "github:alice" {
			t.Fatalf("audit actor = %q", entry.Parameters["actor"])
		}
	}
}

func TestWorkItems_ExecutionListAndSupersedeVisibility(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, bob, svc := e.user("alice"), e.user("bob"), auth.NewServiceUser()
	id := e.open(alice, nil)["id"].(string)

	empty := e.do(alice, "GET", "/api/v1/work-items/"+id+"/executions", nil)
	if empty.code != http.StatusOK || !strings.Contains(empty.raw, `"executions":[]`) {
		t.Fatalf("no executions = %d %s; want an empty array, not null", empty.code, empty.raw)
	}
	for _, ref := range []string{"run-1", "run-2"} {
		e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "argo", "engine_ref": ref, "phase": "Succeeded"})
	}
	list := e.do(alice, "GET", "/api/v1/work-items/"+id+"/executions", nil)
	execs, _ := list.body["executions"].([]any)
	if list.code != http.StatusOK || len(execs) != 2 || execs[0].(map[string]any)["attempt"] != float64(1) || execs[1].(map[string]any)["engine_ref"] != "run-2" {
		t.Fatalf("executions = %s", list.raw)
	}

	// superseded_by must name an item the caller can see: a missing id and
	// someone else's private item answer the same 400.
	hidden := e.open(bob, map[string]any{"visibility": "private"})["id"].(string)
	for _, next := range []string{"wi_missing", hidden} {
		res := e.do(alice, "PATCH", "/api/v1/work-items/"+id, map[string]any{"action": "supersede", "superseded_by": next, "expected_state_version": 1})
		if res.code != http.StatusBadRequest || code(res) != "invalid_request" {
			t.Errorf("supersede by %s = %d %s", next, res.code, res.raw)
		}
	}
}

func TestWorkItems_LongRequestIDNeverFailsAWrite(t *testing.T) {
	e := newWorkItemsEnv(t)
	raw, _ := json.Marshal(map[string]any{"tenant": e.tenant, "title": "x"})
	req := httptest.NewRequest("POST", "/api/v1/work-items", bytes.NewReader(raw))
	ctx := auth.WithUser(req.Context(), e.user("alice"))
	ctx = context.WithValue(ctx, clientMetaKey{}, ClientMeta{RequestID: strings.Repeat("a", 300) + "\xff"})
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusCreated {
		t.Fatalf("300-byte X-Request-Id = %d %s", rec.Code, rec.Body.String())
	}
}

func TestWorkItems_AnotherPrincipalCannotReplayYourKey(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, bob := e.user("alice"), e.user("bob")
	body := map[string]any{"tenant": e.tenant, "title": "same"}
	if res := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k"); res.code != http.StatusCreated {
		t.Fatalf("alice = %d", res.code)
	}
	if res := e.do(bob, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k"); res.code != http.StatusConflict || code(res) != "idempotency_key_reused" {
		t.Fatalf("bob with alice's key = %d %s", res.code, res.raw)
	}
}

func TestWorkItems_ListWithoutTenantStaysInsideTheCallersTenants(t *testing.T) {
	e := newWorkItemsEnv(t)
	other := e.tenant + "-b"
	alice := e.user("alice")
	carol := auth.NewGitHubUser("carol", []string{other})
	mine := e.open(alice, nil)["id"].(string)
	res := e.do(carol, "POST", "/api/v1/work-items", map[string]any{"tenant": other, "title": "theirs"})
	if res.code != http.StatusCreated {
		t.Fatalf("create in second tenant = %d %s", res.code, res.raw)
	}
	theirs := res.body["work_item"].(map[string]any)["id"].(string)

	ids := func(res wiResponse) map[string]bool {
		out := map[string]bool{}
		items, _ := res.body["items"].([]any)
		for _, it := range items {
			out[it.(map[string]any)["id"].(string)] = true
		}
		return out
	}
	if got := ids(e.do(alice, "GET", "/api/v1/work-items", nil)); !got[mine] || got[theirs] {
		t.Errorf("member without ?tenant= lists %v", got)
	}
	if got := ids(e.do(carol, "GET", "/api/v1/work-items", nil)); got[mine] || !got[theirs] {
		t.Errorf("second member without ?tenant= lists %v", got)
	}
	admin := auth.NewGitHubUser("root", []string{"admins"})
	if got := ids(e.do(admin, "GET", "/api/v1/work-items?limit=500", nil)); !got[mine] || !got[theirs] {
		t.Errorf("admin without ?tenant= lists %v", got)
	}
}

func TestWorkItems_LimitAndTenantAreValidated(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	for _, q := range []string{"0", "-1", "abc", "501"} {
		if res := e.do(alice, "GET", "/api/v1/work-items?limit="+q, nil); res.code != http.StatusBadRequest {
			t.Errorf("limit=%s = %d %s", q, res.code, res.raw)
		}
	}
	if res := e.do(alice, "GET", "/api/v1/work-items?limit=500", nil); res.code != http.StatusOK {
		t.Errorf("limit=500 = %d %s", res.code, res.raw)
	}
	if res := e.do(alice, "POST", "/api/v1/work-items", map[string]any{"title": "no tenant"}); res.code != http.StatusBadRequest {
		t.Errorf("missing tenant = %d %s", res.code, res.raw)
	}
}

func TestWorkItems_KeyInHeaderOrBodyIsTheSameRequest(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	body := map[string]any{"tenant": e.tenant, "title": "once"}
	first := e.do(alice, "POST", "/api/v1/work-items", body, "Idempotency-Key", "k-hb")
	body["idempotency_key"] = "k-hb"
	again := e.do(alice, "POST", "/api/v1/work-items", body)
	if first.code != http.StatusCreated || again.code != http.StatusOK {
		t.Fatalf("header then body key = %d, %d %s", first.code, again.code, again.raw)
	}
}

func TestWorkItems_SurfaceRefsRefuseAnIdempotencyKeyAndAForgedActor(t *testing.T) {
	e := newWorkItemsEnv(t)
	svc := auth.NewServiceUser()
	id := e.open(e.user("alice"), nil)["id"].(string)
	path := "/api/v1/work-items/" + id + "/surface-refs"
	ref := map[string]any{"surface": "telegram", "external_id": "chat:1"}
	if res := e.do(svc, "POST", path, ref, "Idempotency-Key", "k"); res.code != http.StatusBadRequest {
		t.Errorf("surface-refs with Idempotency-Key = %d %s", res.code, res.raw)
	}
	forged := map[string]any{"surface": "telegram", "external_id": "chat:1", "actor": "tg:123"}
	if res := e.do(svc, "POST", path, forged); res.code != http.StatusBadRequest || code(res) != "actor_not_accepted" {
		t.Errorf("surface-refs with forged actor = %d %s", res.code, res.raw)
	}
}
