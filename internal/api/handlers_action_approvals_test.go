package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Every request here is scoped to the test's tenant through its execution
// id, which the env's cleanup deletes by.
func (e *workItemsEnv) approvalBody(key string) map[string]any {
	return map[string]any{
		"execution_id":    e.tenant + "-exec",
		"action_kind":     "github.merge_pr",
		"target":          "mctlhq/mctl-api#1",
		"args_digest":     "sha256:args",
		"policy_rule_id":  "merge-needs-human",
		"policy_version":  "v3",
		"artifact_hash":   "sha256:diff",
		"idempotency_key": key,
		"expires_at":      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func (e *workItemsEnv) requestApproval(key string) map[string]any {
	e.t.Helper()
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", e.approvalBody(key))
	if res.code != http.StatusCreated {
		e.t.Fatalf("create = %d %s", res.code, res.raw)
	}
	return res.body["approval"].(map[string]any)
}

func (e *workItemsEnv) decide(u *auth.User, id, decision string) wiResponse {
	e.t.Helper()
	return e.do(u, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": decision, "reason": "looked at it"})
}

func (e *workItemsEnv) consume(id, hash string) wiResponse {
	e.t.Helper()
	return e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": hash})
}

// expire moves a request's expiry into the past, as time passing would.
func (e *workItemsEnv) expire(id string) {
	e.t.Helper()
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET expires_at = now() - interval '1 second' WHERE id=$1`, id); err != nil {
		e.t.Fatal(err)
	}
}

func (e *workItemsEnv) auditOps(op, id string) int {
	n := 0
	entries := e.audit.List(1000)
	for i := range entries {
		if entries[i].Operation == op && entries[i].Parameters["approval_id"] == id {
			n++
		}
	}
	return n
}

var rootAdmin = auth.NewGitHubUser("root", []string{"admins"})

func TestActionApprovals_CreateIsIdempotentAndBindsTheIntent(t *testing.T) {
	e := newWorkItemsEnv(t)
	svc := auth.NewServiceUser()
	body := e.approvalBody("k-1")
	res := e.do(svc, "POST", "/api/v1/action-approvals", body)
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	a := res.body["approval"].(map[string]any)
	id := a["id"].(string)
	want := workitems.IntentHash(workitems.ActionIntent{
		ExecutionID: e.tenant + "-exec", ActionKind: "github.merge_pr", Target: "mctlhq/mctl-api#1", ArgsDigest: "sha256:args",
		PolicyRuleID: "merge-needs-human", PolicyVersion: "v3", ArtifactHash: "sha256:diff",
	})
	if !strings.HasPrefix(id, workitems.ActionApprovalIDPrefix) || a["state"] != "pending" || a["intent_hash"] != want ||
		a["requested_by"] != "service:"+auth.ServiceUserID || res.body["schema_version"] != workitems.ActionApprovalSchemaVersion {
		t.Fatalf("created = %s", res.raw)
	}

	// The same key and intent, key in the header this time, with the
	// matching client hash: the stored request, 200, not audited again.
	replay := e.approvalBody("")
	delete(replay, "idempotency_key")
	replay["intent_hash"] = want
	res = e.do(svc, "POST", "/api/v1/action-approvals", replay, "Idempotency-Key", "k-1")
	if res.code != http.StatusOK || res.body["approval"].(map[string]any)["id"] != id {
		t.Fatalf("replay = %d %s", res.code, res.raw)
	}
	if n := e.auditOps("action_approval.create", id); n != 1 {
		t.Fatalf("create audited %d times", n)
	}
	// The same key with a different intent.
	drift := e.approvalBody("k-1")
	drift["target"] = "mctlhq/mctl-api#2"
	if res := e.do(svc, "POST", "/api/v1/action-approvals", drift); res.code != http.StatusConflict || code(res) != aarCodeIdempotencyConflict {
		t.Fatalf("drift = %d %s", res.code, res.raw)
	}
	// A client hash that is not the hash of the fields sent.
	wrong := e.approvalBody("k-2")
	wrong["intent_hash"] = "sha256:" + strings.Repeat("0", 64)
	if res := e.do(svc, "POST", "/api/v1/action-approvals", wrong); res.code != http.StatusBadRequest || code(res) != aarCodeIntentHashInvalid {
		t.Fatalf("wrong hash = %d %s", res.code, res.raw)
	}

	bad := map[string]func(map[string]any){
		"no execution": func(b map[string]any) { delete(b, "execution_id") },
		"no target":    func(b map[string]any) { b["target"] = "" },
		"no key":       func(b map[string]any) { delete(b, "idempotency_key") },
		"no expiry":    func(b map[string]any) { delete(b, "expires_at") },
		"past expiry":  func(b map[string]any) { b["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) },
		"far expiry": func(b map[string]any) {
			b["expires_at"] = time.Now().Add(8 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
		"long target":   func(b map[string]any) { b["target"] = strings.Repeat("t", workitems.MaxApprovalTargetBytes+1) },
		"unknown field": func(b map[string]any) { b["extra"] = true },
		"bad expiry":    func(b map[string]any) { b["expires_at"] = "tomorrow" },
	}
	for name, mutate := range bad {
		b := e.approvalBody("k-bad-" + name)
		mutate(b)
		if res := e.do(svc, "POST", "/api/v1/action-approvals", b); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
			t.Errorf("%s: %d %s", name, res.code, res.raw)
		}
	}
	for _, field := range []string{"requested_by", "actor"} {
		b := e.approvalBody("k-actor")
		b[field] = "service:someone-else"
		if res := e.do(svc, "POST", "/api/v1/action-approvals", b); res.code != http.StatusBadRequest || code(res) != wiCodeActorNotAccepted {
			t.Errorf("%s: %d %s", field, res.code, res.raw)
		}
	}
	if res := e.do(svc, "POST", "/api/v1/action-approvals", e.approvalBody("k-3"), "Idempotency-Key", "k-other"); res.code != http.StatusBadRequest {
		t.Errorf("header/body key mismatch = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_OnlyADirectServiceCreatesOrConsumes(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.requestApproval("k-1")
	if res := e.decide(rootAdmin, a["id"].(string), "approve"); res.code != http.StatusOK {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"tenant user": e.user("alice"),
		"human admin": rootAdmin,
		"surface":     surface,
		"relayed":     auth.NewRelayedUser("root", []string{"admins", e.tenant}, surface),
	} {
		if res := e.do(u, "POST", "/api/v1/action-approvals", e.approvalBody("k-"+name)); res.code != http.StatusForbidden || code(res) != aarCodeRequesterForbidden {
			t.Errorf("%s create = %d %s", name, res.code, res.raw)
		}
		res := e.do(u, "POST", "/api/v1/action-approvals/"+a["id"].(string)+"/consume", map[string]any{"intent_hash": a["intent_hash"]})
		if res.code != http.StatusForbidden || code(res) != aarCodeRequesterForbidden {
			t.Errorf("%s consume = %d %s", name, res.code, res.raw)
		}
	}
	// Nothing was spent by the refusals.
	if res := e.consume(a["id"].(string), a["intent_hash"].(string)); res.code != http.StatusOK {
		t.Fatalf("consume = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_OnlyAHumanAdminDecides(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.requestApproval("k-1")
	id := a["id"].(string)
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"service (the requester, and in admins)": auth.NewServiceUser(),
		"tenant user":                            e.user("alice"),
		"surface":                                surface,
		"relayed admin":                          auth.NewRelayedUser("root", []string{"admins", e.tenant}, surface),
	} {
		if res := e.decide(u, id, "approve"); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
			t.Errorf("%s: %d %s", name, res.code, res.raw)
		}
	}
	res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if res.code != http.StatusOK || res.body["approval"].(map[string]any)["state"] != "pending" {
		t.Fatalf("refusals changed it: %s", res.raw)
	}
	if res := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision", map[string]any{"decision": "approve", "decided_by": "github:other"}); res.code != http.StatusBadRequest || code(res) != wiCodeActorNotAccepted {
		t.Fatalf("decided_by in body = %d %s", res.code, res.raw)
	}
	if res := e.decide(rootAdmin, id, "maybe"); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
		t.Fatalf("bad decision = %d %s", res.code, res.raw)
	}

	res = e.decide(rootAdmin, id, "approve")
	got := res.body["approval"].(map[string]any)
	if res.code != http.StatusOK || got["state"] != "approved" || got["decided_by"] != "github:root" || got["decided_at"] == nil || got["reason"] != "looked at it" {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if n := e.auditOps("action_approval.decision", id); n != 1 {
		t.Fatalf("decision audited %d times", n)
	}
	// Only from pending.
	if res := e.decide(rootAdmin, id, "deny"); res.code != http.StatusConflict || code(res) != aarCodeAlreadyDecided {
		t.Fatalf("re-decide = %d %s", res.code, res.raw)
	}
	if res := e.decide(rootAdmin, "aar_missing", "approve"); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("missing = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_ConsumeIsSingleUseAndTyped(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.requestApproval("k-1")
	id, hash := a["id"].(string), a["intent_hash"].(string)

	if res := e.consume(id, hash); res.code != http.StatusConflict || code(res) != aarCodeNotApproved {
		t.Fatalf("pending = %d %s", res.code, res.raw)
	}
	e.decide(rootAdmin, id, "approve")
	if res := e.consume(id, "sha256:"+strings.Repeat("0", 64)); res.code != http.StatusConflict || code(res) != aarCodeIntentMismatch {
		t.Fatalf("mismatch = %d %s", res.code, res.raw)
	}
	if res := e.consume(id, ""); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
		t.Fatalf("no hash = %d %s", res.code, res.raw)
	}

	// Racing consumes: exactly one spends it.
	const racers = 8
	codes := make([]int, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest("POST", "/api/v1/action-approvals/"+id+"/consume", strings.NewReader(`{"intent_hash":"`+hash+`"}`))
			req = req.WithContext(auth.WithUser(req.Context(), auth.NewServiceUser()))
			rec := httptest.NewRecorder()
			e.router.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}()
	}
	close(start)
	wg.Wait()
	won := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			won++
		case http.StatusConflict:
		default:
			t.Fatalf("racer = %d", c)
		}
	}
	if won != 1 {
		t.Fatalf("%d consumes succeeded, want exactly 1 (%v)", won, codes)
	}
	if n := e.auditOps("action_approval.consume", id); n != 1 {
		t.Fatalf("consume audited %d times", n)
	}
	res := e.consume(id, hash)
	if res.code != http.StatusConflict || code(res) != aarCodeConsumed {
		t.Fatalf("again = %d %s", res.code, res.raw)
	}
	res = e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
	if got := res.body["approval"].(map[string]any); got["state"] != "consumed" || got["consumed_at"] == nil {
		t.Fatalf("read = %s", res.raw)
	}

	denied := e.requestApproval("k-2")
	e.decide(rootAdmin, denied["id"].(string), "deny")
	if res := e.consume(denied["id"].(string), denied["intent_hash"].(string)); res.code != http.StatusConflict || code(res) != aarCodeDenied {
		t.Fatalf("denied = %d %s", res.code, res.raw)
	}
	if res := e.consume("aar_missing", hash); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("missing = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_ExpireLazily(t *testing.T) {
	e := newWorkItemsEnv(t)
	pending := e.requestApproval("k-pending")
	ok := e.requestApproval("k-approved")
	e.decide(rootAdmin, ok["id"].(string), "approve")
	e.expire(pending["id"].(string))
	e.expire(ok["id"].(string))

	for _, id := range []string{pending["id"].(string), ok["id"].(string)} {
		res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/"+id, nil)
		if res.code != http.StatusOK || res.body["approval"].(map[string]any)["state"] != "expired" {
			t.Fatalf("read %s = %s", id, res.raw)
		}
	}
	if res := e.decide(rootAdmin, pending["id"].(string), "approve"); res.code != http.StatusConflict || code(res) != aarCodeExpired {
		t.Fatalf("decide = %d %s", res.code, res.raw)
	}
	if res := e.consume(ok["id"].(string), ok["intent_hash"].(string)); res.code != http.StatusConflict || code(res) != aarCodeExpired {
		t.Fatalf("consume = %d %s", res.code, res.raw)
	}
	res := e.do(rootAdmin, "GET", "/api/v1/action-approvals?state=expired&execution_id="+e.tenant+"-exec", nil)
	if list := res.body["approvals"].([]any); res.code != http.StatusOK || len(list) != 2 {
		t.Fatalf("expired list = %s", res.raw)
	}
	res = e.do(rootAdmin, "GET", "/api/v1/action-approvals?state=pending&execution_id="+e.tenant+"-exec", nil)
	if list := res.body["approvals"].([]any); len(list) != 0 {
		t.Fatalf("pending list = %s", res.raw)
	}
}

func TestActionApprovals_ReadersAndFilters(t *testing.T) {
	e := newWorkItemsEnv(t)
	a := e.requestApproval("k-1")
	b := e.requestApproval("k-2")
	e.decide(rootAdmin, b["id"].(string), "deny")
	exec := "/api/v1/action-approvals?execution_id=" + e.tenant + "-exec"

	for name, u := range map[string]*auth.User{"admin": rootAdmin, "requesting service": auth.NewServiceUser()} {
		res := e.do(u, "GET", exec, nil)
		if list := res.body["approvals"].([]any); res.code != http.StatusOK || len(list) != 2 {
			t.Fatalf("%s list = %s", name, res.raw)
		}
		res = e.do(u, "GET", exec+"&state=denied", nil)
		if list := res.body["approvals"].([]any); len(list) != 1 || list[0].(map[string]any)["id"] != b["id"] {
			t.Fatalf("%s denied = %s", name, res.raw)
		}
		if res := e.do(u, "GET", "/api/v1/action-approvals/"+a["id"].(string), nil); res.code != http.StatusOK {
			t.Fatalf("%s get = %d", name, res.code)
		}
	}
	if res := e.do(rootAdmin, "GET", exec+"&limit=1", nil); len(res.body["approvals"].([]any)) != 1 {
		t.Fatalf("limit = %s", res.raw)
	}
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"tenant user":   e.user("alice"),
		"surface":       surface,
		"relayed admin": auth.NewRelayedUser("root", []string{"admins", e.tenant}, surface),
	} {
		if res := e.do(u, "GET", exec, nil); res.code != http.StatusForbidden || code(res) != aarCodeReaderForbidden {
			t.Errorf("%s list = %d %s", name, res.code, res.raw)
		}
		if res := e.do(u, "GET", "/api/v1/action-approvals/"+a["id"].(string), nil); res.code != http.StatusForbidden || code(res) != aarCodeReaderForbidden {
			t.Errorf("%s get = %d %s", name, res.code, res.raw)
		}
	}
	for _, q := range []string{"&state=granted", "&limit=0", "&limit=501", "&limit=x"} {
		if res := e.do(rootAdmin, "GET", exec+q, nil); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
			t.Errorf("%s = %d %s", q, res.code, res.raw)
		}
	}
	if res := e.do(rootAdmin, "GET", "/api/v1/action-approvals/aar_missing", nil); res.code != http.StatusNotFound || code(res) != aarCodeNotFound {
		t.Fatalf("missing = %d %s", res.code, res.raw)
	}
}

func TestActionApprovals_UnconfiguredStoreAnswers503(t *testing.T) {
	r := workItemsRouter(&Handlers{})
	for _, rt := range [][2]string{{"POST", "/api/v1/action-approvals"}, {"GET", "/api/v1/action-approvals"}, {"GET", "/api/v1/action-approvals/aar_x"},
		{"POST", "/api/v1/action-approvals/aar_x/decision"}, {"POST", "/api/v1/action-approvals/aar_x/consume"}} {
		req := httptest.NewRequest(rt[0], rt[1], strings.NewReader("{}"))
		req = req.WithContext(auth.WithUser(req.Context(), auth.NewServiceUser()))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", rt[0], rt[1], rec.Code)
		}
	}
}

func TestActionApprovalRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	for _, want := range []string{
		"POST /api/v1/action-approvals",
		"GET /api/v1/action-approvals",
		"GET /api/v1/action-approvals/{id}",
		"POST /api/v1/action-approvals/{id}/decision",
		"POST /api/v1/action-approvals/{id}/consume",
	} {
		if !found[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}
