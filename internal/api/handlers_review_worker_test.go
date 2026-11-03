// Copyright 2025 MCTL Authors
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

// POST /api/v1/review-receipts, the worker receipt route (mctl-api#917),
// against a real work-items store (provenance) and a real review store. The
// proposal's T1-T4, T6, T8-T13 at the HTTP layer; every refusal asserts the
// code AND zero rows for the request in both tables.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/k8s"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/reviewstore"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

type tenantEvidence struct{ tenant string }

func (f tenantEvidence) List(context.Context, evidence.Filter) (*evidence.ListResult, error) {
	return &evidence.ListResult{Evidence: []*evidence.Evidence{{Ref: &evidence.EvidenceRef{Tenant: f.tenant}}}}, nil
}

type brokenProvenance struct{}

func (brokenProvenance) ExecutionProvenance(context.Context, string) (*workitems.Provenance, error) {
	return nil, errors.New("db down")
}

func (brokenProvenance) LineageAttempts(context.Context, string, []string) (map[string]bool, error) {
	return nil, errors.New("db down")
}

// reviewWorkerEnv is a work-items env plus a review store whose provenance
// is the env's work-items store, the worker route behind the agent scope
// gate, and the provenance read route.
type reviewWorkerEnv struct {
	*workItemsEnv
	reviews *reviewstore.Store
	pool    *pgxpool.Pool
	author  string // a platform-attached authoring execution
}

func newReviewWorkerEnv(t *testing.T) *reviewWorkerEnv {
	t.Helper()
	e := newWorkItemsEnv(t)
	ctx := context.Background()
	rs, err := reviewstore.NewStore(ctx, e.connStr, reviewstore.Config{PoolMax: 1 << 30})
	if err != nil {
		t.Fatalf("reviewstore.NewStore: %v", err)
	}
	pool, err := pgxpool.New(ctx, e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		rs.Close()
	})
	rs.SetEvidence(tenantEvidence{tenant: e.tenant})
	rs.SetProvenance(e.h.opts.WorkItems)
	e.h.opts.ReviewStore = rs
	e.h.opts.ReviewWorkerIngestEnabled = true
	e.router.With(e.h.agentScopeGate).Post("/api/v1/review-receipts", e.h.SubmitWorkerReview)
	e.router.Get("/api/v1/executions/{execution_id}/provenance", e.h.GetExecutionProvenance)
	env := &reviewWorkerEnv{workItemsEnv: e, reviews: rs, pool: pool}
	env.author = env.platformExecution()
	return env
}

// platformExecution is an execution attached by the service principal
// acting directly: reviewer-eligible.
func (e *reviewWorkerEnv) platformExecution() string {
	e.t.Helper()
	item := e.open(auth.NewServiceUser(), nil)
	return e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-"+uuid.NewString(), "Running")
}

func (e *reviewWorkerEnv) provenance(exec string) *workitems.Provenance {
	e.t.Helper()
	p, err := e.h.opts.WorkItems.ExecutionProvenance(context.Background(), exec)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// ingest seals and stores a request of mode authored by e.author.
func (e *reviewWorkerEnv) ingest(mode string, authors ...string) reviewreceipts.ReviewRequest {
	e.t.Helper()
	p := e.provenance(e.author)
	req, err := reviewreceipts.SealRequest(reviewreceipts.SealRequestInput{
		Subject: reviewreceipts.ReviewSubject{
			Kind: reviewreceipts.SubjectProposal, Service: "mctl-api", Slug: "w-" + uuid.NewString()[:8],
			GitopsCommit: strings.Repeat("a", 40), ContentDigest: "sha256:" + strings.Repeat("b", 64),
		},
		Mode: mode, Nonce: "nonce-" + uuid.NewString(), AuthorActors: authors,
		AuthoringExecutionID: e.author, AuthoringAttemptIDs: []string{p.AttemptID}, AuthoringLineageRoot: p.LineageRoot,
		CreatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(req.Dict())
	if _, _, err := e.reviews.IngestRequest(context.Background(), raw, reviewstore.Actor{Name: "svc"}); err != nil {
		e.t.Fatalf("IngestRequest: %v", err)
	}
	e.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = e.pool.Exec(ctx, `DELETE FROM review_nonce_consumptions WHERE request_id = $1`, req.RequestID)
		_, _ = e.pool.Exec(ctx, `DELETE FROM review_receipts WHERE request_id = $1`, req.RequestID)
	})
	return req
}

func workerBody(req reviewreceipts.ReviewRequest) map[string]any {
	criteria := []map[string]any{}
	for _, id := range []string{"scope_bounded", "contracts_specified", "acceptance_testable", "rollback_defined", "matches_issue"} {
		criteria = append(criteria, map[string]any{"id": id, "status": "met"})
	}
	return map[string]any{
		"request_id": req.RequestID, "subject": req.Subject.Dict(), "nonce": req.Nonce,
		"outcome": "PASS", "criteria": criteria,
	}
}

func reviewRun(exec string) *auth.User {
	return auth.NewAgentUser("review-worker", auth.AgentRun{Scope: auth.AgentScopeReview, ExecutionID: exec, RunID: "art_" + uuid.NewString()[:8]})
}

func (e *reviewWorkerEnv) submit(u *auth.User, body any) wiResponse {
	e.t.Helper()
	return e.do(u, "POST", "/api/v1/review-receipts", body)
}

func (e *reviewWorkerEnv) rows(requestID string) (receipts, consumptions int) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM review_receipts WHERE request_id = $1`, requestID).Scan(&receipts); err != nil {
		e.t.Fatal(err)
	}
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM review_nonce_consumptions WHERE request_id = $1`, requestID).Scan(&consumptions); err != nil {
		e.t.Fatal(err)
	}
	return receipts, consumptions
}

func (e *reviewWorkerEnv) wantRefused(what string, res wiResponse, status int, wantCode, requestID string) {
	e.t.Helper()
	if res.code != status || code(res) != wantCode {
		e.t.Errorf("%s: %d %s, want %d %s", what, res.code, res.raw, status, wantCode)
	}
	if r, c := e.rows(requestID); r != 0 || c != 0 {
		e.t.Errorf("%s: wrote %d receipt(s), %d consumption(s); want none", what, r, c)
	}
}

// refusalAudits counts review.worker_submit_refused rows carrying code.
func (e *reviewWorkerEnv) refusalAudits(wantCode string) int {
	n := 0
	entries := e.audit.List(10000)
	for i := range entries {
		entry := &entries[i]
		if entry.Operation == "review.worker_submit_refused" && entry.Status == "failed" && entry.Parameters["code"] == wantCode {
			n++
		}
	}
	return n
}

// T1: a review run token bound to a platform-attached execution answers a
// worker request: 201, one row in each table, reviewer facts from the
// token's execution provenance, an audit row, and the independent gate PASS.
// The token is minted through the real exchange and resolved by the store.
func TestSubmitWorkerReview_HappyPath(t *testing.T) {
	e := newReviewWorkerEnv(t)
	ctx := context.Background()
	reviewerExec := e.platformExecution()
	b := &fakeBinder{binding: &k8s.AgentRunBinding{
		Agent: "review-worker", Scope: auth.AgentScopeReview, ExecutionID: reviewerExec,
		Namespace: "argo-workflows", ServiceAccount: "mctl-agents-runner", Pod: "rv-1-pod", Workflow: "rv-1",
		Template: "mctl-agents-review", Deadline: time.Now().Add(30 * time.Minute),
	}}
	e.h.opts.AgentRunBinder = b
	e.router.Post("/api/v1/agent-run-tokens/exchange", e.h.ExchangeAgentRunToken)
	minted := e.exchange("sa-token", nil)
	if minted.code != http.StatusCreated {
		t.Fatalf("exchange = %d %s", minted.code, minted.raw)
	}
	run, err := e.h.opts.WorkItems.ResolveAgentRunToken(ctx, minted.body["token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	u := auth.NewAgentUser(run.Agent, *run)

	req := e.ingest(reviewreceipts.ModeWorker)
	res := e.submit(u, workerBody(req))
	if res.code != http.StatusCreated {
		t.Fatalf("submit = %d %s", res.code, res.raw)
	}
	p := e.provenance(reviewerExec)
	doc, _ := res.body["receipt"].(map[string]any)
	if res.body["mode"] != "worker" || res.body["assurance"] != "independent" || res.body["request_id"] != req.RequestID ||
		doc["reviewer_actor"] != "agent:review-worker" || doc["reviewer_execution_id"] != reviewerExec ||
		doc["attempt_id"] != p.AttemptID || doc["lineage_root"] != p.LineageRoot {
		t.Fatalf("receipt = %s, want the token execution's facts %+v", res.raw, p)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("%d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
	found := false
	for _, entry := range e.audit.List(10000) {
		if entry.Operation == "review.worker_submit" && entry.Status == "succeeded" &&
			entry.Parameters["execution_id"] == reviewerExec && entry.Parameters["request_id"] == req.RequestID &&
			entry.Parameters["run_id"] == run.RunID && entry.Parameters["receipt_id"] == res.body["receipt_id"] {
			found = true
		}
	}
	if !found {
		t.Error("no review.worker_submit audit row naming the run, execution, request and receipt")
	}

	sr, pool, err := e.reviews.GateInput(ctx, req.Subject)
	if err != nil || sr == nil {
		t.Fatalf("GateInput: %v %v", sr, err)
	}
	if v, err := reviewreceipts.EvaluateReviewGate(&req.Subject, &sr.Request, pool, reviewreceipts.AssuranceIndependent); err != nil || v != reviewreceipts.GateSatisfied {
		t.Fatalf("gate = %s %v, want %s", v, err, reviewreceipts.GateSatisfied)
	}

	// The provenance read route exposes the recorded eligibility facts.
	pr := e.do(adminUser(), "GET", "/api/v1/executions/"+reviewerExec+"/provenance", nil)
	if pr.code != http.StatusOK || !strings.Contains(pr.raw, `"attach_path":"attach"`) || !strings.Contains(pr.raw, `"attached_direct_service":true`) {
		t.Fatalf("provenance read = %d %s", pr.code, pr.raw)
	}
}

// failOnRead is a request body that fails the test if anything reads it.
type failOnRead struct{ t *testing.T }

func (f failOnRead) Read([]byte) (int, error) {
	f.t.Error("the request body was read")
	return 0, io.EOF
}

func (failOnRead) Close() error { return nil }

// T2: with the flag off every caller, a valid review run included, gets 501
// and the body is never touched.
func TestSubmitWorkerReview_DisabledNeverReadsTheBody(t *testing.T) {
	for name, u := range map[string]*auth.User{
		"admin":      adminUser(),
		"review run": reviewRun("we_" + uuid.NewString()),
		"service":    auth.NewServiceUser(),
	} {
		router := NewRouter(Options{AuthMiddleware: injectUser(u), ReviewStore: &reviewstore.Store{}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/review-receipts", nil)
		req.Body = failOnRead{t}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented || bodyCode(rec) != codeReviewWorkerIngestDisabled {
			t.Errorf("%s: %d %s, want 501 %s", name, rec.Code, rec.Body.String(), codeReviewWorkerIngestDisabled)
		}
	}
}

// T3: only an execution-bound review run token reaches the store. Each
// mutation of the credential is 403 review_run_token_required with nothing
// stored and a refusal audit row. The agent cases are bound to an ELIGIBLE
// execution, so only the token check can stop them.
func TestSubmitWorkerReview_NeedsAnExecutionBoundReviewToken(t *testing.T) {
	e := newReviewWorkerEnv(t)
	req := e.ingest(reviewreceipts.ModeWorker)
	eligible := e.platformExecution()
	surface := auth.NewSurfaceUser("telegram")
	cases := map[string]*auth.User{
		"human admin":           adminUser(),
		"service principal":     auth.NewServiceUser(),
		"surface":               surface,
		"surface-relayed admin": auth.NewRelayedUser("root", []string{"admins"}, surface),
		"investigate agent": auth.NewAgentUser("review-worker", auth.AgentRun{
			Scope: auth.AgentScopeInvestigate, ExecutionID: eligible, WorkItemID: "wi_x", RunID: "art_inv"}),
		"unscoped agent":         auth.NewAgentUser("review-worker", auth.AgentRun{ExecutionID: eligible, RunID: "art_unscoped"}),
		"review without exec":    auth.NewAgentUser("review-worker", auth.AgentRun{Scope: auth.AgentScopeReview, RunID: "art_unbound"}),
		"review, not we_ id":     auth.NewAgentUser("review-worker", auth.AgentRun{Scope: auth.AgentScopeReview, ExecutionID: "ex-0123456789abcdef"}),
		"review, malformed we_ ": auth.NewAgentUser("review-worker", auth.AgentRun{Scope: auth.AgentScopeReview, ExecutionID: "we_NOTHEX"}),
	}
	raw, _ := json.Marshal(workerBody(req))
	for name, u := range cases {
		// The handler's own check, without the router's gates in front.
		hreq := httptest.NewRequest(http.MethodPost, "/api/v1/review-receipts", bytes.NewReader(raw))
		hreq = hreq.WithContext(auth.WithUser(hreq.Context(), u))
		rec := httptest.NewRecorder()
		before := e.refusalAudits(codeReviewRunTokenRequired)
		e.h.SubmitWorkerReview(rec, hreq)
		e.wantRefused(name, wiResponse{code: rec.Code, raw: rec.Body.String(), body: recorderBody(rec)}, http.StatusForbidden, codeReviewRunTokenRequired, req.RequestID)
		if got := e.refusalAudits(codeReviewRunTokenRequired); got != before+1 {
			t.Errorf("%s: %d new refusal audit row(s), want 1", name, got-before)
		}
	}
	// Through the gated route an investigate token is stopped by its scope
	// before the handler; still a 403 and still nothing stored.
	res := e.submit(cases["investigate agent"], workerBody(req))
	if res.code != http.StatusForbidden {
		t.Errorf("investigate token through the gate: %d %s, want 403", res.code, res.raw)
	}
	if r, c := e.rows(req.RequestID); r != 0 || c != 0 {
		t.Errorf("gate refusal wrote %d/%d rows", r, c)
	}
}

func recorderBody(rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m
}

// T4: reviewer identity is never caller-asserted. Each such key, even with
// otherwise valid content, is 400 review_unknown_key and stores nothing.
func TestSubmitWorkerReview_RefusesCallerAssertedIdentity(t *testing.T) {
	e := newReviewWorkerEnv(t)
	req := e.ingest(reviewreceipts.ModeWorker)
	u := reviewRun(e.platformExecution())
	other := e.platformExecution()
	for key, value := range map[string]any{
		"reviewer_execution_id": other,
		"attempt_id":            e.provenance(other).AttemptID,
		"lineage_root":          e.provenance(other).LineageRoot,
		"reviewer_actor":        "agent:someone-else",
		"assurance":             "independent",
		"mode":                  "worker",
		"tenant":                e.tenant,
		"created_at":            "2026-01-01T00:00:00Z",
	} {
		body := workerBody(req)
		body[key] = value
		before := e.refusalAudits(reviewreceipts.CodeUnknownKey)
		e.wantRefused(key, e.submit(u, body), http.StatusBadRequest, reviewreceipts.CodeUnknownKey, req.RequestID)
		// The audit row names the code the caller was answered.
		if got := e.refusalAudits(reviewreceipts.CodeUnknownKey); got != before+1 {
			t.Errorf("%s: %d new review_unknown_key audit row(s), want 1", key, got-before)
		}
	}
	// Trailing data and a malformed body are refused too.
	raw, _ := json.Marshal(workerBody(req))
	malformed := e.refusalAudits(reviewreceipts.CodeMalformed)
	e.wantRefused("trailing data", e.submit(u, string(raw)+`{}`), http.StatusBadRequest, reviewreceipts.CodeMalformed, req.RequestID)
	e.wantRefused("not JSON", e.submit(u, "{"), http.StatusBadRequest, reviewreceipts.CodeMalformed, req.RequestID)
	if got := e.refusalAudits(reviewreceipts.CodeMalformed); got != malformed+2 {
		t.Errorf("%d new review_malformed audit row(s), want 2", got-malformed)
	}
	// The same body without the extra key is accepted: the refusals above
	// are the key check, not a broken body.
	if res := e.submit(u, workerBody(req)); res.code != http.StatusCreated {
		t.Fatalf("clean body = %d %s", res.code, res.raw)
	}
}

// T6, T8, T10-T13 at the HTTP layer: each refusal's status and code, with
// nothing stored. Developer attach and developer resume go through the real
// work-item routes, so attached_direct_service is written by mutationFor.
func TestSubmitWorkerReview_Refusals(t *testing.T) {
	e := newReviewWorkerEnv(t)
	ctx := context.Background()
	alice, svc := e.user("alice"), auth.NewServiceUser()

	// T10: a developer attach ...
	devItem := e.open(alice, nil)["id"].(string)
	devAttached := e.attachExecution(alice, devItem, "run-dev", "Running")
	// ... and a developer resume.
	resItem := e.open(alice, nil)["id"].(string)
	e.attachExecution(svc, resItem, "run-r1", "Running")
	e.do(alice, "PATCH", "/api/v1/work-items/"+resItem, map[string]any{"action": "wait", "waiting_reason": "input", "expected_state_version": 1})
	if res := e.do(svc, "POST", "/api/v1/work-items/"+resItem+"/executions", map[string]any{"engine": "temporal", "engine_ref": "run-r1", "phase": "Failed"}); res.code != http.StatusOK {
		t.Fatalf("finish run-r1 = %d %s", res.code, res.raw)
	}
	resumed := e.do(alice, "POST", "/api/v1/work-items/"+resItem+"/resume",
		map[string]any{"expected_state_version": 2, "engine": "temporal", "engine_ref": "run-r2"}, "Idempotency-Key", "rv-"+uuid.NewString())
	if resumed.code != http.StatusCreated {
		t.Fatalf("developer resume = %d %s", resumed.code, resumed.raw)
	}
	devResumed := resumed.body["execution"].(map[string]any)["id"].(string)

	req := e.ingest(reviewreceipts.ModeWorker)
	for name, exec := range map[string]string{"developer attach": devAttached, "developer resume": devResumed} {
		if p := e.provenance(exec); p.AttachedDirectService {
			t.Fatalf("%s recorded attached_direct_service=true: %+v", name, p)
		}
		e.wantRefused(name, e.submit(reviewRun(exec), workerBody(req)), http.StatusForbidden, codeReviewReviewerIneligible, req.RequestID)
	}

	eligible := e.platformExecution()
	// T8: nonce mismatch.
	bad := workerBody(req)
	bad["nonce"] = "nonce-wrong"
	e.wantRefused("nonce mismatch", e.submit(reviewRun(eligible), bad), http.StatusForbidden, codeReviewNonceMismatch, req.RequestID)
	// T11: the authoring execution reviewing itself.
	e.wantRefused("reviewer is the author", e.submit(reviewRun(e.author), workerBody(req)), http.StatusConflict, codeReviewNotIndependent, req.RequestID)
	// T11: the reviewer actor is an author.
	byAuthor := e.ingest(reviewreceipts.ModeWorker, "agent:review-worker")
	e.wantRefused("reviewer actor is an author", e.submit(reviewRun(eligible), workerBody(byAuthor)), http.StatusConflict, codeReviewNotIndependent, byAuthor.RequestID)
	// T13: manual-mode request, binding mismatch, unknown request.
	manual := e.ingest(reviewreceipts.ModeManual)
	e.wantRefused("manual-mode request", e.submit(reviewRun(eligible), workerBody(manual)), http.StatusConflict, codeReviewRequestModeManual, manual.RequestID)
	mismatch := workerBody(req)
	subj := req.Subject
	subj.ContentDigest = "sha256:" + strings.Repeat("c", 64)
	mismatch["subject"] = subj.Dict()
	e.wantRefused("binding mismatch", e.submit(reviewRun(eligible), mismatch), http.StatusConflict, codeReviewBindingMismatch, req.RequestID)
	unknown := workerBody(req)
	unknown["request_id"] = "rr_0000000000000000"
	e.wantRefused("unknown request", e.submit(reviewRun(eligible), unknown), http.StatusNotFound, codeReviewRequestNotFound, req.RequestID)

	// T12: absent provenance, provenance unreadable, provenance not wired.
	e.wantRefused("absent provenance", e.submit(reviewRun("we_"+uuid.NewString()), workerBody(req)), http.StatusForbidden, codeReviewExecutionUnproven, req.RequestID)
	e.reviews.SetProvenance(brokenProvenance{})
	e.wantRefused("provenance unreadable", e.submit(reviewRun(eligible), workerBody(req)), http.StatusServiceUnavailable, codeReviewProvenanceUnavail, req.RequestID)
	e.reviews.SetProvenance(nil)
	e.wantRefused("provenance not wired", e.submit(reviewRun(eligible), workerBody(req)), http.StatusServiceUnavailable, codeReviewProvenanceUnavail, req.RequestID)
	e.reviews.SetProvenance(e.h.opts.WorkItems)

	// Every refusal above was audited with its code.
	for _, c := range []string{codeReviewReviewerIneligible, codeReviewNonceMismatch, codeReviewNotIndependent,
		codeReviewRequestModeManual, codeReviewBindingMismatch, codeReviewRequestNotFound, codeReviewExecutionUnproven, codeReviewProvenanceUnavail} {
		if e.refusalAudits(c) == 0 {
			t.Errorf("no review.worker_submit_refused audit row with code %s", c)
		}
	}

	// T6: the first valid submit wins, the replay is 409 and adds nothing.
	if res := e.submit(reviewRun(eligible), workerBody(req)); res.code != http.StatusCreated {
		t.Fatalf("valid submit = %d %s", res.code, res.raw)
	}
	if res := e.submit(reviewRun(eligible), workerBody(req)); res.code != http.StatusConflict || code(res) != codeReviewNonceConsumed {
		t.Fatalf("replay = %d %s, want 409 %s", res.code, res.raw, codeReviewNonceConsumed)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("after replay: %d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
	_ = ctx
}

// T9 and T12 (store errors): a receipt INSERT that fails after the nonce
// INSERT rolls the consumption back, and a database error on the nonce
// INSERT itself, each answer 503 review_store_unavailable with nothing
// stored.
func TestSubmitWorkerReview_StoreFailuresAre503AndAtomic(t *testing.T) {
	e := newReviewWorkerEnv(t)
	ctx := context.Background()
	eligible := e.platformExecution()
	p := e.provenance(eligible)

	req := e.ingest(reviewreceipts.ModeWorker)
	body := workerBody(req)
	criteria := []reviewreceipts.Criterion{}
	for _, c := range body["criteria"].([]map[string]any) {
		criteria = append(criteria, reviewreceipts.Criterion{ID: c["id"].(string), Status: c["status"].(string)})
	}
	rc, err := reviewreceipts.SealReceipt(req, reviewreceipts.SealReceiptInput{
		Outcome: "PASS", Criteria: criteria, ReviewerActor: "agent:review-worker",
		ReviewerExecutionID: eligible, AttemptID: p.AttemptID, LineageRoot: p.LineageRoot, CreatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(rc.Dict())
	host := e.ingest(reviewreceipts.ModeWorker)
	if _, err := e.pool.Exec(ctx, `INSERT INTO review_receipts (receipt_id, request_id, content_hash, document, mode, assurance, tenant, submitted_by, submitted_at)
VALUES ($1, $2, $3, $4, 'worker', 'independent', $5, 'seed', now())`, rc.ReceiptID, host.RequestID, rc.ContentHash, doc, e.tenant); err != nil {
		t.Fatalf("seed colliding receipt: %v", err)
	}
	e.wantRefused("receipt insert fails", e.submit(reviewRun(eligible), body), http.StatusServiceUnavailable, codeReviewStoreUnavailable, req.RequestID)

	other := e.ingest(reviewreceipts.ModeWorker)
	name := "t917_api_" + strings.TrimPrefix(other.RequestID, "rr_")
	for _, q := range []string{
		`CREATE OR REPLACE FUNCTION ` + name + `() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected evidence DB failure'; END; $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON review_nonce_consumptions FOR EACH ROW WHEN (NEW.request_id = '` + other.RequestID + `') EXECUTE FUNCTION ` + name + `()`,
	} {
		if _, err := e.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+name+` ON review_nonce_consumptions`)
		_, _ = e.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+name+`()`)
	})
	e.wantRefused("nonce insert fails", e.submit(reviewRun(eligible), workerBody(other)), http.StatusServiceUnavailable, codeReviewStoreUnavailable, other.RequestID)
	if e.refusalAudits(codeReviewStoreUnavailable) != 2 {
		t.Errorf("store failures audited %d time(s), want 2", e.refusalAudits(codeReviewStoreUnavailable))
	}
}

// Minting: a review token must be bound to an execution. The pod exchange
// is the only path that can ask for an unbound token, and it is refused
// for the review scope (and audited); bound, the same exchange succeeds.
func TestReviewScopeMint_RequiresAnExecution(t *testing.T) {
	e, b, execID := exchangeEnv(t)
	b.binding.Agent, b.binding.Scope, b.binding.ExecutionID = "review-worker", auth.AgentScopeReview, ""
	res := e.exchange("sa-token", nil)
	if res.code != http.StatusBadRequest || code(res) != artCodeExecutionRequired {
		t.Fatalf("unbound review exchange = %d %s, want 400 %s", res.code, res.raw, artCodeExecutionRequired)
	}
	if n := e.auditOpCount("agent_run_token.exchange_refused", artCodeExecutionRequired); n != 1 {
		t.Errorf("%d refusal audit row(s), want 1", n)
	}
	b.binding.ExecutionID = execID
	if res := e.exchange("sa-token", nil); res.code != http.StatusCreated || res.body["scope"] != auth.AgentScopeReview || res.body["execution_id"] != execID {
		t.Fatalf("bound review exchange = %d %s", res.code, res.raw)
	}
	// The scope is not for any other agent.
	if res := e.mintRunToken(auth.NewServiceUser(), map[string]any{"agent": "implementer", "scope": auth.AgentScopeReview, "execution_id": execID}); res.code != http.StatusBadRequest || code(res) != artCodeScopeNotForAgent {
		t.Fatalf("review scope for implementer = %d %s", res.code, res.raw)
	}
}

// Task 1: ActorDirectService is true only for the service principal acting
// directly.
func TestMutationFor_ActorDirectService(t *testing.T) {
	surface := auth.NewSurfaceUser("telegram")
	for name, c := range map[string]struct {
		u    *auth.User
		want bool
	}{
		"direct service":       {auth.NewServiceUser(), true},
		"human":                {auth.NewGitHubUser("alice", []string{"acme"}), false},
		"human admin":          {adminUser(), false},
		"relayed via surface":  {auth.NewRelayedUser("root", []string{"admins"}, surface), false},
		"surface":              {surface, false},
		"agent run":            {auth.NewAgentUser("review-worker", auth.AgentRun{Scope: auth.AgentScopeReview, ExecutionID: "we_1"}), false},
		"evidence writer":      {auth.NewEvidenceWriterUser(), false},
		"unscoped agent (svc)": {auth.NewAgentUser("mctl-agent", auth.AgentRun{ExecutionID: "we_1"}), false},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/work-items/wi_x/executions", nil)
		m, ok := mutationFor(httptest.NewRecorder(), req, c.u, "attach", "wi_x", "", "", nil)
		if !ok {
			t.Fatalf("%s: mutationFor refused", name)
		}
		if m.ActorDirectService != c.want {
			t.Errorf("%s: ActorDirectService = %v, want %v", name, m.ActorDirectService, c.want)
		}
	}
}
