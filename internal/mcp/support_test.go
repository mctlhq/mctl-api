package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/auth"
)

const (
	testToken      = "caller-token-123"
	wantAnswerText = "example-app is crash looping because of a bad config value.\n- Fix the config value.\n- Redeploy example-app."
	wantSummary    = "example-app is crash looping because of a bad config value."
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/support/" + name) //nolint:gosec // fixed test fixture names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureTask(t *testing.T, name string) *a2aTask {
	t.Helper()
	var tk a2aTask
	if err := json.Unmarshal(fixture(t, name), &tk); err != nil {
		t.Fatal(err)
	}
	return &tk
}

type recorded struct {
	method, path, auth, version string
	body                        []byte
}

type fakeSupport struct {
	mu   sync.Mutex
	reqs []recorded
	srv  *httptest.Server
}

func (f *fakeSupport) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if method == "" || r.method == method {
			n++
		}
	}
	return n
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request, n int)) *fakeSupport {
	t.Helper()
	f := &fakeSupport{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("A2A-Version"), b})
		n := len(f.reqs)
		f.mu.Unlock()
		h(w, r, n)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func writeFixture(t *testing.T, w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(fixture(t, name))
}

const mintedToken = "minted-support-token-456"

type fakeMinter struct {
	mu    sync.Mutex
	err   error
	calls []time.Duration
}

func (m *fakeMinter) IssueSupportToken(u *auth.User, ttl time.Duration) (auth.SupportToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, ttl)
	if m.err != nil {
		return auth.SupportToken{}, m.err
	}
	return auth.SupportToken{Token: mintedToken, JTI: "jti-1", Audience: "https://support.example", ExpiresAt: time.Now().Add(ttl)}, nil
}

type fakeMintAuditor struct {
	mu   sync.Mutex
	recs []SupportTokenMintRecord
}

func (a *fakeMintAuditor) AuditSupportTokenMint(_ context.Context, rec SupportTokenMintRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recs = append(a.recs, rec)
}

func withMint(s *Server) (*fakeMinter, *fakeMintAuditor) {
	m, a := &fakeMinter{}, &fakeMintAuditor{}
	s.SetSupportTokenMinter(m)
	s.SetSupportTokenAuditor(a)
	return m, a
}

func supportServer(f *fakeSupport, wait time.Duration) *Server {
	s := NewServer("http://127.0.0.1:1", "")
	s.SetSupportConfig(SupportConfig{BaseURL: f.srv.URL, Wait: wait, PollInterval: 10 * time.Millisecond, RequestTimeout: 500 * time.Millisecond})
	withMint(s)
	withMint(s)
	return s
}

func memberCtx(tenant string) context.Context {
	ctx := auth.WithUser(context.Background(), &auth.User{ID: "u", Groups: []string{tenant}})
	return auth.WithToken(ctx, testToken)
}

func callSupportTool(t *testing.T, ctx context.Context, h func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error), args map[string]any) (string, bool) {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res.Content[0].(mcplib.TextContent).Text, res.IsError
}

func ask(t *testing.T, s *Server, ctx context.Context, extra map[string]any) (string, bool) {
	_, h := s.toolAskSupport()
	args := map[string]any{"tenant": "example-tenant", "question": "Why is example-app failing?"}
	for k, v := range extra {
		args[k] = v
	}
	return callSupportTool(t, ctx, h, args)
}

func decodeAnswer(t *testing.T, text string) supportAnswer {
	t.Helper()
	var a supportAnswer
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatalf("not an answer: %v\n%s", err, text)
	}
	return a
}

func wantMainAnswer(t *testing.T, a supportAnswer) {
	t.Helper()
	if a.AnswerSource != "status_message" || a.Text != wantAnswerText || a.State != "COMPLETED" || !a.Terminal {
		t.Fatalf("answer = %+v", a)
	}
	var res map[string]any
	if err := json.Unmarshal(a.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res["summary"] != wantSummary || len(res) != 6 || len(a.AdditionalData) != 0 {
		t.Fatalf("result = %s", a.Result)
	}
	if strings.Contains(string(a.Result)+a.Text, "Why is example-app failing in") {
		t.Fatal("history leaked into the answer")
	}
}

func completedFlow(t *testing.T, completed string) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		switch {
		case r.Method == http.MethodPost:
			writeFixture(t, w, "send_task_submitted.json")
		case n == 2:
			writeFixture(t, w, "task_working.json")
		default:
			writeFixture(t, w, completed)
		}
	}
}

func TestAskSupport_RequestShapeAndParity(t *testing.T) { // T4, T5, T21
	f := newFake(t, completedFlow(t, "task_completed_status_message.json"))
	text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), map[string]any{"context_id": "ctx-1"})
	if isErr {
		t.Fatal(text)
	}
	a := decodeAnswer(t, text)
	wantMainAnswer(t, a)

	if f.count("POST") != 1 {
		t.Fatalf("POST count = %d", f.count("POST"))
	}
	post := f.reqs[0]
	if post.path != "/message:send" || post.version != "1.0" || post.auth != "Bearer "+mintedToken {
		t.Fatalf("send headers: %+v", post)
	}
	if strings.Contains(string(post.body), "blocking") {
		t.Fatal("blocking key in body")
	}
	var body struct {
		Message struct {
			MessageID string           `json:"messageId"`
			Role      string           `json:"role"`
			ContextID string           `json:"contextId"`
			Parts     []map[string]any `json:"parts"`
			Metadata  any              `json:"metadata"`
		} `json:"message"`
		Configuration map[string]any `json:"configuration"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(post.body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Metadata["tenant"] != "example-tenant" || body.Message.Metadata != nil ||
		body.Configuration["returnImmediately"] != true || body.Message.Role != "ROLE_USER" ||
		body.Message.MessageID == "" || body.Message.ContextID != "ctx-1" ||
		body.Message.Parts[0]["text"] != "Why is example-app failing?" {
		t.Fatalf("body = %s", post.body)
	}

	// Parity with a direct GET decoded without the tool.
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/tasks/x", nil)
	req.Header.Set("Authorization", "Bearer "+mintedToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var direct a2aTask
	if err := json.NewDecoder(resp.Body).Decode(&direct); err != nil {
		t.Fatal(err)
	}
	want, err := renderSupportAnswer(&direct, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got, wantRes bytes.Buffer
	if err := json.Compact(&got, a.Result); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&wantRes, want.Result); err != nil {
		t.Fatal(err)
	}
	if a.Text != want.Text || got.String() != wantRes.String() || a.AnswerSource != want.AnswerSource {
		t.Fatalf("tool %+v != direct %+v", a, want)
	}
}

func TestAskSupport_TenantRefusal(t *testing.T) { // T1, T3
	f := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
	s := supportServer(f, time.Second)
	text, isErr := ask(t, s, memberCtx("other-tenant"), nil)
	if !isErr || !strings.Contains(text, "tenant_forbidden") || f.count("") != 0 {
		t.Fatalf("got %q err=%v reqs=%d", text, isErr, f.count(""))
	}

	for _, status := range []int{200, 500} {
		whoami := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status != 200 {
				http.Error(w, "boom", status)
				return
			}
			_, _ = w.Write([]byte(`{"groups":["other-tenant"],"isAdmin":false}`))
		}))
		st := NewServer(whoami.URL, testToken)
		st.SetSupportConfig(SupportConfig{BaseURL: f.srv.URL, Wait: time.Second})
		text, isErr := ask(t, st, context.Background(), nil)
		whoami.Close()
		if !isErr || f.count("") != 0 {
			t.Fatalf("stdio status %d: %q err=%v reqs=%d", status, text, isErr, f.count(""))
		}
	}
}

func TestAskSupport_NoTokenAndValidation(t *testing.T) { // T10
	f := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
	s := supportServer(f, time.Second)
	if _, isErr := ask(t, s, context.Background(), nil); !isErr {
		t.Fatal("no caller must be refused")
	}
	for _, extra := range []map[string]any{
		{"question": ""}, {"question": strings.Repeat("x", supportMaxQuestion+1)},
		{"tenant": "a/b"}, {"context_id": 5},
	} {
		if _, isErr := ask(t, s, memberCtx("example-tenant"), extra); !isErr {
			t.Errorf("%v accepted", extra)
		}
	}
	_, h := s.toolGetSupportTask()
	for _, id := range []string{"", "..", "a/b"} {
		if _, isErr := callSupportTool(t, memberCtx("x"), h, map[string]any{"id": id}); !isErr {
			t.Errorf("id %q accepted", id)
		}
	}
	if f.count("") != 0 {
		t.Fatalf("upstream contacted %d times", f.count(""))
	}
}

func TestAskSupport_NotConfigured(t *testing.T) { // T11
	s := NewServer("http://127.0.0.1:1", "")
	if text, isErr := ask(t, s, memberCtx("example-tenant"), nil); !isErr || !strings.Contains(text, "not configured") {
		t.Fatal(text)
	}
	_, h := s.toolGetSupportTask()
	if text, isErr := callSupportTool(t, memberCtx("example-tenant"), h, map[string]any{"id": "x"}); !isErr || !strings.Contains(text, "not configured") {
		t.Fatal(text)
	}
}

func TestAskSupport_Refusal403(t *testing.T) { // T2
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"tenant not allowed"}`))
	})
	text, isErr := ask(t, supportServer(f, time.Second), memberCtx("example-tenant"), nil)
	if !isErr || !strings.Contains(text, "403") || strings.Contains(text, "support_send_outcome_unknown") {
		t.Fatal(text)
	}
}

func TestAskSupport_TerminalFailuresAndInterrupted(t *testing.T) { // T7, T9
	for fx, want := range map[string]string{
		"task_failed.json":   "example reason",
		"task_rejected.json": "example reason",
		"task_canceled.json": "example reason",
	} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
			if r.Method == http.MethodPost {
				writeFixture(t, w, "send_task_submitted.json")
				return
			}
			writeFixture(t, w, fx)
		})
		text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
		if !isErr || !strings.Contains(text, want) {
			t.Errorf("%s: %q err=%v", fx, text, isErr)
		}
	}
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		writeFixture(t, w, "task_input_required.json")
	})
	text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
	a := decodeAnswer(t, text)
	if isErr || a.State != "INPUT_REQUIRED" || !strings.Contains(a.Reason, "environment") || a.ContextID == "" || f.count("GET") != 1 {
		t.Fatalf("%q err=%v gets=%d", text, isErr, f.count("GET"))
	}
}

func TestAskSupport_TimeoutThenGet(t *testing.T) { // T6
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		writeFixture(t, w, "task_working.json")
	})
	s := supportServer(f, 150*time.Millisecond)
	text, isErr := ask(t, s, memberCtx("example-tenant"), nil)
	a := decodeAnswer(t, text)
	if isErr || a.Terminal || a.TaskID == "" || !strings.Contains(a.Note, "mctl_get_support_task") {
		t.Fatalf("%q err=%v", text, isErr)
	}

	g := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Path != "/tasks/abc" {
			t.Errorf("path %s", r.URL.Path)
		}
		writeFixture(t, w, "task_completed_status_message.json")
	})
	_, h := supportServer(g, time.Second).toolGetSupportTask()
	text, isErr = callSupportTool(t, memberCtx("example-tenant"), h, map[string]any{"id": "abc"})
	if isErr {
		t.Fatal(text)
	}
	wantMainAnswer(t, decodeAnswer(t, text))
	if g.reqs[0].auth != "Bearer "+mintedToken || g.reqs[0].version != "1.0" {
		t.Fatalf("%+v", g.reqs[0])
	}
}

func TestAskSupport_FailureIsNotAbsence(t *testing.T) { // T8, T24, T25
	// Send failures: unknown outcome, one POST, no GET, no resend.
	sends := map[string]func(http.ResponseWriter, *http.Request, int){
		"502":      func(w http.ResponseWriter, r *http.Request, n int) { w.WriteHeader(502) },
		"garbage":  func(w http.ResponseWriter, r *http.Request, n int) { _, _ = w.Write([]byte("not json")) },
		"neither":  func(w http.ResponseWriter, r *http.Request, n int) { _, _ = w.Write([]byte(`{"x":1}`)) },
		"deadline": func(w http.ResponseWriter, r *http.Request, n int) { time.Sleep(400 * time.Millisecond) },
	}
	for name, h := range sends {
		f := newFake(t, h)
		start := time.Now()
		text, isErr := ask(t, supportServer(f, 200*time.Millisecond), memberCtx("example-tenant"), nil)
		if !isErr || !strings.Contains(text, "support_send_outcome_unknown") || !strings.Contains(text, "message ") ||
			f.count("POST") != 1 || f.count("GET") != 0 {
			t.Errorf("%s: %q posts=%d gets=%d", name, text, f.count("POST"), f.count("GET"))
		}
		if name == "deadline" && time.Since(start) > 350*time.Millisecond {
			t.Errorf("send outlived the budget: %s", time.Since(start))
		}
	}
	// Connection refused on send.
	dead := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
	s := supportServer(dead, time.Second)
	dead.srv.Close()
	if text, isErr := ask(t, s, memberCtx("example-tenant"), nil); !isErr || !strings.Contains(text, "support_send_outcome_unknown") {
		t.Errorf("refused: %q", text)
	}

	// Poll failures with a known id.
	for _, code := range []int{503, 429} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
			switch {
			case r.Method == http.MethodPost:
				writeFixture(t, w, "send_task_submitted.json")
			case n == 2:
				w.WriteHeader(code)
			default:
				writeFixture(t, w, "task_completed_status_message.json")
			}
		})
		text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
		if isErr {
			t.Fatalf("%d: %s", code, text)
		}
		wantMainAnswer(t, decodeAnswer(t, text))
	}
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"404":  func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) },
		"text": nil,
	} {
		if h == nil {
			continue
		}
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
			if r.Method == http.MethodPost {
				writeFixture(t, w, "send_task_submitted.json")
				return
			}
			h(w, r)
		})
		text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
		if !isErr || !strings.Contains(text, "00000000-0000-4000-8000-000000000001") || f.count("GET") != 1 {
			t.Errorf("%s: %q gets=%d", name, text, f.count("GET"))
		}
	}
	// Persistent 500 and non-task bodies on poll end in a tool error naming the task.
	for _, h := range []func(http.ResponseWriter){
		func(w http.ResponseWriter) { w.WriteHeader(500) },
		func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) },
		func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"hello":"world"}`)) },
	} {
		h := h
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
			if r.Method == http.MethodPost {
				writeFixture(t, w, "send_task_submitted.json")
				return
			}
			h(w)
		})
		text, isErr := ask(t, supportServer(f, 200*time.Millisecond), memberCtx("example-tenant"), nil)
		if !isErr || !strings.Contains(text, "00000000-0000-4000-8000-000000000001") {
			t.Errorf("%q err=%v", text, isErr)
		}
	}
}

func TestAskSupport_RedirectNotFollowed(t *testing.T) { // T8
	target := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		http.Redirect(w, r, target.srv.URL+"/x", http.StatusFound)
	})
	text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
	if !isErr || !strings.Contains(text, "00000000-0000-4000-8000-000000000001") || f.count("GET") != 1 || target.count("") != 0 {
		t.Fatalf("%q gets=%d target=%d", text, f.count("GET"), target.count(""))
	}
}

func TestAskSupport_SharedBudget(t *testing.T) { // T22
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			time.Sleep(200 * time.Millisecond)
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		writeFixture(t, w, "task_working.json")
	})
	start := time.Now()
	text, isErr := ask(t, supportServer(f, 300*time.Millisecond), memberCtx("example-tenant"), nil)
	if el := time.Since(start); el > 420*time.Millisecond {
		t.Fatalf("took %s, polling got a fresh budget", el)
	}
	if isErr || decodeAnswer(t, text).Terminal {
		t.Fatalf("%q err=%v", text, isErr)
	}
}

func TestAskSupport_BlockingServerAndDirectMessage(t *testing.T) { // T23
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"task":` + string(fixture(t, "task_completed_status_message.json")) + `}`))
	})
	text, isErr := ask(t, supportServer(f, time.Second), memberCtx("example-tenant"), nil)
	if isErr {
		t.Fatal(text)
	}
	wantMainAnswer(t, decodeAnswer(t, text))
	if f.count("GET") != 0 {
		t.Fatal("polled a terminal send reply")
	}

	m := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { writeFixture(t, w, "send_message_reply.json") })
	text, isErr = ask(t, supportServer(m, time.Second), memberCtx("example-tenant"), nil)
	a := decodeAnswer(t, text)
	if isErr || a.TaskID != "" || a.Text != "Direct reply text." || a.AnswerSource != "message" {
		t.Fatalf("%q", text)
	}
}

func TestGetSupportTask_RequestTimeout(t *testing.T) { // T26
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { time.Sleep(600 * time.Millisecond) })
	s := NewServer("http://127.0.0.1:1", "")
	s.SetSupportConfig(SupportConfig{BaseURL: f.srv.URL, Wait: time.Second, RequestTimeout: 100 * time.Millisecond})
	withMint(s)
	_, h := s.toolGetSupportTask()
	start := time.Now()
	text, isErr := callSupportTool(t, memberCtx("x"), h, map[string]any{"id": "task-9"})
	if !isErr || !strings.Contains(text, "task-9") || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("%q after %s", text, time.Since(start))
	}
}

func TestRenderSupportAnswer_Contract(t *testing.T) { // T15-T19
	a, err := renderSupportAnswer(fixtureTask(t, "task_completed_status_message.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMainAnswer(t, a)

	a, err = renderSupportAnswer(fixtureTask(t, "task_completed_artifacts_only.json"), nil)
	if err != nil || a.AnswerSource != "artifacts" || a.Text != "Artifact answer for example-app." || !strings.Contains(string(a.Result), "Artifact summary.") {
		t.Fatalf("%+v %v", a, err)
	}

	a, err = renderSupportAnswer(fixtureTask(t, "task_completed_both_sources.json"), nil)
	if err != nil || a.AnswerSource != "status_message" || a.Text != "Status message answer." ||
		strings.Contains(a.Text+string(a.Result), "must not appear") || !strings.Contains(string(a.Result), "Status message summary.") {
		t.Fatalf("%+v %v", a, err)
	}

	a, err = renderSupportAnswer(fixtureTask(t, "task_completed_multi_text.json"), nil)
	if err != nil || a.Text != "Part one.\nPart three." ||
		string(a.Result) != `{"summary":"First object."}` || len(a.AdditionalData) != 1 || string(a.AdditionalData[0]) != `{"summary":"Second object."}` {
		t.Fatalf("%+v %v", a, err)
	}

	empty := []*a2aTask{
		fixtureTask(t, "task_completed_no_answer.json"),
		{ID: "t", Status: a2aStatus{State: "TASK_STATE_COMPLETED"}},
		{ID: "t", Status: a2aStatus{State: "COMPLETED", Message: &a2aMessage{Parts: []a2aPart{{URL: ptr("https://example.invalid")}, {Raw: json.RawMessage(`"AAAA"`)}}}}},
	}
	for i, tk := range empty {
		if _, err := renderSupportAnswer(tk, nil); err == nil || !strings.Contains(err.Error(), "support_empty_answer") {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestAskSupport_EmptyAnswerIsToolError(t *testing.T) { // T18
	f := newFake(t, completedFlow(t, "task_completed_no_answer.json"))
	text, isErr := ask(t, supportServer(f, 5*time.Second), memberCtx("example-tenant"), nil)
	if !isErr || !strings.HasPrefix(text, "support_empty_answer") || !strings.Contains(text, "00000000-0000-4000-8000-000000000001") {
		t.Fatalf("%q", text)
	}
	g := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeFixture(t, w, "task_completed_no_answer.json")
	})
	_, h := supportServer(g, time.Second).toolGetSupportTask()
	text, isErr = callSupportTool(t, memberCtx("example-tenant"), h, map[string]any{"id": "x"})
	if !isErr || !strings.HasPrefix(text, "support_empty_answer") {
		t.Fatalf("%q", text)
	}
}

func ptr(s string) *string { return &s }

func TestParseSupportConfig(t *testing.T) { // T14
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, err := ParseSupportConfig(env(nil)); err != nil || c.BaseURL != "" {
		t.Fatalf("unset: %+v %v", c, err)
	}
	ok, err := ParseSupportConfig(env(map[string]string{"SUPPORT_A2A_URL": "https://support.example.invalid/"}))
	if err != nil || ok.BaseURL != "https://support.example.invalid" || ok.Wait != 60*time.Second ||
		ok.PollInterval != 2*time.Second || ok.RequestTimeout != 15*time.Second {
		t.Fatalf("defaults: %+v %v", ok, err)
	}
	if _, err := ParseSupportConfig(env(map[string]string{"SUPPORT_A2A_URL": "http://localhost:9"})); err != nil {
		t.Fatalf("loopback http: %v", err)
	}
	bad := []map[string]string{
		{"SUPPORT_A2A_URL": "support.example.invalid"},
		{"SUPPORT_A2A_URL": "http://support.example.invalid"},
		{"SUPPORT_A2A_URL": "https://s.example.invalid", "SUPPORT_ASK_WAIT": "4s"},
		{"SUPPORT_A2A_URL": "https://s.example.invalid", "SUPPORT_ASK_WAIT": "91s"},
		{"SUPPORT_A2A_URL": "https://s.example.invalid", "SUPPORT_ASK_WAIT": "10s", "SUPPORT_REQUEST_TIMEOUT": "11s"},
		{"SUPPORT_A2A_URL": "https://s.example.invalid", "SUPPORT_POLL_INTERVAL": "100ms"},
	}
	for _, m := range bad {
		if _, err := ParseSupportConfig(env(m)); err == nil {
			t.Errorf("%v accepted", m)
		}
	}
}

func TestAskSupport_SupportScopeDenied(t *testing.T) { // T12
	res, ran := runScopeArgs(t, supportCtx(), "mctl_ask_support", map[string]any{"tenant": "labs", "question": "q"})
	if ran || !res.IsError || !strings.Contains(res.Content[0].(mcplib.TextContent).Text, AgentScopeCodeDenied) {
		t.Fatalf("ran=%v res=%+v", ran, res)
	}
}

// The request's own deadline (not the budget) ends the send: still an unknown
// outcome naming the messageId, never a bare context error.
func TestAskSupport_ParentDeadlineDuringSend(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		time.Sleep(300 * time.Millisecond)
		writeFixture(t, w, "send_task_submitted.json")
	})
	ctx, cancel := context.WithTimeout(memberCtx("example-tenant"), 100*time.Millisecond)
	defer cancel()
	text, isErr := ask(t, supportServer(f, time.Second), ctx, nil)
	if !isErr || !strings.HasPrefix(text, "support_send_outcome_unknown: message ") {
		t.Fatalf("%q err=%v", text, isErr)
	}
}

// A client cancellation while polling is returned as the handler's error.
func TestAskSupport_ClientCancelDuringPoll(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		writeFixture(t, w, "task_working.json")
	})
	ctx, cancel := context.WithCancel(memberCtx("example-tenant"))
	time.AfterFunc(100*time.Millisecond, cancel)
	_, h := supportServer(f, time.Second).toolAskSupport()
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tenant": "example-tenant", "question": "q"}
	if res, err := h(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %+v; want context.Canceled", err, res)
	}
}

// The send used the whole budget, so no poll was attempted: the send reply is
// the last successful read and the result is an unfinished task, not an error.
func TestAskSupport_SendUsedBudgetNoPoll(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		writeFixture(t, w, "send_task_submitted.json")
	})
	s := NewServer("http://127.0.0.1:1", "")
	s.SetSupportConfig(SupportConfig{BaseURL: f.srv.URL, Wait: 100 * time.Millisecond, PollInterval: time.Second, RequestTimeout: 500 * time.Millisecond})
	withMint(s)
	text, isErr := ask(t, s, memberCtx("example-tenant"), nil)
	a := decodeAnswer(t, text)
	if isErr || a.Terminal || a.TaskID == "" || a.State != "SUBMITTED" {
		t.Fatalf("%q err=%v", text, isErr)
	}
}

func TestSupport_MintedBearerOnly(t *testing.T) { // T4, T13
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == http.MethodPost {
			writeFixture(t, w, "send_task_submitted.json")
			return
		}
		writeFixture(t, w, "task_completed_status_message.json")
	})
	s := supportServer(f, 2*time.Second)
	m, a := withMint(s)
	text, isErr := ask(t, s, memberCtx("example-tenant"), nil)
	if isErr {
		t.Fatal(text)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) < 2 {
		t.Fatalf("reqs = %d", len(f.reqs))
	}
	for _, r := range f.reqs {
		if r.auth != "Bearer "+mintedToken || strings.Contains(string(r.body), testToken) {
			t.Fatalf("request %s %s carried %q", r.method, r.path, r.auth)
		}
	}
	if strings.Contains(text, testToken) || strings.Contains(text, mintedToken) {
		t.Fatal("a token reached the tool result")
	}
	if len(m.calls) != 1 || m.calls[0] != supportDefaultTokenTTL {
		t.Fatalf("mint calls = %v", m.calls)
	}
	if len(a.recs) != 1 || a.recs[0].Tool != "mctl_ask_support" || a.recs[0].Tenant != "example-tenant" || a.recs[0].JTI == "" {
		t.Fatalf("audit = %+v", a.recs)
	}
}

func TestGetSupportTask_MintedBearerAndTTL(t *testing.T) { // T5
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		writeFixture(t, w, "task_completed_status_message.json")
	})
	s := supportServer(f, time.Second)
	m, a := withMint(s)
	_, h := s.toolGetSupportTask()
	if text, isErr := callSupportTool(t, memberCtx("x"), h, map[string]any{"id": "task-1"}); isErr {
		t.Fatal(text)
	}
	if f.reqs[0].auth != "Bearer "+mintedToken {
		t.Fatalf("auth = %q", f.reqs[0].auth)
	}
	if len(m.calls) != 1 || m.calls[0] != 500*time.Millisecond+60*time.Second {
		t.Fatalf("ttl = %v", m.calls)
	}
	if len(a.recs) != 1 || a.recs[0].Tenant != "" || a.recs[0].Tool != "mctl_get_support_task" {
		t.Fatalf("audit = %+v", a.recs)
	}
}

func TestSupport_MintFailuresFailClosed(t *testing.T) { // T6, T7, T8
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"disabled": {auth.ErrSupportResourceDisabled, "support_audience_not_configured"},
		"refused":  {auth.ErrSupportTokenRefused, "support_token_refused"},
		"other":    {errors.New("boom " + testToken), "support_token_unavailable"},
	} {
		f := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
		s := supportServer(f, time.Second)
		m, _ := withMint(s)
		m.err = tc.err
		text, isErr := ask(t, s, memberCtx("example-tenant"), nil)
		if !isErr || !strings.Contains(text, tc.want) || strings.Contains(text, testToken) || f.count("") != 0 {
			t.Errorf("%s: %q err=%v reqs=%d", name, text, isErr, f.count(""))
		}
		_, h := s.toolGetSupportTask()
		text, isErr = callSupportTool(t, memberCtx("x"), h, map[string]any{"id": "t"})
		if !isErr || !strings.Contains(text, tc.want) || f.count("") != 0 {
			t.Errorf("%s get: %q err=%v reqs=%d", name, text, isErr, f.count(""))
		}
	}
}

func TestSupport_NoMinterOrAuditor(t *testing.T) { // T7
	f := newFake(t, func(http.ResponseWriter, *http.Request, int) {})
	s := NewServer("http://127.0.0.1:1", testToken)
	s.SetSupportConfig(SupportConfig{BaseURL: f.srv.URL})
	s.SetSupportTokenMinter(&fakeMinter{})
	for _, ctx := range []context.Context{memberCtx("example-tenant"), context.Background()} {
		text, isErr := ask(t, s, ctx, nil)
		if !isErr || !strings.Contains(text, "support_token_unavailable") {
			t.Fatalf("%q err=%v", text, isErr)
		}
		_, h := s.toolGetSupportTask()
		if text, isErr = callSupportTool(t, ctx, h, map[string]any{"id": "t"}); !isErr || !strings.Contains(text, "support_token_unavailable") {
			t.Fatalf("%q err=%v", text, isErr)
		}
	}
	if f.count("") != 0 {
		t.Fatal("upstream contacted")
	}
}

func TestParseSupportConfig_TokenTTL(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			switch k {
			case "SUPPORT_A2A_URL":
				return "https://support.example"
			case "SUPPORT_TOKEN_TTL":
				return v
			}
			return ""
		}
	}
	for v, ok := range map[string]bool{"": true, "2m": true, "15m": true, "119s": false, "16m": false, "x": false} {
		cfg, err := ParseSupportConfig(env(v))
		if (err == nil) != ok {
			t.Errorf("%q: err = %v", v, err)
		}
		if v == "" && cfg.TokenTTL != 11*time.Minute {
			t.Errorf("default ttl = %s", cfg.TokenTTL)
		}
	}
}
