package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.temporal.io/api/serviceerror"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// Fixtures sealed by mctl-agents' own seal_request (see
// internal/humaninput/testdata). ascii_single_choice asks github:alice;
// unicode_free_text asks github:alice and telegram:12345. Both name the
// workflow dev-loop-mctlhq-mctl-api-261, run run-1, and expire at
// 2026-09-24T02:00:00Z.
const (
	hiASCII   = "hir-377a93a48528eb13"
	hiUnicode = "hir-accc85063686b5e0"
	hiWF      = "dev-loop-mctlhq-mctl-api-261"
)

func humanInputFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "humaninput", "testdata", name+".json")) //nolint:gosec // fixed test fixture names
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// humanInputGitReader stubs only ListHumanInputRequests; the human-input
// handlers touch no other GitReader method.
type humanInputGitReader struct {
	GitReader
	files []gitops.HumanInputRequestFile
}

func (r *humanInputGitReader) ListHumanInputRequests() ([]gitops.HumanInputRequestFile, error) {
	return r.files, nil
}

func withHumanInputClock(t *testing.T, at string) {
	t.Helper()
	now, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	prev := humanInputNow
	humanInputNow = func() time.Time { return now }
	t.Cleanup(func() { humanInputNow = prev })
}

// newHumanInputHandlers serves the ascii fixture (issue-261) and the
// unicode fixture (issue-262). The workflow is WAITING on the ascii one.
func newHumanInputHandlers(t *testing.T) (*Handlers, *fakeDevLoopClient) {
	t.Helper()
	withHumanInputClock(t, "2026-09-23T12:00:00Z")
	git := &humanInputGitReader{files: []gitops.HumanInputRequestFile{
		{Service: "mctl-api", Proposal: "issue-261-x", Raw: humanInputFixture(t, "ascii_single_choice")},
		{Service: "mctl-api", Proposal: "issue-262-y", Raw: humanInputFixture(t, "unicode_free_text")},
	}}
	tc := &fakeDevLoopClient{humanInputStates: map[string]*temporalclient.HumanInputState{
		hiWF: {State: temporalclient.HumanInputWaitingForInput, RequestID: hiASCII},
	}}
	return &Handlers{opts: Options{GitReader: git, TemporalClient: tc}}, tc
}

func asUser(r *http.Request, u *auth.User) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(), u))
}

func listHumanInputs(t *testing.T, h *Handlers, u *auth.User, query string) (int, []humanInputView, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/human-input"+query, nil)
	if u != nil {
		req = asUser(req, u)
	}
	w := httptest.NewRecorder()
	h.ListHumanInputs(w, req)
	var body struct {
		Items []humanInputView `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Items, w.Body.String()
}

func getHumanInput(t *testing.T, h *Handlers, u *auth.User, id string) (int, humanInputView, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/human-input/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	if u != nil {
		req = asUser(req, u)
	}
	w := httptest.NewRecorder()
	h.GetHumanInput(w, req)
	var v humanInputView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v, w.Body.String()
}

var (
	alice = auth.NewGitHubUser("alice", nil)
	bob   = auth.NewGitHubUser("bob", nil)
	admin = &auth.User{ID: "root", Groups: []string{"admins"}}
)

func TestListHumanInputs_PendingComesFromTheWorkflow(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	code, items, body := listHumanInputs(t, h, alice, "")
	if code != http.StatusOK || len(items) != 1 {
		t.Fatalf("list = %d %s", code, body)
	}
	v := items[0]
	if v.RequestID != hiASCII || v.State != HumanInputPending || !v.CanRespond || v.Question != "Which library should the fix use?" {
		t.Fatalf("item = %+v", v)
	}
	// The query targets the workflow AND run named in the sealed request.
	if len(tc.humanInputQueries) == 0 || tc.humanInputQueries[0] != hiWF+"@run-1" {
		t.Fatalf("queries = %v", tc.humanInputQueries)
	}
	// state=all also shows the request the workflow is NOT waiting on.
	_, all, _ := listHumanInputs(t, h, alice, "?state=all")
	states := map[string]string{}
	for _, v := range all {
		states[v.RequestID] = v.State
	}
	if states[hiASCII] != HumanInputPending || states[hiUnicode] != HumanInputNotPending {
		t.Fatalf("states = %v", states)
	}
}

// A request is visible only to its eligible respondents, admins and the
// service principal; the allow-list itself only to the latter two.
func TestHumanInput_VisibilityAndRedaction(t *testing.T) {
	h, _ := newHumanInputHandlers(t)
	if _, items, _ := listHumanInputs(t, h, bob, "?state=all"); len(items) != 0 {
		t.Fatalf("bob sees %d requests", len(items))
	}
	if code, _, _ := getHumanInput(t, h, bob, hiASCII); code != http.StatusNotFound {
		t.Fatalf("bob get = %d, want 404", code)
	}
	code, v, body := getHumanInput(t, h, alice, hiASCII)
	if code != http.StatusOK || v.EligibleActors != nil || !v.CanRespond {
		t.Fatalf("alice get = %d %s", code, body)
	}
	for _, internal := range []string{"target_repository_sha", "c963963", "profile_content_hash", "question_hash", "argo_workflow_name"} {
		if strings.Contains(body, internal) {
			t.Fatalf("view leaks %q: %s", internal, body)
		}
	}
	for _, u := range []*auth.User{admin, auth.NewServiceUser()} {
		_, v, _ := getHumanInput(t, h, u, hiUnicode)
		if len(v.EligibleActors) != 2 || v.CanRespond {
			t.Fatalf("%s view = %+v", u.ID, v)
		}
	}
	// telegram:12345 is eligible on the unicode request; the unicode question
	// round-trips intact.
	_, v, _ = getHumanInput(t, h, admin, hiUnicode)
	if !strings.HasPrefix(v.Question, "Какой") {
		t.Fatalf("question = %q", v.Question)
	}
}

// A request altered after sealing is never shown, not even to an admin, but
// admins do see that a document was skipped.
func TestHumanInput_TamperedRequestIsNeverShown(t *testing.T) {
	h, _ := newHumanInputHandlers(t)
	var m map[string]any
	if err := json.Unmarshal(humanInputFixture(t, "ascii_single_choice"), &m); err != nil {
		t.Fatal(err)
	}
	m["question"] = "Approve the merge?"
	raw, _ := json.Marshal(m)
	h.opts.GitReader = &humanInputGitReader{files: []gitops.HumanInputRequestFile{{Service: "mctl-api", Proposal: "issue-261-x", Raw: raw}}}
	if _, items, _ := listHumanInputs(t, h, admin, "?state=all"); len(items) != 0 {
		t.Fatalf("tampered request listed: %+v", items)
	}
	if _, _, body := listHumanInputs(t, h, admin, "?state=all"); !strings.Contains(body, `"invalid_documents":1`) {
		t.Fatalf("admin list does not report the skipped document: %s", body)
	}
	if _, _, body := listHumanInputs(t, h, alice, "?state=all"); strings.Contains(body, "invalid_documents") {
		t.Fatalf("non-admin list reports skipped documents: %s", body)
	}
	if code, _, _ := getHumanInput(t, h, admin, hiASCII); code != http.StatusNotFound {
		t.Fatalf("tampered get = %d", code)
	}
}

func TestListHumanInputs_PendingNeedsTemporal(t *testing.T) {
	h, _ := newHumanInputHandlers(t)
	h.opts.TemporalClient = nil
	if code, _, _ := listHumanInputs(t, h, alice, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("pending without Temporal = %d, want 503", code)
	}
	_, items, _ := listHumanInputs(t, h, alice, "?state=all")
	for _, v := range items {
		if v.State != HumanInputUnknown {
			t.Fatalf("state without Temporal = %s, want unknown", v.State)
		}
	}
}

// A failed query is never pending, and state=pending does not turn it into
// a short list that reads as "nothing is waiting": it answers 503.
func TestListHumanInputs_QueryFailureIsNeverPending(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	tc.humanInputErr = errors.New("no worker")
	if code, items, body := listHumanInputs(t, h, alice, ""); code != http.StatusServiceUnavailable || len(items) != 0 {
		t.Fatalf("pending list with a failed query = %d %s, want 503", code, body)
	}
	_, v, _ := getHumanInput(t, h, alice, hiASCII)
	if v.State != HumanInputUnknown {
		t.Fatalf("state = %s", v.State)
	}
	// state=all still answers, with the state marked unknown.
	code, items, _ := listHumanInputs(t, h, alice, "?state=all")
	if code != http.StatusOK || len(items) != 2 {
		t.Fatalf("state=all = %d %+v", code, items)
	}
	for _, v := range items {
		if v.State != HumanInputUnknown {
			t.Fatalf("state=all item = %s", v.State)
		}
	}
}

// A GitHub login is only a GitHub login when authentication proved it. A
// Dex (or dev-mode) principal whose ID equals an eligible login is not that
// person: it neither sees the request nor may answer it.
func TestHumanInput_OnlyVerifiedGitHubLoginsAreRespondents(t *testing.T) {
	h, _ := newHumanInputHandlers(t)
	impostor := &auth.User{ID: "alice"} // e.g. Dex preferred_username
	if _, items, _ := listHumanInputs(t, h, impostor, "?state=all"); len(items) != 0 {
		t.Fatalf("unverified alice sees %d requests", len(items))
	}
	if code, _, _ := getHumanInput(t, h, impostor, hiASCII); code != http.StatusNotFound {
		t.Fatalf("unverified alice get = %d, want 404", code)
	}
	// An admin reached through Dex still reads it, but cannot answer.
	dexAdmin := &auth.User{ID: "alice", Groups: []string{"admins"}}
	if _, v, _ := getHumanInput(t, h, dexAdmin, hiASCII); v.CanRespond {
		t.Fatal("unverified admin alice reported as a respondent")
	}
}

// One query per owning execution, however many of its requests are listed;
// an expired request is never queried at all.
func TestListHumanInputs_QueriesEachExecutionOnce(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	if _, items, _ := listHumanInputs(t, h, admin, "?state=all"); len(items) != 2 {
		t.Fatalf("items = %d", len(items))
	}
	if len(tc.humanInputQueries) != 1 {
		t.Fatalf("queries = %v, want one for the shared execution", tc.humanInputQueries)
	}
	tc.humanInputQueries = nil
	withHumanInputClock(t, "2026-09-24T02:00:00Z")
	code, items, _ := listHumanInputs(t, h, admin, "")
	if code != http.StatusOK || len(items) != 0 || len(tc.humanInputQueries) != 0 {
		t.Fatalf("pending after expiry = %d %+v, queries %v", code, items, tc.humanInputQueries)
	}
}

// Past expires_at the workflow still decides the terminal state: an
// answered request reads resolved and a timed-out one timed_out, not
// "expired" for everything.
func TestHumanInput_TerminalStateOutlivesExpiry(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	withHumanInputClock(t, "2026-09-25T00:00:00Z")
	tc.humanInputStates[hiWF] = &temporalclient.HumanInputState{State: temporalclient.HumanInputRunning, RequestID: hiASCII, ResumeCount: 1}
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputResolved {
		t.Fatalf("answered, then expired: GET state = %s, want resolved", v.State)
	}
	_, items, _ := listHumanInputs(t, h, admin, "?state=all")
	found := false
	for _, v := range items {
		if v.RequestID == hiASCII {
			found = true
			if v.State != HumanInputResolved {
				t.Fatalf("answered, then expired: list state = %s, want resolved", v.State)
			}
		}
	}
	if !found {
		t.Fatalf("%s missing from the list: %+v", hiASCII, items)
	}
	// Past Temporal retention the execution is gone; the sealed expiry is
	// still the better answer than "not pending".
	tc.humanInputStates[hiWF] = nil
	tc.humanInputErr = serviceerror.NewNotFound("gone")
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputExpired {
		t.Fatalf("expired and past retention: state = %s, want expired", v.State)
	}
	tc.humanInputErr = nil
	tc.humanInputStates[hiWF] = &temporalclient.HumanInputState{State: temporalclient.HumanInputTimedOut, RequestID: hiASCII}
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputTimedOut {
		t.Fatalf("timed out: state = %s", v.State)
	}
}

// A worker outage costs one bounded budget, not 3s per request.
func TestListHumanInputs_OutageIsBounded(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	tc.humanInputBlocks = true
	prev := humanInputListBudget
	humanInputListBudget = 50 * time.Millisecond
	t.Cleanup(func() { humanInputListBudget = prev })
	start := time.Now()
	code, _, _ := listHumanInputs(t, h, admin, "")
	if code != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("outage = %d after %s", code, time.Since(start))
	}
}

// A workflow that no longer exists is not waiting on anything; a nil state
// from a client is unknown, never a panic.
func TestHumanInputState_NotFoundAndNil(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	tc.humanInputErr = serviceerror.NewNotFound("gone")
	if code, items, body := listHumanInputs(t, h, alice, ""); code != http.StatusOK || len(items) != 0 {
		t.Fatalf("pending with the workflow gone = %d %s", code, body)
	}
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputNotPending {
		t.Fatalf("state = %s", v.State)
	}
	tc.humanInputErr = nil
	tc.humanInputStates[hiWF] = nil
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputUnknown {
		t.Fatalf("nil state = %s", v.State)
	}
}

func TestListHumanInputs_Filters(t *testing.T) {
	h, _ := newHumanInputHandlers(t)
	if _, items, _ := listHumanInputs(t, h, admin, "?state=all&work_item_id=other"); len(items) != 0 {
		t.Fatalf("work_item filter ignored: %d", len(items))
	}
	if _, items, _ := listHumanInputs(t, h, admin, "?state=all&work_item_id=wi-261"); len(items) != 2 {
		t.Fatalf("work_item filter = %d", len(items))
	}
	if code, _, _ := listHumanInputs(t, h, admin, "?state=waiting"); code != http.StatusBadRequest {
		t.Fatalf("bad state filter = %d", code)
	}
	if code, _, _ := listHumanInputs(t, h, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", code)
	}
	if code, _, _ := getHumanInput(t, h, admin, "../../etc"); code != http.StatusBadRequest {
		t.Fatalf("bad id = %d", code)
	}
}

func TestDeriveHumanInputState(t *testing.T) {
	raw := humanInputFixture(t, "ascii_single_choice")
	withHumanInputClock(t, "2026-09-23T12:00:00Z")
	sealed, _, err := (&Handlers{opts: Options{GitReader: &humanInputGitReader{files: []gitops.HumanInputRequestFile{{Raw: raw}}}}}).loadHumanInputRequests()
	if err != nil || len(sealed) != 1 {
		t.Fatal(err)
	}
	req := sealed[0].req
	before := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	after := time.Date(2026, 9, 24, 2, 0, 0, 0, time.UTC) // == expires_at
	for _, tc := range []struct {
		name string
		st   temporalclient.HumanInputState
		now  time.Time
		want string
	}{
		{"waiting on it", temporalclient.HumanInputState{State: "WAITING_FOR_INPUT", RequestID: hiASCII}, before, HumanInputPending},
		{"waiting but expired", temporalclient.HumanInputState{State: "WAITING_FOR_INPUT", RequestID: hiASCII}, after, HumanInputExpired},
		{"timed out", temporalclient.HumanInputState{State: "INPUT_TIMED_OUT", RequestID: hiASCII}, before, HumanInputTimedOut},
		{"answered and resumed", temporalclient.HumanInputState{State: "RUNNING", RequestID: hiASCII, ResumeCount: 1}, before, HumanInputResolved},
		{"never waited", temporalclient.HumanInputState{State: "RUNNING"}, before, HumanInputNotPending},
		{"waiting on another", temporalclient.HumanInputState{State: "WAITING_FOR_INPUT", RequestID: "hir-ffffffffffffffff"}, before, HumanInputNotPending},
		{"unrecognised", temporalclient.HumanInputState{State: "PAUSED", RequestID: hiASCII}, before, HumanInputUnknown},
	} {
		st := tc.st
		if got, _ := deriveHumanInputState(&st, req, tc.now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Both endpoints decide expiry from the sealed timestamp, before and
// without Temporal.
func TestGetHumanInput_ExpiredWithoutTemporal(t *testing.T) {
	h, tc := newHumanInputHandlers(t)
	withHumanInputClock(t, "2026-09-24T02:00:00Z")
	h.opts.TemporalClient = nil
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputExpired {
		t.Fatalf("state = %s, want expired", v.State)
	}
	h.opts.TemporalClient = tc
	tc.humanInputErr = errors.New("no worker")
	if _, v, _ := getHumanInput(t, h, alice, hiASCII); v.State != HumanInputExpired {
		t.Fatalf("state = %s", v.State)
	}
}

// The handlers are only reachable if the router registers them; every other
// test here calls them directly.
func TestHumanInputRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, want := range []string{"GET /api/v1/human-input", "GET /api/v1/human-input/{request_id}"} {
		if !found[want] {
			t.Errorf("route %q is not registered", want)
		}
	}
}
