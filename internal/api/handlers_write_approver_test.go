package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// reviewedDigest is a well-formed proposal content digest: a direct approve
// must carry one (mctl-api#722), so every approval meant to succeed sends it.
var reviewedDigest = "sha256:" + strings.Repeat("a", 64)

// mctl-agents-approve writes approved_by into .status.yaml and into the gitops
// commit message, so the approver must be a fact about who called rather than
// a field the caller fills in (gitops#986). These assert on the value that
// reaches the executor — a 202 alone says nothing about what was recorded.
func approveParams(t *testing.T, router http.Handler, exec *fakeExecutor, body map[string]string, user *auth.User) (*int, map[string]string) {
	t.Helper()
	before := len(exec.submittedParams)
	w := postAs(t, router, "/api/v1/operations/mctl-agents-approve/execute", body, user)
	code := w.Code
	if len(exec.submittedParams) == before {
		return &code, nil
	}
	return &code, exec.submittedParams[len(exec.submittedParams)-1]
}

func TestApprove_ApproverComesFromTheCaller(t *testing.T) {
	router, exec := newTestRouter(t)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-1", "expected_content_digest": reviewedDigest,
	}, adminUser)

	if *code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", *code)
	}
	if params["approver"] != adminUser.ID {
		t.Errorf("approver = %q, want %q", params["approver"], adminUser.ID)
	}
}

func TestApprove_ExplicitDifferentApproverIsRejected(t *testing.T) {
	router, exec := newTestRouter(t)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-2", "approver": "someone-else", "expected_content_digest": reviewedDigest,
	}, adminUser)

	if *code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", *code)
	}
	// Rejected outright, not silently corrected: nothing may be submitted.
	if params != nil {
		t.Errorf("a workflow was submitted despite the rejection: %v", params)
	}
}

// Naming yourself is redundant but not a lie, so it is accepted rather than
// made an error — the same shape handlers_dev_loop.go settled on.
func TestApprove_NamingYourselfIsAccepted(t *testing.T) {
	router, exec := newTestRouter(t)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-3", "approver": adminUser.ID, "expected_content_digest": reviewedDigest,
	}, adminUser)

	if *code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", *code)
	}
	if params["approver"] != adminUser.ID {
		t.Errorf("approver = %q, want %q", params["approver"], adminUser.ID)
	}
}

// A service principal off the grant path cannot carry a content digest (it
// may not assert one, TestApprove_ServiceMayNotAssertAContentDigest), so it
// cannot approve at all: the approve CWFT refuses an unbound flip
// (mctl-gitops#1979), and the API refuses it first, before submit
// (mctl-api#722). This used to be the Temporal worker's relay; the worker now
// approves through an action-approval grant. Nothing is defaulted on the way
// out either: no "unknown" approver, no submit. Naming someone else is a
// relay attempt and is counted as refused; naming nobody or itself is not a
// relay and moves no counter.
func TestApprove_ServiceWithoutAGrantCannotApprove(t *testing.T) {
	for approver, isRelay := range map[string]bool{"": false, auth.ServiceUserID: false, "mashkovd": true, "unknown": true} {
		router, exec, logger := newApproveRouter(t, false)
		before := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("relayed"))
		refused := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused"))
		w := postAs(t, router, "/api/v1/operations/mctl-agents-approve/execute", map[string]string{
			"service": "mctl-web", "slug": "issue-4", "approver": approver,
		}, auth.NewServiceUser())
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "approval_content_unbound") {
			t.Errorf("approver %q: %d %s, want 400 approval_content_unbound", approver, w.Code, w.Body.String())
		}
		if len(exec.submittedParams) != 0 {
			t.Errorf("approver %q: a workflow was submitted: %v", approver, exec.submittedParams)
		}
		// A refused relay is not a use of the relay, but it is an attempt:
		// counted as refused, never as relayed or as a legacy_relay row.
		if d := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("relayed")) - before; d != 0 {
			t.Errorf("approver %q: relayed counter moved by %v, want 0", approver, d)
		}
		want := 0.0
		if isRelay {
			want = 1
		}
		if d := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused")) - refused; d != want {
			t.Errorf("approver %q: refused counter moved by %v, want %v", approver, d, want)
		}
		if n := len(entriesFor(logger, "approver.legacy_relay")); n != 0 {
			t.Errorf("approver %q: %d legacy_relay entries, want 0", approver, n)
		}
	}
}

// A human whose GitHub login or Dex username happens to be "mctl-agent" must
// not inherit the service principal's relay privilege. IsService() is proof of
// how the caller authenticated, not a claim about their name (claude P2).
func TestApprove_AHumanNamedLikeTheServiceMayNotRelay(t *testing.T) {
	router, exec := newTestRouter(t)
	impostor := &auth.User{ID: auth.ServiceUserID, Groups: []string{"admins"}}

	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-6", "approver": "mashkovd",
	}, impostor)

	if *code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — only a token-authenticated service principal may relay", *code)
	}
	if params != nil {
		t.Errorf("a workflow was submitted for an impostor: %v", params)
	}
}

// The denial must leave a record: it returns before Submit, so the audit entry
// written on the success path never happens here.
func TestApprove_ASpoofAttemptIsAudited(t *testing.T) {
	router, exec := newTestRouter(t)
	_, _ = approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-7", "approver": "someone-else",
	}, adminUser)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req = req.WithContext(auth.WithUser(req.Context(), adminUser))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var payload struct {
		Entries []struct {
			Operation string `json:"operation"`
			Status    string `json:"status"`
			UserID    string `json:"userId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding audit list: %v (body %s)", err, rec.Body.String())
	}
	for _, e := range payload.Entries {
		if e.Operation == "mctl-agents-approve" && e.Status == "denied" && e.UserID == adminUser.ID {
			return
		}
	}
	t.Errorf("no denied audit entry for the spoof attempt; body: %s", rec.Body.String())
}

// newApproveRouter is newTestRouter's executor and registry with the legacy
// approver flag under test, and the audit logger kept so a test can read
// exactly what a request recorded.
func newApproveRouter(t *testing.T, legacyOff bool) (http.Handler, *fakeExecutor, *audit.Logger) {
	t.Helper()
	if os.Getenv("AUTH_REQUIRED") == "" {
		t.Setenv("AUTH_REQUIRED", "false")
	}
	exec := &fakeExecutor{}
	logger := audit.NewLogger()
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:               operations.NewRegistry(),
		GitReader:              &fakeGitReader{},
		ArgoCD:                 &fakeArgoCD{},
		AuditLog:               logger,
		Executor:               exec,
		LegacyApproverDisabled: legacyOff,
	})
	return router, exec, logger
}

func entriesFor(logger *audit.Logger, operation string) []audit.Entry {
	var out []audit.Entry
	entries := logger.List(1000)
	for i := range entries {
		if entries[i].Operation == operation {
			out = append(out, entries[i])
		}
	}
	return out
}

// mctl-api#571 kept the free-text relay alive behind a flag, counting and
// auditing every use. A relay carries no content digest, so since
// mctl-api#722 it is refused even with the flag on, and the refusal is
// audited as a denied approve with its typed code, never as a relay, and
// counted as a refused attempt so the counter still shows who relays.
func TestApprove_LegacyRelayWithoutADigestIsRefusedAndCounted(t *testing.T) {
	router, exec, logger := newApproveRouter(t, false)
	relayed := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("relayed"))
	refused := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused"))
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-8", "approver": "mashkovd",
	}, auth.NewServiceUser())
	if *code != http.StatusBadRequest || params != nil {
		t.Fatalf("status = %d, submitted = %v; want 400 and nothing submitted", *code, params)
	}
	if d := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("relayed")) - relayed; d != 0 {
		t.Errorf("relayed counter moved by %v, want 0", d)
	}
	if d := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused")) - refused; d != 1 {
		t.Errorf("refused counter moved by %v, want 1", d)
	}
	if n := len(entriesFor(logger, "approver.legacy_relay")); n != 0 {
		t.Errorf("%d legacy_relay entries for a refused relay, want 0", n)
	}
	denied := entriesFor(logger, "mctl-agents-approve")
	if len(denied) != 1 || denied[0].Status != "denied" || denied[0].Parameters["code"] != "approval_content_unbound" {
		t.Fatalf("want one denied entry with code approval_content_unbound, got %+v", denied)
	}
	want := map[string]string{
		"approver": "mashkovd", "calling_principal": auth.ServiceUserID,
		"operation": "mctl-agents-approve", "service": "mctl-web", "slug": "issue-8",
	}
	for k, v := range want {
		if denied[0].Parameters[k] != v {
			t.Errorf("parameter %s = %q, want %q", k, denied[0].Parameters[k], v)
		}
	}
}

// With the flag off the free-text relay is refused outright: nothing is
// submitted, the refusal is typed and audited, and no relay is recorded.
func TestApprove_LegacyRelayRefusedWhenDisabled(t *testing.T) {
	router, exec, logger := newApproveRouter(t, true)
	before := len(exec.submittedParams)
	refused := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused"))
	w := postAs(t, router, "/api/v1/operations/mctl-agents-approve/execute", map[string]string{
		"service": "mctl-web", "slug": "issue-10", "approver": "mashkovd",
	}, auth.NewServiceUser())

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "legacy_approver_disabled") {
		t.Errorf("body = %s, want the legacy_approver_disabled code", w.Body.String())
	}
	if len(exec.submittedParams) != before {
		t.Error("a workflow was submitted although the relay is disabled")
	}
	if d := testutil.ToFloat64(mctlapi.LegacyRelayTotal.WithLabelValues("refused")) - refused; d != 1 {
		t.Errorf("refused counter moved by %v, want 1", d)
	}
	if n := len(entriesFor(logger, "approver.legacy_relay")); n != 0 {
		t.Errorf("%d legacy_relay entries for a refused relay, want 0", n)
	}
	denied := entriesFor(logger, "mctl-agents-approve")
	if len(denied) != 1 || denied[0].Status != "denied" || denied[0].Parameters["approver"] != "mashkovd" {
		t.Errorf("want one denied mctl-agents-approve entry naming the refused approver, got %+v", denied)
	}
}

// The flag governs the service relay only: a human approving as themselves
// is untouched by it.
func TestApprove_HumanUnaffectedByTheFlag(t *testing.T) {
	router, exec, _ := newApproveRouter(t, true)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-11", "expected_content_digest": reviewedDigest,
	}, adminUser)
	if *code != http.StatusAccepted || params["approver"] != adminUser.ID {
		t.Errorf("status = %d, approver = %q", *code, params["approver"])
	}
}

// The content digest is what binds the approve CWFT to the content a human
// decided on, and only an action-approval grant carries that decision. Off
// the grant path a service principal may not assert one, relayed approver or
// not; a human admin calling directly is the decider and may (mctl-agents#681).
func TestApprove_ServiceMayNotAssertAContentDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, body := range []map[string]string{
		{"service": "mctl-web", "slug": "issue-681", "expected_content_digest": digest},
		{"service": "mctl-web", "slug": "issue-681", "approver": "mashkovd", "expected_content_digest": digest},
	} {
		router, exec, logger := newApproveRouter(t, false)
		code, params := approveParams(t, router, exec, body, auth.NewServiceUser())
		if *code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for %v", *code, body)
		}
		if params != nil {
			t.Fatalf("a workflow was submitted with a self-asserted digest: %v", params)
		}
		denied := entriesFor(logger, "mctl-agents-approve")
		if len(denied) != 1 || denied[0].Status != "denied" {
			t.Errorf("want one denied audit entry, got %+v", denied)
		}
	}

	router, exec := newTestRouter(t)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-681", "expected_content_digest": digest,
	}, adminUser)
	if *code != http.StatusAccepted {
		t.Fatalf("human admin: status = %d, want 202", *code)
	}
	if params["expected_content_digest"] != digest {
		t.Errorf("human admin digest = %q, want %q", params["expected_content_digest"], digest)
	}
}

// Approval provenance: approval_ref names the grant an approve spends and is
// set by the server from that grant alone. Off the grant path there is no
// grant, so a body naming one is refused for a human admin and for the
// service principal alike, whatever its value, and audited.
func TestApprove_BodyApprovalRefIsRefusedOffTheGrantPath(t *testing.T) {
	ref := "aar_" + strings.Repeat("0", 32)
	for name, user := range map[string]*auth.User{
		"human admin": adminUser,
		"service":     auth.NewServiceUser(),
	} {
		for _, value := range []string{ref, ""} {
			for _, body := range []map[string]string{
				{"service": "mctl-web", "slug": "issue-ref", "approval_ref": value},
				{"service": "mctl-web", "slug": "issue-ref", "approver": "mashkovd", "approval_ref": value},
			} {
				router, exec, logger := newApproveRouter(t, false)
				code, params := approveParams(t, router, exec, body, user)
				if *code != http.StatusBadRequest {
					t.Fatalf("%s: status = %d, want 400 for %v", name, *code, body)
				}
				if params != nil {
					t.Fatalf("%s: a workflow was submitted with a body approval_ref: %v", name, params)
				}
				denied := entriesFor(logger, "mctl-agents-approve")
				if len(denied) != 1 || denied[0].Status != "denied" {
					t.Errorf("%s: want one denied audit entry, got %+v", name, denied)
				}
			}
		}
	}
	// Without the field a direct human approve still submits, and the
	// argument is absent altogether, not "": only a spent grant puts one in
	// the submit. (A service principal off the grant path cannot approve at
	// all: TestApprove_ServiceWithoutAGrantCannotApprove.)
	router, exec := newTestRouter(t)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-ref", "expected_content_digest": reviewedDigest,
	}, adminUser)
	if *code != http.StatusAccepted {
		t.Fatalf("human admin without approval_ref: status = %d, want 202", *code)
	}
	if v, present := params["approval_ref"]; present {
		t.Errorf("human admin: approval_ref = %q submitted off the grant path, want it absent", v)
	}
}

// mctl-api#722: a direct approve is bound to the content its approver
// reviewed, or it is refused before anything is submitted, with the code the
// approve CWFT itself would refuse with, and an audit row carrying that code.
func TestApprove_DirectApproveWithoutADigestIsUnbound(t *testing.T) {
	router, exec, logger := newApproveRouter(t, true)
	w := postAs(t, router, "/api/v1/operations/mctl-agents-approve/execute", map[string]string{
		"service": "mctl-web", "slug": "issue-722",
	}, adminUser)
	assertDigestRefusal(t, w, exec, logger, "approval_content_unbound")
}

// A malformed digest gets its own code ahead of ValidateInput's generic
// "validation failed", and the refused value is not echoed back or audited.
func TestApprove_DirectApproveWithAMalformedDigestIsRefused(t *testing.T) {
	for _, digest := range []string{
		strings.Repeat("a", 64),                        // no prefix
		"sha256:" + strings.Repeat("A", 64),            // uppercase hex
		"sha256:" + strings.Repeat("a", 63),            // short
		"sha256:" + strings.Repeat("a", 64) + "\nx: y", // trailing line
		"sha512:" + strings.Repeat("a", 64),
	} {
		router, exec, logger := newApproveRouter(t, true)
		w := postAs(t, router, "/api/v1/operations/mctl-agents-approve/execute", map[string]string{
			"service": "mctl-web", "slug": "issue-722", "expected_content_digest": digest,
		}, adminUser)
		assertDigestRefusal(t, w, exec, logger, "approval_content_digest_malformed")
		if strings.Contains(w.Body.String(), digest) {
			t.Errorf("digest %q echoed in the refusal: %s", digest, w.Body.String())
		}
	}
}

func assertDigestRefusal(t *testing.T, w *httptest.ResponseRecorder, exec *fakeExecutor, logger *audit.Logger, wantCode string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusBadRequest || body.Code != wantCode {
		t.Fatalf("got %d %s, want 400 %s", w.Code, w.Body.String(), wantCode)
	}
	if len(exec.submittedParams) != 0 {
		t.Fatalf("a workflow was submitted: %v", exec.submittedParams)
	}
	denied := entriesFor(logger, "mctl-agents-approve")
	if len(denied) != 1 || denied[0].Status != "denied" || denied[0].Parameters["code"] != wantCode {
		t.Fatalf("want one denied audit entry with code %s, got %+v", wantCode, denied)
	}
	if denied[0].UserID != adminUser.ID || denied[0].Parameters["slug"] != "issue-722" {
		t.Errorf("audit entry does not name the caller and proposal: %+v", denied[0])
	}
	if _, present := denied[0].Parameters["expected_content_digest"]; present {
		t.Errorf("the refused digest was audited: %+v", denied[0].Parameters)
	}
}
