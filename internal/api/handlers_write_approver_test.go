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
)

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
		"service": "mctl-web", "slug": "issue-1",
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
		"service": "mctl-web", "slug": "issue-2", "approver": "someone-else",
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
		"service": "mctl-web", "slug": "issue-3", "approver": adminUser.ID,
	}, adminUser)

	if *code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", *code)
	}
	if params["approver"] != adminUser.ID {
		t.Errorf("approver = %q, want %q", params["approver"], adminUser.ID)
	}
}

// The Temporal worker submits under the service principal while relaying the
// human approver from its signal payload — which the dev-loop approve endpoint
// took from ITS authenticated caller. That relay is the one legitimate case,
// and it is allowed for this principal alone.
func TestApprove_ServicePrincipalMayRelayAHumanApprover(t *testing.T) {
	router, exec := newTestRouter(t)
	worker := auth.NewServiceUser()

	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-4", "approver": "mashkovd",
	}, worker)

	if *code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", *code)
	}
	if params["approver"] != "mashkovd" {
		t.Errorf("approver = %q, want the relayed human identity", params["approver"])
	}
}

// The registry no longer manufactures an approver: "unknown" is not an
// identity, and the implementer refuses an approval naming nobody.
func TestApprove_NoApproverIsDefaultedToUnknown(t *testing.T) {
	router, exec := newTestRouter(t)
	worker := auth.NewServiceUser()

	_, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-5",
	}, worker)

	if params["approver"] == "unknown" {
		t.Error(`approver was defaulted to "unknown"; that is not an identity`)
	}
	// The service principal naming nobody records itself, which is at least true.
	if params["approver"] != auth.ServiceUserID {
		t.Errorf("approver = %q, want %q", params["approver"], auth.ServiceUserID)
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
	for _, e := range logger.List(1000) {
		if e.Operation == operation {
			out = append(out, e)
		}
	}
	return out
}

// mctl-api#571: while the relay is still allowed, every use leaves exactly
// one approver.legacy_relay entry naming who was relayed, by whom, for which
// proposal. That entry is the evidence the flag can be turned off.
func TestApprove_LegacyRelayIsAuditedOncePerUse(t *testing.T) {
	router, exec, logger := newApproveRouter(t, false)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-8", "approver": "mashkovd",
	}, auth.NewServiceUser())

	if *code != http.StatusAccepted || params["approver"] != "mashkovd" {
		t.Fatalf("status = %d, approver = %q; the relay must keep working while the flag is on", *code, params["approver"])
	}
	got := entriesFor(logger, "approver.legacy_relay")
	if len(got) != 1 {
		t.Fatalf("approver.legacy_relay entries = %d, want exactly 1", len(got))
	}
	want := map[string]string{
		"approver": "mashkovd", "calling_principal": auth.ServiceUserID,
		"operation": "mctl-agents-approve", "service": "mctl-web", "slug": "issue-8",
	}
	for k, v := range want {
		if got[0].Parameters[k] != v {
			t.Errorf("parameter %s = %q, want %q", k, got[0].Parameters[k], v)
		}
	}
}

// A service principal naming nobody, or itself, relays no one: that is not
// the legacy path and must not count as a use of it, or the "zero uses"
// gate before flag-off could never be met.
func TestApprove_ServiceNamingNobodyIsNotALegacyRelay(t *testing.T) {
	for _, approver := range []string{"", auth.ServiceUserID} {
		router, exec, logger := newApproveRouter(t, true)
		code, params := approveParams(t, router, exec, map[string]string{
			"service": "mctl-web", "slug": "issue-9", "approver": approver,
		}, auth.NewServiceUser())
		if *code != http.StatusAccepted || params["approver"] != auth.ServiceUserID {
			t.Errorf("approver %q: status = %d, recorded %q", approver, *code, params["approver"])
		}
		if n := len(entriesFor(logger, "approver.legacy_relay")); n != 0 {
			t.Errorf("approver %q: %d legacy_relay entries, want 0", approver, n)
		}
	}
}

// With the flag off the free-text relay is refused outright: nothing is
// submitted, the refusal is typed and audited, and no relay is recorded.
func TestApprove_LegacyRelayRefusedWhenDisabled(t *testing.T) {
	router, exec, logger := newApproveRouter(t, true)
	before := len(exec.submittedParams)
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
		"service": "mctl-web", "slug": "issue-11",
	}, adminUser)
	if *code != http.StatusAccepted || params["approver"] != adminUser.ID {
		t.Errorf("status = %d, approver = %q", *code, params["approver"])
	}
}
