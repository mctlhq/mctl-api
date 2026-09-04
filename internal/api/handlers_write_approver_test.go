package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
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
