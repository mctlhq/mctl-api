package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/governance"
)

// F6: a request lacking mandatory context cannot be approved, and stays
// pending; a deny is never gated.
func TestF6_IncompleteContextCannotBeApproved(t *testing.T) {
	e := newWorkItemsEnv(t)
	b := e.approvalBody("k-incomplete")
	delete(b, "side_effect")
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", b)
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	id := res.body["approval"].(map[string]any)["id"].(string)
	dc := res.body["decision_context"].(map[string]any)
	if dc["context_complete"] != false {
		t.Fatalf("decision_context = %v", dc)
	}

	res = e.decide(rootAdmin, id, "approve")
	if res.code != http.StatusUnprocessableEntity || code(res) != aarCodeContextIncomplete {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if missing, _ := res.body["details"].(map[string]any)["missing_fields"].([]any); len(missing) != 1 || missing[0] != "side_effect" {
		t.Fatalf("details = %s", res.raw)
	}
	if got := e.approvalState(id)["state"]; got != "pending" {
		t.Fatalf("state = %v, want pending", got)
	}
	if res := e.decide(rootAdmin, id, "deny"); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
}

// F6: the reviewer sees the mandatory context, and the decision is bound to
// the digest of what they saw.
func TestF6_DecisionBoundToContextDigest(t *testing.T) {
	e := newWorkItemsEnv(t)
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", e.approvalBody("k-digest"))
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	id := res.body["approval"].(map[string]any)["id"].(string)
	dc := res.body["decision_context"].(map[string]any)
	if dc["context_complete"] != true || dc["risk_level"] == "" || dc["side_effect"] == "" || dc["intent_source"] == "" {
		t.Fatalf("decision_context = %v", dc)
	}
	digest, _ := dc["context_digest"].(string)

	bad := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision",
		map[string]any{"decision": "approve", "context_digest": "sha256:other"})
	if bad.code != http.StatusConflict || code(bad) != aarCodeContextChanged {
		t.Fatalf("wrong digest = %d %s", bad.code, bad.raw)
	}
	ok := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision",
		map[string]any{"decision": "approve", "context_digest": digest})
	if ok.code != http.StatusOK {
		t.Fatalf("approve = %d %s", ok.code, ok.raw)
	}
	a := ok.body["approval"].(map[string]any)
	if a["decided_context_digest"] != digest || a["authority_basis"] != "platform_admin" || a["fresh_until"] == nil {
		t.Fatalf("captured = %v", a)
	}
}

// Revalidation before spend (mctl-api#700): each way an approval's basis can
// have moved refuses the consume, names the code, says a fresh approval is
// needed (or that authority is unreadable), and leaves the approval approved.
func TestF3_ConsumeRevalidatesBeforeSpend(t *testing.T) {
	policies := func(version string) governance.PolicySet {
		return governance.PolicySet{"merge-needs-human": {Version: version, Decision: "require_approval"}}
	}
	for name, tc := range map[string]struct {
		setup  func(h *Handlers, pr *relayPrincipals)
		status int
		code   string
		reapp  bool
	}{
		"authority revoked": {func(h *Handlers, _ *relayPrincipals) { h.opts.AdminPrincipals = map[string]bool{} },
			http.StatusConflict, aarCodeAuthorityRevoked, true},
		"decider disabled": {func(_ *Handlers, pr *relayPrincipals) { pr.err = auth.ErrPrincipalDisabled },
			http.StatusConflict, aarCodeDeciderDisabled, true},
		"authority unavailable": {func(_ *Handlers, pr *relayPrincipals) { pr.err = errors.New("store down") },
			http.StatusServiceUnavailable, aarCodeAuthorityUnavailable, false},
		"stale": {func(h *Handlers, _ *relayPrincipals) {
			h.opts.Clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
		}, http.StatusConflict, aarCodeStale, true},
		"policy drift": {func(h *Handlers, _ *relayPrincipals) {
			h.opts.Policies = policies("v4")
			h.opts.RequireRegisteredPolicy = true
		}, http.StatusConflict, aarCodePolicyDrift, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWorkItemsEnv(t)
			pr := &relayPrincipals{byLogin: map[string]string{auth.ServiceUserID: "prn_SERVICE", "root": "prn_ROOT"}}
			e.h.opts.TenantAuthzMode = TenantAuthzPrincipal
			e.h.opts.Principals = pr
			e.h.opts.AdminPrincipals = map[string]bool{"prn_ROOT": true}
			e.h.opts.Policies = policies("v3")
			e.h.opts.ApprovalMaxDecisionAge = time.Minute
			svc, admin := auth.NewServiceUser(), auth.NewGitHubUser("root", []string{"admins"})
			for _, u := range []*auth.User{svc, admin} {
				if err := auth.AttachPrincipal(context.Background(), pr, u); err != nil {
					t.Fatal(err)
				}
			}
			res := e.do(svc, "POST", "/api/v1/action-approvals", e.approvalBody("k-reval-"+name))
			if res.code != http.StatusCreated {
				t.Fatalf("create = %d %s", res.code, res.raw)
			}
			a := res.body["approval"].(map[string]any)
			id := a["id"].(string)
			if d := e.decide(admin, id, "approve"); d.code != http.StatusOK {
				t.Fatalf("decide = %d %s", d.code, d.raw)
			}
			tc.setup(e.h, pr)
			got := e.do(svc, "POST", "/api/v1/action-approvals/"+id+"/consume", map[string]any{"intent_hash": a["intent_hash"]})
			if got.code != tc.status || code(got) != tc.code {
				t.Fatalf("consume = %d %s", got.code, got.raw)
			}
			details, _ := got.body["details"].(map[string]any)
			if (details["reapproval_required"] == true) != tc.reapp {
				t.Fatalf("details = %s", got.raw)
			}
			if st := e.approvalState(id)["state"]; st != "approved" {
				t.Fatalf("state = %v, want approved (not spent)", st)
			}
		})
	}
}

// A row without a decision context (written before the columns existed) is
// refused an approve only while the approve could otherwise succeed: a
// terminal request keeps its own refusal.
func TestF6_ContextGateDoesNotMaskTerminalRefusal(t *testing.T) {
	e := newWorkItemsEnv(t)
	id := e.requestApproval("k-legacy")["id"].(string)
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET side_effect='' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusUnprocessableEntity || code(res) != aarCodeContextIncomplete {
		t.Fatalf("pending approve = %d %s", res.code, res.raw)
	}
	if res := e.decide(rootAdmin, id, "deny"); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
	if res := e.decide(rootAdmin, id, "approve"); res.code != http.StatusConflict || code(res) != aarCodeAlreadyDecided {
		t.Fatalf("approve after deny = %d %s", res.code, res.raw)
	}
}
