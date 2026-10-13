package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/delegation"
)

// selfPrincipals resolves every caller in these tests by its display name.
var selfPrincipals = &relayPrincipals{byLogin: map[string]string{
	"implementer": "prn_AGENT", "alice": "prn_ALICE", "surface:telegram": "prn_SURFACE",
}}

func selfResolved(t *testing.T, u *auth.User) *auth.User {
	t.Helper()
	if err := auth.AttachPrincipal(context.Background(), selfPrincipals, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// identitySelfAs runs GET /identity/self through the delegation gate, the
// same order the router applies them in.
func identitySelfAs(t *testing.T, u *auth.User, ref string) map[string]any {
	t.Helper()
	h := &Handlers{opts: Options{
		AuditLog: audit.NewLogger(), Principals: selfPrincipals, Delegation: &fakeDelegation{fn: alwaysGrant},
	}}
	rec := httptest.NewRecorder()
	h.agentPrincipalGate(http.HandlerFunc(h.GetIdentitySelf)).ServeHTTP(rec, delegatedReq(http.MethodGet, "/api/v1/identity/self", u, ref))
	if rec.Code != http.StatusOK {
		t.Fatalf("identity/self = %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func party(id, kind, name string) map[string]any {
	return map[string]any{"principal_id": id, "kind": kind, "name": name}
}

func TestIdentitySelf(t *testing.T) {
	run := auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"}
	for _, tc := range []struct {
		name string
		user *auth.User
		ref  string
		want map[string]any
	}{{
		// A delegated run: the actor is the agent, the subject is the
		// human the grant names, and the grant is reported.
		name: "delegated agent",
		user: selfResolved(t, auth.NewAgentUser("implementer", run)),
		ref:  "xr_1",
		want: map[string]any{
			"schema_version": IdentitySelfSchemaVersion,
			"actor":          party("prn_AGENT", auth.KindAgent, "implementer"),
			"subject":        party("prn_ALICE", auth.KindHuman, "alice"),
			"execution_id":   "we_1", "work_item_id": "wi_1", "agent_run_id": "art_1",
			"grant": map[string]any{"kind": delegation.KindExecutionRequest, "ref": "xr_1"},
		},
	}, {
		// The same run acting for itself: subject and grant are null, not
		// a copy of the actor.
		name: "agent for itself",
		user: selfResolved(t, auth.NewAgentUser("implementer", run)),
		want: map[string]any{
			"schema_version": IdentitySelfSchemaVersion,
			"actor":          party("prn_AGENT", auth.KindAgent, "implementer"),
			"subject":        nil,
			"execution_id":   "we_1", "work_item_id": "wi_1", "agent_run_id": "art_1",
			"grant": nil,
		},
	}, {
		name: "human",
		user: selfResolved(t, auth.NewGitHubUser("alice", nil)),
		want: map[string]any{
			"schema_version": IdentitySelfSchemaVersion,
			"actor":          party("prn_ALICE", auth.KindHuman, "alice"),
			"subject":        nil,
			"execution_id":   "", "work_item_id": "", "agent_run_id": "",
			"grant": nil,
		},
	}, {
		// A surface relay is on-behalf-of too: the surface is the actor.
		name: "surface relay",
		user: selfResolved(t, auth.NewRelayedUser("alice", nil, selfResolved(t, auth.NewSurfaceUser("telegram")))),
		want: map[string]any{
			"schema_version": IdentitySelfSchemaVersion,
			"actor":          party("prn_SURFACE", auth.KindService, "surface:telegram"),
			"subject":        party("prn_ALICE", auth.KindHuman, "alice"),
			"execution_id":   "", "work_item_id": "", "agent_run_id": "",
			"grant": nil,
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := identitySelfAs(t, tc.user, tc.ref); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestIdentitySelfIsADelegationRouteForReadsOnly(t *testing.T) {
	if !delegationAllowlisted(http.MethodGet, "/api/v1/identity/self") {
		t.Error("GET /identity/self must accept X-MCTL-On-Behalf-Of")
	}
	if delegationAllowlisted(http.MethodPost, "/api/v1/identity/self") {
		t.Error("only GET is a delegation route")
	}
}

// The route is registered outside the write group and answers any
// authenticated caller.
func TestIdentitySelfIsRouted(t *testing.T) {
	router := NewRouter(Options{AuditLog: audit.NewLogger()})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/v1/identity/self", nil), auth.NewGitHubUser("alice", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/identity/self = %d %s", rec.Code, rec.Body.String())
	}
}
