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

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/delegation"
)

// zedPRN is a ZITADEL-only human's canonical principal: no GitHub identity.
const zedPRN = "prn_01JZED00000000000000000000"

// newZedEnv is a principal-mode env with zed, a human proven by ZITADEL
// only, whose principal authentication resolved, and zed's principal a
// member of the env's tenant.
func newZedEnv(t *testing.T) (*sidEnv, *relayPrincipals) {
	t.Helper()
	return newZedEnvWith(t, false)
}

// resolveOnly is a principal store that resolves identities but cannot
// check a stored principal.
type resolveOnly struct{ pr auth.PrincipalResolver }

func (r resolveOnly) ResolvePrincipal(ctx context.Context, id auth.Identity) (string, error) {
	return r.pr.ResolvePrincipal(ctx, id)
}

// newZedEnvWith is newZedEnv whose router, if noChecker, gets a principal
// store with no CheckPrincipal.
func newZedEnvWith(t *testing.T, noChecker bool) (*sidEnv, *relayPrincipals) {
	t.Helper()
	pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE", "zed@example.com": zedPRN}}
	var store auth.PrincipalResolver = pr
	if noChecker {
		store = resolveOnly{pr}
	}
	var authz *auth.PrincipalAuthz
	e := newSIDEnvOpts(t, store, func(o *Options) {
		o.TenantAuthzMode = TenantAuthzPrincipal
		tenant := o.TenantResolver.(sidTenants)["carol"][0]
		authz = &auth.PrincipalAuthz{Members: tenantsByPrincipal{zedPRN: {tenant}, "prn_ALICE": {tenant}}}
		o.PrincipalAuthz = authz
	})
	zed := auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330001", "zed@example.com", auth.KindHuman)
	// As auth.Middleware does.
	if err := auth.AttachPrincipal(context.Background(), pr, zed); err != nil {
		t.Fatal(err)
	}
	if _, gh := zed.GitHubLogin(); gh || zed.PrincipalID() != zedPRN {
		t.Fatalf("zed = %+v; want a ZITADEL-only human with %s", zed, zedPRN)
	}
	if err := authz.Apply(zed); err != nil {
		t.Fatal(err)
	}
	e.users["zed"] = zed
	return e, pr
}

// mctl-api#646: a human with no GitHub identity links a surface identity
// to its canonical principal, the surface relays as that principal, and
// the human lists and revokes the link like a GitHub human does.
func TestSurfaceIdentity_ZitadelHumanLinksByPrincipal(t *testing.T) {
	e, _ := newZedEnv(t)
	code, body := e.redeem("telegram", e.challenge("zed", "telegram"), "7070")
	if code != http.StatusCreated {
		t.Fatalf("redeem = %d %v", code, body)
	}
	link := body["link"].(map[string]any)
	if link["principal"] != zedPRN || link["subject"] != "oidc:zed@example.com" {
		t.Fatalf("link = %v; want principal %s, subject oidc:zed@example.com", link, zedPRN)
	}
	id := link["id"].(string)

	code, self := e.do("telegram", "GET", "/api/v1/identity/self", nil, SurfaceActorHeader, "7070")
	if code != http.StatusOK {
		t.Fatalf("relayed identity/self = %d %v", code, self)
	}
	subject, _ := self["subject"].(map[string]any)
	if subject["kind"] != auth.KindHuman || subject["name"] != "zed@example.com" || subject["principal_id"] != zedPRN {
		t.Errorf("relayed subject = %v, want zed by principal", subject)
	}

	// The relayed write is zed's, by the same name zed acts under directly.
	code, created := e.relayCreate("telegram", "7070", nil)
	if code != http.StatusCreated {
		t.Fatalf("relayed create = %d %v", code, created)
	}
	item := created["work_item"].(map[string]any)
	if item["owner_principal"] != "oidc:zed@example.com" {
		t.Errorf("owner_principal = %v, want oidc:zed@example.com", item["owner_principal"])
	}
	if code, got := e.do("zed", "GET", "/api/v1/work-items/"+item["id"].(string), nil); code != http.StatusOK {
		t.Errorf("zed reading the item relayed for zed = %d %v", code, got)
	}

	code, list := e.do("zed", "GET", "/api/v1/surface-identities", nil)
	if links, _ := list["links"].([]any); code != http.StatusOK || len(links) != 1 {
		t.Fatalf("zed lists %d %v", code, list)
	}
	if code, _ := e.do("alice", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusNotFound {
		t.Errorf("alice revoking zed's link = %d", code)
	}
	if code, body := e.do("zed", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusOK || body["link"].(map[string]any)["revoked_by"] != zedPRN {
		t.Fatalf("zed revoke = %d %v", code, body)
	}
	if code, body := e.do("telegram", "GET", "/api/v1/identity/self", nil, SurfaceActorHeader, "7070"); code != http.StatusForbidden || body["code"] != sidCodeLinkRevoked {
		t.Errorf("relay after revoke = %d %v", code, body)
	}
}

// Only a human acting directly with a resolved principal gets a challenge:
// not an unresolved OIDC human, not a federated service, not an agent, not
// a relayed or delegated principal subject.
func TestSurfaceIdentity_PrincipalChallengeNeedsAResolvedHuman(t *testing.T) {
	e, pr := newZedEnv(t)
	unresolved := auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330002", "nobody@example.com", auth.KindHuman)
	if err := auth.AttachPrincipal(context.Background(), pr, unresolved); err != nil {
		t.Fatal(err)
	}
	e.users["unresolved"] = unresolved
	svc := auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330003", "bot@example.com", auth.KindService)
	pr.byLogin["bot@example.com"] = "prn_01JB0T00000000000000000000"
	if err := auth.AttachPrincipal(context.Background(), pr, svc); err != nil {
		t.Fatal(err)
	}
	e.users["fed-service"] = svc
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	e.users["as-zed"] = auth.NewDelegatedPrincipalUser("zed@example.com", zedPRN, false, []string{e.tenant}, agent)
	e.users["relayed-zed"] = auth.NewRelayedPrincipalUser("zed@example.com", zedPRN, e.users["telegram"])
	e.users["agent"] = agent

	for _, who := range []string{"unresolved", "fed-service", "agent", "as-zed", "relayed-zed"} {
		code, body := e.do(who, "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": "telegram"})
		if code != http.StatusForbidden || body["code"] != sidCodeHumanOnly {
			t.Errorf("challenge by %s: %d %v, want 403 %s", who, code, body, sidCodeHumanOnly)
		}
		// Nor does it have links to list: never the links of principal "".
		if code, body := e.do(who, "GET", "/api/v1/surface-identities", nil); code != http.StatusForbidden || body["code"] != sidCodeHumanOnly {
			t.Errorf("list by %s: %d %v, want 403 %s", who, code, body, sidCodeHumanOnly)
		}
	}
}

// The relay checks a principal link's principal on every request and
// refuses exactly what authentication refuses; a principal that cannot be
// checked is a 503, never a relay without one.
func TestSurfaceRelay_PrincipalLinkFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		drop      bool
		noChecker bool
		wantCode  int
		wantErr   string
	}{
		"disabled":             {err: auth.ErrPrincipalDisabled, wantCode: http.StatusForbidden, wantErr: sidCodePrincipalDisabled},
		"refused":              {err: auth.ErrIdentityRefused, wantCode: http.StatusForbidden, wantErr: sidCodeIdentityRefused},
		"no such":              {drop: true, wantCode: http.StatusForbidden, wantErr: sidCodeIdentityRefused},
		"store down":           {err: errors.New("dial tcp: connection refused"), wantCode: http.StatusServiceUnavailable, wantErr: sidCodeUnavailable},
		"store has no checker": {noChecker: true, wantCode: http.StatusServiceUnavailable, wantErr: sidCodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e, pr := newZedEnvWith(t, tc.noChecker)
			e.link("zed", "telegram", "7070")
			pr.err = tc.err
			if tc.drop {
				delete(pr.byLogin, "zed@example.com")
			}
			code, body := e.relayCreate("telegram", "7070", nil)
			if code != tc.wantCode || body["code"] != tc.wantErr {
				t.Fatalf("relayed create = %d %v, want %d %s", code, body, tc.wantCode, tc.wantErr)
			}
		})
	}
}

// A principal link whose recorded name is missing or malformed is no
// subject at all: the relay refuses it rather than inventing a name.
func TestSurfaceRelay_PrincipalLinkNeedsItsSubject(t *testing.T) {
	for _, stored := range []string{"", "github:zed", "oidc:"} {
		t.Run(stored, func(t *testing.T) {
			e, _ := newZedEnv(t)
			id := e.link("zed", "telegram", "7070")
			if _, err := e.pool.Exec(context.Background(), `UPDATE surface_identity_links SET subject=$1 WHERE id=$2`, stored, id); err != nil {
				t.Fatal(err)
			}
			code, body := e.relayCreate("telegram", "7070", nil)
			if code != http.StatusForbidden || body["code"] != sidCodeNotFound {
				t.Fatalf("relayed create = %d %v, want 403 %s", code, body, sidCodeNotFound)
			}
		})
	}
}

// A sil_ grant of a prn_ link carries the link's principal (mctl-api#646):
// the gate checks it like any stored principal, never resolves the name,
// and the subject's principalOf is the link's recorded oidc: name.
func TestAgentPrincipalGate_PrincipalSurfaceLinkDelegatesByPrincipal(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	silGrant := &fakeDelegation{fn: func(ref string, _ auth.AgentRun) (delegation.Grant, error) {
		return delegation.Grant{Ref: ref, Kind: delegation.KindSurfaceLink, Subject: "oidc:zed@example.com", SubjectPrincipalID: zedPRN}, nil
	}}

	t.Run("active", func(t *testing.T) {
		pr := &relayPrincipals{byLogin: map[string]string{"zed@example.com": zedPRN}}
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: silGrant}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "sil_1"))
		if !next.called || rec.Code != http.StatusOK {
			t.Fatalf("called=%v code=%d %s", next.called, rec.Code, rec.Body.String())
		}
		u := next.user
		if u.PrincipalID() != zedPRN || principalOf(u) != "oidc:zed@example.com" || u.IsAdmin() || u.IsAgent() {
			t.Fatalf("subject = %q %q admin=%v agent=%v", u.PrincipalID(), principalOf(u), u.IsAdmin(), u.IsAgent())
		}
		if len(pr.checked) != 1 || pr.checked[0] != zedPRN || len(pr.seen) != 0 {
			t.Fatalf("checked=%v seen=%v, want only a check of %s", pr.checked, pr.seen, zedPRN)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		pr := &relayPrincipals{err: auth.ErrPrincipalDisabled}
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: silGrant}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "sil_1"))
		if next.called || rec.Code != http.StatusForbidden {
			t.Fatalf("called=%v code=%d", next.called, rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
			t.Fatalf("code = %v, want %s", body["code"], delegationCodeUnresolved)
		}
	})
}

// Under delegation, a prn_ link binds as a surface actor only for that
// principal: the owner is the link's principal, checked active, never a
// name comparison.
func TestDelegatedSurfaceRef_PrincipalLinkBindsOnlyItsPrincipal(t *testing.T) {
	e, pr := newZedEnv(t)
	e.link("zed", "telegram", "7070")
	e.link("alice", "telegram", "4242")
	_, created := e.relayCreate("telegram", "7070", nil)
	id := created["work_item"].(map[string]any)["id"].(string)
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: id})
	e.users["as-zed"] = auth.NewDelegatedPrincipalUser("zed@example.com", zedPRN, false, []string{e.tenant}, agent)
	e.users["as-other-zed"] = auth.NewDelegatedPrincipalUser("zed@example.com", "prn_01JQTHER000000000000000000", false, []string{e.tenant}, agent)
	path := "/api/v1/work-items/" + id + "/surface-refs"
	bind := func(who, actor string) (int, map[string]any) {
		return e.do(who, "POST", path, map[string]any{
			"surface": "telegram", "external_id": "chat-" + who + "-" + actor, "actor_external_id": actor,
		})
	}

	if code, body := bind("as-zed", "7070"); code != http.StatusCreated {
		t.Fatalf("zed binding zed's own identity = %d %v", code, body)
	}
	for _, tc := range []struct{ who, actor string }{{"as-zed", "4242"}, {"as-other-zed", "7070"}} {
		if code, body := bind(tc.who, tc.actor); code != http.StatusForbidden || body["code"] != delegationCodeNotBound {
			t.Errorf("%s binding %s = %d %v, want 403 %s", tc.who, tc.actor, code, body, delegationCodeNotBound)
		}
	}

	pr.err = auth.ErrPrincipalDisabled
	if code, body := bind("as-zed", "7070"); code != http.StatusForbidden || body["code"] != delegationCodeNotBound {
		t.Errorf("disabled owner = %d %v, want 403 %s", code, body, delegationCodeNotBound)
	}
	pr.err = errors.New("principal store down")
	if code, body := bind("as-zed", "7070"); code != http.StatusServiceUnavailable || body["code"] != delegationCodeUnavailable {
		t.Errorf("store outage = %d %v, want 503 %s", code, body, delegationCodeUnavailable)
	}
	if n := e.surfaceRefRows(id, "4242"); n != 0 {
		t.Errorf("a refused binding wrote %d rows", n)
	}
}

// A principal store that cannot check a prn_ owner is a 503 for the
// binding, never read as a match or a mismatch.
func TestDelegatedSurfaceRef_PrincipalLinkOwnerUncheckable(t *testing.T) {
	e, _ := newZedEnvWith(t, true)
	e.link("zed", "telegram", "7070")
	// The relay of zed's link needs the same check, so alice relays the item.
	e.link("alice", "telegram", "4242")
	_, created := e.relayCreate("telegram", "4242", nil)
	if created["work_item"] == nil {
		t.Fatalf("relayed create = %v", created)
	}
	id := created["work_item"].(map[string]any)["id"].(string)
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: id})
	e.users["as-zed"] = auth.NewDelegatedPrincipalUser("zed@example.com", zedPRN, false, []string{e.tenant}, agent)
	code, body := e.do("as-zed", "POST", "/api/v1/work-items/"+id+"/surface-refs", map[string]any{
		"surface": "telegram", "external_id": "chat-1", "actor_external_id": "7070",
	})
	if code != http.StatusServiceUnavailable || body["code"] != delegationCodeUnavailable {
		t.Fatalf("= %d %v, want 503 %s", code, body, delegationCodeUnavailable)
	}
}

// Outside principal mode a prn_ link would relay a subject with no tenants
// (they come from the principal, and only principal mode resolves them), so
// the challenge is refused up front rather than making a dead link. A
// GitHub human links as before.
func TestSurfaceIdentity_PrincipalLinkNeedsPrincipalMode(t *testing.T) {
	pr := &relayPrincipals{byLogin: map[string]string{"zed@example.com": zedPRN}}
	e := newSIDEnvOpts(t, pr, nil)
	zed := auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330001", "zed@example.com", auth.KindHuman)
	if err := auth.AttachPrincipal(context.Background(), pr, zed); err != nil {
		t.Fatal(err)
	}
	e.users["zed"] = zed
	code, body := e.do("zed", "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": "telegram"})
	if code != http.StatusForbidden || body["code"] != sidCodePrincipalModeRequired {
		t.Errorf("legacy-mode challenge by zed = %d %v, want 403 %s", code, body, sidCodePrincipalModeRequired)
	}
	e.challenge("alice", "telegram")
}

// hankPRN is one human reachable through GitHub and through ZITADEL.
const hankPRN = "prn_01JHANK0000000000000000000"

// A human who signs in through GitHub and through ZITADEL onto one principal
// keeps a link made in the ZITADEL session: the GitHub session lists and
// revokes it. Someone else's GitHub session still does neither.
func TestSurfaceIdentity_PrincipalLinkStaysTheHumansAcrossSessions(t *testing.T) {
	e, pr := newZedEnv(t)
	pr.byLogin["hank"] = hankPRN
	pr.byLogin["hank@example.com"] = hankPRN
	for name, u := range map[string]*auth.User{
		"hank-zitadel": auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330009", "hank@example.com", auth.KindHuman),
		"hank-github":  auth.NewGitHubUser("hank", nil),
	} {
		if err := auth.AttachPrincipal(context.Background(), pr, u); err != nil {
			t.Fatal(err)
		}
		if u.PrincipalID() != hankPRN {
			t.Fatalf("%s principal = %q, want %s", name, u.PrincipalID(), hankPRN)
		}
		e.users[name] = u
	}
	code, body := e.redeem("telegram", e.challenge("hank-zitadel", "telegram"), "8080")
	if code != http.StatusCreated {
		t.Fatalf("redeem = %d %v", code, body)
	}
	id := body["link"].(map[string]any)["id"].(string)
	// And a GitHub-held one, so the merged list is both.
	if code, body := e.redeem("portal", e.challenge("hank-github", "portal"), "hank-portal"); code != http.StatusCreated {
		t.Fatalf("github redeem = %d %v", code, body)
	}

	code, list := e.do("hank-github", "GET", "/api/v1/surface-identities", nil)
	links, _ := list["links"].([]any)
	if code != http.StatusOK || len(links) != 2 {
		t.Fatalf("hank's GitHub session lists %d %v, want both links", code, list)
	}
	if code, list := e.do("hank-github", "GET", "/api/v1/surface-identities?principal="+hankPRN, nil); code != http.StatusOK || len(list["links"].([]any)) != 1 {
		t.Errorf("hank's GitHub session listing %s = %d %v", hankPRN, code, list)
	}
	if code, _ := e.do("alice", "GET", "/api/v1/surface-identities?principal="+hankPRN, nil); code != http.StatusForbidden {
		t.Errorf("alice listing hank's principal = %d, want 403", code)
	}
	if code, _ := e.do("alice", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusNotFound {
		t.Errorf("alice revoking hank's link = %d, want 404", code)
	}
	code, body = e.do("hank-github", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil)
	if code != http.StatusOK || body["link"].(map[string]any)["revoked_by"] != "github:hank" {
		t.Fatalf("hank's GitHub session revoking the prn_ link = %d %v", code, body)
	}
}
