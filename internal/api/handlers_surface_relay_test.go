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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// link makes a verified link the way the protocol does: the human asks for
// a challenge, the surface principal redeems it.
func (e *sidEnv) link(who, surface, externalID string) string {
	e.t.Helper()
	code, body := e.redeem(surface, e.challenge(who, surface), externalID)
	if code != http.StatusCreated {
		e.t.Fatalf("link %s %s:%s = %d %v", who, surface, externalID, code, body)
	}
	return body["link"].(map[string]any)["id"].(string)
}

func (e *sidEnv) relayCreate(surface, externalID string, body map[string]any) (int, map[string]any) {
	e.t.Helper()
	if body == nil {
		body = map[string]any{"tenant": e.tenant, "title": "relayed"}
	}
	return e.do(surface, "POST", "/api/v1/work-items", body, SurfaceActorHeader, externalID)
}

func TestSurfaceRelay_FailsClosed(t *testing.T) {
	e := newSIDEnv(t)
	e.link("alice", "telegram", "4242")
	revoked := e.link("bob", "telegram", "555")
	if code, _ := e.do("bob", "POST", "/api/v1/surface-identities/"+revoked+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	e.link("bob", "telegram", "777")
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE surface_identity_links SET expires_at=$1 WHERE external_id='777'`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, who, externalID string
		want                  int
		code                  string
	}{
		{"no actor named", "telegram", "", http.StatusForbidden, sidCodeRelayRequired},
		{"unknown link", "telegram", "999", http.StatusForbidden, sidCodeNotFound},
		{"forged external_id", "telegram", "42420", http.StatusForbidden, sidCodeNotFound},
		{"revoked link", "telegram", "555", http.StatusForbidden, sidCodeLinkRevoked},
		{"expired link", "telegram", "777", http.StatusForbidden, sidCodeLinkExpired},
		// alice's link is a telegram link: the portal principal cannot use it.
		{"wrong surface", "portal", "4242", http.StatusForbidden, sidCodeNotFound},
		// mctl-agent has no relay authority at all.
		{"service principal", "service", "4242", http.StatusBadRequest, sidCodeActorNotAccepted},
		{"a human naming someone", "bob", "4242", http.StatusBadRequest, sidCodeActorNotAccepted},
	} {
		code, body := e.relayCreate(c.who, c.externalID, nil)
		if code != c.want || body["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, code, body)
		}
	}
	// Every human-input and work-item relay route relays: none runs as the
	// surface principal itself.
	for _, route := range [][2]string{
		{"GET", "/api/v1/human-input"},
		{"GET", "/api/v1/human-input/hir-x"},
		{"POST", "/api/v1/human-input/hir-x/response"},
		{"POST", "/api/v1/work-items"},
		{"GET", "/api/v1/work-items/wi_x"},
		{"POST", "/api/v1/work-items/wi_x/intents"},
		{"POST", "/api/v1/work-items/wi_x/surface-refs"},
		{"POST", "/api/v1/work-items/wi_x/execution-requests"},
		{"GET", "/api/v1/work-items/wi_x/execution-requests"},
		{"GET", "/api/v1/work-items/wi_x/execution-requests/xr_x"},
	} {
		if code, body := e.do("telegram", route[0], route[1], nil); code != http.StatusForbidden || body["code"] != sidCodeRelayRequired {
			t.Errorf("%s %s without an actor = %d %v", route[0], route[1], code, body)
		}
	}
	// Resume declares engine identity, so it is no relay route at all
	// (mctl-api#368): a surface requests execution instead.
	if code, body := e.do("telegram", "POST", "/api/v1/work-items/wi_x/resume", nil, SurfaceActorHeader, "4242"); code != http.StatusForbidden || body["code"] != sidCodeRouteNotAllowed {
		t.Errorf("relayed resume = %d %v", code, body)
	}
	// Redeem is not a relay route: the surface acts as itself there, so an
	// already-linked actor gains nothing — the challenge is still checked.
	if code, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem",
		map[string]any{"code": "AAAA-AAAA"}, SurfaceActorHeader, "4242"); code != http.StatusForbidden || body["code"] != sidCodeChallengeInvalid {
		t.Errorf("redeem by a linked actor = %d %v", code, body)
	}
	// Caller-supplied actor in a relayed body.
	if code, body := e.relayCreate("telegram", "4242",
		map[string]any{"tenant": e.tenant, "title": "x", "created_by": "github:bob"}); code != http.StatusBadRequest || body["code"] != "actor_not_accepted" {
		t.Errorf("relayed body naming an actor = %d %v", code, body)
	}

	var refusals int
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "surface_identity.relay_refused" {
			refusals++
			if entry.Parameters["acting_principal"] == "" || entry.Parameters["reason"] == "" {
				t.Errorf("relay_refused audit = %v", entry.Parameters)
			}
		}
	}
	if refusals == 0 {
		t.Error("no relay_refused audit rows")
	}
}

func TestSurfaceRelay_WorkItemsAttributeToTheHuman(t *testing.T) {
	e := newSIDEnv(t)
	e.link("alice", "telegram", "4242")

	code, body := e.relayCreate("telegram", "4242", nil)
	if code != http.StatusCreated {
		t.Fatalf("relayed create = %d %v", code, body)
	}
	item := body["work_item"].(map[string]any)
	if item["owner_principal"] != "github:alice" || item["origin_surface"] != "telegram" {
		t.Fatalf("relayed item = %v", item)
	}
	id := item["id"].(string)
	if code, body := e.do("telegram", "POST", "/api/v1/work-items/"+id+"/intents",
		map[string]any{"text": "retry it"}, SurfaceActorHeader, "4242"); code != http.StatusCreated {
		t.Fatalf("relayed intent = %d %v", code, body)
	}
	if code, body := e.do("telegram", "GET", "/api/v1/work-items/"+id, nil, SurfaceActorHeader, "4242"); code != http.StatusOK {
		t.Fatalf("relayed get = %d %v", code, body)
	}

	// Both identities, never collapsed: the event row and the audit.
	rows, err := e.pool.Query(context.Background(),
		`SELECT actor_principal, acting_principal, surface FROM work_item_events WHERE work_item_id=$1 ORDER BY seq`, id)
	if err != nil {
		t.Fatal(err)
	}
	var events int
	for rows.Next() {
		var actor, acting, surface string
		if err := rows.Scan(&actor, &acting, &surface); err != nil {
			t.Fatal(err)
		}
		events++
		if actor != "github:alice" || acting != "surface:telegram" || surface != "telegram" {
			t.Errorf("event = actor %q acting %q surface %q", actor, acting, surface)
		}
	}
	rows.Close()
	if events < 2 {
		t.Fatalf("events = %d", events)
	}
	var audited int
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "work_item.create" || entry.Operation == "work_item.intent" {
			audited++
			if entry.UserID != "alice" || entry.Parameters["actor"] != "github:alice" || entry.Parameters["acting_principal"] != "surface:telegram" {
				t.Errorf("%s audit = user %q %v", entry.Operation, entry.UserID, entry.Parameters)
			}
		}
	}
	if audited != 2 {
		t.Fatalf("audited = %d", audited)
	}

	// A relayed request speaks for its own surface only.
	if code, body := e.relayCreate("telegram", "4242",
		map[string]any{"tenant": e.tenant, "title": "x", "origin_surface": "portal"}); code != http.StatusBadRequest {
		t.Errorf("relayed create claiming portal = %d %v", code, body)
	}
	if code, body := e.do("telegram", "POST", "/api/v1/work-items/"+id+"/intents",
		map[string]any{"text": "x", "surface": "cli"}, SurfaceActorHeader, "4242"); code != http.StatusBadRequest {
		t.Errorf("relayed intent claiming cli = %d %v", code, body)
	}
	// Relaying never confers admin: alice's resolver groups include
	// "admins", yet her relayed self reaches only her own tenants.
	if code, body := e.relayCreate("telegram", "4242",
		map[string]any{"tenant": "acme", "title": "x"}); code != http.StatusForbidden {
		t.Errorf("relayed create in a foreign tenant = %d %v", code, body)
	}
}

func TestSurfaceRelay_HumanInputAnswerIsTheHumansCarriedByTheSurface(t *testing.T) {
	h, tc, _, log := newHumanInputResponseHandlers(t)
	tc.onSignal = workflowAccepts
	telegram := auth.NewSurfaceUser("telegram")
	relayedAlice := auth.NewRelayedUser("alice", nil, telegram)
	body := `{"request_hash":"` + hiASCIIHash + `","value":"library A"}`

	// The surface cannot answer as itself, nor relay for someone the
	// request does not name, nor claim another surface.
	for name, tt := range map[string]struct {
		u    *auth.User
		body string
		code int
	}{
		"surface principal itself": {telegram, body, http.StatusNotFound},
		"relayed non-respondent":   {auth.NewRelayedUser("bob", nil, telegram), body, http.StatusNotFound},
		"relayed, claiming portal": {relayedAlice, answer(`"library A"`), http.StatusBadRequest},
	} {
		if got := respond(t, h, tt.u, hiASCII, tt.body); got.code != tt.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, tt.code)
		}
	}
	if len(tc.humanInputSignals) != 0 {
		t.Fatalf("signals = %v", tc.humanInputSignals)
	}

	got := respond(t, h, relayedAlice, hiASCII, body)
	if got.code != http.StatusOK || got.res.Respondent != "github:alice" {
		t.Fatalf("relayed answer = %d %s", got.code, got.raw)
	}
	if doc := tc.humanInputSignals[0]; doc["surface"] != "telegram" {
		t.Errorf("signal surface = %v, want telegram", doc["surface"])
	}
	var accepted bool
	for _, e := range log.List(100) {
		if e.Operation == "human_input.response_accepted" {
			accepted = true
			if e.UserID != "alice" || e.Parameters["respondent"] != "github:alice" ||
				e.Parameters["acting_principal"] != "surface:telegram" || e.Parameters["surface"] != "telegram" {
				t.Errorf("accepted audit = user %q %v", e.UserID, e.Parameters)
			}
		}
	}
	if !accepted {
		t.Fatalf("audit = %v", auditOps(log))
	}
}

// A link is made by the human directly: a relayed subject cannot mint a
// challenge (and so cannot chain one link into another), even if a route
// ever let it reach the handler.
func TestSurfaceRelay_RelayedSubjectCannotCreateAChallenge(t *testing.T) {
	h := &Handlers{opts: Options{SurfaceIdentities: &surfaceid.Store{}}}
	req := httptest.NewRequest("POST", "/api/v1/surface-identities/challenges", strings.NewReader(`{"surface":"portal"}`))
	relayed := auth.NewRelayedUser("alice", nil, auth.NewSurfaceUser("telegram"))
	req = req.WithContext(auth.WithUser(req.Context(), relayed))
	rec := httptest.NewRecorder()
	h.CreateSurfaceChallenge(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("relayed challenge = %d %s", rec.Code, rec.Body)
	}
}

func TestRelayedUserIsNeverAdminAndNeedsASurface(t *testing.T) {
	telegram := auth.NewSurfaceUser("telegram")
	u := auth.NewRelayedUser("alice", []string{"acme", "admins"}, telegram)
	if u.IsAdmin() || !u.HasTenantAccess("acme") || u.HasTenantAccess("other") {
		t.Fatalf("relayed groups = %v", u.Groups)
	}
	if login, ok := u.GitHubLogin(); !ok || login != "alice" || u.ActingPrincipal() != "surface:telegram" || u.IsService() {
		t.Fatalf("relayed user = %+v", u)
	}
	if s, ok := u.RelaySurface(); !ok || s != "telegram" {
		t.Fatalf("relay surface = %q %v", s, ok)
	}
	for _, acting := range []*auth.User{auth.NewServiceUser(), auth.NewGitHubUser("root", []string{"admins"})} {
		if auth.NewRelayedUser("alice", nil, acting) != nil {
			t.Errorf("%s may relay", acting.ID)
		}
	}
}

// Relayed calls, and relay calls the gate refuses, count against the
// surface's aggregate ceiling like any other call it makes.
func TestSurfaceRelay_CountsAgainstTheSurfaceCeiling(t *testing.T) {
	e := newSIDEnv(t)
	limited := false
	for i := 1; i <= surfaceAggregateLimitPerMinute+5 && !limited; i++ {
		code, _ := e.do("telegram", "GET", "/api/v1/work-items/wi_x", nil, SurfaceActorHeader, strconv.Itoa(i))
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("relay calls never reached the surface ceiling")
	}
}

// Review follow-ups from #358 (P3): listing takes the same reading as
// revoking, a redeem must name its identity at the gate, and retiring an
// expired link is audited.
func TestSurfaceIdentity_ReviewFollowUps(t *testing.T) {
	e := newSIDEnv(t)
	e.users["dexadmin"] = &auth.User{ID: "root", Groups: []string{"admins"}}
	e.link("alice", "telegram", "4242")
	if code, body := e.do("dexadmin", "GET", "/api/v1/surface-identities?principal=github:alice", nil); code != http.StatusForbidden {
		t.Errorf("an unverified admin listing alice = %d %v", code, body)
	}
	if code, body := e.do("alice", "GET", "/api/v1/surface-identities?principal=github:alice", nil); code != http.StatusOK {
		t.Errorf("alice naming herself = %d %v", code, body)
	}

	for i := 0; i < 25; i++ {
		if code, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem", map[string]any{"code": "AAAA"}); code != http.StatusBadRequest {
			t.Fatalf("redeem without an actor, attempt %d = %d %v", i, code, body)
		}
	}

	if _, err := e.pool.Exec(context.Background(),
		`UPDATE surface_identity_links SET expires_at=$1 WHERE external_id='4242'`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.link("bob", "telegram", "4242")
	var retired bool
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "surface_identity.revoked" && entry.Parameters["subject"] == "github:alice" {
			retired = entry.Parameters["revoked_by"] == surfaceid.RevokedByExpiry && entry.Parameters["acting_principal"] == "surface:telegram"
		}
	}
	if !retired {
		t.Fatal("retiring alice's expired link left no audit row")
	}
	var by string
	if err := e.pool.QueryRow(context.Background(),
		`SELECT revoked_by FROM surface_identity_links WHERE principal='github:alice' AND external_id='4242'`).Scan(&by); err != nil || by != surfaceid.RevokedByExpiry {
		t.Fatalf("revoked_by = %q, %v", by, err)
	}
}

// #359 review: a failed tenant lookup grants nothing even with a partial
// list; every 403 relay refusal is audited, including a missing header and
// a link that does not name a GitHub principal; surface-refs relays.
func TestSurfaceRelay_ReviewFollowUps(t *testing.T) {
	e := newSIDEnv(t)
	e.link("carol", "telegram", "3333")
	if code, body := e.relayCreate("telegram", "3333", nil); code != http.StatusForbidden {
		t.Errorf("relay after a failed tenant lookup = %d %v", code, body)
	}

	if _, err := e.pool.Exec(context.Background(), `INSERT INTO surface_identity_links
		(id, surface, external_id, principal, challenge_id, created_at) VALUES ('sil_dex','telegram','9191','dex:bob','sic_x',now())`); err != nil {
		t.Fatal(err)
	}
	if code, body := e.relayCreate("telegram", "9191", nil); code != http.StatusForbidden || body["code"] != sidCodeNotFound {
		t.Errorf("relay through a non-GitHub link = %d %v", code, body)
	}
	e.relayCreate("telegram", "", nil)
	reasons := map[string]bool{}
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "surface_identity.relay_refused" {
			reasons[entry.Parameters["external_id"]+"/"+entry.Parameters["reason"]] = true
		}
	}
	if !reasons["9191/"+sidCodeNotFound] || !reasons["/"+sidCodeRelayRequired] {
		t.Errorf("relay_refused audit = %v", reasons)
	}

	e.link("alice", "telegram", "4242")
	_, body := e.relayCreate("telegram", "4242", nil)
	id := body["work_item"].(map[string]any)["id"].(string)
	if code, body := e.do("telegram", "POST", "/api/v1/work-items/"+id+"/surface-refs",
		map[string]any{"external_id": "chat-9"}, SurfaceActorHeader, "4242"); code != http.StatusCreated {
		t.Fatalf("relayed surface-ref = %d %v", code, body)
	}
	var surface, acting string
	if err := e.pool.QueryRow(context.Background(), `SELECT surface, acting_principal FROM work_item_events
		WHERE work_item_id=$1 AND kind='surface_linked'`, id).Scan(&surface, &acting); err != nil || surface != "telegram" || acting != "surface:telegram" {
		t.Fatalf("surface_linked event = %q %q %v", surface, acting, err)
	}
}
