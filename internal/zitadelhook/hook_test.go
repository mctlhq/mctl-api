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

package zitadelhook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/gitops"
)

const (
	orgCustomers = "300000000000000001"
	orgAdmins    = "300000000000000002"
	idpGitHub    = "300000000000000003"
	loginClient  = "300000000000000004"
	clientWeb    = "300000000000000005"
)

type fakeTenants struct {
	tenants []gitops.Tenant
	err     error
}

func (f fakeTenants) ListTenantsStrict() ([]gitops.Tenant, error) { return f.tenants, f.err }

type ghEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// newHook returns a hook against a fake GitHub that serves emails (or the
// given status) for token "tok".
func newHook(t *testing.T, tenants TenantLister, emails []ghEmail, status int) *Hook {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/emails" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected", http.StatusTeapot)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(emails)
	}))
	t.Cleanup(gh.Close)
	if tenants == nil {
		tenants = fakeTenants{tenants: []gitops.Tenant{{Name: "acme", Members: []gitops.TenantMember{{UserID: "alice"}}},
			{Name: "multi", Teams: []gitops.Team{{Name: "x", Members: []gitops.TenantMember{{UserID: "TeamUser"}}}}}}}
	}
	h, err := New(Config{
		CustomersOrgID:    orgCustomers,
		GitHubIdPID:       idpGitHub,
		LoginClientUserID: loginClient,
		ClaimClientIDs:    []string{clientWeb},
		ReservedLogins:    []string{"AdminOne"},
		GitHubAPIURL:      gh.URL,
	}, tenants, gh.Client())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var verified = []ghEmail{{Email: "public@example.com", Primary: false, Verified: true}, {Email: "bob@example.com", Primary: true, Verified: true}}

func intentBody(idp, id, login, userID string, raw map[string]any) []byte {
	if raw == nil {
		raw = map[string]any{"id": json.Number(id), "login": login, "type": "User", "name": "Bob B", "email": "public@example.com"}
	}
	resp := map[string]any{
		"details": map[string]any{"sequence": "1"},
		"idpInformation": map[string]any{
			"oauth":          map[string]any{"accessToken": "tok"},
			"idpId":          idp,
			"userId":         id,
			"userName":       login,
			"rawInformation": raw,
		},
		"addHumanUser": map[string]any{"username": "public@example.com"},
	}
	if userID != "" {
		resp["userId"] = userID
	}
	b, _ := json.Marshal(map[string]any{"fullMethod": MethodIntentRetrieve, "response": resp})
	return b
}

func decodeResponse(t *testing.T, r Result) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return out
}

func refusedWith(t *testing.T, r Result, code int) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status %d (%s), want 200 refusal", r.Status, r.Reason)
	}
	out := decodeResponse(t, r)
	if got, _ := out["forwardedStatusCode"].(float64); int(got) != code {
		t.Fatalf("forwardedStatusCode %v (%s), want %d", out["forwardedStatusCode"], r.Reason, code)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestIntentCreatesCustomerAccount(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "Bob-B", "", nil))
	if r.Reason != "intent_create" {
		t.Fatalf("reason %s", r.Reason)
	}
	out := decodeResponse(t, r)
	if _, ok := out["addHumanUser"]; ok {
		t.Fatal("deprecated addHumanUser must be removed")
	}
	if _, ok := out["idpInformation"]; !ok {
		t.Fatal("other response fields must be kept")
	}
	cu := out["createUser"].(map[string]any)
	if cu["organizationId"] != orgCustomers {
		t.Fatalf("organizationId %v", cu["organizationId"])
	}
	if cu["username"] != "bob-b@mctl.ai" {
		t.Fatalf("username %v", cu["username"])
	}
	human := cu["human"].(map[string]any)
	email := human["email"].(map[string]any)
	if email["email"] != "bob@example.com" || email["isVerified"] != true {
		t.Fatalf("email %v: must be the primary verified address, not the public one", email)
	}
	links := human["idpLinks"].([]any)
	if len(links) != 1 || links[0].(map[string]any)["userId"] != "4242" || links[0].(map[string]any)["idpId"] != idpGitHub {
		t.Fatalf("idpLinks %v", links)
	}
	md := cu["metadata"].([]any)
	got := map[string]string{}
	for _, m := range md {
		mm := m.(map[string]any)
		v, _ := base64.StdEncoding.DecodeString(mm["value"].(string))
		got[mm["key"].(string)] = string(v)
	}
	if got[MetaGitHubID] != "4242" || got[MetaGitHubLogin] != "Bob-B" {
		t.Fatalf("metadata %v", got)
	}
	// The response the hook produced must pass its own creation gate.
	gate := h.CreateGate(context.Background(), createBodyFrom(t, cu, loginClient))
	if gate.Reason != "gate_customer_create" || len(gate.Body) != 0 {
		t.Fatalf("gate on hook output: %s %s", gate.Reason, gate.Body)
	}
}

func createBodyFrom(t *testing.T, req map[string]any, caller string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"fullMethod": MethodV2CreateUser, "orgID": orgAdmins, "userID": caller, "request": req})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIntentNameFallsBackToLogin(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	raw := map[string]any{"id": 4242, "login": "bob", "type": "User", "name": nil}
	out := decodeResponse(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", raw)))
	p := out["createUser"].(map[string]any)["human"].(map[string]any)["profile"].(map[string]any)
	if p["givenName"] != "bob" || p["familyName"] != "-" {
		t.Fatalf("profile %v", p)
	}
}

func TestIntentOtherIdPPassesThrough(t *testing.T) {
	h := newHook(t, nil, nil, http.StatusInternalServerError)
	r := h.Intent(context.Background(), intentBody("999", "4242", "bob", "", nil))
	if r.Status != http.StatusOK || len(r.Body) != 0 {
		t.Fatalf("got %d %q, want untouched pass-through", r.Status, r.Body)
	}
}

func TestIntentNoVerifiedEmailRefused(t *testing.T) {
	for name, emails := range map[string][]ghEmail{
		"public only":         {{Email: "public@example.com", Primary: false, Verified: true}},
		"primary unverified":  {{Email: "bob@example.com", Primary: true, Verified: false}},
		"none":                {},
		"primary not address": {{Email: "nonsense", Primary: true, Verified: true}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHook(t, nil, emails, 0)
			r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", nil))
			refusedWith(t, r, http.StatusPreconditionFailed)
		})
	}
}

func TestIntentGitHubDownFailsClosed(t *testing.T) {
	h := newHook(t, nil, nil, http.StatusBadGateway)
	r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", nil))
	if r.Status != http.StatusServiceUnavailable {
		t.Fatalf("status %d (%s), want 503", r.Status, r.Reason)
	}
}

func TestIntentReservedLoginsRefused(t *testing.T) {
	for _, login := range []string{"adminone", "ALICE", "teamuser", "acme"} {
		t.Run(login, func(t *testing.T) {
			h := newHook(t, nil, verified, 0)
			refusedWith(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", login, "", nil)), http.StatusForbidden)
		})
	}
}

func TestIntentReservedUnreadableFailsClosed(t *testing.T) {
	h := newHook(t, fakeTenants{err: errors.New("checkout not synced")}, verified, 0)
	r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", nil))
	if r.Status != http.StatusServiceUnavailable {
		t.Fatalf("status %d (%s), want 503", r.Status, r.Reason)
	}
}

func TestIntentNonUserAccountRefused(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	raw := map[string]any{"id": 4242, "login": "some-bot", "type": "Bot"}
	refusedWith(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "some-bot", "", raw)), http.StatusForbidden)
}

func TestIntentIDMismatchRefused(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	raw := map[string]any{"id": 1, "login": "bob", "type": "User"}
	refusedWith(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", raw)), http.StatusForbidden)
}

func TestIntentRawInformationRequired(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"no type":        {"id": 4242, "login": "bob"},
		"no id":          {"login": "bob", "type": "User"},
		"no login":       {"id": 4242, "type": "User"},
		"login mismatch": {"id": 4242, "login": "mallory", "type": "User"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHook(t, nil, verified, 0)
			refusedWith(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", raw)), http.StatusForbidden)
		})
	}
	// GitHub logins are case-insensitive; a case difference is not a mismatch.
	h := newHook(t, nil, verified, 0)
	raw := map[string]any{"id": 4242, "login": "Bob", "type": "User"}
	if r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "", raw)); r.Reason != "intent_create" {
		t.Fatalf("reason %s", r.Reason)
	}
}

func TestIntentUnparsableUserIDFailsClosed(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	var m map[string]any
	_ = json.Unmarshal(intentBody(idpGitHub, "4242", "bob", "", nil), &m)
	m["response"].(map[string]any)["userId"] = map[string]any{"x": 1}
	b, _ := json.Marshal(m)
	if r := h.Intent(context.Background(), b); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("status %d (%s), want 503", r.Status, r.Reason)
	}
}

func TestIntentExistingUserSurvivesGitHubOutage(t *testing.T) {
	h := newHook(t, nil, nil, http.StatusBadGateway)
	r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "u-1", nil))
	if r.Reason != "intent_update" {
		t.Fatalf("status %d reason %s, want intent_update", r.Status, r.Reason)
	}
	out := decodeResponse(t, r)
	if _, ok := out["updateUser"].(map[string]any)["human"].(map[string]any)["email"]; ok {
		t.Fatal("no email may be set when GitHub could not be read")
	}
}

func TestIntentReservedCheckedBeforeGitHub(t *testing.T) {
	// A reserved login is a 403 even while GitHub is down.
	h := newHook(t, nil, nil, http.StatusBadGateway)
	refusedWith(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "adminone", "", nil)), http.StatusForbidden)
}

func TestIntentExistingUserUpdatesLoginNotID(t *testing.T) {
	// A reserved tenant member login must not lock an existing customer
	// out: reservation applies at creation only.
	h := newHook(t, nil, verified, 0)
	r := h.Intent(context.Background(), intentBody(idpGitHub, "4242", "alice", "u-1", nil))
	if r.Reason != "intent_update" {
		t.Fatalf("reason %s", r.Reason)
	}
	out := decodeResponse(t, r)
	if _, ok := out["createUser"]; ok {
		t.Fatal("existing user must not get createUser")
	}
	uu := out["updateUser"].(map[string]any)
	if uu["userId"] != "u-1" {
		t.Fatalf("userId %v", uu["userId"])
	}
	md := uu["metadata"].([]any)
	if len(md) != 1 || md[0].(map[string]any)["key"] != MetaGitHubLogin {
		t.Fatalf("update must write github_login only, never github_id: %v", md)
	}
	if _, ok := uu["username"]; ok {
		t.Fatal("username is never changed on update")
	}
}

func TestIntentExistingUserWithoutVerifiedEmailKeepsStoredEmail(t *testing.T) {
	h := newHook(t, nil, []ghEmail{{Email: "bob@example.com", Primary: true}}, 0)
	out := decodeResponse(t, h.Intent(context.Background(), intentBody(idpGitHub, "4242", "bob", "u-1", nil)))
	if _, ok := out["updateUser"].(map[string]any)["human"].(map[string]any)["email"]; ok {
		t.Fatal("an unverified address must never replace the stored one")
	}
}

func TestIntentMalformed(t *testing.T) {
	h := newHook(t, nil, verified, 0)
	for name, body := range map[string]string{
		"not json":     `nope`,
		"no response":  `{"fullMethod":"` + MethodIntentRetrieve + `"}`,
		"wrong method": `{"fullMethod":"/x/Y","response":{"idpInformation":{"idpId":"` + idpGitHub + `"}}}`,
		"no idp info":  `{"fullMethod":"` + MethodIntentRetrieve + `","response":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if r := h.Intent(context.Background(), []byte(body)); r.Status != http.StatusServiceUnavailable {
				t.Fatalf("status %d (%s), want 503", r.Status, r.Reason)
			}
		})
	}
}

// ------------------------------------------------------------- gate

func goodCreate() map[string]any {
	return map[string]any{
		"organizationId": orgCustomers,
		"username":       "bob@mctl.ai",
		"human": map[string]any{
			"profile":  map[string]any{"givenName": "Bob", "familyName": "-"},
			"email":    map[string]any{"email": "bob@example.com", "isVerified": true},
			"idpLinks": []any{map[string]any{"idpId": idpGitHub, "userId": "4242", "userName": "bob"}},
		},
		"metadata": []any{
			map[string]any{"key": MetaGitHubID, "value": b64("4242")},
			map[string]any{"key": MetaGitHubLogin, "value": b64("bob")},
		},
	}
}

func TestGateAllowsHookShapedCreate(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	r := h.CreateGate(context.Background(), createBodyFrom(t, goodCreate(), loginClient))
	if r.Status != http.StatusOK || len(r.Body) != 0 {
		t.Fatalf("got %d %s (%s)", r.Status, r.Body, r.Reason)
	}
}

func TestGateRefusesEveryDeviation(t *testing.T) {
	cases := map[string]struct {
		mutate func(m map[string]any)
		caller string
	}{
		"other caller":     {func(map[string]any) {}, "someone-else"},
		"no caller":        {func(map[string]any) {}, ""},
		"unverified email": {func(m map[string]any) { hm(m)["email"] = map[string]any{"email": "bob@example.com"} }, loginClient},
		"no email":         {func(m map[string]any) { delete(hm(m), "email") }, loginClient},
		"no idp link":      {func(m map[string]any) { delete(hm(m), "idpLinks") }, loginClient},
		"two idp links": {func(m map[string]any) {
			hm(m)["idpLinks"] = append(hm(m)["idpLinks"].([]any), hm(m)["idpLinks"].([]any)[0])
		}, loginClient},
		"other idp": {func(m map[string]any) { link(m)["idpId"] = "999" }, loginClient},
		"github_id mismatch": {func(m map[string]any) {
			m["metadata"].([]any)[0] = map[string]any{"key": MetaGitHubID, "value": b64("1")}
		}, loginClient},
		"no github_id": {func(m map[string]any) { m["metadata"] = m["metadata"].([]any)[1:] }, loginClient},
		"conflicting dup meta": {func(m map[string]any) {
			// The later (human) entry matches the link; the conflict alone must refuse.
			m["metadata"].([]any)[0] = map[string]any{"key": MetaGitHubID, "value": b64("1")}
			hm(m)["metadata"] = []any{map[string]any{"key": MetaGitHubID, "value": b64("4242")}}
		}, loginClient},
		"human and machine": {func(m map[string]any) { m["machine"] = map[string]any{"name": "m"} }, loginClient},
		"wrong username":    {func(m map[string]any) { m["username"] = "bob@example.com" }, loginClient},
		"password":          {func(m map[string]any) { hm(m)["password"] = map[string]any{"password": "x"} }, loginClient},
		"hashed password":   {func(m map[string]any) { hm(m)["hashedPassword"] = map[string]any{"hash": "x"} }, loginClient},
		"totp":              {func(m map[string]any) { hm(m)["totpSecret"] = "x" }, loginClient},
		"machine":           {func(m map[string]any) { delete(m, "human"); m["machine"] = map[string]any{"name": "m"} }, loginClient},
		"reserved login": {func(m map[string]any) {
			link(m)["userName"] = "alice"
			m["username"] = "alice@mctl.ai"
			m["metadata"].([]any)[1] = map[string]any{"key": MetaGitHubLogin, "value": b64("alice")}
		}, loginClient},
		"github link outside customers": {func(m map[string]any) { m["organizationId"] = orgAdmins }, loginClient},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHook(t, nil, nil, 0)
			m := goodCreate()
			c.mutate(m)
			refusedWith(t, h.CreateGate(context.Background(), createBodyFrom(t, m, c.caller)), http.StatusForbidden)
		})
	}
}

func hm(m map[string]any) map[string]any { return m["human"].(map[string]any) }
func link(m map[string]any) map[string]any {
	return hm(m)["idpLinks"].([]any)[0].(map[string]any)
}

func TestGateCreateUserInOtherOrgPasses(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	req := map[string]any{"organizationId": orgAdmins, "username": "ops", "human": map[string]any{"email": map[string]any{"email": "ops@example.com"}}}
	r := h.CreateGate(context.Background(), createBodyFrom(t, req, "iac-user"))
	if r.Status != http.StatusOK || len(r.Body) != 0 {
		t.Fatalf("got %d %s (%s)", r.Status, r.Body, r.Reason)
	}
}

func TestGateCreateUserWithoutOrgUsesContextOrg(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	m := goodCreate()
	delete(m, "organizationId")
	b, _ := json.Marshal(map[string]any{"fullMethod": MethodV2CreateUser, "orgID": orgCustomers, "userID": loginClient, "request": m})
	// Organization only from context: still customers rules, and the
	// request does not name customers explicitly, so it is refused.
	refusedWith(t, h.CreateGate(context.Background(), b), http.StatusForbidden)
}

func TestGateOtherMethods(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	refuse := map[string]map[string]any{
		"v2 AddHumanUser by org id":     {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"orgId": orgCustomers}}},
		"v2 AddHumanUser by domain":     {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"orgDomain": "MCTL.ai"}}},
		"v2 AddHumanUser context org":   {"fullMethod": MethodV2AddHumanUser, "orgID": orgCustomers, "request": map[string]any{"username": "x"}},
		"v2beta AddHumanUser":           {"fullMethod": MethodV2BetaAddHumanUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"orgId": orgCustomers}}},
		"v2 AddHumanUser github link":   {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"idpLinks": []any{map[string]any{"idpId": idpGitHub}}}},
		"mgmt ImportHumanUser":          {"fullMethod": MethodMgmtImportHumanUser, "orgID": orgCustomers, "request": map[string]any{"userName": "x"}},
		"mgmt AddHumanUser":             {"fullMethod": MethodMgmtAddHumanUser, "orgID": orgCustomers, "request": map[string]any{"userName": "x"}},
		"mgmt AddMachineUser":           {"fullMethod": MethodMgmtAddMachineUser, "orgID": orgCustomers, "request": map[string]any{"userName": "x"}},
		"mgmt ImportHumanUser idp link": {"fullMethod": MethodMgmtImportHumanUser, "orgID": orgAdmins, "request": map[string]any{"idps": []any{map[string]any{"configId": idpGitHub}}}},
		"admin ImportData":              {"fullMethod": MethodAdminImportData, "orgID": orgAdmins, "request": map[string]any{"dataOrgs": map[string]any{"orgs": []any{map[string]any{"orgId": orgCustomers}}}}},
		"v3alpha CreateUser":            {"fullMethod": MethodV3AlphaCreateUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"orgId": orgCustomers}}},
		"v2 AddHumanUser other domain":  {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"orgDomain": "customers.auth.example"}}},
		"v2 AddHumanUser snake domain":  {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"organization": map[string]any{"org_domain": "x"}}},
		"v2 AddIDPLink github":          {"fullMethod": MethodV2AddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": idpGitHub}}},
		"v2beta AddIDPLink github":      {"fullMethod": MethodV2BetaAddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": idpGitHub}}},
		"v3alpha AddIDPAuthenticator":   {"fullMethod": MethodV3AlphaAddIDPAuthenticator, "orgID": orgAdmins, "request": map[string]any{"id": "u-9", "authenticator": map[string]any{"idpId": idpGitHub}}},
		"v2 AddIDPLink in customers":    {"fullMethod": MethodV2AddIDPLink, "orgID": orgCustomers, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": "777"}}},
		"unknown method":                {"fullMethod": "/zitadel.user.v9.UserService/MakeUser", "orgID": orgAdmins, "request": map[string]any{}},
	}
	for name, p := range refuse {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(p)
			refusedWith(t, h.CreateGate(context.Background(), b), http.StatusForbidden)
		})
	}
	pass := map[string]map[string]any{
		"v2 AddHumanUser admin org":   {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"username": "ops"}},
		"mgmt AddMachineUser admin":   {"fullMethod": MethodMgmtAddMachineUser, "orgID": orgAdmins, "request": map[string]any{"userName": "svc"}},
		"mgmt ImportHumanUser tenant": {"fullMethod": MethodMgmtImportHumanUser, "orgID": "300000000000000099", "request": map[string]any{"userName": "x"}},
		"v2 AddIDPLink other idp":     {"fullMethod": MethodV2AddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": "777"}}},
		"v2beta AddIDPLink other idp": {"fullMethod": MethodV2BetaAddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": "777"}}},
		"v3alpha AddIDPAuth other":    {"fullMethod": MethodV3AlphaAddIDPAuthenticator, "orgID": orgAdmins, "request": map[string]any{"id": "u-9", "authenticator": map[string]any{"idpId": "777"}}},
	}
	for name, p := range pass {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(p)
			if r := h.CreateGate(context.Background(), b); r.Status != http.StatusOK || len(r.Body) != 0 {
				t.Fatalf("got %d %s (%s), want pass-through", r.Status, r.Body, r.Reason)
			}
		})
	}
}

func TestGateCreateUserUnrecognisedShapeRefused(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	for name, req := range map[string]map[string]any{
		"empty request": {},
		// snake_case names customers but parses as neither human nor machine.
		"snake case org": {"organization_id": orgCustomers, "user_name": "x"},
		// A field rename leaves organizationId empty; the raw org id still counts.
		"renamed org field": {"orgId": orgCustomers, "username": "x", "human": map[string]any{}},
		"renamed idp field": {"organizationId": orgAdmins, "human": map[string]any{"links": []any{map[string]any{"provider": idpGitHub}}}},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"fullMethod": MethodV2CreateUser, "orgID": orgAdmins, "userID": "iac-user", "request": req})
			refusedWith(t, h.CreateGate(context.Background(), b), http.StatusForbidden)
		})
	}
}

func TestGateUnparsable(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	for _, body := range []string{`nope`, `{"fullMethod":"` + MethodV2CreateUser + `"}`} {
		if r := h.CreateGate(context.Background(), []byte(body)); r.Status != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d", body, r.Status)
		}
	}
}

// ------------------------------------------------------------ tokens

func tokenBody(org, client string, meta map[string]string) []byte {
	var md []map[string]any
	for k, v := range meta {
		md = append(md, map[string]any{"key": k, "value": b64(v)})
	}
	b, _ := json.Marshal(map[string]any{
		"function":      "function/preuserinfo",
		"user":          map[string]any{"id": "u-1", "resource_owner": org},
		"user_metadata": md,
		"application":   map[string]any{"client_id": client},
	})
	return b
}

func claimsOf(t *testing.T, r Result) map[string]any {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status %d (%s)", r.Status, r.Reason)
	}
	var out struct {
		AppendClaims []struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		} `json:"append_claims"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	m := map[string]any{}
	for _, c := range out.AppendClaims {
		m[c.Key] = c.Value
	}
	return m
}

func TestTokenClaimsForCustomer(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	c := claimsOf(t, h.TokenClaims(context.Background(), tokenBody(orgCustomers, clientWeb, map[string]string{MetaGitHubID: "4242", MetaGitHubLogin: "bob"})))
	if c[ClaimGitHubID] != "4242" || c[ClaimGitHubLogin] != "bob" || c[ClaimOrg] != "customers" || c[ClaimIdP] != "github" {
		t.Fatalf("claims %v", c)
	}
	if _, ok := c[ClaimRefused]; ok {
		t.Fatal("unexpected refusal")
	}
}

func TestTokenClaimsPreAccessTokenToo(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	body := strings.Replace(string(tokenBody(orgCustomers, clientWeb, map[string]string{MetaGitHubID: "4242", MetaGitHubLogin: "bob"})), "preuserinfo", "preaccesstoken", 1)
	if c := claimsOf(t, h.TokenClaims(context.Background(), []byte(body))); c[ClaimGitHubID] != "4242" {
		t.Fatalf("claims %v", c)
	}
}

func TestTokenClaimsNone(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	meta := map[string]string{MetaGitHubID: "4242", MetaGitHubLogin: "bob"}
	for name, body := range map[string][]byte{
		"admin org":       tokenBody(orgAdmins, clientWeb, meta),
		"unlisted client": tokenBody(orgCustomers, "other-client", meta),
	} {
		t.Run(name, func(t *testing.T) {
			if c := claimsOf(t, h.TokenClaims(context.Background(), body)); len(c) != 0 {
				t.Fatalf("claims %v, want none", c)
			}
		})
	}
}

func TestTokenClaimsRefusals(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	for name, tc := range map[string]struct {
		meta map[string]string
		want string
	}{
		"no github_id":       {map[string]string{MetaGitHubLogin: "bob"}, RefusedNoGitHubIdentity},
		"non-numeric id":     {map[string]string{MetaGitHubID: "abc", MetaGitHubLogin: "bob"}, RefusedNoGitHubIdentity},
		"no login":           {map[string]string{MetaGitHubID: "4242"}, RefusedNoGitHubIdentity},
		"renamed to admin":   {map[string]string{MetaGitHubID: "4242", MetaGitHubLogin: "adminone"}, RefusedLoginReserved},
		"no metadata at all": {nil, RefusedNoGitHubIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			c := claimsOf(t, h.TokenClaims(context.Background(), tokenBody(orgCustomers, clientWeb, tc.meta)))
			if c[ClaimRefused] != tc.want || c[ClaimGitHubID] != nil {
				t.Fatalf("claims %v, want only %s=%s", c, ClaimRefused, tc.want)
			}
		})
	}
}

func TestTokenClaimsTenantMemberLoginNotRefused(t *testing.T) {
	// A customer who now owns workspace "acme" is its member under their
	// own login; that must not refuse their tokens.
	h := newHook(t, nil, nil, 0)
	c := claimsOf(t, h.TokenClaims(context.Background(), tokenBody(orgCustomers, clientWeb, map[string]string{MetaGitHubID: "4242", MetaGitHubLogin: "alice"})))
	if c[ClaimGitHubID] != "4242" {
		t.Fatalf("claims %v", c)
	}
}

func TestTokenClaimsMalformed(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	for _, body := range []string{`nope`, `{"function":"function/presamlresponse"}`} {
		if r := h.TokenClaims(context.Background(), []byte(body)); r.Status != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d", body, r.Status)
		}
	}
}

func TestNewRequiresConfig(t *testing.T) {
	full := Config{CustomersOrgID: "a", GitHubIdPID: "b", LoginClientUserID: "c", ClaimClientIDs: []string{"d"}}
	if _, err := New(full, fakeTenants{}, nil); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"org":     func(c *Config) { c.CustomersOrgID = "" },
		"idp":     func(c *Config) { c.GitHubIdPID = "" },
		"login":   func(c *Config) { c.LoginClientUserID = "" },
		"clients": func(c *Config) { c.ClaimClientIDs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := full
			mut(&c)
			if _, err := New(c, fakeTenants{}, nil); err == nil {
				t.Fatal("want error")
			}
		})
	}
	if _, err := New(full, nil, nil); err == nil {
		t.Fatal("nil tenants must be refused")
	}
}
