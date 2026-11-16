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
	"sync/atomic"
	"testing"
)

const (
	idpGoogle = "300000000000000006"
	googleSub = "109876543210987654321"
)

// newGoogleHook returns a hook with both customers IdPs configured. Its
// fake GitHub counts calls: the Google path must make none. Reserved
// logins, the tenant reader, the invitation store and the deletion probe
// all refuse or fail, so a Google creation that consulted any of them
// would not pass.
func newGoogleHook(t *testing.T, googleSubs []string) (*Hook, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	t.Cleanup(gh.Close)
	h, err := New(Config{
		CustomersOrgID:    orgCustomers,
		GitHubIdPID:       idpGitHub,
		GoogleIdPID:       idpGoogle,
		LoginClientUserID: loginClient,
		ClaimClientIDs:    []string{clientWeb},
		ReservedLogins:    []string{"AdminOne"},
		GitHubAPIURL:      gh.URL,

		CustomerCreateGitHubIDs:  []string{CreateAnyone},
		CustomerCreateGoogleSubs: googleSubs,
		CustomerInvitationAllowed: func(context.Context, string) (bool, error) {
			t.Error("the GitHub invitation store must not be consulted for Google")
			return false, nil
		},
		// The deletion probe is consulted for a Google creation too, keyed
		// on the Google subject; it reports nothing pending here.
		CreationPending: func(_ context.Context, provider, subject string) (bool, error) {
			if provider != IdPGoogle || !googleSubRE.MatchString(subject) {
				t.Errorf("deletion probe asked for %s %q, want a Google subject", provider, subject)
			}
			return false, nil
		},
	}, fakeTenants{err: errFakeTenants}, gh.Client())
	if err != nil {
		t.Fatal(err)
	}
	return h, &calls
}

var errFakeTenants = &json.UnsupportedValueError{Str: "tenant reader must not be read for Google"}

func googleRaw() map[string]any {
	return map[string]any{
		"sub": googleSub, "email": "carol@gmail.com", "email_verified": true,
		"name": "Carol C", "given_name": "Carol", "family_name": "C",
	}
}

func googleIntentBody(idp, sub, userID string, raw map[string]any) []byte {
	resp := map[string]any{
		"details": map[string]any{"sequence": "1"},
		"idpInformation": map[string]any{
			"oauth":          map[string]any{"accessToken": "gtok", "idToken": "x.y.z"},
			"idpId":          idp,
			"userId":         sub,
			"userName":       "carol@gmail.com",
			"rawInformation": raw,
		},
		"addHumanUser": map[string]any{"username": "carol@gmail.com"},
	}
	if userID != "" {
		resp["userId"] = userID
	}
	b, _ := json.Marshal(map[string]any{"fullMethod": MethodIntentRetrieve, "response": resp})
	return b
}

func metaOf(t *testing.T, cu map[string]any) map[string]string {
	t.Helper()
	got := map[string]string{}
	md, _ := cu["metadata"].([]any)
	for _, m := range md {
		mm := m.(map[string]any)
		v, _ := base64.StdEncoding.DecodeString(mm["value"].(string))
		got[mm["key"].(string)] = string(v)
	}
	return got
}

func TestGoogleIntentCreatesCustomerAccount(t *testing.T) {
	h, calls := newGoogleHook(t, []string{CreateAnyone})
	r := h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "", googleRaw()))
	if r.Reason != "intent_create" {
		t.Fatalf("reason %s %s", r.Reason, r.Body)
	}
	if calls.Load() != 0 {
		t.Fatalf("the Google path called GitHub %d times", calls.Load())
	}
	out := decodeResponse(t, r)
	if _, ok := out["addHumanUser"]; ok {
		t.Fatal("ZITADEL's proposed user action must be removed")
	}
	cu := out["createUser"].(map[string]any)
	if cu["organizationId"] != orgCustomers {
		t.Fatalf("organizationId %v", cu["organizationId"])
	}
	if cu["username"] != "google."+googleSub+"@mctl.ai" {
		t.Fatalf("username %v", cu["username"])
	}
	human := cu["human"].(map[string]any)
	if e := human["email"].(map[string]any); e["email"] != "carol@gmail.com" || e["isVerified"] != true {
		t.Fatalf("email %v", e)
	}
	if p := human["profile"].(map[string]any); p["displayName"] != "Carol C" {
		t.Fatalf("profile %v", p)
	}
	links := human["idpLinks"].([]any)
	l := links[0].(map[string]any)
	if len(links) != 1 || l["idpId"] != idpGoogle || l["userId"] != googleSub || l["userName"] != "carol@gmail.com" {
		t.Fatalf("idpLinks %v", links)
	}
	if got := metaOf(t, cu); len(got) != 1 || got[MetaGoogleSub] != googleSub {
		t.Fatalf("metadata %v, want only %s", got, MetaGoogleSub)
	}
	// The hook's own output passes its gate, without the tenant reader,
	// the invitation store or the deletion probe.
	gate := h.CreateGate(context.Background(), createBodyFrom(t, cu, loginClient))
	if gate.Reason != "gate_customer_create" || len(gate.Body) != 0 {
		t.Fatalf("gate on hook output: %s %s", gate.Reason, gate.Body)
	}
}

// A Google username can never equal a GitHub-derived one: the dot is not
// in GitHub's login grammar.
func TestGoogleUsernameNamespaceDisjointFromGitHub(t *testing.T) {
	h, _ := newGoogleHook(t, nil)
	local := strings.TrimSuffix(h.googleUsername(googleSub), "@mctl.ai")
	if githubLoginRE.MatchString(local) {
		t.Fatalf("%q is a valid GitHub login; the namespaces would collide", local)
	}
}

func TestGoogleIntentCreationAllowlist(t *testing.T) {
	for name, tc := range map[string]struct {
		subs []string
		want string
	}{
		"unset":     {nil, "intent_customer_create_not_allowed:google:" + googleSub},
		"other sub": {[]string{"1"}, "intent_customer_create_not_allowed:google:" + googleSub},
		"listed":    {[]string{"1", googleSub}, "intent_create"},
		"anyone":    {[]string{CreateAnyone}, "intent_create"},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newGoogleHook(t, tc.subs)
			r := h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "", googleRaw()))
			if r.Reason != tc.want {
				t.Fatalf("reason %s, want %s", r.Reason, tc.want)
			}
			if strings.Contains(r.Reason, "carol") {
				t.Fatal("the reason must never carry the email")
			}
		})
	}
}

func TestGoogleIntentRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		sub    string
		mutate func(map[string]any)
		code   int
	}{
		"non-numeric sub":        {"abc", func(m map[string]any) { m["sub"] = "abc" }, http.StatusForbidden},
		"sub mismatch":           {googleSub, func(m map[string]any) { m["sub"] = "1" }, http.StatusForbidden},
		"no sub in userinfo":     {googleSub, func(m map[string]any) { delete(m, "sub") }, http.StatusForbidden},
		"numeric sub in raw":     {googleSub, func(m map[string]any) { m["sub"] = json.Number(googleSub) }, http.StatusForbidden},
		"email not verified":     {googleSub, func(m map[string]any) { m["email_verified"] = false }, http.StatusPreconditionFailed},
		"email_verified missing": {googleSub, func(m map[string]any) { delete(m, "email_verified") }, http.StatusPreconditionFailed},
		"email_verified string":  {googleSub, func(m map[string]any) { m["email_verified"] = "true" }, http.StatusPreconditionFailed},
		"no email":               {googleSub, func(m map[string]any) { delete(m, "email") }, http.StatusPreconditionFailed},
		"malformed email":        {googleSub, func(m map[string]any) { m["email"] = "carol" }, http.StatusPreconditionFailed},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newGoogleHook(t, []string{CreateAnyone})
			raw := googleRaw()
			tc.mutate(raw)
			refusedWith(t, h.Intent(context.Background(), googleIntentBody(idpGoogle, tc.sub, "", raw)), tc.code)
		})
	}
}

func TestGoogleIntentExistingUser(t *testing.T) {
	// Creation closed: an existing account still signs in and is updated.
	h, _ := newGoogleHook(t, nil)
	out := decodeResponse(t, h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "u-7", googleRaw())))
	if _, ok := out["createUser"]; ok {
		t.Fatal("an existing user must not be created")
	}
	uu := out["updateUser"].(map[string]any)
	if uu["userId"] != "u-7" {
		t.Fatalf("userId %v", uu["userId"])
	}
	if _, ok := uu["metadata"]; ok {
		t.Fatal("the update must write no metadata: google_sub is immutable")
	}
	if e := uu["human"].(map[string]any)["email"].(map[string]any); e["email"] != "carol@gmail.com" || e["isVerified"] != true {
		t.Fatalf("email %v", e)
	}
	// Unverified now: the stored address is kept, not overwritten.
	raw := googleRaw()
	raw["email_verified"] = false
	out = decodeResponse(t, h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "u-7", raw)))
	if _, ok := out["updateUser"].(map[string]any)["human"].(map[string]any)["email"]; ok {
		t.Fatal("an unverified address must not replace the stored one")
	}
	// The update passes the metadata gate: it names no identity key.
	b, _ := json.Marshal(map[string]any{"fullMethod": MethodV2UpdateUser, "orgID": orgCustomers, "userID": loginClient, "request": out["updateUser"]})
	if r := h.CreateGate(context.Background(), b); r.Status != http.StatusOK || len(r.Body) != 0 {
		t.Fatalf("gate on update: %d %s (%s)", r.Status, r.Body, r.Reason)
	}
}

// With no Google IdP configured, a Google intent passes through and the
// create gate refuses whatever ZITADEL then proposes for customers.
func TestGoogleUnconfiguredFailsClosed(t *testing.T) {
	h := newHook(t, nil, nil, 0)
	if r := h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "", googleRaw())); r.Reason != "intent_other_idp" {
		t.Fatalf("intent reason %s", r.Reason)
	}
	refusedWith(t, h.CreateGate(context.Background(), createBodyFrom(t, goodGoogleCreate(), loginClient)), http.StatusForbidden)
}

func goodGoogleCreate() map[string]any {
	return map[string]any{
		"organizationId": orgCustomers,
		"username":       "google." + googleSub + "@mctl.ai",
		"human": map[string]any{
			"profile":  map[string]any{"givenName": "Carol", "familyName": "-"},
			"email":    map[string]any{"email": "carol@gmail.com", "isVerified": true},
			"idpLinks": []any{map[string]any{"idpId": idpGoogle, "userId": googleSub, "userName": "carol@gmail.com"}},
		},
		"metadata": []any{map[string]any{"key": MetaGoogleSub, "value": b64(googleSub)}},
	}
}

func TestGateGoogleRefusesEveryDeviation(t *testing.T) {
	cases := map[string]struct {
		mutate func(m map[string]any)
		caller string
	}{
		"other caller":       {func(map[string]any) {}, "someone-else"},
		"unverified email":   {func(m map[string]any) { hm(m)["email"] = map[string]any{"email": "carol@gmail.com"} }, loginClient},
		"no email":           {func(m map[string]any) { delete(hm(m), "email") }, loginClient},
		"link name != email": {func(m map[string]any) { link(m)["userName"] = "mallory@gmail.com" }, loginClient},
		"non-numeric sub": {func(m map[string]any) {
			link(m)["userId"] = "abc"
			m["username"] = "google.abc@mctl.ai"
			m["metadata"] = []any{map[string]any{"key": MetaGoogleSub, "value": b64("abc")}}
		}, loginClient},
		"sub mismatch": {func(m map[string]any) {
			m["metadata"] = []any{map[string]any{"key": MetaGoogleSub, "value": b64("1")}}
		}, loginClient},
		"no google_sub": {func(m map[string]any) { delete(m, "metadata") }, loginClient},
		"plus github_id": {func(m map[string]any) {
			m["metadata"] = append(m["metadata"].([]any), map[string]any{"key": MetaGitHubID, "value": b64("4242")})
		}, loginClient},
		"plus github_login": {func(m map[string]any) {
			m["metadata"] = append(m["metadata"].([]any), map[string]any{"key": MetaGitHubLogin, "value": b64("bob")})
		}, loginClient},
		"email username":  {func(m map[string]any) { m["username"] = "carol@mctl.ai" }, loginClient},
		"github username": {func(m map[string]any) { m["username"] = googleSub + "@mctl.ai" }, loginClient},
		"two links": {func(m map[string]any) {
			hm(m)["idpLinks"] = append(hm(m)["idpLinks"].([]any), map[string]any{"idpId": idpGitHub, "userId": "4242", "userName": "bob"})
		}, loginClient},
		"password":          {func(m map[string]any) { hm(m)["password"] = map[string]any{"password": "x"} }, loginClient},
		"machine":           {func(m map[string]any) { m["machine"] = map[string]any{"name": "m"} }, loginClient},
		"outside customers": {func(m map[string]any) { m["organizationId"] = orgAdmins }, loginClient},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := newGoogleHook(t, []string{CreateAnyone})
			m := goodGoogleCreate()
			c.mutate(m)
			refusedWith(t, h.CreateGate(context.Background(), createBodyFrom(t, m, c.caller)), http.StatusForbidden)
		})
	}
}

func TestGateGoogleCreationAllowlist(t *testing.T) {
	h, _ := newGoogleHook(t, []string{"1"})
	r := h.CreateGate(context.Background(), createBodyFrom(t, goodGoogleCreate(), loginClient))
	if r.Reason != "gate_customer_create_not_allowed:google:"+googleSub {
		t.Fatalf("reason %s", r.Reason)
	}
	refusedWith(t, r, http.StatusForbidden)
}

// A GitHub account never carries a Google identity too.
func TestGateGitHubCreateWithGoogleSubRefused(t *testing.T) {
	h, _ := newGoogleHook(t, []string{CreateAnyone})
	m := goodCreate()
	m["metadata"] = append(m["metadata"].([]any), map[string]any{"key": MetaGoogleSub, "value": b64(googleSub)})
	r := h.CreateGate(context.Background(), createBodyFrom(t, m, loginClient))
	if r.Reason != "gate_metadata_mixed_identity" {
		t.Fatalf("reason %s", r.Reason)
	}
}

// Linking and the non-CreateUser paths treat the Google IdP like the
// GitHub one: naming it anywhere touches customers.
func TestGateGoogleLinkPathsClosed(t *testing.T) {
	h, _ := newGoogleHook(t, []string{CreateAnyone})
	for name, p := range map[string]map[string]any{
		"v2 AddIDPLink google":        {"fullMethod": MethodV2AddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": idpGoogle}}},
		"v2beta AddIDPLink google":    {"fullMethod": MethodV2BetaAddIDPLink, "orgID": orgAdmins, "request": map[string]any{"userId": "u-9", "idpLink": map[string]any{"idpId": idpGoogle}}},
		"v3alpha AddIDPAuthenticator": {"fullMethod": MethodV3AlphaAddIDPAuthenticator, "orgID": orgAdmins, "request": map[string]any{"id": "u-9", "authenticator": map[string]any{"idpId": idpGoogle}}},
		"v2 AddHumanUser google link": {"fullMethod": MethodV2AddHumanUser, "orgID": orgAdmins, "request": map[string]any{"idpLinks": []any{map[string]any{"idpId": idpGoogle}}}},
		"v2 CreateUser google link in other org": {"fullMethod": MethodV2CreateUser, "orgID": orgAdmins, "userID": loginClient, "request": map[string]any{
			"organizationId": orgAdmins, "username": "x", "human": map[string]any{"idpLinks": []any{map[string]any{"idpId": idpGoogle, "userId": googleSub}}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(p)
			refusedWith(t, h.CreateGate(context.Background(), b), http.StatusForbidden)
		})
	}
}

func TestGateGoogleSubImmutable(t *testing.T) {
	h, _ := newGoogleHook(t, nil)
	subMeta := []any{map[string]any{"key": MetaGoogleSub, "value": b64("1")}}
	for name, p := range map[string]map[string]any{
		"mgmt SetUserMetadata other org":   {"fullMethod": MethodMgmtSetUserMetadata, "orgID": orgAdmins, "userID": "iac-user", "request": map[string]any{"id": "u-1", "key": MetaGoogleSub, "value": b64("1")}},
		"mgmt Bulk":                        {"fullMethod": MethodMgmtBulkSetUserMetadata, "orgID": orgAdmins, "request": map[string]any{"id": "u-1", "metadata": subMeta}},
		"v2 SetUserMetadata":               {"fullMethod": MethodV2SetUserMetadata, "orgID": orgAdmins, "request": map[string]any{"userId": "u-1", "metadata": subMeta}},
		"v2 UpdateUser by login client":    {"fullMethod": MethodV2UpdateUser, "orgID": orgCustomers, "userID": loginClient, "request": map[string]any{"userId": "u-1", "metadata": subMeta}},
		"onto a GitHub customer, by admin": {"fullMethod": MethodV2SetUserMetadata, "orgID": orgCustomers, "userID": "admin", "request": map[string]any{"userId": "u-1", "metadata": subMeta}},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(p)
			r := h.CreateGate(context.Background(), b)
			refusedWith(t, r, http.StatusForbidden)
			if r.Reason != "gate_google_sub_immutable" {
				t.Fatalf("reason %s", r.Reason)
			}
		})
	}
}

func TestTokenClaimsGoogle(t *testing.T) {
	h, _ := newGoogleHook(t, nil)
	c := claimsOf(t, h.TokenClaims(context.Background(), tokenBody(orgCustomers, clientWeb, map[string]string{MetaGoogleSub: googleSub})))
	if c[ClaimOrg] != "customers" || c[ClaimIdP] != IdPGoogle || c[ClaimGoogleSub] != googleSub {
		t.Fatalf("claims %v", c)
	}
	if c[ClaimGitHubID] != nil || c[ClaimGitHubLogin] != nil || c[ClaimRefused] != nil {
		t.Fatalf("claims %v: a Google account carries no GitHub claims and no refusal", c)
	}
	for name, tc := range map[string]struct {
		meta map[string]string
		want string
	}{
		"both identities":      {map[string]string{MetaGoogleSub: googleSub, MetaGitHubID: "4242", MetaGitHubLogin: "bob"}, RefusedAmbiguousIdentity},
		"google and github_id": {map[string]string{MetaGoogleSub: googleSub, MetaGitHubID: "4242"}, RefusedAmbiguousIdentity},
		"google and login":     {map[string]string{MetaGoogleSub: googleSub, MetaGitHubLogin: "bob"}, RefusedAmbiguousIdentity},
		"malformed sub":        {map[string]string{MetaGoogleSub: "abc"}, RefusedNoGoogleIdentity},
		"empty sub":            {map[string]string{MetaGoogleSub: ""}, RefusedNoGoogleIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			c := claimsOf(t, h.TokenClaims(context.Background(), tokenBody(orgCustomers, clientWeb, tc.meta)))
			if c[ClaimRefused] != tc.want || c[ClaimGitHubID] != nil || c[ClaimGoogleSub] != nil {
				t.Fatalf("claims %v, want only %s=%s", c, ClaimRefused, tc.want)
			}
		})
	}
}

func TestParseCustomerCreateGoogleAllowlist(t *testing.T) {
	for _, ok := range [][]string{nil, {googleSub}, {"1", googleSub}, {"*"}} {
		if _, err := ParseCustomerCreateGoogleAllowlist(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"carol@gmail.com"}, {"abc"}, {"1", "*"}, {""}} {
		if _, err := ParseCustomerCreateGoogleAllowlist(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if _, err := New(Config{CustomersOrgID: "a", GitHubIdPID: "b", LoginClientUserID: "c", ClaimClientIDs: []string{"d"}, CustomerCreateGoogleSubs: []string{"x"}}, fakeTenants{}, nil); err == nil {
		t.Fatal("New must refuse a malformed Google allowlist")
	}
}

// A Google link outside customers is refused under its own reason, so logs
// do not report it as a GitHub one.
func TestGateGoogleLinkOutsideCustomersReason(t *testing.T) {
	h, _ := newGoogleHook(t, []string{CreateAnyone})
	m := goodGoogleCreate()
	m["organizationId"] = orgAdmins
	if r := h.CreateGate(context.Background(), createBodyFrom(t, m, loginClient)); r.Reason != "gate_google_link_outside_customers" {
		t.Fatalf("reason %s", r.Reason)
	}
	g := goodCreate()
	g["organizationId"] = orgAdmins
	if r := h.CreateGate(context.Background(), createBodyFrom(t, g, loginClient)); r.Reason != "gate_github_link_outside_customers" {
		t.Fatalf("GitHub reason changed: %s", r.Reason)
	}
}

// mctl-api#1079: a Google customer cannot be re-created while a deletion of
// that Google subject is unfinished, at Intent or at the create gate, and an
// unreadable probe is a failure, never a pass. An existing account signs in
// without the probe.
func TestGoogleCreationWaitsForDeletion(t *testing.T) {
	for name, tc := range map[string]struct {
		pending          bool
		err              error
		intent, gate     string
		gateRefusedFully bool
	}{
		"pending":  {true, nil, "intent_deletion_in_progress", "gate_deletion_in_progress", true},
		"unknown":  {false, errors.New("unavailable"), "intent_deletion_unreadable", "gate_deletion_unreadable", false},
		"complete": {false, nil, "intent_create", "gate_customer_create", false},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newGoogleHook(t, []string{CreateAnyone})
			var asked []string
			h.cfg.CreationPending = func(_ context.Context, provider, subject string) (bool, error) {
				asked = append(asked, provider+":"+subject)
				return tc.pending, tc.err
			}
			r := h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "", googleRaw()))
			if r.Reason != tc.intent {
				t.Fatalf("intent reason %s, want %s", r.Reason, tc.intent)
			}
			if tc.pending {
				refusedWith(t, r, http.StatusForbidden)
			}
			if tc.err != nil && r.Status != http.StatusServiceUnavailable {
				t.Fatalf("unreadable intent probe status %d", r.Status)
			}
			g := h.CreateGate(context.Background(), createBodyFrom(t, goodGoogleCreate(), loginClient))
			if g.Reason != tc.gate {
				t.Fatalf("gate reason %s, want %s", g.Reason, tc.gate)
			}
			if tc.gateRefusedFully {
				refusedWith(t, g, http.StatusForbidden)
			}
			if tc.err != nil && g.Status != http.StatusServiceUnavailable {
				t.Fatalf("unreadable gate probe status %d", g.Status)
			}
			if len(asked) != 2 || asked[0] != "google:"+googleSub || asked[1] != "google:"+googleSub {
				t.Fatalf("deletion probe asked %v, want the Google subject twice", asked)
			}
			// An existing account is updated without asking.
			asked = nil
			r = h.Intent(context.Background(), googleIntentBody(idpGoogle, googleSub, "existing-user", googleRaw()))
			if r.Reason != "intent_update" || len(asked) != 0 {
				t.Fatalf("existing Google account: %s, probe asked %v", r.Reason, asked)
			}
		})
	}
}
