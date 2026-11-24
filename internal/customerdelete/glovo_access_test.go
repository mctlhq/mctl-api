// Copyright 2026 MCTL Authors
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

package customerdelete

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

const glovoTestMail = "person@example.invalid"

// glovoIdP is a fake ZITADEL and Worker for the Glovo access calls.
type glovoIdP struct {
	search       string // raw body of the user search answer
	searchStatus int
	owner        string
	links        string
	searches     int
	gotQuery     map[string]any
	siteStatus   int
	siteBody     string
	gotSite      string
	gotSiteAuth  string
}

func (f *glovoIdP) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/oauth/v2/token":
			_, _ = w.Write([]byte(`{"access_token":"machine-jwt"}`))
		case r.URL.Path == "/v2/users" && r.Method == http.MethodPost:
			f.searches++
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &f.gotQuery)
			if f.searchStatus != 0 {
				w.WriteHeader(f.searchStatus)
			}
			_, _ = w.Write([]byte(f.search))
		case r.URL.Path == "/v2/users/7001" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{"userId": "7001", "human": map[string]any{}, "details": map[string]string{"resourceOwner": f.owner}}})
		case r.URL.Path == "/v2/users/7001/links/_search":
			_, _ = w.Write([]byte(f.links))
		case r.URL.Path == GlovoAccessNotifyPath && r.Method == http.MethodPost:
			raw, _ := io.ReadAll(r.Body)
			f.gotSite, f.gotSiteAuth = string(raw), r.Header.Get("Authorization")
			if f.siteStatus != 0 {
				w.WriteHeader(f.siteStatus)
			}
			_, _ = w.Write([]byte(f.siteBody))
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func glovoSearch(username, owner, email string, verified bool) string {
	raw, _ := json.Marshal(map[string]any{
		"details": map[string]any{"totalResult": "1"},
		"result": []map[string]any{{
			"userId": "7001", "username": username, "details": map[string]string{"resourceOwner": owner},
			"human": map[string]any{"email": map[string]any{"email": email, "isVerified": verified}},
		}},
	})
	return string(raw)
}

func glovoProviders(url string) *Providers {
	return &Providers{Issuer: url, CustomerOrg: "customers", GitHubIDP: "github-idp", GoogleIDP: "google-idp",
		ClientID: "lifecycle", ClientSecret: "secret", SessionAudience: "worker-project", SiteBase: url}
}

func TestCustomerEmailGoogleAndGitHub(t *testing.T) {
	f := &glovoIdP{owner: "customers"}
	p := glovoProviders(f.server(t).URL)
	ctx := context.Background()

	f.search = glovoSearch("google.1234567890@mctl.example", "customers", glovoTestMail, true)
	f.links = `{"details":{"totalResult":"1"},"result":[{"idpId":"google-idp","userId":"1234567890"}]}`
	got, err := p.CustomerEmail(ctx, auth.ProviderGoogle, "1234567890", "google.1234567890@mctl.example")
	if err != nil || got != glovoTestMail {
		t.Fatalf("google = %q %v", got, err)
	}
	// The search is confined to the customers organization and to the exact
	// username.
	raw, _ := json.Marshal(f.gotQuery)
	if !strings.Contains(string(raw), `"organizationId":"customers"`) || !strings.Contains(string(raw), `"userName":"google.1234567890@mctl.example"`) ||
		!strings.Contains(string(raw), "TEXT_QUERY_METHOD_EQUALS") {
		t.Fatalf("search query %s", raw)
	}

	f.search = glovoSearch("alice@mctl.example", "customers", glovoTestMail, true)
	f.links = `{"details":{"totalResult":"1"},"result":[{"idpId":"github-idp","userId":"123"}]}`
	if got, err := p.CustomerEmail(ctx, auth.ProviderGitHub, "123", "alice@mctl.example"); err != nil || got != glovoTestMail {
		t.Fatalf("github = %q %v", got, err)
	}
}

// Only the IdP's own "no such user" and "no verified address" are absence.
func TestCustomerEmailAbsenceIsDocumentedOnly(t *testing.T) {
	const user = "google.1234567890@mctl.example"
	googleLink := `{"details":{"totalResult":"1"},"result":[{"idpId":"google-idp","userId":"1234567890"}]}`
	absent := map[string]string{
		"empty listing":      `{"details":{"totalResult":"0"}}`,
		"empty result":       `{"details":{"totalResult":"0"},"result":[]}`,
		"unverified address": glovoSearch(user, "customers", glovoTestMail, false),
		"no address":         glovoSearch(user, "customers", "", true),
		"address with name":  glovoSearch(user, "customers", "Person <"+glovoTestMail+">", true),
		"two addresses":      glovoSearch(user, "customers", "a@example.invalid,b@example.invalid", true),
		"header injection":   glovoSearch(user, "customers", glovoTestMail+"\nBcc: x@example.invalid", true),
	}
	for name, body := range absent {
		f := &glovoIdP{owner: "customers", search: body, links: googleLink}
		p := glovoProviders(f.server(t).URL)
		if got, err := p.CustomerEmail(context.Background(), auth.ProviderGoogle, "1234567890", user); !errors.Is(err, ErrNoCustomerEmail) || got != "" {
			t.Fatalf("%s = %q %v, want ErrNoCustomerEmail", name, got, err)
		}
	}
}

func TestCustomerEmailFailuresAreNotAbsence(t *testing.T) {
	const user = "google.1234567890@mctl.example"
	googleLink := `{"details":{"totalResult":"1"},"result":[{"idpId":"google-idp","userId":"1234567890"}]}`
	good := glovoSearch(user, "customers", glovoTestMail, true)
	// The right user first, so only the count can refuse it.
	two := strings.TrimSuffix(good, "]}") + `,{"userId":"7002"}]}`
	cases := map[string]glovoIdP{
		"search refused":        {owner: "customers", search: good, searchStatus: 403, links: googleLink},
		"search down":           {owner: "customers", search: good, searchStatus: 500, links: googleLink},
		"not json":              {owner: "customers", search: `<html>`, links: googleLink},
		"no listing details":    {owner: "customers", search: `{}`, links: googleLink},
		"null details":          {owner: "customers", search: `{"details":null,"result":[]}`, links: googleLink},
		"two users":             {owner: "customers", search: two, links: googleLink},
		"another username":      {owner: "customers", search: glovoSearch("google.999@mctl.example", "customers", glovoTestMail, true), links: googleLink},
		"listed in another org": {owner: "customers", search: glovoSearch(user, "staff", glovoTestMail, true), links: googleLink},
		"user in another org":   {owner: "staff", search: good, links: googleLink},
		"link to another sub":   {owner: "customers", search: good, links: `{"details":{"totalResult":"1"},"result":[{"idpId":"google-idp","userId":"999"}]}`},
		"link to another idp":   {owner: "customers", search: good, links: `{"details":{"totalResult":"1"},"result":[{"idpId":"github-idp","userId":"1234567890"}]}`},
		"two links":             {owner: "customers", search: good, links: `{"details":{"totalResult":"2"},"result":[{"idpId":"google-idp","userId":"1234567890"},{"idpId":"github-idp","userId":"1"}]}`},
		"machine user":          {owner: "customers", search: strings.Replace(good, `"human"`, `"machine"`, 1), links: googleLink},
	}
	for name, c := range cases {
		f := c
		p := glovoProviders(f.server(t).URL)
		got, err := p.CustomerEmail(context.Background(), auth.ProviderGoogle, "1234567890", user)
		if err == nil || errors.Is(err, ErrNoCustomerEmail) || got != "" {
			t.Fatalf("%s = %q %v, want a failure", name, got, err)
		}
		if strings.Contains(err.Error(), glovoTestMail) {
			t.Fatalf("%s: the error quotes the address: %v", name, err)
		}
	}
	// Bad input never reaches the IdP.
	f := &glovoIdP{owner: "customers", search: good, links: googleLink}
	p := glovoProviders(f.server(t).URL)
	for _, in := range [][3]string{
		{"mctl", "1234567890", user}, {auth.ProviderGoogle, "", user}, {auth.ProviderGoogle, "1234567890", ""},
		{auth.ProviderGoogle, "1234567890", `a"b@mctl.example`}, {auth.ProviderGoogle, "1234567890", "a\nb@mctl.example"},
	} {
		if _, err := p.CustomerEmail(context.Background(), in[0], in[1], in[2]); err == nil || errors.Is(err, ErrNoCustomerEmail) {
			t.Fatalf("input %q = %v", in, err)
		}
	}
	if f.searches != 0 {
		t.Fatalf("%d searches for bad input", f.searches)
	}
}

func TestGlovoAccessSite(t *testing.T) {
	f := &glovoIdP{siteBody: `{"delivery_key":"k","delivery_id":"d"}`}
	p := glovoProviders(f.server(t).URL)
	got, err := p.GlovoAccessSite(context.Background(), []byte(`{"kind":"lapsed"}`))
	if err != nil || string(got) != f.siteBody || f.gotSite != `{"kind":"lapsed"}` || f.gotSiteAuth != "Bearer machine-jwt" {
		t.Fatalf("site = %q %v sent %q auth %q", got, err, f.gotSite, f.gotSiteAuth)
	}
	for _, status := range []int{202, 400, 403, 503} {
		f.siteStatus = status
		if _, err := p.GlovoAccessSite(context.Background(), []byte(`{}`)); err == nil {
			t.Fatalf("HTTP %d accepted", status)
		}
	}
	// The invitation bridge still refuses any other path.
	if _, err := p.SignupSite(context.Background(), "POST", GlovoAccessNotifyPath, nil); err == nil {
		t.Fatal("SignupSite reached the glovo bridge")
	}
}

func TestGlovoAccessConfigured(t *testing.T) {
	full := glovoProviders("https://idp.example")
	if !full.GlovoAccessConfigured() {
		t.Fatal("complete providers not configured")
	}
	var none *Providers
	if none.GlovoAccessConfigured() {
		t.Fatal("nil providers configured")
	}
	for _, strip := range []func(*Providers){
		func(p *Providers) { p.Issuer = "" }, func(p *Providers) { p.CustomerOrg = "" }, func(p *Providers) { p.ClientID = "" },
		func(p *Providers) { p.ClientSecret = "" }, func(p *Providers) { p.SiteBase = "" }, func(p *Providers) { p.SessionAudience = "" },
		func(p *Providers) { p.GitHubIDP = "" }, func(p *Providers) { p.GoogleIDP = "" },
	} {
		p := glovoProviders("https://idp.example")
		strip(p)
		if p.GlovoAccessConfigured() {
			t.Fatalf("incomplete providers configured: %+v", p)
		}
	}
	// The bridge alone, which is all the owner card needs, does not need
	// the customers organization or the IdP ids.
	if none.GlovoAccessBridgeConfigured() || !full.GlovoAccessBridgeConfigured() {
		t.Fatal("bridge readiness wrong for nil or complete providers")
	}
	card := glovoProviders("https://idp.example")
	card.CustomerOrg, card.GitHubIDP, card.GoogleIDP = "", "", ""
	if !card.GlovoAccessBridgeConfigured() || card.GlovoAccessConfigured() {
		t.Fatal("bridge-only providers misjudged")
	}
	for _, strip := range []func(*Providers){
		func(p *Providers) { p.Issuer = "" }, func(p *Providers) { p.ClientID = "" }, func(p *Providers) { p.ClientSecret = "" },
		func(p *Providers) { p.SiteBase = "" }, func(p *Providers) { p.SessionAudience = "" },
	} {
		p := glovoProviders("https://idp.example")
		strip(p)
		if p.GlovoAccessBridgeConfigured() {
			t.Fatalf("incomplete bridge configured: %+v", p)
		}
	}
}
