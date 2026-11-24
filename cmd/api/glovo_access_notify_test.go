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

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// notifyAccessStore is an access store with the outbox; only the switch is
// ever called here.
type notifyAccessStore struct {
	api.GlovoAccessStore
	api.GlovoAccessNotifyStore
	api.GlovoAccessLinkStore
	on, calls int
	// email is the last value SetAccessEmail got; emailCalls counts them.
	email      bool
	emailCalls int
}

func (s *notifyAccessStore) SetAccessEmail(v bool) {
	s.emailCalls++
	s.email = v
}

func (s *notifyAccessStore) SetAccessNotify(v bool) {
	s.calls++
	if v {
		s.on++
	}
}

func (s *notifyAccessStore) GetAccess(context.Context, string) (glovoconsent.Access, error) {
	return glovoconsent.Access{}, errors.New("not used")
}

func (s *notifyAccessStore) MintDecideToken(context.Context, string, time.Time) (string, error) {
	return "", errors.New("not used")
}

type notifyIdentity struct{}

func (notifyIdentity) IdentityFacts(context.Context, string) (glovoconsent.IdentityFacts, error) {
	return glovoconsent.IdentityFacts{}, nil
}

func notifyDeps() (glovoAccessNotifyDeps, *notifyAccessStore) {
	st := &notifyAccessStore{}
	return glovoAccessNotifyDeps{
		Routes: &api.GlovoConsentRoutes{Enabled: true, Access: st, AccessLinks: st},
		Identities: func(context.Context, string) ([]principals.ExternalIdentity, error) {
			return nil, nil
		},
		Identity: notifyIdentity{},
		Providers: &customerdelete.Providers{Issuer: "https://idp.example", CustomerOrg: "customers", GitHubIDP: "gh", GoogleIDP: "g", ClientID: "c", ClientSecret: "s",
			SiteBase: "https://site.example", SessionAudience: "aud"},
		UsernameDomain: "mctl.example",
		PageBaseURL:    "https://api.example",
	}, st
}

func notifyEnvLookup(v string, set bool) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if k == "GLOVO_ACCESS_NOTIFY_ENABLED" && set {
			return v, true
		}
		return "", false
	}
}

// notifyEnvBoth sets the card switch and the email switch.
func notifyEnvBoth(card, email string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		switch k {
		case "GLOVO_ACCESS_NOTIFY_ENABLED":
			return card, true
		case "GLOVO_ACCESS_EMAIL_ENABLED":
			return email, true
		}
		return "", false
	}
}

// The card alone is the default of the card switch: the emails stay off, the
// notifier has no recipient lookup, and what only the emails need (the
// customers organization, the username domain) is not required.
func TestGlovoAccessNotifyCardWithoutEmails(t *testing.T) {
	for _, email := range []string{"", "false"} {
		deps, st := notifyDeps()
		deps.Providers.CustomerOrg, deps.Providers.GitHubIDP, deps.Providers.GoogleIDP, deps.UsernameDomain = "", "", "", ""
		n, err := configureGlovoAccessNotify(notifyEnvBoth("true", email), deps)
		if err != nil || n == nil || !n.Ready() || n.Recipient != nil {
			t.Fatalf("%q: notifier %v err %v", email, n, err)
		}
		if st.on != 1 || st.emailCalls != 1 || st.email {
			t.Fatalf("%q: card on %d, email set %v in %d calls", email, st.on, st.email, st.emailCalls)
		}
	}
}

func TestGlovoAccessNotifyEmailsOn(t *testing.T) {
	deps, st := notifyDeps()
	n, err := configureGlovoAccessNotify(notifyEnvBoth("true", "true"), deps)
	if err != nil || n == nil || !n.Ready() || n.Recipient == nil || st.on != 1 || !st.email {
		t.Fatalf("notifier %v err %v card %d email %v", n, err, st.on, st.email)
	}
}

// The emails never come on by themselves or half-configured, and a bad
// email switch does not take the card down with it.
func TestGlovoAccessNotifyEmailsStayOff(t *testing.T) {
	// Without the card switch the email switch is an error and nothing runs.
	for _, card := range []string{"", "false"} {
		deps, st := notifyDeps()
		n, err := configureGlovoAccessNotify(notifyEnvBoth(card, "true"), deps)
		if n != nil || err == nil || st.calls != 0 || st.emailCalls != 0 {
			t.Fatalf("card %q: notifier %v err %v", card, n, err)
		}
	}
	for name, tc := range map[string]struct {
		email string
		strip func(*glovoAccessNotifyDeps)
	}{
		"malformed switch":   {"yes", func(*glovoAccessNotifyDeps) {}},
		"upper case":         {"TRUE", func(*glovoAccessNotifyDeps) {}},
		"no customers org":   {"true", func(d *glovoAccessNotifyDeps) { d.Providers.CustomerOrg = "" }},
		"no github idp":      {"true", func(d *glovoAccessNotifyDeps) { d.Providers.GitHubIDP = "" }},
		"no google idp":      {"true", func(d *glovoAccessNotifyDeps) { d.Providers.GoogleIDP = "" }},
		"no username domain": {"true", func(d *glovoAccessNotifyDeps) { d.UsernameDomain = " " }},
	} {
		deps, st := notifyDeps()
		tc.strip(&deps)
		n, err := configureGlovoAccessNotify(notifyEnvBoth("true", tc.email), deps)
		if err == nil || !strings.Contains(err.Error(), "emails stay off") {
			t.Fatalf("%s: err %v", name, err)
		}
		if n == nil || !n.Ready() || n.Recipient != nil || st.on != 1 || st.email || st.emailCalls != 1 {
			t.Fatalf("%s: notifier %v card %d email %v", name, n, st.on, st.email)
		}
	}
	// A malformed email switch with the card off is still reported.
	deps, st := notifyDeps()
	if n, err := configureGlovoAccessNotify(notifyEnvBoth("false", "yes"), deps); n != nil || err == nil || st.calls != 0 {
		t.Fatalf("malformed email switch, card off: %v %v", n, err)
	}
}

// Off, which is the default, builds nothing and leaves the outbox alone.
func TestGlovoAccessNotifyOffByDefault(t *testing.T) {
	for _, tc := range []struct {
		v   string
		set bool
	}{{"", false}, {"", true}, {"false", true}, {" false ", true}} {
		deps, st := notifyDeps()
		n, err := configureGlovoAccessNotify(notifyEnvLookup(tc.v, tc.set), deps)
		if n != nil || err != nil || st.calls != 0 {
			t.Fatalf("%q: notifier %v err %v switch calls %d", tc.v, n, err, st.calls)
		}
	}
}

func TestGlovoAccessNotifyMalformedSwitchStaysOff(t *testing.T) {
	for _, v := range []string{"1", "yes", "TRUE", "on", "true,false"} {
		deps, st := notifyDeps()
		n, err := configureGlovoAccessNotify(notifyEnvLookup(v, true), deps)
		if n != nil || err == nil || st.calls != 0 {
			t.Fatalf("%q: notifier %v err %v switch calls %d", v, n, err, st.calls)
		}
	}
}

func TestGlovoAccessNotifyOnNeedsEverything(t *testing.T) {
	deps, st := notifyDeps()
	n, err := configureGlovoAccessNotify(notifyEnvLookup("true", true), deps)
	if err != nil || n == nil || !n.Ready() || st.on != 1 || st.calls != 1 {
		t.Fatalf("complete: notifier %v err %v on %d", n, err, st.on)
	}
	for name, strip := range map[string]func(*glovoAccessNotifyDeps){
		"no routes":           func(d *glovoAccessNotifyDeps) { d.Routes = nil },
		"routes off":          func(d *glovoAccessNotifyDeps) { d.Routes.Enabled = false },
		"no access store":     func(d *glovoAccessNotifyDeps) { d.Routes.Access = nil },
		"store has no outbox": func(d *glovoAccessNotifyDeps) { d.Routes.Access = struct{ api.GlovoAccessStore }{} },
		"no link store":       func(d *glovoAccessNotifyDeps) { d.Routes.AccessLinks = nil },
		"no decision page":    func(d *glovoAccessNotifyDeps) { d.PageBaseURL = "" },
		"page not https":      func(d *glovoAccessNotifyDeps) { d.PageBaseURL = "http://api.example" },
		"page with a path":    func(d *glovoAccessNotifyDeps) { d.PageBaseURL = "https://api.example/x" },
		"no identities":       func(d *glovoAccessNotifyDeps) { d.Identities = nil },
		"no identity source":  func(d *glovoAccessNotifyDeps) { d.Identity = nil },
		"no providers":        func(d *glovoAccessNotifyDeps) { d.Providers = nil },
		"no machine secret":   func(d *glovoAccessNotifyDeps) { d.Providers.ClientSecret = "" },
		"no worker audience":  func(d *glovoAccessNotifyDeps) { d.Providers.SessionAudience = "" },
	} {
		deps, st := notifyDeps()
		strip(&deps)
		n, err := configureGlovoAccessNotify(notifyEnvLookup("true", true), deps)
		if n != nil || err == nil || st.calls != 0 {
			t.Fatalf("%s: notifier %v err %v switch calls %d", name, n, err, st.calls)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("%s: error %v", name, err)
		}
	}
}

func TestGlovoAccessRecipient(t *testing.T) {
	const pid = "prn_AAAAAAAAAAAAAAAAAAAAAAAAA1"
	const mail = "person@example.invalid"
	revoked := time.Now()
	google := principals.ExternalIdentity{Provider: auth.ProviderGoogle, Subject: "112233445566778899001"}
	github := principals.ExternalIdentity{Provider: auth.ProviderGitHub, Subject: "123", Display: "Alice"}
	type call struct{ provider, subject, username string }
	run := func(ids []principals.ExternalIdentity, idErr error, mailErr error) (string, []call, error) {
		var calls []call
		f := glovoAccessRecipient(
			func(_ context.Context, p string) ([]principals.ExternalIdentity, error) {
				if p != pid {
					t.Fatalf("asked for %s", p)
				}
				return ids, idErr
			},
			func(_ context.Context, provider, subject, username string) (string, error) {
				calls = append(calls, call{provider, subject, username})
				if mailErr != nil {
					return "", mailErr
				}
				return mail, nil
			}, "mctl.example")
		got, err := f(context.Background(), pid)
		return got, calls, err
	}

	got, calls, err := run([]principals.ExternalIdentity{google}, nil, nil)
	if err != nil || got != mail || len(calls) != 1 || calls[0] != (call{"google", google.Subject, "google." + google.Subject + "@mctl.example"}) {
		t.Fatalf("google = %q %v %v", got, err, calls)
	}
	got, calls, err = run([]principals.ExternalIdentity{github}, nil, nil)
	if err != nil || got != mail || len(calls) != 1 || calls[0] != (call{"github", "123", "alice@mctl.example"}) {
		t.Fatalf("github = %q %v %v", got, err, calls)
	}

	// No single customer identity: no recipient, and the IdP is not asked.
	gRevoked, gFederated, other := google, google, google
	gRevoked.RevokedAt = &revoked
	gFederated.Issuer = "https://issuer.example"
	other.Provider = "dex"
	badSub := google
	badSub.Subject = "not-a-sub"
	for name, ids := range map[string][]principals.ExternalIdentity{
		"none": nil, "both": {google, github}, "revoked": {gRevoked}, "federated": {gFederated}, "other provider": {other}, "malformed subject": {badSub},
	} {
		got, calls, err := run(ids, nil, nil)
		if !errors.Is(err, api.ErrGlovoNoRecipient) || got != "" || len(calls) != 0 {
			t.Fatalf("%s = %q %v %v", name, got, err, calls)
		}
	}
	// A revoked second identity does not hide the live one.
	if got, _, err := run([]principals.ExternalIdentity{gRevoked, github}, nil, nil); err != nil || got != mail {
		t.Fatalf("revoked + live = %q %v", got, err)
	}

	// The IdP's documented absence is no recipient; a failure is a failure.
	if _, _, err := run([]principals.ExternalIdentity{google}, nil, customerdelete.ErrNoCustomerEmail); !errors.Is(err, api.ErrGlovoNoRecipient) {
		t.Fatalf("absent email = %v", err)
	}
	if _, _, err := run([]principals.ExternalIdentity{google}, nil, errors.New("IdP down")); err == nil || errors.Is(err, api.ErrGlovoNoRecipient) {
		t.Fatalf("IdP failure = %v", err)
	}
	if _, calls, err := run(nil, errors.New("db down"), nil); err == nil || errors.Is(err, api.ErrGlovoNoRecipient) || len(calls) != 0 {
		t.Fatalf("unreadable identities = %v", err)
	}
}
