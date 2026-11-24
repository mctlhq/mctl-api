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
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// configureGlovoConsent builds the Glovo link consent routes (mctl-glovo
// epic #11, C2-1c). Dark and fail-closed, like configureGlovoBasketJoin: the
// routes are mounted only when GLOVO_CONSENT_ENABLED is exactly true, the
// consent reader is named (GLOVO_CONSENT_SERVICE_PROVIDER, a federated
// provider of kind service, and GLOVO_CONSENT_SERVICE_SUBJECT), a database is configured
// (GLOVO_CONSENT_DB_URL, else AUDIT_DB_URL) and the store opens. A value
// that is set but wrong is an error for the boot log and leaves the routes
// unmounted (404); it never mounts with a default and never stops the boot.
//
// GLOVO_ACCESS_REQUIRED (default false) switches slot accounting to approved
// access requests (mctl-glovo#82) and makes the glovo:c2 grant source require
// approved access (wireGlovoPersonalGrants). Anything but "", false and true is
// a boot-log error and leaves consent off. The access routes work either way.
//
// GLOVO_C2_CAPACITY caps the active consents. Unset, 0 or malformed is
// closed, logged at boot: the routes still mount, consent can be read and
// withdrawn, but no new one is recorded (409 capacity_reached).
func configureGlovoConsent(ctx context.Context, lookup func(string) (string, bool), openStore func(ctx context.Context, dbURL string, accessRequired bool) (glovoconsent.Store, error)) (*api.GlovoConsentRoutes, error) {
	v, _ := lookup("GLOVO_CONSENT_ENABLED")
	switch strings.TrimSpace(v) {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fmt.Errorf("GLOVO_CONSENT_ENABLED %q must be true or false; glovo consent stays off", v)
	}
	rawAccess, _ := lookup("GLOVO_ACCESS_REQUIRED")
	accessRequired := false
	switch strings.TrimSpace(rawAccess) {
	case "", "false":
	case "true":
		accessRequired = true
	default:
		return nil, fmt.Errorf("GLOVO_ACCESS_REQUIRED %q must be true or false; glovo consent stays off", rawAccess)
	}
	provider, _ := lookup("GLOVO_CONSENT_SERVICE_PROVIDER")
	subject, _ := lookup("GLOVO_CONSENT_SERVICE_SUBJECT")
	provider, subject = strings.TrimSpace(provider), strings.TrimSpace(subject)
	switch {
	case provider == "" || subject == "":
		return nil, errors.New("GLOVO_CONSENT_ENABLED=true requires GLOVO_CONSENT_SERVICE_PROVIDER and GLOVO_CONSENT_SERVICE_SUBJECT; glovo consent stays off")
	case auth.IsReservedProviderName(provider):
		return nil, fmt.Errorf("GLOVO_CONSENT_SERVICE_PROVIDER %q is a built-in identity namespace, not a federated service provider; glovo consent stays off", provider)
	}
	dbURL, _ := lookup("GLOVO_CONSENT_DB_URL")
	if strings.TrimSpace(dbURL) == "" {
		dbURL, _ = lookup("AUDIT_DB_URL")
	}
	dbURL = postgresURL(strings.TrimSpace(dbURL))
	if dbURL == "" {
		return nil, errors.New("GLOVO_CONSENT_ENABLED=true requires GLOVO_CONSENT_DB_URL or AUDIT_DB_URL; glovo consent stays off")
	}
	store, err := openStore(ctx, dbURL, accessRequired)
	if err != nil {
		return nil, fmt.Errorf("glovo consent store: %w; glovo consent stays off", err)
	}
	rawCap, _ := lookup("GLOVO_C2_CAPACITY")
	capacity, closedWhy := glovoC2Capacity(rawCap)
	if closedWhy != "" {
		slog.Error("glovo link consent is closed: no new consent can be recorded", "GLOVO_C2_CAPACITY", closedWhy)
	} else {
		slog.Info("glovo link consent capacity", "capacity", capacity)
	}
	slog.Info("glovo access required", "enabled", accessRequired)
	routes := &api.GlovoConsentRoutes{Enabled: true, Store: store, Capacity: capacity, AccessRequired: accessRequired,
		ServiceProvider: provider, ServiceSubject: subject}
	// The Postgres store carries the access side too. A store without it
	// leaves the access routes and the `access` field off.
	if as, ok := store.(api.GlovoAccessStore); ok {
		routes.Access = as
		if ls, ok := store.(api.GlovoAccessLinkStore); ok {
			routes.AccessLinks = ls
		}
	}
	return routes, nil
}

// glovoC2Capacity parses GLOVO_C2_CAPACITY: a positive decimal integer of at
// most seven digits. Anything else is 0, closed, with the reason for the boot
// log: a typo must close the gate, never open it wide or to a default.
func glovoC2Capacity(raw string) (int, string) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return 0, "unset"
	case !glovoC2CapacityPattern.MatchString(raw):
		return 0, fmt.Sprintf("%q is not a positive integer", raw)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Sprintf("%q is not a positive integer", raw)
	}
	return n, ""
}

var glovoC2CapacityPattern = regexp.MustCompile(`^[1-9][0-9]{0,6}$`)

// wireGlovoPersonalGrants admits personal Glovo grants: a human with no
// eligible team who holds the glovo:c2 consent is scoped to itself. It needs
// both the Glovo pilot (its resolver) and the consent routes; with either off
// nothing is set, and the OAuth server and the resolver stay team-only,
// exactly as before. The consent source is the consent table itself, read on
// every check: nothing is cached, so a withdrawn consent refuses the next
// scope resolve and the next refresh.
//
// With GLOVO_ACCESS_REQUIRED on the source also reads the access state on
// every check and requires it to be approved. If the access store is missing
// then, the grants are not wired at all (fail closed: no personal grant is
// better than an ungated one).
func wireGlovoPersonalGrants(o *auth.OAuthServer, routes *api.GlovoRoutes, consent *api.GlovoConsentRoutes) bool {
	if o == nil || routes == nil || !routes.Enabled || routes.Resolver == nil || consent == nil || !consent.Enabled || consent.Store == nil {
		return false
	}
	src := glovoconsent.ConsentGrants{Store: consent.Store}
	if consent.AccessRequired {
		if glovo.IsNil(consent.Access) {
			slog.Error("glovo personal grants not wired: GLOVO_ACCESS_REQUIRED is on but the store has no access side")
			return false
		}
		src.Access = consent.Access
	}
	o.GlovoConsent = src
	routes.Resolver.Consent = src
	return true
}
