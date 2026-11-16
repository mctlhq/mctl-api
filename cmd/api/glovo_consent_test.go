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
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

type nopConsentStore struct{}

func (nopConsentStore) Record(context.Context, string, string, int) (glovoconsent.Record, bool, error) {
	return glovoconsent.Record{}, false, errors.New("unused")
}
func (nopConsentStore) Revoke(context.Context, string, string) (glovoconsent.Record, error) {
	return glovoconsent.Record{}, errors.New("unused")
}
func (nopConsentStore) Active(context.Context, string) (glovoconsent.Record, error) {
	return glovoconsent.Record{}, errors.New("unused")
}

func TestConfigureGlovoConsent(t *testing.T) {
	full := map[string]string{
		"GLOVO_CONSENT_ENABLED":          "true",
		"GLOVO_CONSENT_SERVICE_PROVIDER": "k8s-glovo",
		"GLOVO_CONSENT_SERVICE_SUBJECT":  "system:serviceaccount:glovo:mctl-glovo",
		"GLOVO_C2_CAPACITY":              "25",
		"AUDIT_DB_URL":                   "postgres://u@db.example/mctl",
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range full {
			m[kk] = vv
		}
		if v == "<unset>" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	opened := 0
	open := func(context.Context, string) (glovoconsent.Store, error) { opened++; return nopConsentStore{}, nil }
	failOpen := func(context.Context, string) (glovoconsent.Store, error) { return nil, errors.New("db down") }
	cfg := func(env map[string]string, o func(context.Context, string) (glovoconsent.Store, error)) (bool, error) {
		r, err := configureGlovoConsent(context.Background(), func(k string) (string, bool) { v, ok := env[k]; return v, ok }, o)
		return r != nil, err
	}

	if on, err := cfg(full, open); !on || err != nil {
		t.Fatalf("full config = %v %v", on, err)
	}
	// The capacity never unmounts the routes: closed still reads and
	// withdraws. Unset, 0 or malformed is closed (0), never a default.
	for raw, want := range map[string]int{
		"25": 25, "\t7\n": 7, "<unset>": 0, "": 0, "0": 0, "-3": 0, "+5": 0, "05": 0,
		"ten": 0, "1.5": 0, "99999999": 0, "1e3": 0,
	} {
		r, err := configureGlovoConsent(context.Background(), func(k string) (string, bool) {
			v, ok := with("GLOVO_C2_CAPACITY", raw)[k]
			return v, ok
		}, open)
		if err != nil || r == nil || r.Capacity != want {
			t.Errorf("GLOVO_C2_CAPACITY %q = %+v %v, want mounted with capacity %d", raw, r, err, want)
		}
	}
	for name, c := range map[string]struct {
		env     map[string]string
		open    func(context.Context, string) (glovoconsent.Store, error)
		wantErr bool
	}{
		"unset":            {with("GLOVO_CONSENT_ENABLED", "<unset>"), open, false},
		"false":            {with("GLOVO_CONSENT_ENABLED", "false"), open, false},
		"typo flag":        {with("GLOVO_CONSENT_ENABLED", "yes"), open, true},
		"no provider":      {with("GLOVO_CONSENT_SERVICE_PROVIDER", ""), open, true},
		"no subject":       {with("GLOVO_CONSENT_SERVICE_SUBJECT", "<unset>"), open, true},
		"reserved":         {with("GLOVO_CONSENT_SERVICE_PROVIDER", "service"), open, true},
		"no database":      {with("AUDIT_DB_URL", "<unset>"), open, true},
		"store open fails": {full, failOpen, true},
	} {
		before := opened
		on, err := cfg(c.env, c.open)
		if on || (err != nil) != c.wantErr {
			t.Errorf("%s: mounted=%v err=%v, want unmounted, error %v", name, on, err, c.wantErr)
		}
		if name != "store open fails" && opened != before {
			t.Errorf("%s: opened a store for a configuration that stays off", name)
		}
	}
}
