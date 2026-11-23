// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package scope

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

type accessConsentStore struct{ rec glovoconsent.Record }

func (s accessConsentStore) Record(context.Context, string, string, int) (glovoconsent.Record, bool, error) {
	return s.rec, false, nil
}
func (s accessConsentStore) Revoke(context.Context, string, string) (glovoconsent.Record, error) {
	return s.rec, nil
}
func (s accessConsentStore) Active(context.Context, string) (glovoconsent.Record, error) {
	return s.rec, nil
}

type accessFake struct {
	st  glovoconsent.AccessStatus
	err error
}

func (a *accessFake) AccessState(context.Context, string) (glovoconsent.AccessStatus, error) {
	return a.st, a.err
}

// The personal resolver with the real consent grant source and the access
// gate on: resolves only while access is approved, at every request.
func TestResolvePersonalRequiresApprovedAccess(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		gate bool
		acc  accessFake
		want glovo.Code // "" = resolves
	}{
		"gate off, no access":    {false, accessFake{st: glovoconsent.AccessNone}, ""},
		"gate on, approved":      {true, accessFake{st: glovoconsent.AccessApproved}, ""},
		"gate on, none":          {true, accessFake{st: glovoconsent.AccessNone}, glovo.CodeNotAuthorized},
		"gate on, pending":       {true, accessFake{st: glovoconsent.AccessPending}, glovo.CodeNotAuthorized},
		"gate on, revoked":       {true, accessFake{st: glovoconsent.AccessRevoked}, glovo.CodeNotAuthorized},
		"gate on, rejected":      {true, accessFake{st: glovoconsent.AccessRejected}, glovo.CodeNotAuthorized},
		"gate on, access error":  {true, accessFake{err: errors.New("down")}, glovo.CodeUnavailable},
		"gate on, unknown state": {true, accessFake{st: "weird"}, glovo.CodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := newPersonalEnv(t)
			src := glovoconsent.ConsentGrants{Store: accessConsentStore{rec: glovoconsent.Record{
				ID: "gcn_1", PrincipalID: prnA, Version: glovoconsent.Version, RecordedAt: e.g.g.CreatedAt.Add(-time.Minute)}}}
			if tc.gate {
				acc := tc.acc
				src.Access = &acc
			}
			e.r.Consent = src
			_, err := e.r.Resolve(ctx, e.personalUser(t, prnA, "pgr_1", ""))
			if tc.want == "" && err != nil || tc.want != "" && code(err) != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
