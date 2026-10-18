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

package auth

import (
	"context"
	"testing"
	"time"
)

// A consent decision older than consentTTL is refused like an unknown
// token, and taking it still spends it: the expiry is the in-memory
// path's only time bound on code issuance.
func TestTakeConsentRefusesExpiredEntry(t *testing.T) {
	s := &OAuthServer{BaseURL: "https://api.mctl.ai"}
	ctx := context.Background()
	if err := s.StoreConsent(ctx, "fresh", ConsentEntry{PrincipalID: "prn_fresh"}); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreConsent(ctx, "stale", ConsentEntry{PrincipalID: "prn_stale"}); err != nil {
		t.Fatal(err)
	}
	s.consents.Store("stale", consentMem{e: ConsentEntry{PrincipalID: "prn_stale"}, expires: time.Now().Add(-time.Second)})

	if e, ok, err := s.TakeConsent(ctx, "fresh"); err != nil || !ok || e.PrincipalID != "prn_fresh" {
		t.Fatalf("fresh consent: %+v ok=%v err=%v", e, ok, err)
	}
	if e, ok, err := s.TakeConsent(ctx, "stale"); err != nil || ok {
		t.Fatalf("expired consent was accepted: %+v ok=%v err=%v", e, ok, err)
	}
	if _, ok := s.consents.Load("stale"); ok {
		t.Error("an expired consent stays stored after it was presented")
	}
}
