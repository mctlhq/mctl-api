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

package surfaceid

import (
	"context"
	"errors"
	"testing"
	"time"
)

func linkFor(t *testing.T, s *Store, principal, surface, externalID string) *Link {
	t.Helper()
	ctx := context.Background()
	c, err := s.CreateChallenge(ctx, principal, surface)
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Redeem(ctx, surface, c.Code, externalID)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// LinkByID (mctl-api#376 slice B, delegation.SurfaceLinkSource) reuses
// Resolve's own liveness rules: not found, revoked and expired are the same
// three sentinels Resolve yields.
func TestLinkByID_ReusesResolvesLivenessRules(t *testing.T) {
	s := newStoreForTest(t, 0)
	ctx := context.Background()

	live := linkFor(t, s, "github:alice", SurfaceTelegram, "4242")
	surface, externalID, principal, err := s.LinkByID(ctx, live.ID)
	if err != nil || surface != SurfaceTelegram || externalID != "4242" || principal != "github:alice" {
		t.Fatalf("live link = %q %q %q %v", surface, externalID, principal, err)
	}

	if _, _, _, err := s.LinkByID(ctx, "sil_doesnotexist"); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrLinkNotFound", err)
	}

	revoked := linkFor(t, s, "github:bob", SurfaceTelegram, "555")
	if _, err := s.Revoke(ctx, revoked.ID, "github:bob", false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.LinkByID(ctx, revoked.ID); !errors.Is(err, ErrLinkRevoked) {
		t.Fatalf("revoked link: err = %v, want ErrLinkRevoked", err)
	}

	expiring := newStoreForTest(t, time.Hour)
	exp := linkFor(t, expiring, "github:carol", SurfaceTelegram, "777")
	if _, err := expiring.pool.Exec(ctx, `UPDATE surface_identity_links SET expires_at=$1 WHERE id=$2`, expiring.now().Add(-time.Minute), exp.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := expiring.LinkByID(ctx, exp.ID); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("expired link: err = %v, want ErrLinkExpired", err)
	}
}
