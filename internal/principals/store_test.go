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

package principals

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed principal test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	wipe := func() {
		for _, q := range []string{
			"DELETE FROM external_identities",
			"DELETE FROM principals",
			// The surface tables exist once any test built a surface store.
			"DELETE FROM surface_identity_links",
			"DELETE FROM surface_identity_challenges",
		} {
			if _, err := s.pool.Exec(ctx, q); err != nil && !isUndefinedTable(err) {
				t.Fatal(err)
			}
		}
	}
	wipe()
	t.Cleanup(func() { wipe(); s.Close() })
	return s
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

func github(id int64, login string) auth.Identity {
	return auth.Identity{Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(id, 10), Display: login, Kind: auth.KindHuman}
}

func TestProvisionIsIdempotentUnderConcurrency(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	const rounds, workers = 8, 24
	for round := 0; round < rounds; round++ {
		id := github(int64(1000+round), "user"+strconv.Itoa(round))
		start := make(chan struct{})
		var wg sync.WaitGroup
		ids := make([]string, workers)
		errs := make([]error, workers)
		for i := range ids {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				p, err := s.Provision(ctx, id)
				if err == nil {
					ids[i] = p.ID
				}
				errs[i] = err
			}(i)
		}
		close(start)
		wg.Wait()
		for i := range ids {
			if errs[i] != nil {
				t.Fatalf("round %d: %v", round, errs[i])
			}
			if ids[i] != ids[0] {
				t.Fatalf("round %d: one identity got two principals: %s and %s", round, ids[0], ids[i])
			}
		}
	}
	var principals, identities int
	if err := s.pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM principals), (SELECT count(*) FROM external_identities)").Scan(&principals, &identities); err != nil {
		t.Fatal(err)
	}
	if principals != rounds || identities != rounds {
		t.Fatalf("%d principals, %d identities; want %d and %d", principals, identities, rounds, rounds)
	}
}

// The regression the model exists for: a Dex subject spelled like a GitHub
// login is someone else.
func TestDexUsernameSpelledLikeAGitHubLoginIsADifferentPrincipal(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	gh, err := s.Provision(ctx, github(7, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	dex, err := s.Provision(ctx, auth.Identity{Provider: auth.ProviderDex, Issuer: "https://dex.example", Subject: "bob", Display: "bob", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	if dex.ID == gh.ID {
		t.Fatal("a Dex user named bob became the GitHub user bob")
	}
	// And the login-only path finds only the GitHub one.
	p, err := s.ResolveGitHubLogin(ctx, "bob")
	if err != nil || p.ID != gh.ID {
		t.Fatalf("login bob resolved to %v, %v; want %s", p, err, gh.ID)
	}
}

// A renamed GitHub account keeps its principal (it is keyed on the numeric
// id), and a login that changes hands never reaches the previous owner.
func TestGitHubRenameKeepsThePrincipalAndMovesTheLogin(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	first, err := s.Provision(ctx, github(1, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := s.Provision(ctx, github(1, "alice-renamed"))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != first.ID {
		t.Fatal("a rename produced a new principal")
	}
	if _, err := s.ResolveGitHubLogin(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the old login still resolves: %v", err)
	}
	taker, err := s.Provision(ctx, github(2, "alice-renamed"))
	if err != nil {
		t.Fatal(err)
	}
	if taker.ID == first.ID {
		t.Fatal("the account that took the login inherited the old principal")
	}
	p, err := s.ResolveGitHubLogin(ctx, "ALICE-RENAMED")
	if err != nil || p.ID != taker.ID {
		t.Fatalf("login now resolves to %v, %v; want the new holder %s", p, err, taker.ID)
	}
	// The previous holder's row no longer carries the login at all, so no
	// ordering of verified_at can ever route the login back to it.
	idents, err := s.Identities(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range idents {
		if strings.EqualFold(x.Display, "alice-renamed") {
			t.Fatalf("the previous holder still carries the login: %+v", x)
		}
	}
}

// Two accounts swapping logins at once: each claim writes the other's row.
// Serialized on the login, neither deadlocks.
func TestCrossedLoginClaimsDoNotDeadlock(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	for round := 0; round < 20; round++ {
		a, b := "x"+strconv.Itoa(round), "y"+strconv.Itoa(round)
		ida, idb := int64(5000+2*round), int64(5001+2*round)
		if _, err := s.Provision(ctx, github(ida, a)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Provision(ctx, github(idb, b)); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		for _, c := range []struct {
			id    int64
			login string
		}{{ida, b}, {idb, a}} {
			go func(id int64, login string) {
				<-start
				_, err := s.Provision(ctx, github(id, login))
				errs <- err
			}(c.id, c.login)
		}
		close(start)
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
}

// A surface may not take an authentication provider's name: its mirror row
// would collide with, and repoint, a real identity.
func TestMirrorRefusesReservedProviderNames(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	gh, err := s.Provision(ctx, github(4242, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Provision(ctx, github(77, "bob")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{auth.ProviderGitHub, auth.ProviderDex, auth.ProviderService, auth.ProviderDev} {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// "bob" linking surface-native id 4242 on a surface named github
		// would otherwise move alice's GitHub identity onto bob.
		err = s.MirrorLink(ctx, tx, name, "4242", "github:bob")
		_ = tx.Rollback(ctx)
		if err == nil {
			t.Fatalf("surface %q was mirrored", name)
		}
	}
	p, err := s.ResolveGitHubLogin(ctx, "alice")
	if err != nil || p.ID != gh.ID {
		t.Fatalf("alice now resolves to %v, %v", p, err)
	}
}

func TestProvisionRejectsMalformedIdentities(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	for name, id := range map[string]auth.Identity{
		"github login as subject": {Provider: auth.ProviderGitHub, Subject: "alice", Kind: auth.KindHuman},
		"no subject":              {Provider: auth.ProviderDex, Issuer: "x", Kind: auth.KindHuman},
		"unknown kind":            {Provider: auth.ProviderService, Subject: "mctl-agent", Kind: "robot"},
	} {
		if _, err := s.Provision(ctx, id); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestARevokedIdentityIsRefusedNotReprovisioned(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if _, err := s.Provision(ctx, github(5, "eve")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE external_identities SET revoked_at=now() WHERE subject='5'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Provision(ctx, github(5, "eve")); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("err = %v, want ErrIdentityRefused", err)
	}
	var n int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM principals").Scan(&n)
	if n != 1 {
		t.Fatalf("%d principals; a revoked identity must not get a new one", n)
	}
}

func TestDisabledPrincipalIsRefusedThroughTheResolver(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.Provision(ctx, github(9, "mallory"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus(ctx, p.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver(s, nil, false).ResolvePrincipal(ctx, github(9, "mallory")); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("err = %v, want ErrPrincipalDisabled", err)
	}
}

func TestBackfillIsIdempotent(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	ids := map[string]int64{"alice": 1, "bob": 2}
	calls := 0
	lookup := func(_ context.Context, login string) (int64, error) {
		calls++
		if id, ok := ids[login]; ok {
			return id, nil
		}
		return 0, errors.New("404")
	}
	logins := []string{"alice", "Alice", "bob", "ghost", ""}
	first, err := s.Backfill(ctx, logins, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if first.Logins != 3 || first.Provisioned != 2 || first.Failed != 1 || first.Known != 0 {
		t.Fatalf("first run = %+v", first)
	}
	second, err := s.Backfill(ctx, logins, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if second.Provisioned != 0 || second.Known != 2 {
		t.Fatalf("second run = %+v; want nothing new", second)
	}
	// Known logins cost no GitHub call the second time: only ghost is retried.
	if calls != 4 {
		t.Fatalf("%d lookups, want 4 (3 then 1)", calls)
	}
	var n int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM principals").Scan(&n)
	if n != 2 {
		t.Fatalf("%d principals after two runs, want 2", n)
	}
}

func newSurfaceStore(t *testing.T) *surfaceid.Store {
	t.Helper()
	ss, err := surfaceid.NewStore(context.Background(), os.Getenv("TEST_DATABASE_URL"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Close)
	return ss
}

func link(t *testing.T, ss *surfaceid.Store, login, telegramID string) *surfaceid.Link {
	t.Helper()
	ctx := context.Background()
	c, err := ss.CreateChallenge(ctx, "github:"+login, surfaceid.SurfaceTelegram)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ss.Redeem(ctx, surfaceid.SurfaceTelegram, c.Code, telegramID)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func telegramIdentity(t *testing.T, s *Store, telegramID string) (principalID string, revoked bool, found bool) {
	t.Helper()
	var at *time.Time
	err := s.pool.QueryRow(context.Background(), `SELECT principal_id, revoked_at FROM external_identities
		WHERE provider='telegram' AND issuer='' AND subject=$1`, telegramID).Scan(&principalID, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return principalID, at != nil, true
}

// Mirror, not replace: a redeemed link appears as the human's telegram
// identity in the same transaction, and revoking the link revokes it.
func TestSurfaceLinkIsMirroredAndRevoked(t *testing.T) {
	s := newStoreForTest(t)
	ss := newSurfaceStore(t)
	ss.SetMirror(s)
	ctx := context.Background()
	alice, err := s.Provision(ctx, github(1, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	l := link(t, ss, "alice", "1001")
	pid, revoked, found := telegramIdentity(t, s, "1001")
	if !found || revoked || pid != alice.ID {
		t.Fatalf("mirror = %q revoked=%v found=%v; want alice's principal", pid, revoked, found)
	}
	if _, err := ss.Revoke(ctx, l.ID, "github:alice", false); err != nil {
		t.Fatal(err)
	}
	if _, revoked, _ := telegramIdentity(t, s, "1001"); !revoked {
		t.Fatal("revoking the link left the mirrored identity live")
	}
	link(t, ss, "alice", "1001")
	if _, revoked, _ := telegramIdentity(t, s, "1001"); revoked {
		t.Fatal("a fresh possession proof did not reactivate the mirror")
	}
}

type failingMirror struct{}

func (failingMirror) MirrorLink(context.Context, pgx.Tx, string, string, string) error {
	return errors.New("mirror down")
}
func (failingMirror) MirrorRevoke(context.Context, pgx.Tx, string, string, time.Time) error {
	return errors.New("mirror down")
}

// Same transaction: when the mirror fails, the link is not created either.
func TestAFailedMirrorRollsTheRedeemBack(t *testing.T) {
	newStoreForTest(t)
	ss := newSurfaceStore(t)
	ss.SetMirror(failingMirror{})
	ctx := context.Background()
	c, err := ss.CreateChallenge(ctx, "github:alice", surfaceid.SurfaceTelegram)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Redeem(ctx, surfaceid.SurfaceTelegram, c.Code, "2002"); err == nil {
		t.Fatal("redeem succeeded although its mirror failed")
	}
	if _, err := ss.Resolve(ctx, surfaceid.SurfaceTelegram, "2002"); !errors.Is(err, surfaceid.ErrLinkNotFound) {
		t.Fatalf("a link exists without its mirror: %v", err)
	}
}

// A link made before its human had a principal is mirrored by the backfill,
// once, and a second backfill changes nothing.
func TestBackfillMirrorsLinksMadeBeforeThePrincipal(t *testing.T) {
	s := newStoreForTest(t)
	ss := newSurfaceStore(t)
	ss.SetMirror(s)
	link(t, ss, "carol", "3003") // carol has no principal yet: not mirrored
	if _, _, found := telegramIdentity(t, s, "3003"); found {
		t.Fatal("mirrored before carol had a principal")
	}
	lookup := func(context.Context, string) (int64, error) { return 33, nil }
	res, err := s.Backfill(context.Background(), []string{"carol"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if res.Provisioned != 1 || res.LinksMirrored != 1 {
		t.Fatalf("backfill = %+v", res)
	}
	carol, _ := s.ResolveGitHubLogin(context.Background(), "carol")
	if pid, _, found := telegramIdentity(t, s, "3003"); !found || pid != carol.ID {
		t.Fatalf("mirror = %q found=%v", pid, found)
	}
	again, err := s.Backfill(context.Background(), []string{"carol"}, lookup)
	if err != nil || again.LinksMirrored != 0 || again.Provisioned != 0 {
		t.Fatalf("second backfill = %+v, %v", again, err)
	}
}

// One link that cannot be mirrored is reported, and every other link is
// still mirrored and counted.
func TestBackfillMirrorsTheRestPastAFailingLink(t *testing.T) {
	s := newStoreForTest(t)
	ss := newSurfaceStore(t)
	ss.SetMirror(s)
	ctx := context.Background()
	link(t, ss, "carol", "3003")
	link(t, ss, "dave", "4004")
	// A row no mirror accepts, ordered before the good one.
	if _, err := s.pool.Exec(ctx, `UPDATE surface_identity_links SET surface='github' WHERE external_id='3003'`); err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{"carol": 33, "dave": 44}
	lookup := func(_ context.Context, login string) (int64, error) { return ids[login], nil }
	res, err := s.Backfill(ctx, []string{"carol", "dave"}, lookup)
	if err == nil {
		t.Fatal("the failing link was not reported")
	}
	if res.LinksMirrored != 1 {
		t.Fatalf("backfill = %+v", res)
	}
	dave, _ := s.ResolveGitHubLogin(ctx, "dave")
	if pid, _, found := telegramIdentity(t, s, "4004"); !found || pid != dave.ID {
		t.Fatalf("dave's link after a failing one: %q found=%v", pid, found)
	}
}

func TestMirrorRevokeRefusesReservedProviderNames(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if _, err := s.Provision(ctx, github(4242, "alice")); err != nil {
		t.Fatal(err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = s.MirrorRevoke(ctx, tx, auth.ProviderGitHub, "4242", time.Now())
	if cerr := tx.Commit(ctx); cerr != nil {
		t.Fatal(cerr)
	}
	if err == nil {
		t.Fatal("a surface named github revoked a mirror row")
	}
	if _, err := s.Provision(ctx, github(4242, "alice")); err != nil {
		t.Fatalf("alice's GitHub identity after the refused revoke: %v", err)
	}
}
