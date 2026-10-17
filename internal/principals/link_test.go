package principals

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func zitadel(sub, name string) auth.Identity {
	return auth.Identity{Provider: "zitadel", Issuer: "https://auth.mctl.ai", Subject: sub, Display: name, Kind: auth.KindHuman}
}

func TestLinkIdentityAttachesToTheProvenPrincipal(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.Provision(ctx, github(1, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice"))
	if err != nil || got != LinkLinked {
		t.Fatalf("link = %q, %v; want linked", got, err)
	}
	// The ZITADEL login now resolves to the same principal, not a new one.
	q, err := s.Provision(ctx, zitadel("z1", "alice"))
	if err != nil || q.ID != p.ID {
		t.Fatalf("zitadel resolves to %v (%v), want %s", q, err, p.ID)
	}
	again, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice"))
	if err != nil || again != LinkAlreadyLinked {
		t.Fatalf("relink = %q, %v; want already_linked", again, err)
	}
}

// Owner decision A on #435: an identity already owned by another principal
// is refused, never moved by self-service.
func TestLinkIdentityRefusesAnIdentityOwnedElsewhere(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	q, err := s.Provision(ctx, zitadel("z1", "alice")) // auto-provisioned before linking
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice"))
	var owned *OwnedElsewhereError
	if !errors.As(err, &owned) || owned.PrincipalID != q.ID || !errors.Is(err, ErrIdentityOwnedElsewhere) {
		t.Fatalf("err = %v, want OwnedElsewhereError naming %s", err, q.ID)
	}
	ids, _ := s.Identities(ctx, q.ID)
	if len(ids) != 1 || ids[0].PrincipalID != q.ID {
		t.Fatalf("the identity moved: %+v", ids)
	}
}

func TestLinkIdentityRefusesASecondIdentityOfTheSameProvider(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z2", "alice2")); !errors.Is(err, ErrPrincipalAlreadyLinked) {
		t.Fatalf("err = %v, want ErrPrincipalAlreadyLinked", err)
	}
}

func TestLinkIdentityRefusesARevokedIdentityAndADisabledPrincipal(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); err != nil {
		t.Fatal(err)
	}
	ids, _ := s.Identities(ctx, p.ID)
	var zid string
	for _, x := range ids {
		if x.Provider == "zitadel" {
			zid = x.ID
		}
	}
	if _, err := s.UnlinkIdentity(ctx, p.ID, zid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); !errors.Is(err, ErrIdentityRevoked) {
		t.Fatalf("err = %v, want ErrIdentityRevoked", err)
	}

	d, _ := s.Provision(ctx, github(2, "bob"))
	if err := s.SetStatus(ctx, d.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkIdentity(ctx, d.ID, zitadel("z3", "bob")); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("err = %v, want ErrPrincipalDisabled", err)
	}
}

func TestLinkIdentityRefusesNonHumanIdentities(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	agent := auth.Identity{Provider: auth.ProviderAgent, Subject: "agent:x", Kind: auth.KindAgent}
	if _, err := s.LinkIdentity(ctx, p.ID, agent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

// Two links of one ZITADEL identity to two principals at once: one wins,
// the other is told the identity is owned elsewhere. Never two rows.
func TestConcurrentLinksOfOneIdentityLinkOnce(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	const workers = 12
	ps := make([]string, workers)
	for i := range ps {
		p, err := s.Provision(ctx, github(int64(100+i), "u"+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		ps[i] = p.ID
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range ps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = s.LinkIdentity(ctx, ps[i], zitadel("shared", "x"))
		}(i)
	}
	close(start)
	wg.Wait()
	linked := 0
	for _, err := range errs {
		switch {
		case err == nil:
			linked++
		case errors.Is(err, ErrIdentityOwnedElsewhere):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	var rows int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM external_identities WHERE provider='zitadel'").Scan(&rows)
	if linked != 1 || rows != 1 {
		t.Fatalf("linked=%d rows=%d, want 1 and 1", linked, rows)
	}
}

func TestUnlinkIdentityKeepsTheLastIdentity(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); err != nil {
		t.Fatal(err)
	}
	ids, _ := s.Identities(ctx, p.ID)
	if len(ids) != 2 {
		t.Fatalf("identities = %d, want 2", len(ids))
	}
	first, err := s.UnlinkIdentity(ctx, p.ID, ids[1].ID)
	if err != nil || first.RevokedAt == nil {
		t.Fatalf("unlink = %+v, %v", first, err)
	}
	if _, err := s.UnlinkIdentity(ctx, p.ID, ids[1].ID); err != nil {
		t.Fatalf("second unlink of a revoked identity should be a no-op: %v", err)
	}
	if _, err := s.UnlinkIdentity(ctx, p.ID, ids[0].ID); !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("err = %v, want ErrLastIdentity", err)
	}
	// Someone else's identity is not found, not revoked.
	o, _ := s.Provision(ctx, github(3, "carol"))
	oids, _ := s.Identities(ctx, o.ID)
	if _, err := s.UnlinkIdentity(ctx, p.ID, oids[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// The revoked ZITADEL identity is refused at authentication.
	if _, err := s.Provision(ctx, zitadel("z1", "alice")); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("err = %v, want ErrIdentityRefused", err)
	}
}

func TestMergePrincipalsMovesIdentitiesAndDisablesTheSource(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	q, _ := s.Provision(ctx, zitadel("z1", "alice"))

	res, err := s.MergePrincipals(ctx, q.ID, p.ID)
	if err != nil || res.Moved != 1 || res.AlreadyMerged {
		t.Fatalf("merge = %+v, %v; want 1 moved", res, err)
	}
	got, err := s.Provision(ctx, zitadel("z1", "alice"))
	if err != nil || got.ID != p.ID {
		t.Fatalf("zitadel resolves to %v (%v), want %s", got, err, p.ID)
	}
	src, _ := s.Get(ctx, q.ID)
	if src == nil || src.Status != StatusDisabled {
		t.Fatalf("source principal = %+v, want disabled (kept, not deleted)", src)
	}
}

func TestMergePrincipalsRefusesConflictsAndBadPairs(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); err != nil {
		t.Fatal(err)
	}
	q, _ := s.Provision(ctx, zitadel("z2", "alice-other"))
	if _, err := s.MergePrincipals(ctx, q.ID, p.ID); !errors.Is(err, ErrMergeConflict) {
		t.Fatalf("err = %v, want ErrMergeConflict", err)
	}
	if _, err := s.MergePrincipals(ctx, p.ID, p.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self merge err = %v, want ErrInvalid", err)
	}
	agent, _ := s.Provision(ctx, auth.Identity{Provider: auth.ProviderAgent, Subject: "agent:a", Kind: auth.KindAgent})
	r, _ := s.Provision(ctx, github(2, "bob"))
	if _, err := s.MergePrincipals(ctx, agent.ID, r.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("agent merge err = %v, want ErrInvalid", err)
	}
	if err := s.SetStatus(ctx, r.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergePrincipals(ctx, q.ID, r.ID); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("into disabled err = %v, want ErrPrincipalDisabled", err)
	}
	if _, err := s.MergePrincipals(ctx, "prn_missing", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing err = %v, want ErrNotFound", err)
	}
}

// A merge or an unlink takes effect on the next request, not after the
// resolver cache expires: the caller forgets the affected principals.
func TestResolverForgetsMergedAndUnlinkedPrincipals(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	r := NewResolver(s, nil, false)
	p, _ := s.Provision(ctx, github(1, "alice"))
	q, _ := s.Provision(ctx, zitadel("z1", "alice"))
	if got, err := r.ResolvePrincipal(ctx, zitadel("z1", "alice")); err != nil || got != q.ID {
		t.Fatalf("before merge = %q, %v; want %s", got, err, q.ID)
	}
	if _, err := s.MergePrincipals(ctx, q.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	// Still cached: this is the window Forget closes.
	if got, _ := r.ResolvePrincipal(ctx, zitadel("z1", "alice")); got != q.ID {
		t.Fatalf("cached answer = %q, want the stale %s (else this test proves nothing)", got, q.ID)
	}
	r.Forget(q.ID, p.ID)
	if got, err := r.ResolvePrincipal(ctx, zitadel("z1", "alice")); err != nil || got != p.ID {
		t.Fatalf("after merge = %q, %v; want %s", got, err, p.ID)
	}

	ids, _ := s.Identities(ctx, p.ID)
	var zid string
	for _, x := range ids {
		if x.Provider == "zitadel" {
			zid = x.ID
		}
	}
	if _, err := s.UnlinkIdentity(ctx, p.ID, zid); err != nil {
		t.Fatal(err)
	}
	r.Forget(p.ID)
	if _, err := r.ResolvePrincipal(ctx, zitadel("z1", "alice")); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("after unlink err = %v, want ErrIdentityRefused", err)
	}
	if got, err := r.ResolvePrincipal(ctx, github(1, "alice")); err != nil || got != p.ID {
		t.Fatalf("the remaining identity = %q, %v; want %s", got, err, p.ID)
	}
}

func TestMergePrincipalsLeavesRevokedIdentitiesOnTheSource(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	q, _ := s.Provision(ctx, zitadel("z1", "alice"))
	if _, err := s.LinkIdentity(ctx, q.ID, github(9, "alice-old")); err != nil {
		t.Fatal(err)
	}
	ids, _ := s.Identities(ctx, q.ID)
	for _, x := range ids {
		if x.Provider == auth.ProviderGitHub {
			if _, err := s.UnlinkIdentity(ctx, q.ID, x.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	res, err := s.MergePrincipals(ctx, q.ID, p.ID)
	if err != nil || res.Moved != 1 {
		t.Fatalf("merge = %+v, %v; want 1 live identity moved", res, err)
	}
	left, _ := s.Identities(ctx, q.ID)
	if len(left) != 1 || left[0].RevokedAt == nil {
		t.Fatalf("source keeps %+v, want only its revoked identity", left)
	}
}

// An admin retrying a merge (a timeout, a double click) gets the same answer
// and changes nothing; a source disabled for another reason is refused.
func TestMergePrincipalsIsSafeToRetryAndRefusesADisabledSource(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.Provision(ctx, github(1, "alice"))
	q, _ := s.Provision(ctx, zitadel("z1", "alice"))
	if res, err := s.MergePrincipals(ctx, q.ID, p.ID); err != nil || res.Moved != 1 {
		t.Fatalf("merge = %+v, %v", res, err)
	}
	res, err := s.MergePrincipals(ctx, q.ID, p.ID)
	if err != nil || !res.AlreadyMerged || res.Moved != 0 {
		t.Fatalf("retry = %+v, %v; want already merged, nothing moved", res, err)
	}
	if got, _ := s.Provision(ctx, zitadel("z1", "alice")); got == nil || got.ID != p.ID {
		t.Fatalf("after retry zitadel resolves to %+v, want %s", got, p.ID)
	}

	d, _ := s.Provision(ctx, github(2, "bob"))
	if err := s.SetStatus(ctx, d.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergePrincipals(ctx, d.ID, p.ID); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("disabled source err = %v, want ErrPrincipalDisabled", err)
	}
	if ids, _ := s.Identities(ctx, d.ID); len(ids) != 1 || ids[0].PrincipalID != d.ID {
		t.Fatalf("a refused merge moved identities: %+v", ids)
	}
}

// The orphan case (mctlhq/mctl-api#377): a principal whose only identity is
// a removed ZITADEL user. Disabling it refuses that identity everywhere,
// keeps it bound, and a retry changes nothing.
func TestDisablePrincipalRefusesItsIdentitiesAndIsSafeToRetry(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	r := NewResolver(s, nil, false)
	q, _ := s.Provision(ctx, zitadel("z-orphan", "orphan"))
	if got, err := r.ResolvePrincipal(ctx, zitadel("z-orphan", "orphan")); err != nil || got != q.ID {
		t.Fatalf("before disable = %q, %v", got, err)
	}
	res, err := s.DisablePrincipal(ctx, q.ID, nil)
	if err != nil || res.AlreadyDisabled || res.LiveIdentities != 1 {
		t.Fatalf("disable = %+v, %v; want disabled now with 1 live identity", res, err)
	}
	if got, _ := s.Get(ctx, q.ID); got == nil || got.Status != StatusDisabled {
		t.Fatalf("principal after disable = %+v", got)
	}
	r.Forget(q.ID)
	if _, err := r.ResolvePrincipal(ctx, zitadel("z-orphan", "orphan")); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("resolve after disable err = %v, want ErrPrincipalDisabled", err)
	}
	// The identity stays bound: its next sign-in does not provision a
	// fresh, active principal.
	if got, err := s.Provision(ctx, zitadel("z-orphan", "orphan")); err != nil || got.ID != q.ID || got.Status != StatusDisabled {
		t.Fatalf("provision after disable = %+v, %v; want the disabled %s", got, err, q.ID)
	}
	if ids, _ := s.Identities(ctx, q.ID); len(ids) != 1 || ids[0].RevokedAt != nil {
		t.Fatalf("identities after disable = %+v, want the one, still live", ids)
	}
	res, err = s.DisablePrincipal(ctx, q.ID, nil)
	if err != nil || !res.AlreadyDisabled || res.LiveIdentities != 1 {
		t.Fatalf("retry = %+v, %v; want already disabled", res, err)
	}
	// Still disabled with a live identity, so a merge from it is refused as
	// disabled, not answered as already merged.
	p, _ := s.Provision(ctx, github(1, "alice"))
	if _, err := s.MergePrincipals(ctx, q.ID, p.ID); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("merge from a disabled principal err = %v, want ErrPrincipalDisabled", err)
	}
}

func TestDisablePrincipalRefusesNonHumansAndUnknowns(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	agent, err := s.Provision(ctx, auth.Identity{Provider: auth.ProviderAgent, Subject: "agent:d", Kind: auth.KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DisablePrincipal(ctx, agent.ID, nil); !errors.Is(err, ErrNotHuman) {
		t.Fatalf("agent disable err = %v, want ErrNotHuman", err)
	}
	if got, _ := s.Get(ctx, agent.ID); got == nil || got.Status != StatusActive {
		t.Fatalf("a refused disable changed the agent: %+v", got)
	}
	if _, err := s.DisablePrincipal(ctx, "prn_01M51RRWSHH3VR3W4RTYY9238K", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown principal err = %v, want ErrNotFound", err)
	}
	if _, err := s.DisablePrincipal(ctx, "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty id err = %v, want ErrInvalid", err)
	}
}

// The last active ADMIN_PRINCIPALS principal is never disabled; an admin
// that is disabled, not human, or does not exist does not count as another.
func TestDisablePrincipalKeepsTheLastAdmin(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a, _ := s.Provision(ctx, github(1, "alice"))
	b, _ := s.Provision(ctx, github(2, "bob"))
	agent, _ := s.Provision(ctx, auth.Identity{Provider: auth.ProviderAgent, Subject: "agent:admin", Kind: auth.KindAgent})
	if err := s.SetStatus(ctx, b.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	admins := []string{a.ID, b.ID, agent.ID, "prn_01M51RRWSHH3VR3W4RTYY9238K", ""}
	if _, err := s.DisablePrincipal(ctx, a.ID, admins); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin disable err = %v, want ErrLastAdmin", err)
	}
	if got, _ := s.Get(ctx, a.ID); got == nil || got.Status != StatusActive {
		t.Fatalf("a refused disable changed the last admin: %+v", got)
	}
	if err := s.SetStatus(ctx, b.ID, StatusActive); err != nil {
		t.Fatal(err)
	}
	if res, err := s.DisablePrincipal(ctx, a.ID, admins); err != nil || res.AlreadyDisabled {
		t.Fatalf("disable with another active admin = %+v, %v", res, err)
	}
	// Now b is the last one, and a retry on a stays a no-op.
	if _, err := s.DisablePrincipal(ctx, b.ID, admins); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable of the remaining admin err = %v, want ErrLastAdmin", err)
	}
	if res, err := s.DisablePrincipal(ctx, a.ID, admins); err != nil || !res.AlreadyDisabled {
		t.Fatalf("retry on a disabled admin = %+v, %v", res, err)
	}
}

// Two admins disabling each other at once: at most one succeeds, so at
// least one admin principal stays active.
func TestDisablePrincipalMutualAdminDisableLeavesOne(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		a, _ := s.Provision(ctx, github(int64(100+2*round), "a"+strconv.Itoa(round)))
		b, _ := s.Provision(ctx, github(int64(101+2*round), "b"+strconv.Itoa(round)))
		admins := []string{a.ID, b.ID}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, id := range []string{a.ID, b.ID} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.DisablePrincipal(ctx, id, admins)
			}()
		}
		wg.Wait()
		active := 0
		for _, id := range admins {
			if got, _ := s.Get(ctx, id); got != nil && got.Status == StatusActive {
				active++
			}
		}
		if active != 1 {
			t.Fatalf("round %d: %d admins active after a mutual disable (errs %v), want 1", round, active, errs)
		}
		if (errs[0] == nil) == (errs[1] == nil) || (!errors.Is(errs[0], ErrLastAdmin) && !errors.Is(errs[1], ErrLastAdmin)) {
			t.Fatalf("round %d: errs %v, want one success and one ErrLastAdmin", round, errs)
		}
	}
}

func customer(sub string, githubID int64, login string) auth.Identity {
	id := zitadel(sub, login+"@mctl.ai")
	id.Customer = &auth.CustomerProof{GitHubID: strconv.FormatInt(githubID, 10), GitHubLogin: login}
	return id
}

// Stage C0: a customer lands on the principal of the GitHub id the hook
// proved, the ZITADEL subject is linked to it, and a second sign-in finds
// the same principal.
func TestResolveCustomerKeysOnTheGitHubID(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	gh, err := s.Provision(ctx, github(7, "bob"))
	if err != nil || gh.ID != p.ID {
		t.Fatalf("GitHub id 7 resolves to %v (%v), want the customer's %s", gh, err, p.ID)
	}
	again, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if err != nil || again.ID != p.ID {
		t.Fatalf("second sign-in = %v (%v), want %s", again, err, p.ID)
	}
	ids, _ := s.Identities(ctx, p.ID)
	if len(ids) != 2 {
		t.Fatalf("identities = %+v, want the GitHub id and the ZITADEL subject", ids)
	}
}

// A GitHub id that already has a principal (a legacy sign-up resolved it
// through surface-principals/github) is reused, not duplicated.
func TestResolveCustomerJoinsTheExistingPrincipalOfTheGitHubID(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	existing, err := s.Provision(ctx, github(7, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if err != nil || p.ID != existing.ID {
		t.Fatalf("customer = %v (%v), want the existing %s", p, err, existing.ID)
	}
}

// The Alice/Bob case: a login freed by one GitHub account and taken by
// another resolves by id, so Bob never lands on Alice's principal.
func TestResolveCustomerNeverMatchesAReusedLogin(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	alice, err := s.Provision(ctx, github(1, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.ResolveCustomer(ctx, customer("z2", 2, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if bob.ID == alice.ID {
		t.Fatalf("Bob resolved to Alice's principal %s through the reused login", alice.ID)
	}
}

// A ZITADEL subject that already has a principal of its own is a conflict
// for an admin, refused as such, and nothing moves.
func TestResolveCustomerRefusesASubjectOwnedElsewhere(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	own, err := s.Provision(ctx, zitadel("z1", "bob@mctl.ai"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if !errors.Is(err, auth.ErrIdentityRefused) || !errors.Is(err, ErrCustomerConflict) || !errors.Is(err, ErrIdentityOwnedElsewhere) {
		t.Fatalf("err = %v, want a refused customer conflict", err)
	}
	ids, _ := s.Identities(ctx, own.ID)
	if len(ids) != 1 {
		t.Fatalf("the subject moved: %+v", ids)
	}
	// Deliberate: the GitHub id's own principal exists after the refusal,
	// with only its GitHub identity, for an admin to merge into.
	gh, err := s.Provision(ctx, customer("z1", 7, "bob").Customer.GitHubIdentity())
	if err != nil || gh.ID == own.ID {
		t.Fatalf("GitHub principal = %+v, %v", gh, err)
	}
	if ids, _ := s.Identities(ctx, gh.ID); len(ids) != 1 || ids[0].Provider != auth.ProviderGitHub {
		t.Fatalf("GitHub principal identities = %+v, want only the GitHub one", ids)
	}
}

// A second ZITADEL account for the same GitHub id (a deleted and recreated
// customer) is refused until an admin unlinks the first.
func TestResolveCustomerRefusesASecondSubjectForTheSameGitHubID(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if _, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob")); err != nil {
		t.Fatal(err)
	}
	_, err := s.ResolveCustomer(ctx, customer("z9", 7, "bob"))
	if !errors.Is(err, auth.ErrIdentityRefused) || !errors.Is(err, ErrPrincipalAlreadyLinked) {
		t.Fatalf("err = %v, want refused: principal already linked", err)
	}
}

func TestResolveCustomerRefusesARevokedGitHubIdentity(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE external_identities SET revoked_at=now() WHERE principal_id=$1 AND provider='github'`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob")); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("err = %v, want refused", err)
	}
}

func TestResolveCustomerRefusesADisabledPrincipal(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE principals SET status='disabled' WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ResolveCustomer(ctx, customer("z1", 7, "bob")); err != nil || got.ID != p.ID || got.Status != StatusDisabled {
		t.Fatalf("ResolveCustomer = %+v, %v; want the disabled principal", got, err)
	}
	// Through the resolver, as every caller sees it: refused as disabled,
	// not a failed read that bearer requests would degrade past.
	r := NewResolver(s, nil, false)
	if _, err := r.ResolvePrincipal(ctx, customer("z1", 7, "bob")); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("ResolvePrincipal err = %v, want ErrPrincipalDisabled", err)
	}
	// A disabled principal gets no new identity linked.
	if _, err := r.ResolvePrincipal(ctx, customer("z2", 8, "carol")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE principals SET status='disabled' WHERE id=(SELECT principal_id FROM external_identities WHERE provider='github' AND subject='8')`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ResolveCustomer(ctx, customer("z3", 8, "carol")); err != nil || got.Status != StatusDisabled {
		t.Fatalf("ResolveCustomer = %+v, %v", got, err)
	}
	if _, _, err := s.LinkedGitHub(ctx, zitadel("z3", "carol")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("z3 was linked to a disabled principal: %v", err)
	}
}

func TestResolveCustomerRefusesANonCustomerIdentity(t *testing.T) {
	s := newStoreForTest(t)
	if _, err := s.ResolveCustomer(context.Background(), zitadel("z1", "bob")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

// Disabled between the provision and the link (two transactions): still
// refused as disabled through the resolver, not degraded as a failed read.
func TestResolveCustomerDisabledBetweenProvisionAndLink(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	s.beforeCustomerLink = func() {
		if _, err := s.pool.Exec(ctx, `UPDATE principals SET status='disabled' WHERE id=(SELECT principal_id FROM external_identities WHERE provider='github' AND subject='7')`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewResolver(s, nil, false).ResolvePrincipal(ctx, customer("z1", 7, "bob")); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("err = %v, want ErrPrincipalDisabled", err)
	}
	if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "bob")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("z1 was linked to a disabled principal: %v", err)
	}
}
