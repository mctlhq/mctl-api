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

	moved, err := s.MergePrincipals(ctx, q.ID, p.ID)
	if err != nil || moved != 1 {
		t.Fatalf("merge = %d, %v; want 1 moved", moved, err)
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
	moved, err := s.MergePrincipals(ctx, q.ID, p.ID)
	if err != nil || moved != 1 {
		t.Fatalf("merge = %d, %v; want 1 live identity moved", moved, err)
	}
	left, _ := s.Identities(ctx, q.ID)
	if len(left) != 1 || left[0].RevokedAt == nil {
		t.Fatalf("source keeps %+v, want only its revoked identity", left)
	}
}
