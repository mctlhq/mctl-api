package glovobasket

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const pgPassword = "pw-glovo-basket-test" //nolint:gosec // throwaway password of roles in a per-test scratch database

type pgEnv struct {
	t             *testing.T
	migURL, rtURL string
	rt            string
	pool          *pgxpool.Pool
	store         *PGStore
}

func hexN(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newPGEnv is a scratch database with a migration, a work-items and a Glovo
// runtime role, the approval schema and the basket schema applied, and the
// store on a runtime-role pool, as in production.
func newPGEnv(t *testing.T) *pgEnv {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo basket database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sfx := hexN(6)
	db, mig, wi, rt := "gbk_db_"+sfx, "gbk_mig_"+sfx, "gbk_wi_"+sfx, "gbk_rt_"+sfx
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	var stmts []string
	for _, r := range []string{mig, wi, rt} {
		stmts = append(stmts, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, pgPassword))
	}
	stmts = append(stmts, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, db, mig), fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, db, wi, rt))
	for _, s := range stmts {
		if _, err := root.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	_ = root.Close(ctx)
	urlFor := func(user string) string {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		u.User, u.Path = url.UserPassword(user, pgPassword), "/"+db
		return u.String()
	}
	e := &pgEnv{t: t, migURL: urlFor(mig), rtURL: urlFor(rt), rt: rt}
	t.Cleanup(func() {
		if e.pool != nil {
			e.pool.Close()
		}
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, db))
		for _, r := range []string{rt, wi, mig} {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	if err := ApplySchema(ctx, e.migURL, rt); err == nil {
		t.Fatal("the basket schema applied without the approval schema")
	}
	if err := workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, rt, workitems.WithWorkItemsRole(wi)); err != nil {
		t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
	}
	if err := ApplySchema(ctx, e.migURL, rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	// Applying twice is a no-op.
	if err := ApplySchema(ctx, e.migURL, rt); err != nil {
		t.Fatalf("ApplySchema again: %v", err)
	}
	e.pool, err = pgxpool.New(ctx, e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	e.store = &PGStore{Pool: e.pool}
	return e
}

func (e *pgEnv) exec(sql string, args ...any) error {
	_, err := e.pool.Exec(context.Background(), sql, args...)
	return err
}

var (
	ownerA = Owner{Tenant: "alpha", PrincipalID: prnOwner}
	ownerB = Owner{Tenant: "alpha", PrincipalID: prnOther}
)

func (e *pgEnv) filled(o Owner) *Basket {
	e.t.Helper()
	ctx := context.Background()
	b, created, err := e.store.Create(ctx, o, "k-"+hexN(4), 5)
	if err != nil || !created {
		e.t.Fatalf("create: %v %v", err, created)
	}
	b, err = e.store.Update(ctx, o, b.ID, 1, []Op{{Op: "add", ItemCode: "FAKE-COFFEE", Quantity: 2}, {Op: "add", ItemCode: "FAKE-APPLE", Quantity: 6}})
	if err != nil {
		e.t.Fatalf("update: %v", err)
	}
	return b
}

func TestPGSchemaVerify(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	if err := VerifySchema(ctx, e.pool); err != nil {
		t.Fatalf("VerifySchema: %v", err)
	}
	c, err := pgx.Connect(ctx, e.migURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.Exec(ctx, `ALTER TABLE glovo.basket_revisions DISABLE TRIGGER basket_revisions_frozen`); err != nil {
		t.Fatal(err)
	}
	if err := VerifySchema(ctx, e.pool); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("disabled trigger: %v", err)
	}
	// A failed read is an error, not a verdict either way.
	e.pool.Close()
	if err := VerifySchema(ctx, e.pool); err == nil || errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("closed pool: %v", err)
	}
}

func TestPGBasketLifecycle(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	b, created, err := e.store.Create(ctx, ownerA, "k1", 2)
	if err != nil || !created || b.Current.Revision != 1 || b.Current.Fingerprint != "" {
		t.Fatalf("create: %+v %v", b, err)
	}
	again, created, err := e.store.Create(ctx, ownerA, "k1", 2)
	if err != nil || created || again.ID != b.ID {
		t.Fatalf("idempotent create: %v %v", err, created)
	}
	if _, err := e.store.RequestApproval(ctx, ownerA, b.ID, 1, time.Hour); !errors.Is(err, glovo.Refuse(glovo.CodeInvalidRequest)) {
		t.Fatalf("approval of an empty basket: %v", err)
	}
	b2, err := e.store.Update(ctx, ownerA, b.ID, 1, []Op{{Op: "add", ItemCode: "FAKE-PASTA", Quantity: 3}})
	if err != nil || b2.Current.Revision != 2 || b2.Current.Totals.TotalMinor != 3*159+199+50 {
		t.Fatalf("update: %+v %v", b2, err)
	}
	if _, err := e.store.Update(ctx, ownerA, b.ID, 1, []Op{{Op: "remove", ItemCode: "FAKE-PASTA"}}); !errors.Is(err, glovo.Refuse(glovo.CodeStaleVersion)) {
		t.Fatalf("stale update: %v", err)
	}
	ap, err := e.store.RequestApproval(ctx, ownerA, b.ID, 2, time.Hour)
	if err != nil || !ap.Created || ap.State != "pending" || ap.Fingerprint != b2.Current.Fingerprint {
		t.Fatalf("request: %+v %v", ap, err)
	}
	if again, err := e.store.RequestApproval(ctx, ownerA, b.ID, 2, time.Hour); err != nil || again.Created || again.ApprovalRef != ap.ApprovalRef {
		t.Fatalf("second request: %+v %v", again, err)
	}
	// The owner approves through the ledger.
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workitems.DecideGlovoBasketApprovalTx(ctx, tx, workitems.ActionDecisionInput{ID: ap.ApprovalRef,
		DecidedBy: "prn:" + prnOwner, DecidedByPrincipalID: prnOwner, Decision: workitems.DecisionApprove,
		AuthorityBasis: workitems.GlovoAuthorityBasis, ContextDigest: "sha256:x", AuthzMode: "principal", FreshFor: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := e.store.ApprovalStatus(ctx, ownerA, ap.ApprovalRef)
	if err != nil || st.State != "approved" || !st.AuthorizesCurrent {
		t.Fatalf("approved status: %+v %v", st, err)
	}
	// An update after the approval is a new revision the approval does not cover.
	b3, err := e.store.Update(ctx, ownerA, b.ID, 2, []Op{{Op: "set", ItemCode: "FAKE-PASTA", Quantity: 4}})
	if err != nil || b3.Current.Revision != 3 {
		t.Fatalf("update after approval: %v", err)
	}
	st, err = e.store.ApprovalStatus(ctx, ownerA, ap.ApprovalRef)
	if err != nil || st.State != "approved" || st.AuthorizesCurrent || st.CurrentRevision != 3 {
		t.Fatalf("old approval vs new revision: %+v %v", st, err)
	}
	ap3, err := e.store.RequestApproval(ctx, ownerA, b.ID, 3, time.Hour)
	if err != nil || ap3.ApprovalRef == ap.ApprovalRef || ap3.State != "pending" {
		t.Fatalf("new revision approval: %+v %v", ap3, err)
	}
	// Back to the approved lines: the fingerprint is the approved one again
	// (the canonical form has no revision), but the approval covers revision
	// 2 only, so it still does not authorize the head.
	b4, err := e.store.Update(ctx, ownerA, b.ID, 3, []Op{{Op: "set", ItemCode: "FAKE-PASTA", Quantity: 3}})
	if err != nil || b4.Current.Revision != 4 || b4.Current.Fingerprint != b2.Current.Fingerprint {
		t.Fatalf("update back to the approved lines: %+v %v", b4, err)
	}
	st, err = e.store.ApprovalStatus(ctx, ownerA, ap.ApprovalRef)
	if err != nil || st.State != "approved" || st.AuthorizesCurrent || st.CurrentRevision != 4 {
		t.Fatalf("old approval vs same-content revision: %+v %v", st, err)
	}
	// The decision payload is the approved revision, not the current one.
	p, err := e.store.DecisionPayload(ctx, ap.ApprovalRef)
	if err != nil || p.Revision != 2 || p.Fingerprint != b2.Current.Fingerprint || len(p.Lines) != 1 || p.Lines[0].Quantity != 3 || p.Owner != prnOwner {
		t.Fatalf("payload: %+v %v", p, err)
	}
	if _, err := e.store.DecisionPayload(ctx, "aar_nope"); !errors.Is(err, workitems.ErrApprovalNotFound) {
		t.Fatalf("payload of a missing approval: %v", err)
	}
	// Quota.
	if _, _, err := e.store.Create(ctx, ownerA, "k2", 2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.store.Create(ctx, ownerA, "k3", 2); !errors.Is(err, glovo.Refuse(glovo.CodeRateLimited)) {
		t.Fatalf("quota: %v", err)
	}
}

func TestPGOwnerScopeAndFailedReads(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	b := e.filled(ownerA)
	ap, err := e.store.RequestApproval(ctx, ownerA, b.ID, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]Owner{"other owner": ownerB, "other team": {Tenant: "beta", PrincipalID: prnOwner}} {
		if _, err := e.store.Get(ctx, o, b.ID); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("%s get: %v", name, err)
		}
		if _, err := e.store.Update(ctx, o, b.ID, 2, []Op{{Op: "remove", ItemCode: "FAKE-APPLE"}}); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
		if _, err := e.store.RequestApproval(ctx, o, b.ID, 2, time.Hour); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("%s request: %v", name, err)
		}
		if _, err := e.store.ApprovalStatus(ctx, o, ap.ApprovalRef); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("%s status: %v", name, err)
		}
	}
	e.pool.Close()
	if _, err := e.store.Get(ctx, ownerA, b.ID); err == nil || errors.Is(err, glovo.ErrNotFound) || !errors.Is(err, glovo.Refuse(glovo.CodeUnavailable)) {
		t.Fatalf("failed read: %v, want unavailable", err)
	}
	if _, err := e.store.ApprovalStatus(ctx, ownerA, ap.ApprovalRef); err == nil || errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("failed status read: %v", err)
	}
}

// The database holds the invariants on its own: a revision is frozen, a head
// only moves forward to a written revision, and an approval binds only an
// existing revision of the owner's own basket with its exact fingerprint.
func TestPGDatabaseGuards(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	b := e.filled(ownerA)
	// The runtime role lacks most of these grants, so its refusals prove the
	// grants; the table owner has every privilege, so its refusals prove the
	// triggers themselves.
	mig, err := pgx.Connect(ctx, e.migURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close(ctx) }()
	// An ordered list: an accepted TRUNCATE would empty the table and make
	// the later statements vacuous, so it runs last.
	for _, c := range []struct{ name, sql string }{
		{"revision update", `UPDATE glovo.basket_revisions SET total_minor = 1, subtotal_minor = 1 - delivery_fee_minor - service_fee_minor WHERE basket_id=$1`},
		{"revision lines", `UPDATE glovo.basket_revisions SET lines = '[]' WHERE basket_id=$1 AND revision = 2`},
		{"revision delete", `DELETE FROM glovo.basket_revisions WHERE basket_id=$1`},
		{"basket delete", `DELETE FROM glovo.baskets WHERE basket_id=$1`},
		{"basket identity", `UPDATE glovo.baskets SET client_key = 'other' WHERE basket_id=$1`},
		{"basket jump", `UPDATE glovo.baskets SET current_revision = 9 WHERE basket_id=$1`},
		{"basket rewind", `UPDATE glovo.baskets SET current_revision = 1 WHERE basket_id=$1`},
		{"revision truncate", `TRUNCATE glovo.basket_revisions CASCADE`},
	} {
		args := []any{b.ID}
		if strings.HasPrefix(c.sql, "TRUNCATE") {
			args = nil
		}
		var pe *pgconn.PgError
		if _, err := mig.Exec(ctx, c.sql, args...); err == nil {
			t.Errorf("owner %s: accepted", c.name)
		} else if !errors.As(err, &pe) || pe.Code != "23000" {
			t.Errorf("owner %s: refused by something other than a guard: %v", c.name, err)
		}
	}
	for name, sql := range map[string]string{
		"revision update":   `UPDATE glovo.basket_revisions SET total_minor = 1, subtotal_minor = 1 - delivery_fee_minor - service_fee_minor WHERE basket_id=$1`,
		"revision lines":    `UPDATE glovo.basket_revisions SET lines = '[]' WHERE basket_id=$1 AND revision = 2`,
		"revision delete":   `DELETE FROM glovo.basket_revisions WHERE basket_id=$1`,
		"basket delete":     `DELETE FROM glovo.baskets WHERE basket_id=$1`,
		"basket owner":      `UPDATE glovo.baskets SET current_revision = current_revision WHERE basket_id=$1`,
		"basket jump":       `UPDATE glovo.baskets SET current_revision = 9 WHERE basket_id=$1`,
		"basket rewind":     `UPDATE glovo.baskets SET current_revision = 1 WHERE basket_id=$1`,
		"revision truncate": `TRUNCATE glovo.basket_revisions`,
	} {
		args := []any{b.ID}
		if strings.HasPrefix(sql, "TRUNCATE") {
			args = nil
		}
		if err := e.exec(sql, args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A revision whose fingerprint is not its canonical bytes' hash.
	if err := e.exec(`INSERT INTO glovo.basket_revisions (basket_id, revision, tenant, owner_principal_id, lines, currency, store_ref,
		subtotal_minor, delivery_fee_minor, service_fee_minor, discount_minor, total_minor, canonical, basket_fingerprint, created_at)
		VALUES ($1, 3, $2, $3, '[{"x":1}]', 'EUR', $4, 1, 0, 0, 0, 1, '\x7b7d', $5, now())`,
		b.ID, ownerA.Tenant, ownerA.PrincipalID, StoreRef, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Error("a revision with a forged fingerprint was written")
	}
	// A revision of someone else's basket under another owner.
	if err := e.exec(`INSERT INTO glovo.basket_revisions (basket_id, revision, tenant, owner_principal_id, lines, currency, store_ref,
		subtotal_minor, delivery_fee_minor, service_fee_minor, discount_minor, total_minor, canonical, basket_fingerprint, created_at)
		VALUES ($1, 3, $2, $3, '[]', 'EUR', $4, 0, 0, 0, 0, 0, NULL, '', now())`, b.ID, ownerB.Tenant, ownerB.PrincipalID, StoreRef); err == nil {
		t.Error("a revision under another owner was written")
	}
	// An approval of a fingerprint the revision does not have, of a revision
	// that does not exist, and for another owner: the FK refuses each at
	// insert, inside the same transaction as the aar_.
	for name, in := range map[string]workitems.GlovoBasketApprovalInput{
		"wrong fingerprint": {Tenant: ownerA.Tenant, OwnerPrincipalID: ownerA.PrincipalID, BasketID: b.ID, Revision: 2,
			BasketFingerprint: "sha256:" + strings.Repeat("a", 64), ExpiresIn: time.Hour},
		"missing revision": {Tenant: ownerA.Tenant, OwnerPrincipalID: ownerA.PrincipalID, BasketID: b.ID, Revision: 7,
			BasketFingerprint: b.Current.Fingerprint, ExpiresIn: time.Hour},
		"other owner": {Tenant: ownerB.Tenant, OwnerPrincipalID: ownerB.PrincipalID, BasketID: b.ID, Revision: 2,
			BasketFingerprint: b.Current.Fingerprint, ExpiresIn: time.Hour},
	} {
		tx, err := e.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = workitems.CreateGlovoBasketApprovalTx(ctx, tx, in)
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if err == nil {
			t.Errorf("%s: an approval was bound", name)
		}
	}
}
