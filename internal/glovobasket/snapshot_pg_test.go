package glovobasket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func namesOf(r Revision) map[string]string {
	m := map[string]string{}
	for _, l := range r.Lines {
		m[l.ItemCode] = l.Name
	}
	return m
}

func (e *pgEnv) migConn() *pgx.Conn {
	e.t.Helper()
	c, err := pgx.Connect(context.Background(), e.migURL)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// snapshotOf reads the stored snapshot of one binding.
func (e *pgEnv) snapshotOf(approvalID string) (canonical []byte, lines string, fp string) {
	e.t.Helper()
	if err := e.pool.QueryRow(context.Background(), `SELECT snapshot_canonical, snapshot_lines::text, basket_fingerprint
		FROM glovo.basket_approval_bindings WHERE approval_id=$1`, approvalID).Scan(&canonical, &lines, &fp); err != nil {
		e.t.Fatalf("read snapshot of %s: %v", approvalID, err)
	}
	return canonical, lines, fp
}

func (e *pgEnv) bindingsOf(basketID string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM glovo.basket_approval_bindings WHERE basket_id=$1`, basketID).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func sha(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

// Schema 2 stores every binding with its frozen snapshot: the store writes
// it itself at version 2, and the BEFORE INSERT trigger fills it for a
// writer that does not (a binary still at version 1 semantics).
func TestPGSnapshotIsStoredWithEveryBinding(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	v, err := VerifySchemaVersion(ctx, e.pool)
	if err != nil || v != 2 {
		t.Fatalf("version %d: %v", v, err)
	}
	for name, version := range map[string]int{"store writes it": 2, "trigger fills it": 0} {
		e.store.SchemaVersion = version
		b := e.filled(ownerA)
		ap, err := e.store.RequestApproval(ctx, ownerA, b.ID, b.Current.Revision, time.Hour)
		if err != nil || !ap.Created {
			t.Fatalf("%s: request: %v", name, err)
		}
		canonical, lines, fp := e.snapshotOf(ap.ApprovalRef)
		if !bytes.Equal(canonical, b.Current.Canonical) || sha(canonical) != fp || fp != b.Current.Fingerprint {
			t.Fatalf("%s: snapshot %q fp %s, want %q %s", name, canonical, fp, b.Current.Canonical, b.Current.Fingerprint)
		}
		if !strings.Contains(lines, `"FAKE-COFFEE"`) || !strings.Contains(lines, `"name"`) {
			t.Fatalf("%s: lines %s", name, lines)
		}
	}
}

// forgeBinding writes a second binding for one revision of the basket of an
// existing approval, under a copy of that approval, with raw SQL as the
// runtime role: how a writer that skips every check of the store would
// insert.
func (e *pgEnv) forgeBinding(srcApproval, basketID string, revision int64, fp string, canonical []byte) error {
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cols []string
	rows, err := tx.Query(ctx, `SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'action_approval_requests' ORDER BY ordinal_position`)
	if err != nil {
		e.t.Fatal(err)
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			e.t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()
	sel := make([]string, len(cols))
	for i, c := range cols {
		switch c {
		case "id":
			sel[i] = "$1"
		case "idempotency_key":
			sel[i] = "idempotency_key || '-forged'"
		default:
			sel[i] = c
		}
	}
	id := "aar_" + hexN(16)
	if _, err := tx.Exec(ctx, `INSERT INTO public.action_approval_requests (`+strings.Join(cols, ",")+`)
		SELECT `+strings.Join(sel, ",")+` FROM public.action_approval_requests WHERE id = $2`, id, srcApproval); err != nil {
		e.t.Fatalf("forge approval: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.basket_approval_bindings
		(approval_id, tenant, owner_principal_id, basket_id, revision, basket_fingerprint, created_at, snapshot_canonical, snapshot_lines)
		SELECT $1, tenant, owner_principal_id, $2, $3, $4, clock_timestamp(), $5,
		       CASE WHEN $5::bytea IS NULL THEN NULL ELSE snapshot_lines END
		  FROM glovo.basket_approval_bindings WHERE approval_id = $6`, id, basketID, revision, fp, canonical, srcApproval); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// The CHECK holds against a writer that bypasses the store: a snapshot whose
// hash is not the binding's fingerprint is refused.
func TestPGSnapshotCheckRefusesAForeignSnapshot(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	e.store.SchemaVersion = 2
	b := e.filled(ownerA)
	r2 := b.Current
	b3, err := e.store.Update(ctx, ownerA, b.ID, r2.Revision, []Op{{Op: "add", ItemCode: "FAKE-PASTA", Quantity: 1}})
	if err != nil {
		t.Fatal(err)
	}
	ap, err := e.store.RequestApproval(ctx, ownerA, b.ID, b3.Current.Revision, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var pe *pgconn.PgError
	if err := e.forgeBinding(ap.ApprovalRef, b.ID, r2.Revision, r2.Fingerprint, b3.Current.Canonical); !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "basket_approval_bindings_snapshot_chk" {
		t.Fatalf("snapshot of another revision: %v", err)
	}
	// Control: the same row with the revision's own snapshot passes the
	// CHECK and is refused only by the approval/binding agreement guard, so
	// the refusal above is the snapshot CHECK's alone.
	if err := e.forgeBinding(ap.ApprovalRef, b.ID, r2.Revision, r2.Fingerprint, r2.Canonical); !errors.As(err, &pe) || pe.Code != "23000" {
		t.Fatalf("control: %v", err)
	}
}

// downgradeToV1 turns a schema-2 database into what basket schema 1 left:
// no snapshot columns, trigger, function or CHECK, version 1.
func (e *pgEnv) downgradeToV1() {
	e.t.Helper()
	mig := e.migConn()
	for _, s := range []string{
		`DROP TRIGGER basket_approval_bindings_snapshot ON glovo.basket_approval_bindings`,
		`ALTER TABLE glovo.basket_approval_bindings DROP CONSTRAINT basket_approval_bindings_snapshot_chk`,
		`ALTER TABLE glovo.basket_approval_bindings DROP COLUMN snapshot_canonical, DROP COLUMN snapshot_lines`,
		`DROP FUNCTION glovo.basket_approval_bindings_snapshot()`,
		`UPDATE glovo.basket_schema_version SET version = 1`,
	} {
		if _, err := mig.Exec(context.Background(), s); err != nil {
			e.t.Fatalf("downgrade %q: %v", s, err)
		}
	}
}

// A database still at schema 1 keeps working with this binary (the store
// writes no snapshot, the join path is not_ready), and migrating it to 2
// backfills every existing binding from its revision.
func TestPGSnapshotBackfillFromSchemaV1(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	e.downgradeToV1()
	v, err := VerifySchemaVersion(ctx, e.pool)
	if err != nil || v != 1 {
		t.Fatalf("v1: %d %v", v, err)
	}
	if err := VerifySchema(ctx, e.pool); err != nil {
		t.Fatalf("VerifySchema at v1: %v", err)
	}
	e.store.SchemaVersion = v
	b := e.filled(ownerA)
	ap, err := e.store.RequestApproval(ctx, ownerA, b.ID, b.Current.Revision, time.Hour)
	if err != nil {
		t.Fatalf("request at v1: %v", err)
	}
	snap, err := FreezeSnapshot(b.Current.Canonical, namesOf(b.Current))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.RequestApprovalFromSnapshot(ctx, ownerA, SnapshotApprovalInput{BasketID: b.ID, Revision: b.Current.Revision, Snapshot: snap}, time.Hour); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		t.Fatalf("join at v1: %v", err)
	}
	if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatalf("migrate to v2: %v", err)
	}
	if v, err := VerifySchemaVersion(ctx, e.pool); err != nil || v != 2 {
		t.Fatalf("after migrate: %d %v", v, err)
	}
	canonical, _, fp := e.snapshotOf(ap.ApprovalRef)
	if !bytes.Equal(canonical, b.Current.Canonical) || sha(canonical) != fp {
		t.Fatalf("backfill: %q %s", canonical, fp)
	}
	// The insert-only guard is back on after the backfill.
	if _, err := e.migConn().Exec(ctx, `UPDATE glovo.basket_approval_bindings SET snapshot_lines = snapshot_lines WHERE approval_id=$1`, ap.ApprovalRef); err == nil {
		t.Fatal("binding update accepted after the backfill")
	}
}

// A schema-2 database whose snapshot trigger or CHECK is gone is not ready,
// and a failed read is an error, never a version.
func TestPGVerifySchemaVersionRefusesAPartialV2(t *testing.T) {
	ctx := context.Background()
	for name, sql := range map[string]string{
		"trigger disabled": `ALTER TABLE glovo.basket_approval_bindings DISABLE TRIGGER basket_approval_bindings_snapshot`,
		"check dropped":    `ALTER TABLE glovo.basket_approval_bindings DROP CONSTRAINT basket_approval_bindings_snapshot_chk`,
	} {
		e := newPGEnv(t)
		if _, err := e.migConn().Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySchemaVersion(ctx, e.pool); !errors.Is(err, ErrSchemaNotReady) {
			t.Fatalf("%s: %v", name, err)
		}
		e.pool.Close()
		if v, err := VerifySchemaVersion(ctx, e.pool); err == nil || errors.Is(err, ErrSchemaNotReady) || v != 0 {
			t.Fatalf("%s: closed pool: %d %v", name, v, err)
		}
	}
}

// The join path stores the fingerprint mctl-api computed from the snapshot;
// a fingerprint the caller sent is only compared, and a mismatch writes
// nothing. While the foreign key exists, a revision that is not the owner's
// stored one is refused too.
func TestPGRequestApprovalFromSnapshot(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()
	e.store.SchemaVersion = 2
	b := e.filled(ownerA)
	snap, err := FreezeSnapshot(b.Current.Canonical, namesOf(b.Current))
	if err != nil || snap.Fingerprint != b.Current.Fingerprint {
		t.Fatalf("freeze: %s %v", snap.Fingerprint, err)
	}
	in := SnapshotApprovalInput{BasketID: b.ID, Revision: b.Current.Revision, Snapshot: snap}
	wrongFP := in
	wrongFP.BasketFingerprint = "sha256:" + strings.Repeat("0", 64)
	otherRev := in
	otherRev.Revision = 7
	tampered := in
	tampered.Snapshot.Fingerprint = wrongFP.BasketFingerprint
	for name, c := range map[string]struct {
		o    Owner
		in   SnapshotApprovalInput
		code glovo.Code
	}{
		"caller fingerprint differs": {ownerA, wrongFP, glovo.CodeFingerprintChanged},
		"unknown revision":           {ownerA, otherRev, glovo.CodeFingerprintChanged},
		"another owner":              {ownerB, in, glovo.CodeFingerprintChanged},
		"inconsistent snapshot":      {ownerA, tampered, glovo.CodeInvalidRequest},
	} {
		if _, err := e.store.RequestApprovalFromSnapshot(ctx, c.o, c.in, time.Hour); !errors.Is(err, glovo.Refuse(c.code)) {
			t.Fatalf("%s: %v", name, err)
		}
		if n := e.bindingsOf(b.ID); n != 0 {
			t.Fatalf("%s: %d bindings written", name, n)
		}
	}
	matching := in
	matching.BasketFingerprint = snap.Fingerprint
	ap, err := e.store.RequestApprovalFromSnapshot(ctx, ownerA, matching, time.Hour)
	if err != nil || !ap.Created || ap.Fingerprint != snap.Fingerprint || ap.State != "pending" {
		t.Fatalf("request: %+v %v", ap, err)
	}
	canonical, lines, fp := e.snapshotOf(ap.ApprovalRef)
	if fp != snap.Fingerprint || !bytes.Equal(canonical, snap.Canonical) || !strings.Contains(lines, namesOf(b.Current)["FAKE-APPLE"]) {
		t.Fatalf("stored: %s %q %s", fp, canonical, lines)
	}
	again, err := e.store.RequestApprovalFromSnapshot(ctx, ownerA, in, time.Hour)
	if err != nil || again.Created || again.ApprovalRef != ap.ApprovalRef {
		t.Fatalf("idempotent: %+v %v", again, err)
	}
}
