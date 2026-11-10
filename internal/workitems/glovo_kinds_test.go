package workitems

import (
	"strings"
	"testing"
	"time"
)

func goldenBinding() GlovoBinding {
	return GlovoBinding{
		Tenant: "acme", OwnerPrincipalID: "prn_OWNER00000000000000000001",
		ExecutionID: "we_ABCDEFGHIJKLMNOPQRSTUVWXYZ", WorkItemID: "wi_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		OrderRef: "ordr_ABCDEFGHIJKLMNOPQRSTUVWXYZ", ConnectionRef: "gcn_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		InstallID: "install-1", InstallRevision: "3",
		BasketFingerprint: "sha256:" + strings.Repeat("ab", 32), Provider: "fake",
	}
}

// The intent hash of the golden binding. A change to the encoding or to a
// field's place in it changes this value, which a stored approval would not
// survive, so it is pinned.
const goldenGlovoIntentHash = "sha256:ef84072cbb86b2eeb4cab726094f01289f38c08ef25a19e6a79da847d423cb3b"

func TestGlovoIntentGoldenAndEveryFieldCounts(t *testing.T) {
	b := goldenBinding()
	got := IntentHash(GlovoIntent(b))
	if got != goldenGlovoIntentHash {
		t.Fatalf("golden intent hash moved: %s", got)
	}
	in := GlovoIntent(b)
	if in.ActionKind != ActionKindGlovoPlaceOrderFake || in.PolicyRuleID != GlovoPolicyRuleID || in.PolicyVersion != "1" ||
		in.ArgsDigest != b.BasketFingerprint || in.ArtifactHash != "" || !strings.HasPrefix(in.Target, "glovo:v1:") {
		t.Fatalf("intent shape: %+v", in)
	}
	mut := map[string]func(*GlovoBinding){
		"tenant":      func(b *GlovoBinding) { b.Tenant += "x" },
		"owner":       func(b *GlovoBinding) { b.OwnerPrincipalID += "x" },
		"execution":   func(b *GlovoBinding) { b.ExecutionID += "x" },
		"work_item":   func(b *GlovoBinding) { b.WorkItemID += "x" },
		"order":       func(b *GlovoBinding) { b.OrderRef += "x" },
		"connection":  func(b *GlovoBinding) { b.ConnectionRef += "x" },
		"install":     func(b *GlovoBinding) { b.InstallID += "x" },
		"revision":    func(b *GlovoBinding) { b.InstallRevision += "0" },
		"fingerprint": func(b *GlovoBinding) { b.BasketFingerprint = "sha256:" + strings.Repeat("cd", 32) },
		"provider":    func(b *GlovoBinding) { b.Provider += "x" },
	}
	for name, m := range mut {
		c := goldenBinding()
		m(&c)
		if IntentHash(GlovoIntent(c)) == got {
			t.Errorf("changing %s does not change the intent hash", name)
		}
	}
	// The length prefix keeps field boundaries: moving a character across two
	// fields must not collide.
	x, y := goldenBinding(), goldenBinding()
	x.Tenant, x.OwnerPrincipalID = "ab", "prn_c"
	y.Tenant, y.OwnerPrincipalID = "abprn", "_c"
	if glovoTarget(x) == glovoTarget(y) {
		t.Error("target encoding is ambiguous across fields")
	}
}

func TestIsGlovoKindIsThePrefixPredicate(t *testing.T) {
	for kind, want := range map[string]bool{
		"glovo.place_order_fake": true, "glovo.other": true, "glovo.": true,
		"": false, "glove.place_order_fake": false, "x.glovo.place": false, "deploy.apply": false,
	} {
		if IsGlovoKind(kind) != want {
			t.Errorf("IsGlovoKind(%q) = %v", kind, !want)
		}
	}
	for _, k := range GlovoActionKinds {
		if !IsGlovoKind(k) {
			t.Errorf("%q is listed but not a Glovo kind", k)
		}
	}
	if len(GlovoActionKinds) != 1 || GlovoActionKinds[0] != "glovo.place_order_fake" {
		t.Errorf("M1 has exactly one Glovo kind: %v", GlovoActionKinds)
	}
}

func TestGlovoReceiptStateExpiryPrecedence(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	for _, c := range []struct {
		stored  string
		expires time.Time
		fresh   *time.Time
		want    string
	}{
		{ApprovalPending, future, nil, "pending"},
		{ApprovalPending, past, nil, "expired"},
		{ApprovalApproved, future, &future, "approved"},
		{ApprovalApproved, future, &past, "expired"},
		{ApprovalApproved, past, &future, "expired"},
		{ApprovalReserved, future, &future, "reserved"},
		{ApprovalReserved, past, &future, "expired"},
		{ApprovalReserved, future, &past, "expired"},
		// final records are never read as expired
		{ApprovalConsumed, past, &past, "consumed"},
		{ApprovalUnknown, past, &past, "unknown"},
		{ApprovalDenied, past, &past, "refused"},
	} {
		if got := GlovoReceiptState(c.stored, c.expires, c.fresh, now); got != c.want {
			t.Errorf("%s expires %v fresh %v: got %s want %s", c.stored, c.expires, c.fresh, got, c.want)
		}
	}
}
