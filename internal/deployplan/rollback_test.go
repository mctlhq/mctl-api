package deployplan

import (
	"strings"
	"testing"
)

func rollbackRecord() *Record {
	return &Record{ID: "dep_33333333-3333-3333-3333-333333333333", Tenant: "acme", Service: "web",
		CommitSHA: strings.Repeat("4", 40), ImageDigest: "sha256:" + strings.Repeat("a", 64)}
}

func TestRollbackIntent_RoundTripsAndRefusesAnythingElse(t *testing.T) {
	in := NewRollbackIntent(rollbackRecord())
	canon, err := in.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRollbackIntent(canon)
	if err != nil || got != in {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"unknown field": strings.Replace(canon, "}", `,"x":1}`, 1),
		"trailing":      canon + " {}",
		"reordered":     `{"tenant":"acme",` + strings.TrimPrefix(canon, "{"),
		"empty":         "",
		"short commit":  strings.Replace(canon, strings.Repeat("4", 40), strings.Repeat("4", 39), 1),
		"bad digest":    strings.Replace(canon, strings.Repeat("a", 64), "zz", 1),
		"bad id":        strings.Replace(canon, "dep_3333", "dap_3333", 1),
	} {
		if _, err := ParseRollbackIntent(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRollback_ApprovalIsOwnerOnly(t *testing.T) {
	a := RequiredApproval(EnvironmentProduction, ActionRollback)
	if !a.Required || a.Role != "owner" {
		t.Fatalf("approval = %+v", a)
	}
}

func TestRollbackValuesAfter_BindsCommitAndDigest(t *testing.T) {
	in := NewRollbackIntent(rollbackRecord())
	v := RollbackValuesAfter(in)
	if !strings.Contains(v, in.TargetCommit) || !strings.Contains(v, in.ExpectedDigest) {
		t.Fatalf("values_after hides what is restored: %q", v)
	}
}
